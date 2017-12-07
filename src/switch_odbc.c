/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Anthony Minessale II <anthm@freeswitch.org>
 *
 * switch_odbc.c -- ODBC
 *
 */

#include <switch.h>

#ifdef SWITCH_HAVE_ODBC
#include <sql.h>
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4201)
#include <sqlext.h>
#pragma warning(pop)
#else
#include <sqlext.h>
#endif
#include <sqltypes.h>

#if (ODBCVER < 0x0300)
#define SQL_NO_DATA SQL_SUCCESS
#endif

struct switch_odbc_handle {
	char *dsn;
	char *username;
	char *password;
	SQLHENV env;
	SQLHDBC con;
	switch_odbc_state_t state;
	char odbc_driver[256];
	BOOL is_firebird;
	BOOL is_oracle;
	int affected_rows;
	int num_retries;
};
#endif

SWITCH_DECLARE(switch_odbc_handle_t *) switch_odbc_handle_new(const char *dsn, const char *username, const char *password)
{
#ifdef SWITCH_HAVE_ODBC
	switch_odbc_handle_t *new_handle;

	if (!(new_handle = malloc(sizeof(*new_handle)))) {
		goto err;
	}

	memset(new_handle, 0, sizeof(*new_handle));

	if (!(new_handle->dsn = strdup(dsn))) {
		goto err;
	}

	if (username) {
		if (!(new_handle->username = strdup(username))) {
			goto err;
		}
	}

	if (password) {
		if (!(new_handle->password = strdup(password))) {
			goto err;
		}
	}

	new_handle->env = SQL_NULL_HANDLE;
	new_handle->state = SWITCH_ODBC_STATE_INIT;
	new_handle->affected_rows = 0;
	new_handle->num_retries = DEFAULT_ODBC_RETRIES;

	return new_handle;

  err:
	if (new_handle) {
		switch_safe_free(new_handle->dsn);
		switch_safe_free(new_handle->username);
		switch_safe_free(new_handle->password);
		switch_safe_free(new_handle);
	}
#endif
	return NULL;
}

SWITCH_DECLARE(void) switch_odbc_set_num_retries(switch_odbc_handle_t *handle, int num_retries)
{
#ifdef SWITCH_HAVE_ODBC
	if (handle) {
		handle->num_retries = num_retries;
	}
#endif
}

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_handle_disconnect(switch_odbc_handle_t *handle)
{
#ifdef SWITCH_HAVE_ODBC

	int result;

	if (!handle) {
		return SWITCH_ODBC_FAIL;
	}

	if (handle->state == SWITCH_ODBC_STATE_CONNECTED) {
		result = SQLDisconnect(handle->con);
		if (result == SWITCH_ODBC_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG10, "Disconnected %d from [%s]\n", result, handle->dsn);
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Disconnecting [%s]\n", handle->dsn);
		}
	}

	handle->state = SWITCH_ODBC_STATE_DOWN;

	return SWITCH_ODBC_SUCCESS;
#else
	return SWITCH_ODBC_FAIL;
#endif
}


#ifdef SWITCH_HAVE_ODBC
static switch_odbc_status_t init_odbc_handles(switch_odbc_handle_t *handle, switch_bool_t do_reinit)
{
	int result;

	if (!handle) {
		return SWITCH_ODBC_FAIL;
	}

	/* if handle is already initialized, and we're supposed to reinit - free old handle first */
	if (do_reinit == SWITCH_TRUE && handle->env != SQL_NULL_HANDLE) {
		SQLFreeHandle(SQL_HANDLE_DBC, handle->con);
		SQLFreeHandle(SQL_HANDLE_ENV, handle->env);
		handle->env = SQL_NULL_HANDLE;
	}

	if (handle->env == SQL_NULL_HANDLE) {
		result = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &handle->env);

		if ((result != SQL_SUCCESS) && (result != SQL_SUCCESS_WITH_INFO)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error AllocHandle\n");
			handle->env = SQL_NULL_HANDLE; /* Reset handle value, just in case */
			return SWITCH_ODBC_FAIL;
		}

		result = SQLSetEnvAttr(handle->env, SQL_ATTR_ODBC_VERSION, (void *) SQL_OV_ODBC3, 0);

		if ((result != SQL_SUCCESS) && (result != SQL_SUCCESS_WITH_INFO)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error SetEnv\n");
			SQLFreeHandle(SQL_HANDLE_ENV, handle->env);
			handle->env = SQL_NULL_HANDLE; /* Reset handle value after it's freed */
			return SWITCH_ODBC_FAIL;
		}

		result = SQLAllocHandle(SQL_HANDLE_DBC, handle->env, &handle->con);

		if ((result != SQL_SUCCESS) && (result != SQL_SUCCESS_WITH_INFO)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error AllocHDB %d\n", result);
			SQLFreeHandle(SQL_HANDLE_ENV, handle->env);
			handle->env = SQL_NULL_HANDLE; /* Reset handle value after it's freed */
			return SWITCH_ODBC_FAIL;
		}
		SQLSetConnectAttr(handle->con, SQL_LOGIN_TIMEOUT, (SQLPOINTER *) 10, 0);
	}

	return SWITCH_ODBC_SUCCESS;
}

static int db_is_up(switch_odbc_handle_t *handle)
{
	int ret = 0;
	SQLHSTMT stmt = NULL;
	SQLLEN m = 0;
	int result;
	switch_event_t *event;
	switch_odbc_status_t recon = 0;
	char *err_str = NULL;
	SQLCHAR sql[255] = "";
	int max_tries = DEFAULT_ODBC_RETRIES;
	int code = 0;
	SQLRETURN rc;
	SQLSMALLINT nresultcols;


	if (handle) {
		max_tries = handle->num_retries;
		if (max_tries < 1)
			max_tries = DEFAULT_ODBC_RETRIES;
	}

  top:

	if (!handle) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "No DB Handle\n");
		goto done;
	}

	if (handle->is_oracle) {
		strcpy((char *) sql, "select 1 from dual");
	} else if (handle->is_firebird) {
		strcpy((char *) sql, "select first 1 * from RDB$RELATIONS");
	} else {
		strcpy((char *) sql, "select 1");
	}

	if (SQLAllocHandle(SQL_HANDLE_STMT, handle->con, &stmt) != SQL_SUCCESS) {
		code = __LINE__;
		goto error;
	}

	SQLSetStmtAttr(stmt, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)30, 0);

	if (SQLPrepare(stmt, sql, SQL_NTS) != SQL_SUCCESS) {
		code = __LINE__;
		goto error;
	}

	result = SQLExecute(stmt);

	if (result != SQL_SUCCESS && result != SQL_SUCCESS_WITH_INFO) {
		code = __LINE__;
		goto error;
	}

	SQLRowCount(stmt, &m);
	rc = SQLNumResultCols(stmt, &nresultcols);
	if (rc != SQL_SUCCESS) {
		code = __LINE__;
		goto error;
	}
	ret = (int) nresultcols;
	/* determine statement type */
	if (nresultcols <= 0) {
		/* statement is not a select statement */
		code = __LINE__;
		goto error;
	}

	goto done;

  error:
	err_str = switch_odbc_handle_get_error(handle, stmt);

	/* Make sure to free the handle before we try to reconnect */
	if (stmt) {
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		stmt = NULL;
	}

	recon = switch_odbc_handle_connect(handle);

	max_tries--;

	if (switch_event_create(&event, SWITCH_EVENT_TRAP) == SWITCH_STATUS_SUCCESS) {
		switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Failure-Message", "The sql server is not responding for DSN %s [%s][%d]",
								switch_str_nil(handle->dsn), switch_str_nil(err_str), code);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "The sql server is not responding for DSN %s [%s][%d]\n",
						  switch_str_nil(handle->dsn), switch_str_nil(err_str), code);

		if (recon == SWITCH_ODBC_SUCCESS) {
			switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Additional-Info", "The connection has been re-established");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "The connection has been re-established\n");
		} else {
			switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Additional-Info", "The connection could not be re-established");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "The connection could not be re-established\n");
		}
		if (!max_tries) {
			switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Additional-Info", "Giving up!");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Giving up!\n");
		}

		switch_event_fire(&event);
	}

	if (!max_tries) {
		goto done;
	}

	switch_safe_free(err_str);
	switch_yield(1000000);
	goto top;

  done:

	switch_safe_free(err_str);

	if (stmt) {
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	}

	return ret;
}
#endif

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_statement_handle_free(switch_odbc_statement_handle_t *stmt)
{
	if (!stmt || !*stmt) {
		return SWITCH_ODBC_FAIL;
	}
#ifdef SWITCH_HAVE_ODBC
	SQLFreeHandle(SQL_HANDLE_STMT, *stmt);
	*stmt = NULL;
	return SWITCH_ODBC_SUCCESS;
#else
	return SWITCH_ODBC_FAIL;
#endif
}


SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_handle_connect(switch_odbc_handle_t *handle)
{
#ifdef SWITCH_HAVE_ODBC
	int result;
	SQLINTEGER err;
	int16_t mlen;
	unsigned char msg[200] = "", stat[10] = "";
	SQLSMALLINT valueLength = 0;
	int i = 0;

	init_odbc_handles(handle, SWITCH_FALSE); /* Init ODBC handles, if they are already initialized, don't do it again */

	if (handle->state == SWITCH_ODBC_STATE_CONNECTED) {
		switch_odbc_handle_disconnect(handle);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "Re-connecting %s\n", handle->dsn);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "Connecting %s\n", handle->dsn);

	if (!strstr(handle->dsn, "DRIVER")) {
		result = SQLConnect(handle->con, (SQLCHAR *) handle->dsn, SQL_NTS, (SQLCHAR *) handle->username, SQL_NTS, (SQLCHAR *) handle->password, SQL_NTS);
	} else {
		SQLCHAR outstr[1024] = { 0 };
		SQLSMALLINT outstrlen = 0;
		result =
			SQLDriverConnect(handle->con, NULL, (SQLCHAR *) handle->dsn, (SQLSMALLINT) strlen(handle->dsn), outstr, sizeof(outstr), &outstrlen,
							 SQL_DRIVER_NOPROMPT);
	}

	if ((result != SQL_SUCCESS) && (result != SQL_SUCCESS_WITH_INFO)) {
		char *err_str;
		if ((err_str = switch_odbc_handle_get_error(handle, NULL))) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s\n", err_str);
			free(err_str);
		} else {
			SQLGetDiagRec(SQL_HANDLE_DBC, handle->con, 1, stat, &err, msg, sizeof(msg), &mlen);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error SQLConnect=%d errno=%d [%s]\n", result, (int) err, msg);
		}

		/* Deallocate handles again, more chanses to succeed when reconnecting */
		init_odbc_handles(handle, SWITCH_TRUE); /* Reinit ODBC handles */
		return SWITCH_ODBC_FAIL;
	}

	result = SQLGetInfo(handle->con, SQL_DRIVER_NAME, (SQLCHAR *) handle->odbc_driver, 255, &valueLength);
	if (result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO) {
		for (i = 0; i < valueLength; ++i)
			handle->odbc_driver[i] = (char) toupper(handle->odbc_driver[i]);
	}

	if (strstr(handle->odbc_driver, "SQORA32.DLL") != 0 || strstr(handle->odbc_driver, "SQORA64.DLL") != 0) {
		handle->is_firebird = FALSE;
		handle->is_oracle = TRUE;
	} else if (strstr(handle->odbc_driver, "FIREBIRD") != 0 || strstr(handle->odbc_driver, "FB32") != 0 || strstr(handle->odbc_driver, "FB64") != 0) {
		handle->is_firebird = TRUE;
		handle->is_oracle = FALSE;
	} else {
		handle->is_firebird = FALSE;
		handle->is_oracle = FALSE;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "Connected to [%s]\n", handle->dsn);
	handle->state = SWITCH_ODBC_STATE_CONNECTED;
	return SWITCH_ODBC_SUCCESS;
#else
	return SWITCH_ODBC_FAIL;
#endif
}

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_handle_exec_string(switch_odbc_handle_t *handle, const char *sql, char *resbuf, size_t len, char **err)
{
#ifdef SWITCH_HAVE_ODBC
	switch_odbc_status_t sstatus = SWITCH_ODBC_FAIL;
	switch_odbc_statement_handle_t stmt = NULL;
	SQLCHAR name[1024];
	SQLLEN m = 0;

	handle->affected_rows = 0;

	if (switch_odbc_handle_exec(handle, sql, &stmt, err) == SWITCH_ODBC_SUCCESS) {
		SQLSMALLINT NameLength, DataType, DecimalDigits, Nullable;
		SQLULEN ColumnSize;
		int result;

		SQLRowCount(stmt, &m);
		handle->affected_rows = (int) m;

		if (m == 0) {
			goto done;
		}

		result = SQLFetch(stmt);

		if (result != SQL_SUCCESS && result != SQL_SUCCESS_WITH_INFO && result != SQL_NO_DATA) {
			goto done;
		}

		SQLDescribeCol(stmt, 1, name, sizeof(name), &NameLength, &DataType, &ColumnSize, &DecimalDigits, &Nullable);
		SQLGetData(stmt, 1, SQL_C_CHAR, (SQLCHAR *) resbuf, (SQLLEN) len, NULL);

		sstatus = SWITCH_ODBC_SUCCESS;
	}

	done:

	switch_odbc_statement_handle_free(&stmt);

	return sstatus;
#else
	return SWITCH_ODBC_FAIL;
#endif
}

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_handle_exec_params(switch_odbc_handle_t *handle, const char *sql, switch_odbc_statement_handle_t *rstmt,
															char const* const* params, int params_count, char **err)
{
#ifdef SWITCH_HAVE_ODBC
	SQLLEN nts = SQL_NTS, nul = SQL_NULL_DATA;
	SQLHSTMT stmt = NULL;
	int result;
	char *err_str = NULL, *err2 = NULL;
	SQLLEN m = 0;

	handle->affected_rows = 0;

	if (!db_is_up(handle)) {
		goto error;
	}

	if (SQLAllocHandle(SQL_HANDLE_STMT, handle->con, &stmt) != SQL_SUCCESS) {
		err2 = "SQLAllocHandle failed.";
		goto error;
	}

	if (SQLPrepare(stmt, (unsigned char *) sql, SQL_NTS) != SQL_SUCCESS) {
		err2 = "SQLPrepare failed.";
		goto error;
	}

	if ((params) && (params_count > 0)) {
		SQLUSMALLINT i;
		for(i = 0; i < (SQLUSMALLINT)params_count; ++i) {
			const char *param = params[i];
			if (param == NULL) {
				result = SQLBindParameter(stmt, i + 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 0, 0, NULL, 0, &nul);
			}
			else {
				result = SQLBindParameter(stmt, i + 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 0, 0, (SQLPOINTER)param, 0, &nts);
			}
			if (!SQL_SUCCEEDED(result)) {
				err2 = "Unable to bind SQL parameter!";
				goto error;
			}
		}
	}

	result = SQLExecute(stmt);

	switch (result) {
	case SQL_SUCCESS:
	case SQL_SUCCESS_WITH_INFO:
	case SQL_NO_DATA:
		break;
	case SQL_ERROR:
		err2 = "SQLExecute returned SQL_ERROR.";
		goto error;
		break;
	case SQL_NEED_DATA:
		err2 = "SQLExecute returned SQL_NEED_DATA.";
		goto error;
		break;
	default:
		err2 = "SQLExecute returned unknown result code.";
		goto error;
	}

	SQLRowCount(stmt, &m);
	handle->affected_rows = (int) m;

	if (rstmt) {
		*rstmt = stmt;
	} else {
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	}

	return SWITCH_ODBC_SUCCESS;

  error:


	if (stmt) {
		err_str = switch_odbc_handle_get_error(handle, stmt);
	}

	if (zstr(err_str)) {
		if (err2) {
			err_str = strdup(err2);
		} else {
			err_str = strdup((char *)"SQL ERROR!");
		}
	}

	if (err_str) {
		if (!switch_stristr("already exists", err_str) && !switch_stristr("duplicate key name", err_str)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ERR: [%s]\n[%s]\n", sql, switch_str_nil(err_str));
		}
		if (err) {
			*err = err_str;
		} else {
			free(err_str);
		}
	}

	if (rstmt) {
		*rstmt = stmt;
	} else if (stmt) {
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	}
#endif
	return SWITCH_ODBC_FAIL;
}

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_handle_exec(switch_odbc_handle_t *handle, const char *sql, switch_odbc_statement_handle_t *rstmt,
															char **err)
{
	return switch_odbc_handle_exec_params(handle, sql, rstmt, NULL, 0, err);
}

#ifdef SWITCH_HAVE_ODBC

typedef struct column_buffer_tag {
	char *d;
	size_t s;
	size_t c;
} column_buffer_t;

/*
static void column_buffer_init(column_buffer_t *b) {
	b->d = 0;
	b->s = b->c = 0;
}
*/

static char* column_buffer_reset(column_buffer_t *b) {
	b->s = 0;
	return b->d;
}

static size_t column_buffer_free_size(column_buffer_t *b) {
	return b->c - b->s;
}

static char* column_buffer_ensure(column_buffer_t *b, size_t size) {
	size_t free_space = b->c - b->s;

	if(free_space < size){
		size_t requred_space = size - free_space;
		size_t delta = 0;
		char *tmp;

		if (b->c) {
			delta = b->c >> 1;
		}

		if (delta < requred_space) {
			delta = requred_space;
		}

		tmp = malloc(b->c + delta);
		if (tmp) {
			if (b->d) {
				memcpy(tmp, b->d, b->s);
				free(b->d);
			}
			b->d = tmp;
			b->c += delta;
		}
		else {
			return NULL;
		}
	}
	return b->d + b->s;
}

static void column_buffer_add_size(column_buffer_t *b, size_t size) {
	size_t s = b->s + size;
	switch_assert(s <= b->c);
	b->s = s;
}

static char* column_buffer_data(column_buffer_t *b) {
	return b->d;
}

/*
static size_t column_buffer_size(column_buffer_t *b) {
	return b->s;
}
*/

static void column_buffer_free(column_buffer_t *b) {
	if(b->d){
		free(b->d);
	}
	b->d = 0;
	b->s = b->c = 0;
}

#endif

#ifdef SWITCH_HAVE_ODBC

static int column_has_more_data(SQLHSTMT stmt, SQLRETURN result){
	if (result == SQL_SUCCESS_WITH_INFO) {
		SQLCHAR state[6];
		SQLRETURN rc;
		SQLSMALLINT i = 1;
		while ((rc = SQLGetDiagRec(SQL_HANDLE_STMT, stmt, i, state, NULL, NULL, 0, NULL)) != SQL_NO_DATA) {
			if (SQL_SUCCEEDED(rc) && (0 == strncmp((char*)state, "01004", 5))) {
				return 1;
			}
			i++;
		}
	}
	return 0;
}

#endif

#ifdef SWITCH_HAVE_ODBC
#  define SWITCH_ODBC_INIT_COLUMN_SIZE 4096
#endif

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_handle_callback_exec_detailed_params(const char *file, const char *func, int line,
																			   switch_odbc_handle_t *handle,
																			   const char *sql, switch_core_db_callback_func_t callback, void *pdata,
																			   char const* const* params, int params_count, char **err)
{
#ifdef SWITCH_HAVE_ODBC
	SQLLEN nts = SQL_NTS, nul = SQL_NULL_DATA;
	SQLHSTMT stmt = NULL;
	SQLSMALLINT c = 0, x = 0;
	SQLLEN m = 0;
	char *x_err = NULL, *err_str = NULL;
	SQLRETURN result;
	int err_cnt = 0;
	int done = 0;
	char **names = 0;
	char **vals = 0;
	column_buffer_t *cols = 0;

	handle->affected_rows = 0;

	switch_assert(callback != NULL);

	if (!db_is_up(handle)) {
		x_err = "DB is not up!";
		goto error;
	}

	if (SQLAllocHandle(SQL_HANDLE_STMT, handle->con, &stmt) != SQL_SUCCESS) {
		x_err = "Unable to SQL allocate handle!";
		goto error;
	}

	if (SQLPrepare(stmt, (unsigned char *) sql, SQL_NTS) != SQL_SUCCESS) {
		x_err = "Unable to prepare SQL statement!";
		goto error;
	}

	if ((params) && (params_count > 0)) {
		SQLUSMALLINT i;
		for(i = 0; i < (SQLUSMALLINT)params_count; ++i) {
			const char *param = params[i];
			if (param == NULL) {
				result = SQLBindParameter(stmt, i + 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 0, 0, NULL, 0, &nul);
			}
			else {
				result = SQLBindParameter(stmt, i + 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 0, 0, (SQLPOINTER)param, 0, &nts);
			}
			if (!SQL_SUCCEEDED(result)) {
				x_err = "Unable to bind SQL parameter!";
				goto error;
			}
		}
	}

	result = SQLExecute(stmt);

	if (result != SQL_SUCCESS && result != SQL_SUCCESS_WITH_INFO && result != SQL_NO_DATA) {
		x_err = "execute error!";
		goto error;
	}

	SQLNumResultCols(stmt, &c);
	SQLRowCount(stmt, &m);
	handle->affected_rows = (int) m;

	while (!done) {
		result = SQLFetch(stmt);

		if (result != SQL_SUCCESS) {
			if (result != SQL_NO_DATA) {
				x_err = "Unable to fetch row";
				err_cnt++;
			}
			break;
		}

		if (!names) {
			/* allocate only once and only if Fetch success*/
			names = calloc(2 * c, sizeof(*names));
			cols = calloc(c, sizeof(*cols));

			switch_assert(names && cols);

			memset(names, 0, c * sizeof(*names));
			memset(cols, 0, c * sizeof(*cols));
			vals = &names[c];

			/* call SQLDescribeCol only once for each column*/
			for (x = 0; x < c; x++) {
				SQLSMALLINT NameLength = 256, DataType = 0, DecimalDigits = 0, Nullable = 0;
				SQLULEN ColumnSize = 0; char *data;

				names[x] = malloc(NameLength);

				switch_assert(names[x]);

				memset(names[x], 0, NameLength);

				result = SQLDescribeCol(stmt, x + 1, (SQLCHAR *)names[x], NameLength, &NameLength, &DataType, &ColumnSize, &DecimalDigits, &Nullable);

				if (!SQL_SUCCEEDED(result)) {
					x_err = "Describe column error";
					err_cnt++;
					break;
				}

				/* some drivers returns some big value for all data.
				e.g. pgsql returns by default 8k for TEXT type.
				Sybase ASA drivers returns 32k for all output params
				for stored proc. So we reduce init size to some sane value */
				if ((!ColumnSize) || (ColumnSize > SWITCH_ODBC_INIT_COLUMN_SIZE)) {
					ColumnSize = SWITCH_ODBC_INIT_COLUMN_SIZE - 1;
				}
				ColumnSize++;

				/* allocate column buffer */
				data = column_buffer_ensure(&cols[x], ColumnSize);
				switch_assert(data);
			}

			if (!SQL_SUCCEEDED(result)) {
				break;
			}
		}

		/* Get data for each column*/
		for (x = 0; x < c; x++) {
			SQLLEN got;
			column_buffer_t *value = &cols[x];
			/* buffer has at least `ColumnSize` avaliable memory because we init it when get column names*/
			char *data = column_buffer_reset(value);
			/* we pass full buffer size at first call */
			SQLUINTEGER chunk_size = column_buffer_free_size(value);

			result = SQLGetData(stmt, x+1, SQL_C_CHAR, data, chunk_size, &got);
			if (got != SQL_NULL_DATA) {
				while (column_has_more_data(stmt, result)) {
					if ((got > 0) && ((SQLUINTEGER)got >= chunk_size)) {
						/* driver may returns number of rest of data.
						But this info may be not accurate and some drivers
						has some bugs so we just continue execute in loop */
						column_buffer_add_size(value, chunk_size - 1);
						data = column_buffer_ensure(value, got - (chunk_size - 1) + 1);
					}
					else if (got == SQL_NO_TOTAL) {
						/* unknown size. Driver should fill full buffer */
						column_buffer_add_size(value, chunk_size - 1);
						data = column_buffer_ensure(value, SWITCH_ODBC_INIT_COLUMN_SIZE);
					}
					else {
						/*this is not last chunk but driver fill not full buffer
						this is not documented bihavior and I never see this but just in case.
						assume that driver returns size without null teminated char*/
						column_buffer_add_size(value, got);
						data = column_buffer_ensure(value, SWITCH_ODBC_INIT_COLUMN_SIZE);
					}
					chunk_size = column_buffer_free_size(value);

					switch_assert(data);

					result = SQLGetData(stmt, x+1, SQL_C_CHAR, data, chunk_size, &got);
				}
				/* returns size without last terminated null symbol */
				column_buffer_add_size(value, got + 1);
				vals[x] = column_buffer_data(value);
			}
			else{
				vals[x] = NULL;
			}

			if (!SQL_SUCCEEDED(result)) {
				x_err = "Get column data error";
				err_cnt++;
				break;
			}
		}

		if (!SQL_SUCCEEDED(result)) {
			break;
		}

		if (callback(pdata, c, vals, names)) {
			done = 1;
		}
	}

	if (names) {
		for (x = 0; x < c; x++) {
			free(names[x]);
			column_buffer_free(&cols[x]);
		}
		free(names);
		free(cols);
	}

	if (!err_cnt) {
		/* make sure we can retrive last error for statement */
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		return SWITCH_ODBC_SUCCESS;
	}

  error:

	if (stmt) {
		err_str = switch_odbc_handle_get_error(handle, stmt);
	}

	if (zstr(err_str) && !zstr(x_err)) {
		err_str = strdup(x_err);
	}

	if (err_str) {
		switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, func, line, NULL, SWITCH_LOG_ERROR, "ERR: [%s]\n[%s]\n", sql, switch_str_nil(err_str));
		if (err) {
			*err = err_str;
		} else {
			free(err_str);
		}
	}

	if (stmt) {
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	}

#endif
	return SWITCH_ODBC_FAIL;
}

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_handle_callback_exec_detailed(const char *file, const char *func, int line,
																			   switch_odbc_handle_t *handle,
																			   const char *sql, switch_core_db_callback_func_t callback, void *pdata,
																			   char **err)
{
	return switch_odbc_handle_callback_exec_detailed_params(file, func, line, handle, sql, callback, pdata, NULL, 0, err);
}

SWITCH_DECLARE(void) switch_odbc_handle_destroy(switch_odbc_handle_t **handlep)
{
#ifdef SWITCH_HAVE_ODBC

	switch_odbc_handle_t *handle = NULL;

	if (!handlep) {
		return;
	}
	handle = *handlep;

	if (handle) {
		switch_odbc_handle_disconnect(handle);

		if (handle->env != SQL_NULL_HANDLE) {
			SQLFreeHandle(SQL_HANDLE_DBC, handle->con);
			SQLFreeHandle(SQL_HANDLE_ENV, handle->env);
		}
		switch_safe_free(handle->dsn);
		switch_safe_free(handle->username);
		switch_safe_free(handle->password);
		free(handle);
	}
	*handlep = NULL;
#else
	return;
#endif
}

SWITCH_DECLARE(switch_odbc_state_t) switch_odbc_handle_get_state(switch_odbc_handle_t *handle)
{
#ifdef SWITCH_HAVE_ODBC
	return handle ? handle->state : SWITCH_ODBC_STATE_INIT;
#else
	return SWITCH_ODBC_STATE_ERROR;
#endif
}

SWITCH_DECLARE(char *) switch_odbc_handle_get_error(switch_odbc_handle_t *handle, switch_odbc_statement_handle_t stmt)
{
#ifdef SWITCH_HAVE_ODBC

	char buffer[SQL_MAX_MESSAGE_LENGTH + 1] = "";
	char sqlstate[SQL_SQLSTATE_SIZE + 1] = "";
	SQLINTEGER sqlcode;
	SQLSMALLINT length;
	char *ret = NULL;

	if (SQLError(handle->env, handle->con, stmt, (SQLCHAR *) sqlstate, &sqlcode, (SQLCHAR *) buffer, sizeof(buffer), &length) == SQL_SUCCESS) {
		ret = switch_mprintf("STATE: %s CODE %ld ERROR: %s\n", sqlstate, sqlcode, buffer);
	};

	return ret;
#else
	return NULL;
#endif
}

SWITCH_DECLARE(int) switch_odbc_handle_affected_rows(switch_odbc_handle_t *handle)
{
#ifdef SWITCH_HAVE_ODBC
	return handle->affected_rows;
#else
	return 0;
#endif
}

SWITCH_DECLARE(switch_bool_t) switch_odbc_available(void)
{
#ifdef SWITCH_HAVE_ODBC
	return SWITCH_TRUE;
#else
	return SWITCH_FALSE;
#endif
}

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_SQLSetAutoCommitAttr(switch_odbc_handle_t *handle, switch_bool_t on)
{
#ifdef SWITCH_HAVE_ODBC
	if (on) {
		return SQLSetConnectAttr(handle->con, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER *) SQL_AUTOCOMMIT_ON, 0 );
	} else {
		return SQLSetConnectAttr(handle->con, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER *) SQL_AUTOCOMMIT_OFF, 0 );
	}
#else
	return (switch_odbc_status_t) SWITCH_FALSE;
#endif
}

SWITCH_DECLARE(switch_odbc_status_t) switch_odbc_SQLEndTran(switch_odbc_handle_t *handle, switch_bool_t commit)
{
#ifdef SWITCH_HAVE_ODBC
	if (commit) {
		return SQLEndTran(SQL_HANDLE_DBC, handle->con, SQL_COMMIT);
	} else {
		return SQLEndTran(SQL_HANDLE_DBC, handle->con, SQL_ROLLBACK);
	}
#else
	return (switch_odbc_status_t) SWITCH_FALSE;
#endif
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
