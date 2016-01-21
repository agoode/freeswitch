/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2012, Anthony Minessale II <anthm@freeswitch.org>
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
 * Emmanuel Schmidbauer <eschmidbauer@gmail.com>
 *
 * mod_usrloc.c
 *
 */

#include <switch.h>

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_usrloc_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_usrloc_load);
SWITCH_MODULE_DEFINITION(mod_usrloc, mod_usrloc_load, mod_usrloc_shutdown, NULL);

static const char *global_cf = "usrloc.conf";

static struct {
	char *odbc_dsn;
	char *table_name;
	char *user_column;
	char *domain_column;
	char *received_column;
	char *socket_column;
	switch_bool_t use_proxy;
	uint32_t running;
	switch_mutex_t *mutex;
	switch_memory_pool_t *pool;
} globals;

switch_cache_db_handle_t *get_db_handle(void)
{
	switch_cache_db_handle_t *dbh = NULL;
	char *dsn;
	if (!zstr(globals.odbc_dsn)) {
		dsn = globals.odbc_dsn;
		if (switch_cache_db_get_db_handle_dsn(&dbh, dsn) != SWITCH_STATUS_SUCCESS) {
			dbh = NULL;
		}
	}
	return dbh;
}

static switch_bool_t usrloc_execute_sql(char *sql, switch_core_db_callback_func_t callback, void *pdata)
{
	switch_bool_t retval = SWITCH_FALSE;
	switch_cache_db_handle_t *dbh = NULL;

	if (globals.odbc_dsn && (dbh = get_db_handle())) {
		if (switch_cache_db_execute_sql_callback(dbh, sql, callback, pdata, NULL) != SWITCH_STATUS_SUCCESS) {
			retval = SWITCH_FALSE;
		} else {
			retval = SWITCH_TRUE;
		}
	}
	switch_cache_db_release_db_handle(&dbh);
	return retval;
}

static int usrloc_contact_str_db(void *pArg, int argc, char **argv, char **columnNames)
{
	switch_stream_handle_t *stream = (switch_stream_handle_t *) pArg;

	char *extension = argv[0];
	char *received = argv[1];
	char *socket = argv[2];

	// make sure 'received' starts with 'sip:', and socket starts with a valid protocol
	if ((!strncasecmp(received, "sip:", 4)) && ((!strncasecmp(socket, "udp:", 4) || (!strncasecmp(socket, "tcp:", 4) || (!strncasecmp(socket, "tls:", 4)))))) {
		char *to_server = &received[4];
		char *fs_path = &socket[4];

		// if string is started, prepends a comma
		if (!zstr(stream->data)) {
			stream->write_function(stream, ",");
		}

		if (globals.use_proxy == SWITCH_TRUE) {
			stream->write_function(stream, "sip:%s@%s;fs_path=sip:%s", extension, to_server, fs_path);
		} else {
			stream->write_function(stream, "sip:%s@%s", extension, to_server);
		}
	}

	return 0;
}

static char *usrloc_contact_str(const char *domain, const char *user)
{
	switch_stream_handle_t stream = { 0 };

	SWITCH_STANDARD_STREAM(stream);
	if (user && domain) {
		char *sql = switch_mprintf("select %s, %s, %s from %s where %s = '%q' and %s = '%q'", globals.user_column, globals.received_column, globals.socket_column, globals.table_name, globals.user_column, user, globals.domain_column, domain);
		usrloc_execute_sql(sql, usrloc_contact_str_db, &stream);
		switch_safe_free(sql);
	} else if (domain) {
		char *sql = switch_mprintf("select %s, %s, %s from %s where %s = '%q'", globals.user_column, globals.received_column, globals.socket_column, globals.table_name, globals.domain_column, domain);
		usrloc_execute_sql(sql, usrloc_contact_str_db, &stream);
		switch_safe_free(sql);
	}

	return stream.data;
}

#define USRLOC "sofia_profile domain user"
SWITCH_STANDARD_APP(usrloc_app_function)
{
	char *lbuf;
	if (!zstr(data) && (lbuf = switch_core_session_strdup(session, data))) {
		char *argv[3];
		int argc;
		if ((argc = switch_separate_string(lbuf, ' ', argv, (sizeof(argv) / sizeof(argv[0])))) >= 2) {
			const char *sofia_profile = argv[0];
			const char *domain = argv[1];
			const char *user = NULL;
			char *contact_full = NULL;
			char *contact_uri_dup = NULL;
			switch_memory_pool_t *pool = switch_core_session_get_pool(session); // use the session pool

			if (argc > 2) {
				user = argv[2];
			}

			contact_uri_dup = usrloc_contact_str(domain, user);
			if (contact_uri_dup) {
				switch_stream_handle_t sofia_stream = { 0 };
				int32_t contact_uri_num = 0;
				char *contact_uri_list[512] = { 0 };
				int32_t contact_uri_i;
				contact_uri_num = switch_separate_string(contact_uri_dup, ',', contact_uri_list, (sizeof(contact_uri_list) / sizeof(contact_uri_list[0])));

				SWITCH_STANDARD_STREAM(sofia_stream);
				for (contact_uri_i = 0; contact_uri_i < contact_uri_num; contact_uri_i++) {
					const char *contact_uri = contact_uri_list[contact_uri_i];
					if (contact_uri_i > 0) {
						sofia_stream.write_function(&sofia_stream, ",sofia/%s/%s", sofia_profile, contact_uri);
					} else {
						sofia_stream.write_function(&sofia_stream, "sofia/%s/%s", sofia_profile, contact_uri);
					}
				}

				switch_safe_free(contact_uri_dup);
				contact_full = switch_core_strdup(pool, sofia_stream.data);
				switch_safe_free(sofia_stream.data);
			}

			if (contact_full && !zstr(contact_full)) {
				switch_channel_t *channel = switch_core_session_get_channel(session);
				switch_channel_set_variable(channel, "usrloc_auto_route", contact_full);
			}
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Usage: %s\n", USRLOC);
	}

}

#define USRLOC_API_SYNTAX "\
usrloc [sofia_profile] [domain] [user]\n"
SWITCH_STANDARD_API(usrloc_api_function)
{
	char *mydata = NULL, *argv[3] = { 0 };
	const char *sofia_profile = NULL;
	const char *domain = NULL;
	const char *user = NULL;
	int argc;
	char *contact_full = NULL;
	char *contact_uri_dup = NULL;

	if (!globals.running) {
		return SWITCH_STATUS_FALSE;
	}

	if (zstr(cmd)) {
		stream->write_function(stream, "-USAGE: \n%s\n", USRLOC_API_SYNTAX);
		return SWITCH_STATUS_SUCCESS;
	}

	mydata = strdup(cmd);
	switch_assert(mydata);

	argc = switch_separate_string(mydata, ' ', argv, (sizeof(argv) / sizeof(argv[0])));

	if (argc < 2) {
		stream->write_function(stream, "-USAGE: \n%s\n", USRLOC_API_SYNTAX);
		goto done;
	}

	sofia_profile = argv[0];
	domain = argv[1];

	if (argc > 2) {
		user = argv[2];
	}

	contact_uri_dup = usrloc_contact_str(domain, user);
	if (contact_uri_dup) {
		switch_stream_handle_t sofia_stream = { 0 };
		int32_t contact_uri_num = 0;
		char *contact_uri_list[512] = { 0 };
		int32_t contact_uri_i;
		contact_uri_num = switch_separate_string(contact_uri_dup, ',', contact_uri_list, (sizeof(contact_uri_list) / sizeof(contact_uri_list[0])));

		SWITCH_STANDARD_STREAM(sofia_stream);
		for (contact_uri_i = 0; contact_uri_i < contact_uri_num; contact_uri_i++) {
			const char *contact_uri = contact_uri_list[contact_uri_i];
			if (contact_uri_i > 0) {
				sofia_stream.write_function(&sofia_stream, ",sofia/%s/%s", sofia_profile, contact_uri);
			} else {
				sofia_stream.write_function(&sofia_stream, "sofia/%s/%s", sofia_profile, contact_uri);
			}
		}

		switch_safe_free(contact_uri_dup);
		contact_full = strdup(sofia_stream.data);
		switch_safe_free(sofia_stream.data);
	}

	if (!contact_full || zstr(contact_full)) {
		stream->write_function(stream, "error/user_not_found");
	} else {
		stream->write_function(stream, "%s", contact_full);
	}

done:

	if (contact_full) {
		switch_safe_free(contact_full);
	}

	free(mydata);

	return SWITCH_STATUS_SUCCESS;
}

switch_endpoint_interface_t *usrloc_endpoint_interface;
static switch_call_cause_t usrloc_outgoing_channel(switch_core_session_t *session, switch_event_t *var_event, switch_caller_profile_t *outbound_profile, switch_core_session_t **new_session, switch_memory_pool_t **pool, switch_originate_flag_t flags, switch_call_cause_t *cancel_cause);

switch_io_routines_t usrloc_io_routines = {
	/*.outgoing_channel */ usrloc_outgoing_channel
};

static switch_call_cause_t usrloc_outgoing_channel(switch_core_session_t *session,
												  switch_event_t *var_event,
												  switch_caller_profile_t *call_profile,
												  switch_core_session_t **new_session, switch_memory_pool_t **new_pool, switch_originate_flag_t flags,
												  switch_call_cause_t *cancel_cause)
{
	switch_call_cause_t cause = SWITCH_CAUSE_NONE;
	switch_memory_pool_t *pool = NULL;
 	char *mydata = NULL;
	char *argv[3] = { 0 };
	int argc;
	const char *cid_name_override = NULL;
	const char *cid_num_override = NULL;
	unsigned int timelimit = 60;
	const char *var = NULL;
	const char *sofia_profile = NULL;
	const char *domain = NULL;
	const char *user = NULL;

	char *contact_full = NULL;
	char *contact_uri_dup = NULL;

	switch_core_session_t *locked_session = NULL;

	switch_core_new_memory_pool(&pool);

	if (!call_profile->destination_number) {
		goto done;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Entering usrloc endpoint [%s]\n", call_profile->destination_number);
	mydata = switch_core_strdup(pool, call_profile->destination_number);

	if ((argc = switch_separate_string(mydata, '/', argv, (sizeof(argv) / sizeof(argv[0]))))) {
		if (argc > 1) {
			sofia_profile = switch_core_strdup(pool, argv[0]);
			domain = switch_core_strdup(pool, argv[1]);
			if (argc > 2) {
				user = switch_core_strdup(pool, argv[2]);
			}
		}
	}

	/* at least sofia_profile & domain must be set */
	if (!sofia_profile || zstr(sofia_profile) || !domain || zstr(domain)) {
		goto done;
	}

	contact_uri_dup = usrloc_contact_str(domain, user);
	if (contact_uri_dup) {
		switch_stream_handle_t sofia_stream = { 0 };
		int32_t contact_uri_num = 0;
		char *contact_uri_list[512] = { 0 };
		int32_t contact_uri_i;
		contact_uri_num = switch_separate_string(contact_uri_dup, ',', contact_uri_list, (sizeof(contact_uri_list) / sizeof(contact_uri_list[0])));

		SWITCH_STANDARD_STREAM(sofia_stream);
		for (contact_uri_i = 0; contact_uri_i < contact_uri_num; contact_uri_i++) {
			const char *contact_uri = contact_uri_list[contact_uri_i];
			if (contact_uri_i > 0) {
				sofia_stream.write_function(&sofia_stream, ",sofia/%s/%s", sofia_profile, contact_uri);
			} else {
				sofia_stream.write_function(&sofia_stream, "sofia/%s/%s", sofia_profile, contact_uri);
			}
		}

		switch_safe_free(contact_uri_dup);
		contact_full = switch_core_strdup(pool, sofia_stream.data);
		switch_safe_free(sofia_stream.data);
	}

	if (session) {
		switch_channel_t *channel = switch_core_session_get_channel(session);
		cid_name_override = switch_channel_get_variable(channel, "origination_caller_id_name");
		cid_num_override = switch_channel_get_variable(channel, "origination_caller_id_number");
		if (zstr(cid_name_override)) {
			cid_name_override = switch_channel_get_variable(channel, "effective_caller_id_name");
		}
		if (zstr(cid_num_override)) {
			cid_num_override = switch_channel_get_variable(channel, "effective_caller_id_number");
		}
		if ((var = switch_channel_get_variable(channel, SWITCH_CALL_TIMEOUT_VARIABLE)) || (var = switch_event_get_header(var_event, "leg_timeout"))) {
			timelimit = atoi(var);
		}
	} else if (var_event) {
		char *session_uuid = switch_event_get_header(var_event, "ent_originate_aleg_uuid");
		if (session_uuid) {
			locked_session = switch_core_session_locate(session_uuid);
		}
		cid_name_override = switch_event_get_header(var_event, "origination_caller_id_name");
		cid_num_override = switch_event_get_header(var_event, "origination_caller_id_number");
		if (zstr(cid_name_override)) {
			cid_name_override = switch_event_get_header(var_event, "effective_caller_id_name");
		}
		if (zstr(cid_num_override)) {
			cid_num_override = switch_event_get_header(var_event, "caller_id_number");
		}
		if ((var = switch_event_get_header(var_event, SWITCH_CALL_TIMEOUT_VARIABLE)) || (var = switch_event_get_header(var_event, "leg_timeout"))) {
			timelimit = atoi(var);
		}
	}

	if (contact_full && !zstr(contact_full)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "[%s]\n", contact_full);
		if ((switch_ivr_originate(session, new_session, &cause, contact_full, timelimit, NULL, cid_name_override, cid_num_override, NULL, var_event, flags, cancel_cause) == SWITCH_STATUS_SUCCESS)) {
			switch_core_session_rwunlock(*new_session);
		}
	}

  done:

  	if (locked_session) {
		switch_core_session_rwunlock(locked_session);
	}

	switch_core_destroy_memory_pool(&pool);

	if (cause == SWITCH_CAUSE_NONE) {
		cause = SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
	}

	return cause;
}

static switch_status_t usrloc_load_config(void)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	switch_xml_t cfg, xml, settings, param;
	switch_cache_db_handle_t *dbh = NULL;

	switch_mutex_lock(globals.mutex);

	if (!(xml = switch_xml_open_cfg(global_cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", global_cf);
		status = SWITCH_STATUS_TERM;
		goto end;
	}

	if ((settings = switch_xml_child(cfg, "settings")) != NULL) {
		char *table_name = NULL, *user_column = NULL, *domain_column = NULL, *received_column = NULL, *socket_column = NULL;
		globals.use_proxy = SWITCH_TRUE;
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");

			if (zstr(var) || zstr(val)) {
				continue; // Ignore empty entries
			}
			if (!strcasecmp(var, "odbc-dsn")) {
				globals.odbc_dsn = strdup(val);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set odbc-dsn [%s]\n", globals.odbc_dsn);
			} else if (!strcasecmp(var, "use_proxy")) {
				globals.use_proxy = switch_true(val);
			} else if (!strcasecmp(var, "table_name")) {
				table_name = strdup(val);
			} else if (!strcasecmp(var, "user_column")) {
				user_column = strdup(val);
			} else if (!strcasecmp(var, "domain_column")) {
				domain_column = strdup(val);
			} else if (!strcasecmp(var, "received_column")) {
				received_column = strdup(val);
			} else if (!strcasecmp(var, "socket_column")) {
				socket_column = strdup(val);
			}
		}

		if (table_name) {
			globals.table_name = strdup(table_name);
			switch_safe_free(table_name);
		} else {
			globals.table_name = strdup("location");
		}
		if (user_column) {
			globals.user_column = strdup(user_column);
			switch_safe_free(user_column);
		} else {
			globals.user_column = strdup("username");
		}
		if (domain_column) {
			globals.domain_column = strdup(domain_column);
			switch_safe_free(domain_column);
		} else {
			globals.domain_column = strdup("domain");
		}
		if (received_column) {
			globals.received_column = strdup(received_column);
			switch_safe_free(received_column);
		} else {
			globals.received_column = strdup("received");
		}
		if (socket_column) {
			globals.socket_column = strdup(socket_column);
			switch_safe_free(socket_column);
		} else {
			globals.socket_column = strdup("socket");
		}
		if (globals.use_proxy == SWITCH_TRUE) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set use_proxy [true]\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set use_proxy [false]\n");
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set table_name [%s]\n", globals.table_name);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set user_column [%s]\n", globals.user_column);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set domain_column [%s]\n", globals.domain_column);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set received_column [%s]\n", globals.received_column);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set socket_column [%s]\n", globals.socket_column);
	}

	// Initialize database
	if (!(dbh = get_db_handle())) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Cannot open DB!\n");
		status = SWITCH_STATUS_TERM;
		goto end;
	}

	switch_cache_db_release_db_handle(&dbh);

end:
	switch_mutex_unlock(globals.mutex);

	if (xml) {
		switch_xml_free(xml);
	}

	return status;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_usrloc_load)
{
	switch_application_interface_t *app_interface;
	switch_api_interface_t *api_interface;
	switch_status_t status;

	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;

	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, globals.pool);

	if ((status = usrloc_load_config()) != SWITCH_STATUS_SUCCESS) {
		return status;
	}

	switch_mutex_lock(globals.mutex);
	globals.running = 1;
	switch_mutex_unlock(globals.mutex);

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface, "usrloc", "Return dial-string from usrloc database", "Return dial-string from usrloc database", usrloc_app_function, USRLOC, SAF_NONE);
	SWITCH_ADD_API(api_interface, "usrloc", "usrloc API", usrloc_api_function, "syntax");
	usrloc_endpoint_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_ENDPOINT_INTERFACE);
	usrloc_endpoint_interface->interface_name = "usrloc";
	usrloc_endpoint_interface->io_routines = &usrloc_io_routines;

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_usrloc_shutdown)
{
	switch_mutex_lock(globals.mutex);
	if (globals.running == 1) {
		globals.running = 0;
	}
	switch_mutex_unlock(globals.mutex);

	switch_mutex_lock(globals.mutex);
	switch_safe_free(globals.odbc_dsn);
	switch_safe_free(globals.table_name);
	switch_safe_free(globals.user_column);
	switch_safe_free(globals.domain_column);
	switch_safe_free(globals.received_column);
	switch_safe_free(globals.socket_column);
	switch_mutex_unlock(globals.mutex);

	switch_mutex_destroy(globals.mutex);

	return SWITCH_STATUS_SUCCESS;
}


/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4
 */
