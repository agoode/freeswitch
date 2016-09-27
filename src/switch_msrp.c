/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2011-2016, Seven Du <dujinfang@gmail.com>
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
 * Seven Du <dujinfang@gmail.com>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 *
 *
 * msrp.c -- MSRP lib
 *
 */

#include <switch.h>
#include <switch_msrp.h>

#define MSRP_BUFF_SIZE SWITCH_RTP_MAX_BUF_LEN

static struct {
	int running;
	int debug;
	// switch_mutex_t *mutex;
	char *ip;
	switch_port_t port;
	switch_socket_t *sock;
	switch_thread_t *thread;
} globals;

typedef struct worker_helper{
	int debug;
	switch_memory_pool_t *pool;
	switch_socket_t *sock;
} worker_helper_t;

SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_ip, globals.ip);

static void *SWITCH_THREAD_FUNC msrp_listener(switch_thread_t *thread, void *obj);

static void close_socket(switch_socket_t ** sock)
{
	// switch_mutex_lock(globals.sock_mutex);
	if (*sock) {
		switch_socket_shutdown(*sock, SWITCH_SHUTDOWN_READWRITE);
		switch_socket_close(*sock);
		*sock = NULL;
	}
	// switch_mutex_unlock(globals.sock_mutex);
}

SWITCH_DECLARE(switch_status_t) switch_msrp_init()
{
	switch_memory_pool_t *pool;
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;
	switch_status_t rv;
	switch_sockaddr_t *sa;
	switch_socket_t *sock;

	if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "OH OH no pool\n");
		return SWITCH_STATUS_FALSE;
	}

	memset(&globals, 0, sizeof(globals));
	set_global_ip("0.0.0.0");
	globals.port = (switch_port_t)MSRP_LISTEN_PORT;

	rv = switch_sockaddr_info_get(&sa, globals.ip, SWITCH_INET, globals.port, 0, pool);
	if (rv) goto sock_fail;

	rv = switch_socket_create(&sock, switch_sockaddr_get_family(sa), SOCK_STREAM, SWITCH_PROTO_TCP, pool);
	if (rv) goto sock_fail;

	rv = switch_socket_opt_set(sock, SWITCH_SO_REUSEADDR, 1);
	if (rv) goto sock_fail;

	rv = switch_socket_bind(sock, sa);
	if (rv) goto sock_fail;

	rv = switch_socket_listen(sock, 5);
	if (rv) goto sock_fail;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Socket up listening on %s:%u\n", globals.ip, globals.port);

	globals.running = 1;
	globals.debug = 1;
	globals.sock = sock;

	switch_threadattr_create(&thd_attr, pool);
	// switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, msrp_listener, sock, pool);

	globals.thread = thread;
	return SWITCH_STATUS_SUCCESS;

sock_fail:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Socket Error! Could not listen on %s:%u\n", globals.ip, globals.port);
	return SWITCH_STATUS_FALSE;
}

SWITCH_DECLARE(switch_status_t) switch_msrp_destroy()
{
	switch_status_t st = SWITCH_STATUS_SUCCESS;
	switch_socket_t *sock;
	globals.running = 0;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "destroy thread\n");

	sock = globals.sock;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket error\n");

	close_socket(&sock);
	if (globals.thread) switch_thread_join(&st, globals.thread);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "destroy thread done\n");

	globals.thread = NULL;
	return st;
}

SWITCH_DECLARE(switch_msrp_session_t *)switch_msrp_session_new(switch_memory_pool_t *pool) 
{
	switch_msrp_session_t *ms;
	ms = switch_core_alloc(pool, sizeof(switch_msrp_session_t));
	switch_assert(ms);
	ms->pool = pool;
	ms->msrp_msg_buffer_size = 50; /*TODO: make it configurable*/
	switch_mutex_init(&ms->mutex, SWITCH_MUTEX_NESTED, pool);
	return ms;
}

SWITCH_DECLARE(switch_status_t) switch_msrp_session_destroy(switch_msrp_session_t **ms) 
{
	switch_mutex_destroy((*ms)->mutex);
	ms = NULL;
	return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_msrp_session_push_msg(switch_msrp_session_t *ms, msrp_msg_t *msg)
{
	switch_mutex_lock(ms->mutex);
	if (ms->last_msg == NULL) {
		ms->last_msg = msg;
		ms->msrp_msg = msg;
	} else {
		ms->last_msg->next = msg;
		ms->last_msg = msg;
	}
	ms->msrp_msg_count++;
	switch_mutex_unlock(ms->mutex);
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(msrp_msg_t *)switch_msrp_session_pop_msg(switch_msrp_session_t *ms)
{
	msrp_msg_t *m = ms->msrp_msg;
	if (m == NULL) return NULL;

	switch_mutex_lock(ms->mutex);
	ms->msrp_msg = ms->msrp_msg->next;
	ms->msrp_msg_count--;
	if (ms->msrp_msg == NULL) ms->last_msg = NULL;
	switch_mutex_unlock(ms->mutex);
	return m;
}

switch_status_t msrp_msg_serialize(msrp_msg_t *msrp_msg, char *buf)
{
	char *code_number_str = switch_mprintf("%d", msrp_msg->code_number);
	char method[10];

	switch(msrp_msg->method) {
		case MSRP_METHOD_SEND: sprintf(method, "SEND"); break;
		case MSRP_METHOD_AUTH: sprintf(method, "REPORT"); break;
		case MSRP_METHOD_REPORT: sprintf(method, "REPORT"); break;
		default: sprintf(method, "%d", msrp_msg->method); break;
	}
	sprintf(buf, "=================================\n"
		"MSRP %s %s%s\nFrom: %s\nTo: %s\nMessage-ID: %s\n"
		"Content-Type: %s\n"
		"Byte-Range: %" SWITCH_SIZE_T_FMT "-%" SWITCH_SIZE_T_FMT"/%" SWITCH_SIZE_T_FMT "\n"
		"Payload:\n%s\n%s\n"
		"=================================\n",
		msrp_msg->transaction_id ? switch_str_nil(msrp_msg->transaction_id) : code_number_str,
		msrp_msg->transaction_id ? "" : " ",
		msrp_msg->transaction_id ? method : switch_str_nil(msrp_msg->code_description),
		switch_str_nil(msrp_msg->headers[MSRP_H_FROM_PATH]),
		switch_str_nil(msrp_msg->headers[MSRP_H_TO_PATH]),
		switch_str_nil(msrp_msg->headers[MSRP_H_MESSAGE_ID]),
		switch_str_nil(msrp_msg->headers[MSRP_H_CONTENT_TYPE]),
		msrp_msg->byte_start,
		msrp_msg->byte_end,
		msrp_msg->bytes,
		msrp_msg->payload,
		msrp_msg->delimiter);
	switch_safe_free(code_number_str)
	return SWITCH_STATUS_SUCCESS;
}

void dump_buffer(char *buf, switch_size_t len, int line)
{
	int i, j, k = 0;
	char buff[MSRP_BUFF_SIZE * 2];
	// return;
	for(i=0,j=0; i<len; i++) {
		if (buf[i] == '\0') {
			buff[j++] = '\\';
			buff[j++] = '0';
		} else if(buf[i] == '\r') {
			buff[j++] = '\\';
			buff[j++] = 'r';
		} else if(buf[i] == '\n') {
			buff[j++] = '\\';
			buff[j++] = 'n';
			buff[j++] = '\n';
			k = 0;
		}
		 else {
			buff[j++] = buf[i];
		}
		if ((++k) %80 == 0) buff[j++] = '\n';
		if (j >= MSRP_BUFF_SIZE * 2) break;
	}

	buff[j] = '\0';
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%d:%ldDUMP:%s:DUMP\n", line, len, buff);
}

char *find_delim(char *buf, int len, char *delim)
{
	char *p, *q, *s = NULL;
	char *end;

	p = buf;
	q = delim;

	if (p == NULL) return NULL;
	if (q == NULL) return NULL;

	end = buf + len - strlen(delim);

	while(p < end && *q) {
			if (*p == *q) {
					if (s == NULL) s = p;
					p++;
					q++;
			} else {
					s = NULL;
					p++;
					q = delim;
			}
			if (*q == '\0') return s;
	}
	return NULL;
}
/*
MSRP d4c667b2351e958f SEND
To-Path: msrp://192.168.0.56:2856/73671a97c9dec690d303;tcp
From-Path: msrp://192.168.0.56:2855/2fb5dfec96f3609f7b48;tcp
Message-ID: 7b7c9965ffa8533c
Byte-Range: 1-0/0
-------d4c667b2351e958f$
*/

char *msrp_parse_header(char *start, int skip, const char *end, msrp_msg_t *msrp_msg, int index, switch_memory_pool_t *pool) 
{
	char *p = start + skip;
	char *q;
	if (*p && *p == ' ') p++;
	q = p;
	while(*q != '\n' && q < end) q++;
	if (q > p) {
		if (*(q-1) == '\r') *(q-1) = '\0';
		*q = '\0';
		msrp_msg->headers[index] = switch_core_strdup(pool, p);
		msrp_msg->last_header = msrp_msg->last_header > index ? msrp_msg->last_header : index;
		return q + 1;
	}
	return start;
}

msrp_msg_t *msrp_parse_headers(const char *start, int len, msrp_msg_t *msrp_msg, switch_memory_pool_t *pool)
{
	char *p = (char *)start;
	char *q = p;
	const char *end = start + len;
	int headers = 0;
	char line[1024];


	while(p < end) {
		if (!strncasecmp(p, "MSRP ", 5)) {
			p += 5;
			q = p;
			while(*q && q < end && *q != ' ') q++;
			if (q > p) {
				*q = '\0';
				msrp_msg->transaction_id = switch_core_strdup(pool, p);
				switch_snprintf(line, 128, "-------%s", msrp_msg->transaction_id);
				msrp_msg->delimiter = switch_core_strdup(pool, line);
				msrp_msg->state = MSRP_ST_PARSE_HEADER;
			}
			p = q;
			if (++p >= end) goto done;

			if (!strncasecmp(p, "SEND", 4)) {
				msrp_msg->method = MSRP_METHOD_SEND;
				p +=6; /*skip \r\n*/
			} else if (!strncasecmp(p, "REPORT", 5)) {
				msrp_msg->method = MSRP_METHOD_REPORT;
				p += 7;
			} else if (!strncasecmp(p, "AUTH", 4)) {
				msrp_msg->method = MSRP_METHOD_AUTH;
				p += 6;
			} else {/* MSRP transaction_id coden_number codede_scription */
				msrp_msg->method = MSRP_METHOD_REPLY;
				q = p;
				while(*q && q < end && *q != ' ') q++;
				if (q > p) {
					*q = '\0';
					msrp_msg->code_number = atoi(p);
					p = ++q;
					while(*q && q < end && *q != '\n') q++;
					if (q > p) {
						if (*(q-1) == '\r') *(q-1) = '\0';
						*q = '\0';
						msrp_msg->code_description = switch_core_strdup(pool, p);
						p = ++q;
					}
				}
			}
			headers++;
		} else if (!strncasecmp(p, "From-Path:", 10)) {
			q = msrp_parse_header(p, 10, end, msrp_msg, MSRP_H_FROM_PATH, pool);
			if (q == p) break; /* incomplete header*/
			p = q;
		} else if (!strncasecmp(p, "To-Path:", 8)) {
			q = msrp_parse_header(p, 8, end, msrp_msg, MSRP_H_TO_PATH, pool);
			if (q == p) break; /* incomplete header*/
			p = q;
		} else if (!strncasecmp(p, "Status:", 7)) {
			q = msrp_parse_header(p, 7, end, msrp_msg, MSRP_H_STATUS, pool);
			if (q == p) break; /* incomplete header*/
			p = q;
		} else if (!strncasecmp(p, "Keep-Alive:", 11)) {
			q = msrp_parse_header(p, 11, end, msrp_msg, MSRP_H_KEEPALIVE, pool);
			if (q == p) break; /* incomplete header*/
			p = q;
		} else if (!strncasecmp(p, "Message-ID:", 11)) {
			q = msrp_parse_header(p, 11, end, msrp_msg, MSRP_H_MESSAGE_ID, pool);
			if (q == p) break; /* incomplete header*/
			p = q;
		} else if (!strncasecmp(p, "Content-Type:", 13)) {
			q = msrp_parse_header(p, 13, end, msrp_msg, MSRP_H_CONTENT_TYPE, pool);
			if (q == p) break; /* incomplete header*/
			p = q;
		} else if (!strncasecmp(p, "Success-Report:", 15)) {
			q = msrp_parse_header(p, 15, end, msrp_msg, MSRP_H_SUCCESS_REPORT, pool);
			if (q == p) break; /* incomplete header*/
			p = q;
		} else if (!strncasecmp(p, "Failure-Report:", 15)) {
			q = msrp_parse_header(p, 15, end, msrp_msg, MSRP_H_FAILURE_REPORT, pool);
			if (q == p) break; /* incomplete header*/
			p = q;
		} else if (!strncasecmp(p, "Byte-Range:", 11)) {
			p += 11;
			if (*p && *p == ' ') p++;
			q = p;
			while(*q && q < end && *q != '-') q++;
			if (q > p) {
				*q = '\0';
				msrp_msg->byte_start = atoi(p);
				switch_assert(msrp_msg->byte_start > 0);
				p = ++q;
				if (*p && *p == '*') {
					msrp_msg->range_star = 1;
				}
				while(*q && q < end && *q != '/') q++;
				if (q > p) {
					*q = '\0';
					msrp_msg->byte_end = msrp_msg->range_star ? 0 : atoi(p);
					p = ++q;
					while(*q && q < end && *q != '\n') q++;
					if (q > p) {
						if (*(q-1) == '\r') *(q-1) = '\0';
						*q = '\0';
						msrp_msg->bytes = atoi(p);

						if (!msrp_msg->range_star) {
							msrp_msg->payload_bytes = msrp_msg->byte_end + 1 - msrp_msg->byte_start;
						}

						if (globals.debug) switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%" SWITCH_SIZE_T_FMT " payload bytes\n", msrp_msg->payload_bytes);

						/*Fixme sanity check to avoid large byte-range attack*/
						if (!msrp_msg->range_star && msrp_msg->payload_bytes > msrp_msg->bytes) {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "payload size does't match %" SWITCH_SIZE_T_FMT " != %" SWITCH_SIZE_T_FMT "\n", msrp_msg->payload_bytes, msrp_msg->bytes);
							msrp_msg->state = MSRP_ST_ERROR;
							p = ++q;
							break;
						}
						p = ++q;
					}
				}
			}
			headers++;
		} else if (*p == '\r' && *(p+1) == '\n') {
			msrp_msg->state = MSRP_ST_WAIT_BODY;
			p += 2;
			break;
		} else if (msrp_msg->delimiter &&
			!strncasecmp(p, msrp_msg->delimiter, strlen(msrp_msg->delimiter))) {
				char *x = p + strlen(msrp_msg->delimiter);
				if (x < end) {
					if (*x == '$') {
						p = x + 1;
						msrp_msg->state = MSRP_ST_DONE;
						if (*p == '\r') p++;
						if (*p == '\n') p++;
						break;
					} else if(*x == '+') {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unsupported %c\n", *x);
						if (*p == '\r') p++;
						if (*p == '\n') p++;
						break;
					} else {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unsupported %c\n", *x);
						msrp_msg->state = MSRP_ST_ERROR; //TODO support # etc.
						break;
					}
				}
				break;
		} else {/* unsupported header*/
			q = p;
			while(*q && q < end && *q != ':') q++;
			if (q > p) {
				char *last_p = p;
				*q = '\0';
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "unsupported header [%s]\n", p);
				p = q + 1;
				msrp_msg->last_header = msrp_msg->last_header == 0 ? MSRP_H_UNKNOWN : msrp_msg->last_header + 1;
				q = msrp_parse_header(p, 0, end, msrp_msg, msrp_msg->last_header, pool);
				if (q == p) {
					p = last_p;
					break; /* incomplete header*/
				}
				p = q;
			}
		}
	}

done:
	msrp_msg->last_p = p;
	return msrp_msg;
}

msrp_msg_t *msrp_parse_buffer(char *buf, int len, msrp_msg_t *msrp_msg, switch_memory_pool_t *pool)
{
	const char *start;

	if (!msrp_msg) {
		switch_zmalloc(msrp_msg, sizeof(msrp_msg_t));
		switch_assert(msrp_msg);
		msrp_msg->state = MSRP_ST_WAIT_HEADER;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "parse state: %d\n", msrp_msg->state);
	dump_buffer(buf, len, __LINE__);

	if (msrp_msg->state == MSRP_ST_WAIT_HEADER) {
		if ((start = switch_stristr("MSRP ", buf)) == NULL) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Not an MSRP packet, Skip!\n");
			return msrp_msg;
		}
		msrp_msg = msrp_parse_headers(start, len - (start - buf), msrp_msg, pool);

		if (msrp_msg->state == MSRP_ST_ERROR) return msrp_msg;
		if (msrp_msg->state == MSRP_ST_DONE) return msrp_msg;

		if (msrp_msg->last_p && msrp_msg->last_p < buf + len) {
			msrp_msg = msrp_parse_buffer(msrp_msg->last_p, len - (msrp_msg->last_p - buf), msrp_msg, pool);
		}
	} else if (msrp_msg->state == MSRP_ST_WAIT_BODY) {
		if(!msrp_msg->range_star && msrp_msg->byte_end == 0) {
			msrp_msg->state = MSRP_ST_DONE;
			return msrp_msg;
		}
		if (msrp_msg->range_star) { /* the * case */
			/*hope we can find the delimiter at the end*/
			int dlen;
			char *delim_pos = NULL;
			switch_assert(msrp_msg->delimiter);
			dlen = strlen(msrp_msg->delimiter);
			if (!strncmp(buf + len - dlen - 3, msrp_msg->delimiter, dlen)) { /*bingo*/
				msrp_msg->payload_bytes = len - dlen - 5;
				msrp_msg->payload = switch_core_alloc(pool, msrp_msg->payload_bytes + 1);
				switch_assert(msrp_msg->payload);
				memcpy(msrp_msg->payload, buf, msrp_msg->payload_bytes);
				msrp_msg->byte_end = msrp_msg->byte_start + msrp_msg->payload_bytes - 1;
				msrp_msg->state = MSRP_ST_DONE;
				msrp_msg->last_p = buf + len;
				return msrp_msg;
			} else if ((delim_pos = find_delim(buf, len, msrp_msg->delimiter))){
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "=======================================delimiter: %s\n", delim_pos);
				msrp_msg->payload_bytes = delim_pos - buf - 2;
				// if (msrp_msg->payload_bytes < 0) msrp_msg->payload_bytes = 0;
				msrp_msg->payload = switch_core_alloc(pool, msrp_msg->payload_bytes + 1);
				switch_assert(msrp_msg->payload);
				memcpy(msrp_msg->payload, buf, msrp_msg->payload_bytes);
				msrp_msg->byte_end = msrp_msg->byte_start + msrp_msg->payload_bytes - 1;
				msrp_msg->state = MSRP_ST_DONE;
				msrp_msg->last_p = delim_pos + dlen + 3;
				return msrp_msg;
			} else {/* keep waiting*/
				/*TODO: fix potential overflow here*/
				msrp_msg->last_p = buf;
				return msrp_msg;
			}
		} else if (msrp_msg->payload_bytes == 0) {
			int dlen = strlen(msrp_msg->delimiter);
			if(strncasecmp(buf, msrp_msg->delimiter, dlen)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error find delimiter\n");
				msrp_msg->state = MSRP_ST_ERROR;
				return msrp_msg;
			}
			msrp_msg->payload = NULL;
			msrp_msg->state = MSRP_ST_DONE;
			msrp_msg->last_p = buf + dlen + 3; /*Fixme: assuming end with $\r\n*/
			return msrp_msg;
		} else {
			int dlen = strlen(msrp_msg->delimiter);

			if (msrp_msg->payload_bytes > len) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Waiting payload...%d < %d\n", (int)msrp_msg->payload_bytes, (int)len);
				return msrp_msg; /*keep waiting ?*/
			}

			msrp_msg->payload = switch_core_alloc(pool, msrp_msg->payload_bytes);
			switch_assert(msrp_msg->payload);
			memcpy(msrp_msg->payload, buf, msrp_msg->payload_bytes);
			msrp_msg->last_p = buf + msrp_msg->payload_bytes;
			msrp_msg->state = MSRP_ST_DONE;
			msrp_msg->last_p = buf + msrp_msg->payload_bytes;
			if (msrp_msg->payload_bytes == len - dlen - 5) {
				msrp_msg->last_p = buf + len;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "payload bytes:%d\n", (int)msrp_msg->payload_bytes);

				return msrp_msg; /*Fixme: assuming \r\ndelimiter$\r\n present*/
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%ld %d %d\n", msrp_msg->payload_bytes, len, dlen);

			msrp_msg->state = MSRP_ST_ERROR;
			return msrp_msg;
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "error here! code:%d\n", msrp_msg->state);
	}
	return msrp_msg;
}


switch_status_t msrp_reply(switch_socket_t *sock, msrp_msg_t *msrp_msg)
{
	char buf[2048];
	switch_size_t len;
	sprintf(buf, "MSRP %s 200 OK\r\nTo-Path: %s\r\nFrom-Path: %s\r\n"
		"%s$\r\n",
		switch_str_nil(msrp_msg->transaction_id),
		switch_str_nil(msrp_msg->headers[MSRP_H_FROM_PATH]),
		switch_str_nil(msrp_msg->headers[MSRP_H_TO_PATH]),
		msrp_msg->delimiter);
	len = strlen(buf);

	return switch_socket_send(sock, buf, &len);
}

switch_status_t msrp_report(switch_socket_t *sock, msrp_msg_t *msrp_msg, char *status_code)
{
	char buf[2048];
	switch_size_t len;
	sprintf(buf, "MSRP %s REPORT\r\nTo-Path: %s\r\nFrom-Path: %s\r\nMessage-ID: %s\r\n"
		"Status: 000 %s\r\nByte-Range: 1-%" SWITCH_SIZE_T_FMT "/%" SWITCH_SIZE_T_FMT
		"\r\n%s$\r\n",
		switch_str_nil(msrp_msg->transaction_id),
		switch_str_nil(msrp_msg->headers[MSRP_H_FROM_PATH]),
		switch_str_nil(msrp_msg->headers[MSRP_H_TO_PATH]),
		switch_str_nil(msrp_msg->headers[MSRP_H_MESSAGE_ID]),
		switch_str_nil(status_code),
		msrp_msg->byte_end,
		msrp_msg->bytes,
		msrp_msg->delimiter);
	len = strlen(buf);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "report: %" SWITCH_SIZE_T_FMT " bytes\n%s", len, buf);
	return switch_socket_send(sock, buf, &len);
}

switch_bool_t msrp_find_uuid(char *uuid, char *to_path)
{
	int len = strlen(to_path);
	int i;
	int slash_count = 0;
	switch_assert(to_path);
	for(i=0; i<len; i++){
		if (*(to_path + i) == '/') {
			if (++slash_count == 3) break;
		}
	}
	if (slash_count < 3) return SWITCH_FALSE;
	if (len - i++ < 36) return SWITCH_FALSE;
	switch_snprintf(uuid, 37, to_path + i);
	return SWITCH_TRUE;
}

static void *SWITCH_THREAD_FUNC msrp_worker(switch_thread_t *thread, void *obj)
{
	worker_helper_t *helper = (worker_helper_t *) obj;
	switch_socket_t *sock;
	switch_memory_pool_t *pool;
	char buf[MSRP_BUFF_SIZE];
	char *p;
	char *last_p;
	switch_size_t len = MSRP_BUFF_SIZE;
	switch_status_t status;
	msrp_msg_t *msrp_msg = NULL;
	char uuid[128] = { 0 };
	switch_core_session_t *session = NULL;
	switch_msrp_session_t *msrp_session = NULL;
	switch_channel_t *channel = NULL;
	int sanity = 10;

	pool = helper->pool;
	sock = helper->sock;
	switch_socket_opt_set(sock, SWITCH_SO_TCP_NODELAY, TRUE);
	// switch_socket_opt_set(sock, SWITCH_SO_NONBLOCK, TRUE);

	status = switch_socket_recv(sock, buf, &len);

	msrp_msg = msrp_parse_buffer(buf, len, NULL, pool);
	switch_assert(msrp_msg);

	if (helper->debug) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "status:%d, len:%" SWITCH_SIZE_T_FMT "\n", status, len);

		msrp_msg_serialize(msrp_msg, buf);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s\n", buf);
	}

	if (msrp_msg->state == MSRP_ST_DONE && msrp_msg->method == MSRP_METHOD_SEND) {
		msrp_reply(sock, msrp_msg);
		if (msrp_msg->headers[MSRP_H_SUCCESS_REPORT] &&
			!strcmp(msrp_msg->headers[MSRP_H_SUCCESS_REPORT], "yes")) {
			msrp_report(sock, msrp_msg, "200 OK");
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Parse initial message error!\n");
		goto end;
	}

	if (msrp_find_uuid(uuid, msrp_msg->headers[MSRP_H_TO_PATH]) != SWITCH_TRUE) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid MSRP to-path!\n");
		goto end;
	}

	while (sanity-- && !(session = switch_core_session_locate(uuid))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "waiting for session\n");
		switch_yield(1000000);
	}

	if(!session) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "No such session %s\n", uuid);
		goto end;
	}

	channel = switch_core_session_get_channel(session);
	msrp_session = switch_core_media_get_msrp_session(session);
	switch_assert(msrp_session);
	msrp_session->socket = sock;

	len = MSRP_BUFF_SIZE;
	p = buf;
	last_p = buf;
	switch_safe_free(msrp_msg);
	msrp_msg = NULL;
	while(switch_socket_recv(sock, p, &len) == SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "read bytes:%ld\n", len);

		if (helper->debug) dump_buffer(buf, (p - buf) + len, __LINE__);

		msrp_msg = msrp_parse_buffer(last_p, p - last_p + len, msrp_msg, pool);

		switch_assert(msrp_msg);

		if (msrp_msg->state == MSRP_ST_ERROR) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "msrp parse error!\n");
			goto end;
		}

		if (helper->debug) {
			// char msg_buf[MSRP_BUFF_SIZE * 2];
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "state:%d, len:%" SWITCH_SIZE_T_FMT " payload_bytes:%" SWITCH_SIZE_T_FMT "\n", msrp_msg->state, len, msrp_msg->payload_bytes);
			// {
			// 	char bbb[MSRP_BUFF_SIZE * 2];
			// 	msrp_msg_serialize(msrp_msg_tmp, bbb),
			//
		}

		if (msrp_msg->state == MSRP_ST_DONE && msrp_msg->method == MSRP_METHOD_SEND) {
			msrp_reply(sock, msrp_msg);
			if (msrp_msg->headers[MSRP_H_SUCCESS_REPORT] &&
				!strcmp(msrp_msg->headers[MSRP_H_SUCCESS_REPORT], "yes")) {
				msrp_report(sock, msrp_msg, "200 OK");
			}
			last_p = msrp_msg->last_p;
			switch_msrp_session_push_msg(msrp_session, msrp_msg);
			msrp_msg = NULL;
		} else if (msrp_msg->state == MSRP_ST_DONE) { /* throw away */
			last_p = msrp_msg->last_p;
			switch_safe_free(msrp_msg);
			msrp_msg = NULL;
		} else {
			last_p = msrp_msg->last_p;
		}

		while (msrp_session && msrp_session->msrp_msg_count > msrp_session->msrp_msg_buffer_size) {
			if (!switch_channel_ready(channel)) break;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s reading too fast, relax...\n", uuid);
			switch_yield(100000);
		}

		if (p + len > last_p) {
			p += len;
			if (!msrp_msg) {
				int rest_len = p - last_p;

				memmove(buf, last_p, rest_len);
				p = buf + rest_len;
				len = MSRP_BUFF_SIZE - rest_len;
				last_p = buf;
				continue;
			}

			if (p >= buf + MSRP_BUFF_SIZE) {

				if (msrp_msg->state != MSRP_ST_WAIT_BODY || !msrp_msg->range_star) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "buffer overflow\n");
					/*todo, do a strstr in the whole buffer ?*/
					break;
				}

				/* buffer full*/
				msrp_msg->payload_bytes = p - last_p;
				msrp_msg->byte_end = msrp_msg->byte_start + msrp_msg->payload_bytes - 1;
				msrp_msg->payload = switch_core_alloc(pool, msrp_msg->payload_bytes);
				switch_assert(msrp_msg->payload);
				memcpy(msrp_msg->payload, last_p, msrp_msg->payload_bytes);

				{
					int i;
					msrp_msg_t *msrp_msg_old = msrp_msg;
					msrp_msg = NULL;
					/*dup msrp_msg*/
					switch_zmalloc(msrp_msg, sizeof(msrp_msg_t));
					switch_assert(msrp_msg);
					msrp_msg->state = msrp_msg_old->state;
					msrp_msg->byte_start = msrp_msg_old->byte_end + 1;
					msrp_msg->bytes = msrp_msg_old->bytes;
					msrp_msg->range_star = msrp_msg_old->range_star;
					msrp_msg->method = msrp_msg_old->method;
					msrp_msg->transaction_id = switch_core_strdup(pool, msrp_msg_old->transaction_id);
					msrp_msg->delimiter = switch_core_strdup(pool, msrp_msg_old->delimiter);
					msrp_msg->last_header = msrp_msg_old->last_header;
					for (i = 0; i < msrp_msg->last_header; i++) {
						msrp_msg->headers[i] = switch_core_strdup(pool, msrp_msg_old->headers[i]);
					}

					msrp_msg_old->state = MSRP_ST_DONE;

					if (msrp_msg_old->headers[MSRP_H_SUCCESS_REPORT] &&
						!strcmp(msrp_msg_old->headers[MSRP_H_SUCCESS_REPORT], "yes")) {
						// msrp_report(sock, msrp_msg_old, "200 OK");
					}

					switch_msrp_session_push_msg(msrp_session, msrp_msg_old);
				}

				p = buf;
				len = MSRP_BUFF_SIZE;
				last_p = buf;
				msrp_msg->last_p = buf;
			}
		} else { /* all buffer parsed */
			p = buf;
			len = MSRP_BUFF_SIZE;
			last_p = buf;
		}
		if (!switch_channel_ready(channel)) break;
	}

end:
	if (session) switch_core_session_rwunlock(session);

	switch_socket_close(sock);
	switch_core_destroy_memory_pool(&pool);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "msrp worker %s down\n", uuid);

	return NULL;
}

static void *SWITCH_THREAD_FUNC msrp_listener(switch_thread_t *thread, void *obj)
{
	switch_socket_t *listen_sock = (switch_socket_t *) obj;
	switch_status_t rv;
	switch_socket_t *sock;
	switch_memory_pool_t *pool = NULL;
	switch_threadattr_t *thd_attr = NULL;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "msrp listener start\n");

	if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "OH OH no pool\n");
		return NULL;
	}

	switch_socket_opt_set(listen_sock, SWITCH_SO_TCP_NODELAY, TRUE);
	// switch_socket_opt_set(listen_sock, SWITCH_SO_NONBLOCK, TRUE);

	while (globals.running && (rv = switch_socket_accept(&sock, listen_sock, pool)) == SWITCH_STATUS_SUCCESS) {
		switch_memory_pool_t *worker_pool;
		worker_helper_t *helper;

		if (globals.debug > 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Connection Open\n");
		}

		if (switch_core_new_memory_pool(&worker_pool) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "OH OH no pool\n");
			return NULL;
		}
		switch_zmalloc(helper, sizeof(worker_helper_t));

		switch_assert(helper != NULL);
		helper->pool = worker_pool;
		helper->debug = globals.debug;
		helper->sock = sock;

		switch_threadattr_create(&thd_attr, pool);
		switch_threadattr_detach_set(thd_attr, 1);
		switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
		switch_thread_create(&thread, thd_attr, msrp_worker, helper, worker_pool);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "msrp worker new thread spawned!\n");
	}

	if (pool) switch_core_destroy_memory_pool(&pool);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "msrp listener down\n");

	return NULL;
}

void random_string(char *buf, switch_size_t size)
{
	long val[4];
	int x;

	for (x = 0; x < 4; x++)
		val[x] = random();
	snprintf(buf, size, "%08lx%08lx%08lx%08lx", val[0], val[1], val[2], val[3]);
	*(buf+size) = '\0';
}

SWITCH_DECLARE(switch_status_t) switch_msrp_send(switch_msrp_session_t *ms, msrp_msg_t *msrp_msg)
{
	char transaction_id[32];
	char buf[MSRP_BUFF_SIZE];
	switch_size_t len;
	char *to_path = msrp_msg->headers[MSRP_H_TO_PATH] ? msrp_msg->headers[MSRP_H_TO_PATH] : ms->remote_path;
	char *from_path = msrp_msg->headers[MSRP_H_FROM_PATH] ? msrp_msg->headers[MSRP_H_FROM_PATH] : ms->local_path;

	random_string(transaction_id, 16);

	sprintf(buf, "MSRP %s SEND\r\nTo-Path: %s\r\nFrom-Path: %s\r\n"
		"Content-Type: %s\r\n"
		"Byte-Range: 1-%" SWITCH_SIZE_T_FMT "/%" SWITCH_SIZE_T_FMT "%s",
		transaction_id,
		to_path,
		from_path,
		switch_str_nil(msrp_msg->headers[MSRP_H_CONTENT_TYPE]),
		msrp_msg->payload ? msrp_msg->payload_bytes : 0,
		msrp_msg->payload ? msrp_msg->payload_bytes : 0,
		msrp_msg->payload ? "\r\n\r\n" : "");

	len = strlen(buf);

	if (msrp_msg->payload) {
		if (len + msrp_msg->payload_bytes >= MSRP_BUFF_SIZE) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "payload too large! %" SWITCH_SIZE_T_FMT "\n", len + msrp_msg->payload_bytes);
			return SWITCH_STATUS_FALSE;
		}
		memcpy(buf + len, msrp_msg->payload, msrp_msg->payload_bytes);
		len += msrp_msg->payload_bytes;
	}
	sprintf(buf + len, "\r\n-------%s$\r\n", transaction_id);
	len += (12 + strlen(transaction_id));
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "---------------------send: %" SWITCH_SIZE_T_FMT " bytes\n%s\n", len, buf);

	return ms->socket ? switch_socket_send(ms->socket, buf, &len) : SWITCH_STATUS_FALSE;
}

#if 0
SWITCH_STANDARD_APP(msrp_echo_function)
{
	msrp_session_t *msrp_session = NULL;
	msrp_msg_t *msrp_msg = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	// private_object_t *tech_pvt = switch_core_session_get_private(session);

	if (!tech_pvt) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No tech_pvt!\n");
		return;
	}

	if(!tech_pvt->msrp_session) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No msrp_session!\n");
		return;
	}

	while (switch_channel_ready(channel) && (msrp_session = tech_pvt->msrp_session)) {
		if ((msrp_msg = msrp_session_pop_msg(msrp_session)) == NULL) {
			switch_yield(100000);
			continue;
		}

		if (msrp_msg->method == MSRP_METHOD_SEND) { /*echo back*/
			char *p;
			p = msrp_msg->headers[MSRP_H_TO_PATH];
			msrp_msg->headers[MSRP_H_TO_PATH] = msrp_msg->headers[MSRP_H_FROM_PATH];
			msrp_msg->headers[MSRP_H_FROM_PATH] = p;
			msrp_send(msrp_session->socket, msrp_msg);
		}

		switch_safe_free(msrp_msg);
		msrp_msg = NULL;

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "eat one message, left:%d\n", (int)msrp_session->msrp_msg_count);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Echo down!\n");

}

SWITCH_STANDARD_APP(msrp_recv_function)
{
	msrp_session_t *msrp_session = NULL;
	msrp_msg_t *msrp_msg = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	private_object_t *tech_pvt = switch_core_session_get_private(session);
	switch_memory_pool_t *pool = switch_core_session_get_pool(session);
	switch_file_t *fd;
	const char *filename = data;

	if (!tech_pvt) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No tech_pvt!\n");
		return;
	}

	if(!tech_pvt->msrp_session) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No msrp_session!\n");
		return;
	}

	if (zstr(data)) {
		filename = switch_channel_get_variable(channel, "sip_msrp_file_name");
		if (zstr(filename)) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "No file specified.\n");
			return;
		}
		filename = switch_core_session_sprintf(session, "%s%s%s", SWITCH_GLOBAL_dirs.base_dir, SWITCH_PATH_SEPARATOR, filename);
	}

	if (!(msrp_session = tech_pvt->msrp_session)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Not a msrp session!\n");
		return;
	}

	if (switch_file_open(&fd, filename, SWITCH_FOPEN_WRITE | SWITCH_FOPEN_TRUNCATE | SWITCH_FOPEN_CREATE, SWITCH_FPROT_OS_DEFAULT, pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Open File %s\n", filename);
		return;
	}

	while (1) {
		if ((msrp_msg = msrp_session_pop_msg(msrp_session)) == NULL) {
			if (!switch_channel_ready(channel)) break;
			switch_yield(10000);
			continue;
		}

		if (msrp_msg->method == MSRP_METHOD_SEND) {
			switch_size_t bytes = msrp_msg->payload_bytes;
			char *msg = switch_str_nil(msrp_msg->headers[MSRP_H_MESSAGE_ID]);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s %" SWITCH_SIZE_T_FMT "bytes writing\n", msg, bytes);
			switch_file_write(fd, msrp_msg->payload, &bytes);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%" SWITCH_SIZE_T_FMT "bytes written\n", bytes);
			if (bytes != msrp_msg->payload_bytes) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "write fail, bytes lost!\n");
			}
		}

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "eat one message, left:%d\n", (int)msrp_session->msrp_msg_count);

		switch_safe_free(msrp_msg);
	}

	switch_file_close(fd);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "File closed!\n");
}

SWITCH_STANDARD_APP(msrp_send_function)
{
	msrp_session_t *msrp_session = NULL;
	msrp_msg_t *msrp_msg = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	private_object_t *tech_pvt = switch_core_session_get_private(session);
	switch_memory_pool_t *pool = switch_core_session_get_pool(session);
	switch_file_t *fd;
	const char *filename = data;
	switch_size_t len = 2048;
	char buf[2048];
	int sanity = 10;

	if (!tech_pvt) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No tech_pvt!\n");
		return;
	}

	if(!tech_pvt->msrp_session) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No msrp_session!\n");
		return;
	}

	if (!(msrp_session = tech_pvt->msrp_session)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Not a msrp session!\n");
		return;
	}

	if (switch_file_open(&fd, filename, SWITCH_FOPEN_READ, SWITCH_FPROT_OS_DEFAULT, pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Open File %s\n", filename);
		return;
	}

	switch_assert(pool);

	switch_zmalloc(msrp_msg, sizeof(msrp_msg_t));
	switch_assert(msrp_msg);

	msrp_msg->headers[MSRP_H_FROM_PATH] = switch_mprintf("msrp://%s:%d/%s;tcp",
		tech_pvt->rtpip, tech_pvt->msrp_session->local_port, tech_pvt->msrp_session->call_id);
	msrp_msg->headers[MSRP_H_TO_PATH] = tech_pvt->msrp_session->remote_path;
	/*TODO: send file in octet or maybe guess mime?*/
	msrp_msg->headers[MSRP_H_CONTENT_TYPE] = "application/octet-stream";
	msrp_msg->headers[MSRP_H_CONTENT_TYPE] = "text/plain";

	msrp_msg->bytes = switch_file_get_size(fd);
	msrp_msg->byte_start = 1;

	while(sanity-- && tech_pvt->msrp_session->socket == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Waiting socket\n");
		switch_yield(1000000);
	}

	if (tech_pvt->msrp_session->socket == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Waiting for socket timedout, exiting...\n");
		goto end;
	}

	while (switch_file_read(fd, buf, &len) == SWITCH_STATUS_SUCCESS &&
		switch_channel_ready(channel)) {
		msrp_msg->payload = buf;
		msrp_msg->byte_end = msrp_msg->byte_start + len - 1;
		msrp_msg->payload_bytes = len;

		/*TODO: send in chunk should ending in + but not $ after delimiter*/
		msrp_send(tech_pvt->msrp_session->socket, msrp_msg);

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%ld bytes sent\n", len);

		msrp_msg->byte_start += len;
	}

	sanity = 10;

	while(sanity-- && switch_channel_ready(channel)) {
		switch_yield(1000000);
	}

end:
	switch_file_close(fd);

	switch_safe_free(msrp_msg->headers[MSRP_H_FROM_PATH]);
	switch_safe_free(msrp_msg);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "File sent, closed!\n");
}

SWITCH_STANDARD_APP(msrp_bridge_function)
{
	switch_channel_t *caller_channel = switch_core_session_get_channel(session);
	switch_core_session_t *peer_session = NULL;
	switch_channel_t *peer_channel = NULL;
	msrp_session_t *caller_msrp_session = NULL;
	msrp_session_t *peer_msrp_session = NULL;
	private_object_t *tech_pvt = NULL;
	private_object_t *ptech_pvt = NULL;
	msrp_msg_t *msrp_msg = NULL;
	switch_call_cause_t cause = SWITCH_CAUSE_NORMAL_CLEARING;
	switch_status_t status;

	if (zstr(data)) {
		return;
	}

	if ((status =
		 switch_ivr_originate(session, &peer_session, &cause, data, 0, NULL, NULL, NULL, NULL, NULL, SOF_NONE, NULL)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Originate Failed.  Cause: %s\n", switch_channel_cause2str(cause));
		return;
	}

	switch_ivr_signal_bridge(session, peer_session);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "msrp channel bridged\n");

	peer_channel = switch_core_session_get_channel(session);
	tech_pvt = switch_core_session_get_private(session);
	ptech_pvt = switch_core_session_get_private(peer_session);

	caller_msrp_session = tech_pvt->msrp_session;
	peer_msrp_session = ptech_pvt->msrp_session;
	switch_assert(caller_msrp_session);
	switch_assert(peer_msrp_session);

	if (switch_channel_test_flag(peer_channel, CF_ANSWERED) && !switch_channel_test_flag(caller_channel, CF_ANSWERED)) {
		switch_channel_pass_callee_id(peer_channel, caller_channel);
		switch_channel_answer(caller_channel);
	}

	// TODO we need to run the following code in a new thread
	// TODO we cannot test channel_ready as we don't have (audio) media
	// while (switch_channel_ready(caller_channel) && switch_channel_ready(peer_channel)){
	while (switch_channel_get_state(caller_channel) == CS_HIBERNATE &&
		switch_channel_get_state(peer_channel) == CS_HIBERNATE){
		int found = 0;
		if ((msrp_msg = msrp_session_pop_msg(caller_msrp_session))) {
			if (msrp_msg->method == MSRP_METHOD_SEND) { /* write to peer */
				msrp_msg->headers[MSRP_H_FROM_PATH] = switch_mprintf("msrp://%s:%d/%s;tcp",
					ptech_pvt->rtpip, peer_msrp_session->local_port, peer_msrp_session->call_id);
				msrp_msg->headers[MSRP_H_TO_PATH] = peer_msrp_session->remote_path;

				if (peer_msrp_session->socket) {
					msrp_send(peer_msrp_session->socket, msrp_msg);
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket not ready, discarding one message!!\n");
				}
			}
			switch_safe_free(msrp_msg);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "eat one message, left:%d\n", (int)caller_msrp_session->msrp_msg_count);
			found++;
		}

		if ((msrp_msg = msrp_session_pop_msg(peer_msrp_session))) {
			if (msrp_msg->method == MSRP_METHOD_SEND) { /* write to caller */
				msrp_msg->headers[MSRP_H_FROM_PATH] = switch_mprintf("msrp://%s:%d/%s;tcp",
					tech_pvt->rtpip, caller_msrp_session->local_port, caller_msrp_session->call_id);
				msrp_msg->headers[MSRP_H_TO_PATH] = caller_msrp_session->remote_path;
				msrp_send(caller_msrp_session->socket, msrp_msg);
			}
			switch_safe_free(msrp_msg);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "eat one message, left:%d\n", (int)peer_msrp_session->msrp_msg_count);
			found++;
		}

		msrp_msg = NULL;
		if (!found) switch_yield(100000);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Bridge down!\n");

	if (peer_session) {
		switch_core_session_rwunlock(peer_session);
	}
}

SWITCH_STANDARD_API(uuid_msrp_send_function)
{
	char *mycmd = NULL, *argv[3] = { 0 };
	int argc;
	switch_core_session_t *msession = NULL;
	// msrp_session_t *msrp_session = NULL;
	msrp_msg_t *msrp_msg = NULL;
	private_object_t *tech_pvt = NULL;
	switch_memory_pool_t *pool = NULL;

	if (zstr(cmd) || !(mycmd = strdup(cmd))) {
		goto error;
	}

	argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));

	if (argc < 2 || !argv[0]) {
		goto error;
	}

	if (!(msession = switch_core_session_locate(argv[0]))) {
		stream->write_function(stream, "-ERR Usage: cannot locate session.\n");
		return SWITCH_STATUS_SUCCESS;
	}

	tech_pvt = switch_core_session_get_private(msession);
	pool = switch_core_session_get_pool(msession);
	switch_assert(pool);

	if (!tech_pvt) {
		stream->write_function(stream, "-ERR No tech_pvt.\n");
		switch_core_session_rwunlock(msession);
		return SWITCH_STATUS_SUCCESS;
	}

	if(!tech_pvt->msrp_session) {
		stream->write_function(stream, "-ERR No msrp_session.\n");
		switch_core_session_rwunlock(msession);
		return SWITCH_STATUS_SUCCESS;
	}

	switch_zmalloc(msrp_msg, sizeof(msrp_msg_t));
	switch_assert(msrp_msg);

	msrp_msg->headers[MSRP_H_FROM_PATH] = switch_mprintf("msrp://%s:%d/%s;tcp",
		tech_pvt->rtpip, tech_pvt->msrp_session->local_port, tech_pvt->msrp_session->call_id);
	msrp_msg->headers[MSRP_H_TO_PATH] = tech_pvt->msrp_session->remote_path;
	msrp_msg->headers[MSRP_H_CONTENT_TYPE] = "text/plain";
	msrp_msg->payload = switch_core_strdup(pool, argv[1]);

	msrp_send(tech_pvt->msrp_session->socket, msrp_msg);

	switch_safe_free(msrp_msg->headers[MSRP_H_FROM_PATH]);
	switch_safe_free(msrp_msg);
	stream->write_function(stream, "+OK sent\n");
	switch_core_session_rwunlock(msession);
	return SWITCH_STATUS_SUCCESS;
error:
	stream->write_function(stream, "-ERR Usage: uuid_msrp_send <uuid> msg\n");
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(void) switch_msrp_load_msrp_apis_and_applications(switch_loadable_module_interface_t **module_interface)
{
	switch_application_interface_t *app_interface;
	switch_api_interface_t *api_interface;
	SWITCH_ADD_API(api_interface, "uuid_msrp_send", "send msrp text", uuid_msrp_send_function, "<cmd> <args>");
	SWITCH_ADD_APP(app_interface, "msrp_echo", "Echo msrp message", "Perform an echo test against the msrp channel", msrp_echo_function, "", SAF_NONE);
	SWITCH_ADD_APP(app_interface, "msrp_recv", "Recv msrp message to file", "Recv msrp message", msrp_recv_function, "<filename>", SAF_NONE);
	SWITCH_ADD_APP(app_interface, "msrp_send", "Send file via msrp", "Send file via msrp", msrp_send_function, "<filename>", SAF_NONE);
	SWITCH_ADD_APP(app_interface, "msrp_bridge", "Bridge msrp channels", "Bridge msrp channels", msrp_bridge_function, "dialstr", SAF_NONE);

}

#endif

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
