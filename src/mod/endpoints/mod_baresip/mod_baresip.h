/*
* FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
* Copyright (C) 2005-2015, Anthony Minessale II <anthm@freeswitch.org>
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
* William King <william.king@quentustech.com>
*
*
*/

#ifndef MOD_BARESIP_H
#define MOD_BARESIP_H

#include "switch_private.h"
#include <switch.h>
#include <re/re.h>

typedef struct mod_baresip_globals_s {
	switch_memory_pool_t *pool;
	switch_hash_t *profiles;
	switch_bool_t running;
	uint8_t debug;
} mod_baresip_globals_t;

extern mod_baresip_globals_t baresip_globals;
extern switch_state_handler_table_t baresip_state_handlers;

typedef struct baresip_profile_s {
	char *name;
	char *dialplan;
	char *context;
	char *rtpip;
	char *extrtpip;

	switch_memory_pool_t *pool;
	struct sa laddr;
	struct sip_lsnr *sip_listener;
	struct sipsess_sock *sipsess_listener;
	struct sip *sip;
	struct udp_sock *udp_socket;

	int workers;
	struct mqueue **worker_queue;
	switch_thread_t **thread;
	int workers_running;

	switch_bool_t destroyed;
	switch_threadattr_t *thd_attr;
	switch_mutex_t *profile_mutex;
	bool running;
	bool debug;
} baresip_profile_t;

typedef struct baresip_techpvt_s {
	switch_core_media_params_t *mparams;
	switch_core_session_t *session;
	switch_channel_t *channel;
	baresip_profile_t *profile;
	switch_media_handle_t *smh;
	struct sipsess *sipsess;
	struct sipsess_sock *sipsess_listener;
	char *call_id;
	char *r_sdp;
	const struct sip_msg *invite;
	struct sip_strans *strans;
	int media;
} baresip_techpvt_t;

switch_status_t baresip_profile_alloc(baresip_profile_t **new_profile, char *name);
switch_status_t baresip_profile_transport_add(baresip_profile_t *profile, char *protocol, char *ip, uint16_t port);
switch_status_t baresip_profile_start(baresip_profile_t *profile);
void baresip_profile_destroy(baresip_profile_t **old_profile);
bool baresip_profile_recv_req(const struct sip_msg *msg, void *arg);
void baresip_profile_exit_handler(void *arg);
void baresip_profile_mqueue_handler(int id, void *data, void *arg);
switch_status_t baresip_profile_messagehook (switch_core_session_t *session, switch_core_session_message_t *msg);
int baresip_profile_session_auth_handler(char **username, char **password, const char *realm, void *arg);
int baresip_profile_session_offer_handler(struct mbuf **descp, const struct sip_msg *msg, void *arg);
int baresip_profile_session_answer_handler(const struct sip_msg *msg, void *arg);
void baresip_profile_session_progress_handler(const struct sip_msg *msg, void *arg);
void baresip_profile_session_establish_handler(const struct sip_msg *msg, void *arg);
void baresip_profile_session_info_handler(struct sip *sip, const struct sip_msg *msg, void *arg);
void baresip_profile_session_refer_handler(struct sip *sip, const struct sip_msg *msg, void *arg);
void baresip_profile_session_close_handler(int err, const struct sip_msg *msg, void *arg);

switch_status_t baresip_config();

typedef enum {
	BARESIP_PROFILE_COMMAND_SHUTDOWN = 1,
	BARESIP_SESSION_RINGING = 2,
	BARESIP_SESSION_PROGRESS,
	BARESIP_SESSION_ANSWER
} baresip_profile_command_t;

#endif /* MOD_BARESIP_H */

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
