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
* mod_baresip.c -- sip endpoint using the baresip, libre and librem libraries
*
*
*/

#include <mod_baresip.h>

struct sip_transport {
	struct le le;
	struct sa laddr;
	struct sip *sip;
	struct tls *tls;
	void *sock;
	enum sip_transp tp;
};

struct sip {
	struct list transpl;
	struct list lsnrl;
	struct list reql;
	struct hash *ht_ctrans;
	struct hash *ht_strans;
	struct hash *ht_strans_mrg;
	struct hash *ht_conn;
	struct hash *ht_udpconn;
	struct dnsc *dnsc;
	struct stun *stun;
	char *software;
	sip_exit_h *exith;
	void *arg;
	bool closing;
};

static void *SWITCH_THREAD_FUNC baresip_profile_thread(switch_thread_t *thread, void *obj);
static switch_status_t baresip_send_media_indication(switch_core_session_t *session, int status, const char *phrase);

void baresip_profile_mqueue_handler(int id, void *data, void *arg)
{
	baresip_profile_t *profile = arg;
	(void) profile;

	switch (id) {
	case BARESIP_PROFILE_COMMAND_SHUTDOWN:
		re_cancel();
		break;
	case BARESIP_SESSION_RINGING:
		baresip_send_media_indication(data, 180, "Ringing");
		break;
	case BARESIP_SESSION_PROGRESS:
		baresip_send_media_indication(data, 183, "Session Progress");
		break;
	case BARESIP_SESSION_ANSWER:
		baresip_send_media_indication(data, 200, "OK");
		break;
	}
}


switch_status_t baresip_tech_media(baresip_techpvt_t *tech_pvt, const char *r_sdp, switch_sdp_type_t sdp_type)
{
	uint8_t match = 0, p = 0;

	switch_assert(tech_pvt != NULL);
	switch_assert(r_sdp != NULL);

	if (zstr(r_sdp)) {
		return SWITCH_STATUS_FALSE;
	}

	switch_core_media_set_sdp_codec_string(tech_pvt->session, r_sdp, sdp_type);
	switch_core_media_prepare_codecs(tech_pvt->session, SWITCH_FALSE);

	if ((match = switch_core_media_negotiate_sdp(tech_pvt->session, r_sdp, &p, sdp_type))) {
		if (switch_core_media_choose_ports(tech_pvt->session, SWITCH_TRUE, SWITCH_FALSE) != SWITCH_STATUS_SUCCESS) {
			return SWITCH_STATUS_FALSE;
		}

		if (sdp_type == SDP_TYPE_REQUEST) {
			switch_core_media_gen_local_sdp(tech_pvt->session, SDP_TYPE_RESPONSE, NULL, 0, NULL, 0);
		}

		if (switch_core_media_activate_rtp(tech_pvt->session) != SWITCH_STATUS_SUCCESS) {
			return SWITCH_STATUS_FALSE;
		}

		return SWITCH_STATUS_SUCCESS;
	}


	return SWITCH_STATUS_FALSE;
}

static switch_status_t baresip_send_media_indication(switch_core_session_t *session, int status, const char *phrase)
{
	baresip_techpvt_t *tech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);
	const char *sdp = NULL;
	struct mbuf *sdp_mbuf = NULL;
	int err = 0;

	if ( status < tech_pvt->media ) {
		return SWITCH_STATUS_SUCCESS;
	}

	if (status != 180) {
		if (switch_channel_test_flag(tech_pvt->channel, CF_PROXY_MODE)) {
			switch_core_media_absorb_sdp(session);
		} else if (baresip_tech_media(tech_pvt, tech_pvt->r_sdp,  SDP_TYPE_REQUEST) != SWITCH_STATUS_SUCCESS) {
			return SWITCH_STATUS_FALSE;
		}

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Profile[%s] callid[%s] %d %s\n", tech_pvt->profile->name, tech_pvt->call_id, status, phrase);
		sdp = tech_pvt->mparams->local_sdp_str;
	}
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "LOCAL SDP:\n%s\n", sdp);

	if (sdp) {
		sdp_mbuf = mbuf_alloc(2048);
		mbuf_printf(sdp_mbuf, "%s", sdp);
		mbuf_set_pos(sdp_mbuf, 0);
	}

	switch (status) {
	case 200:
		err = sipsess_answer(tech_pvt->sipsess, 200, "OK", sdp_mbuf, "X-module: mod_baresip\r\n");
		break;
	case 180:
	case 183:
		err = sipsess_progress(tech_pvt->sipsess, status, phrase, sdp_mbuf, "X-module: mod_baresip\r\n");
		break;
	}

	tech_pvt->media = status;

	if ( sdp_mbuf ) {
		mem_deref(sdp_mbuf);
	}
	
	if ( err ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] failed %d on %d %s sip session[%p] %p %p\n",
						  tech_pvt->profile->name, err, status, phrase, (void *)session, (void *) tech_pvt, (void *)tech_pvt->sipsess);

		return SWITCH_STATUS_FALSE;
	}

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t baresip_profile_messagehook (switch_core_session_t *session, switch_core_session_message_t *msg)
{
	baresip_techpvt_t *tech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] message\n", tech_pvt->profile->name);
	// TODO: May need to queue these into the mqueue commands. To prevent concurrent access to the worker thread tmrl(timer list).
	switch(msg->message_id) {
	case SWITCH_MESSAGE_INDICATE_ANSWER:
		mqueue_push(tech_pvt->profile->worker_queue[0], BARESIP_SESSION_ANSWER, (void *)session);
	case SWITCH_MESSAGE_INDICATE_RINGING:
		mqueue_push(tech_pvt->profile->worker_queue[0], BARESIP_SESSION_RINGING, (void *)session);
	case SWITCH_MESSAGE_INDICATE_PROGRESS:
		mqueue_push(tech_pvt->profile->worker_queue[0], BARESIP_SESSION_PROGRESS, (void *)session);
	default:
		break;	
	}

	return SWITCH_STATUS_SUCCESS;
}

static bool baresip_profile_process_invite(baresip_profile_t *profile, const struct sip_msg *msg, char **uuid)
{
	switch_call_cause_t reason = SWITCH_CAUSE_INVALID_MSG_UNSPECIFIED, cancel_cause = 0;
	const struct sip_hdr *cid = sip_msg_hdr(msg, SIP_HDR_CALL_ID);
	switch_caller_profile_t *caller_profile;
	switch_core_session_t *session = NULL;
	switch_channel_t *channel = NULL;
	baresip_techpvt_t *tech_pvt = NULL;
	switch_event_t *var_event;
	char call_id[256], name[512], *destination_extension = NULL;
	char cid_name[256], cid_number[256], remote_host[256];

	snprintf(call_id, sizeof(call_id), "%.*s", (int) cid->val.l, cid->val.p);
	switch_event_create_plain(&var_event, SWITCH_EVENT_CHANNEL_DATA);
	switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, "origination_uuid", call_id);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Profile[%s] recieved new call with call id of [%s]\n", profile->name, call_id);

	if ((reason = switch_core_session_outgoing_channel(NULL, var_event, "rtc",
													   NULL, &session, NULL, SOF_NONE, &cancel_cause)) != SWITCH_CAUSE_SUCCESS) {
		
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Profile[%s] Failed to create channel\n", profile->name);
		goto err;
	}

    channel = switch_core_session_get_channel(session);
	switch_channel_set_direction(channel, SWITCH_CALL_DIRECTION_INBOUND);

    tech_pvt = switch_core_session_alloc(session, sizeof(*tech_pvt));
	tech_pvt->session = session;
	tech_pvt->channel = channel;
	tech_pvt->profile = profile;
	tech_pvt->media = 0;
	tech_pvt->call_id = switch_core_session_strdup(session, call_id);
	tech_pvt->invite = msg;
	tech_pvt->r_sdp = switch_core_session_sprintf(session, "%.*s", mbuf_get_left(msg->mb), mbuf_buf(msg->mb));
	tech_pvt->smh = switch_core_session_get_media_handle(session);
	tech_pvt->mparams = switch_core_media_get_mparams(tech_pvt->smh);

	tech_pvt->mparams->rtpip = profile->rtpip;
	tech_pvt->mparams->extrtpip = profile->extrtpip ? profile->extrtpip : profile->rtpip;

	//add these to profile
	tech_pvt->mparams->timer_name =  "soft";
	tech_pvt->mparams->local_network = "localnet.auto";

	switch_core_session_set_private_class(session, tech_pvt, SWITCH_PVT_SECONDARY);
	
	destination_extension = calloc(1, msg->uri.user.l + 1);
	memcpy(destination_extension, msg->uri.user.p, msg->uri.user.l);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Remote SDP\n%s\n", tech_pvt->r_sdp);

	switch_snprintf(name, sizeof(name), "baresip.rtc/%s", "1234");
	switch_channel_set_name(channel, name);	
	
	snprintf(cid_name, sizeof(cid_name), "%.*s", (int) msg->from.dname.l, msg->from.dname.p);
	snprintf(cid_number, sizeof(cid_number), "%.*s", (int) msg->from.uri.user.l, msg->from.uri.user.p);
	snprintf(remote_host, sizeof(remote_host), "%s", inet_ntoa(msg->src.u.in.sin_addr));

	switch_channel_add_state_handler(channel, &baresip_state_handlers);
	switch_core_event_hook_add_receive_message(session, baresip_profile_messagehook);

    if ((caller_profile = switch_caller_profile_new(switch_core_session_get_pool(session),
													"uid",
													profile->dialplan,
													cid_name,
													cid_number,
													remote_host,
													"ani", "anii", "rdnis",
													"source",
													profile->context,
													destination_extension))) {

		switch_channel_set_caller_profile(channel, caller_profile);
	}

	switch_channel_set_cap(tech_pvt->channel, CC_BYPASS_MEDIA);
	
	switch_channel_set_state(channel, CS_INIT);
	*uuid = switch_core_session_get_uuid(session);
	return true;

 err:
	return false;
}

int baresip_profile_session_auth_handler(char **username, char **password, const char *realm, void *arg)
{
	(void) username;
	(void) password;
	(void) realm;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session answer handler called for [%s]\n", (char *) arg);
	return 0;
}

int baresip_profile_session_offer_handler(struct mbuf **descp, const struct sip_msg *msg, void *arg)
{
	(void) descp;
	(void) msg;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session answer handler called for [%s]\n", (char *) arg);
	return 0;
}

int baresip_profile_session_answer_handler(const struct sip_msg *msg, void *arg)
{
	switch_core_session_t *session = NULL;
	switch_channel_t *channel = NULL;
	baresip_techpvt_t *tech_pvt = NULL;
	char *uuid = arg;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session answer handler called for [%s]\n", (char *) arg);

	session = switch_core_session_locate(uuid);
	channel = switch_core_session_get_channel(session);
	tech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);

	tech_pvt->r_sdp = switch_core_session_sprintf(session, "%.*s", mbuf_get_left(msg->mb), mbuf_buf(msg->mb));

	if (switch_true(switch_channel_get_variable(channel, SWITCH_BYPASS_MEDIA_VARIABLE))) {
		switch_core_session_t *other_session = NULL;
		switch_channel_t *other_channel = NULL;

		if (switch_core_session_get_partner(tech_pvt->session, &other_session) == SWITCH_STATUS_SUCCESS) {
			other_channel = switch_core_session_get_channel(other_session);
			switch_channel_pass_sdp(tech_pvt->channel, other_channel, tech_pvt->r_sdp);

			switch_channel_set_flag(other_channel, CF_PROXY_MODE);
			switch_core_session_queue_indication(other_session, SWITCH_MESSAGE_INDICATE_ANSWER);
			switch_core_session_rwunlock(other_session);
		}
	}

	baresip_tech_media(tech_pvt, tech_pvt->r_sdp,  SDP_TYPE_RESPONSE);
	switch_channel_mark_answered(channel);
	switch_core_media_activate_rtp(session);
	switch_core_session_rwunlock(session);

	return 0;
}

void baresip_profile_session_progress_handler(const struct sip_msg *msg, void *arg)
{
	switch_core_session_t *session = NULL;
	switch_channel_t *channel = NULL;
	baresip_techpvt_t *tech_pvt = NULL;
	char *uuid = arg;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session progress handler called for [%s] code[%d]\n", (char *) arg, msg->scode);

	session = switch_core_session_locate(uuid);
	channel = switch_core_session_get_channel(session);
	tech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);

	if ( msg && msg->scode ) {
		switch(msg->scode) {
		case 100:
			break;
		case 180:
			switch_channel_mark_ring_ready(channel);
			break;
		case 183:
			tech_pvt->r_sdp = switch_core_session_sprintf(session, "%.*s", mbuf_get_left(msg->mb), mbuf_buf(msg->mb));
			baresip_tech_media(tech_pvt, tech_pvt->r_sdp,  SDP_TYPE_RESPONSE);
			switch_core_media_activate_rtp(session);
			switch_channel_mark_pre_answered(channel);
			break;
		default:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "session progress handler called for [%s] with unknown progress code[%d]\n",
							  (char *) arg, msg->scode);
		}
	}
		
	switch_core_session_rwunlock(session);
}

void baresip_profile_session_establish_handler(const struct sip_msg *msg, void *arg)
{
	(void) msg;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session establish handler called for [%s]\n", (char *) arg);
}

void baresip_profile_session_info_handler(struct sip *sip, const struct sip_msg *msg, void *arg)
{
	(void) msg;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session info handler called for [%s]\n", (char *) arg);
}

void baresip_profile_session_refer_handler(struct sip *sip, const struct sip_msg *msg, void *arg)
{
	(void) msg;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session refer handler called for [%s]\n", (char *) arg);
}

void baresip_profile_session_close_handler(int err, const struct sip_msg *msg, void *arg)
{
	switch_core_session_t *session = NULL;
	baresip_techpvt_t *tech_pvt = NULL;
	switch_channel_t *channel = NULL;
	char *uuid = arg;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session close handler called for [%s]\n", uuid);

	session = switch_core_session_locate(uuid);
	if ( !session ) {
		return;
	}

	channel = switch_core_session_get_channel(session);

	tech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);
	switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	switch_core_session_rwunlock(session);

	if ( tech_pvt->sipsess ) {
		tech_pvt->sipsess = mem_deref(tech_pvt->sipsess);
	}
}

static void baresip_profile_sipsess_handler(const struct sip_msg *msg, void *arg)
{
	baresip_profile_t *profile = arg;
	struct sipsess *sipsess = NULL;
	switch_core_session_t *session = NULL;
	baresip_techpvt_t *tech_pvt = NULL;
	char *uuid = NULL;
	int err = 0;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Profile[%s] recieved session connection request of method[%.*s] scode[%d]\n",
					  profile->name, (int)msg->met.l, msg->met.p, msg->scode);

	if (!strncmp(msg->met.p, "INVITE", 6)) {
		baresip_profile_process_invite(profile, msg, &uuid);
	}

	//	sip_reply(profile->sip, msg, 100, "Trying");

	/* sipsess_accept has to send a message with a status code between 101 and 299. So for now, just send a 101. */
	err = sipsess_accept(&sipsess,
				   profile->sipsess_listener,
				   msg,
				   101,      /* response status code */
				   "Trying", /* response reason */
				   "mod_baresip",  /* contact username or uri */
				   "application/sdp",  /* content-type */
				   NULL,     /* mbuf of content */
				   baresip_profile_session_auth_handler,     /* sip auth handler */
				   uuid,     /* sip auth handler arg */
				   false,    /* mem_ref auth arg */
				   baresip_profile_session_offer_handler,     /* offer_handler */
				   baresip_profile_session_answer_handler,     /* answer_handler */
				   baresip_profile_session_establish_handler,     /* established_handler */
				   baresip_profile_session_info_handler,     /* info_handler */
				   baresip_profile_session_refer_handler,     /* refer_handler */
				   baresip_profile_session_close_handler,     /* close_handler */
				   uuid,     /* handler arg */
				   "X-module: mod_bearsip\r\n");  /* Extra sip headers */

	if ( err ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] failed to accept sip session[%d] %p\n", profile->name, err, (void *) sipsess);
	}

	session = switch_core_session_locate(uuid);
	tech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);
	tech_pvt->sipsess = sipsess;
	tech_pvt->sipsess_listener = profile->sipsess_listener;

	switch_core_session_thread_launch(session);
	switch_core_session_rwunlock(session);
}

/*
static bool baresip_profile_request_handler(const struct sip_msg *msg, void *arg)
{
	baresip_profile_t *profile = arg;
	switch_bool_t status = true;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Profile[%s] received request of method[%.*s] scode[%d]\n",
					  profile->name, (int)msg->met.l, msg->met.p, msg->scode);

	if (!strncmp(msg->met.p, "INVITE", 6)) {
		status = baresip_profile_process_invite(profile, msg);
	} else if (!strncmp(msg->met.p, "OPTIONS", 7)) {
		sip_reply(profile->sip, msg, 200, "OK");
	} else {
		sip_reply(profile->sip, msg, 405, "Method Not Allowed");
	}
	
	return status;
}
*/

switch_status_t baresip_profile_transport_add(baresip_profile_t *profile, char *protocol, char *ip, uint16_t port)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if ((status = sa_set_str(&(profile->laddr), ip, port))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] unable to set local listen protocol[%s] ip[%s] port[%u] err[%d]\n", profile->name, protocol, ip, port, status);
		switch_goto_status(SWITCH_STATUS_GENERR, err);
	}

	status = sip_transp_add(profile->sip, SIP_TRANSP_UDP, &(profile->laddr));

 err:
	return status;
}

switch_status_t baresip_profile_start(baresip_profile_t *profile)
{
	int x = 0;

	profile->worker_queue = switch_core_alloc(profile->pool, sizeof(struct mqueue *) * profile->workers);
	memset(profile->worker_queue, 0, profile->workers);

	profile->thread = switch_core_alloc(profile->pool, sizeof(switch_thread_t *) * profile->workers);
	memset(profile->thread, 0, profile->workers);

	for ( x = 0; x < profile->workers; x++) {
		switch_thread_create(&(profile->thread[x]), profile->thd_attr, baresip_profile_thread, (void *) profile, profile->pool);
	}

	switch_core_hash_insert(baresip_globals.profiles, profile->name, (void *) profile);

	return SWITCH_STATUS_SUCCESS;
}

#ifdef HAVE_LIBRE_SIPSETTRACE


static void baresip_profile_siptrace_handler(bool tx, enum sip_transp tp, const struct sa *src, const struct sa *dst, const uint8_t *pkt, size_t len, void *arg)
{
	baresip_profile_t *profile = arg;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "Profile[%s] [%s]:\n%.*s\n", profile->name, tx ? "send" : "recv", (int) len, pkt);
}


#endif

switch_status_t baresip_profile_alloc(baresip_profile_t **new_profile, char *name)
{
	baresip_profile_t *profile = NULL;
	switch_memory_pool_t *pool = NULL;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if ( !name ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create profile due to missing profile name\n");
		switch_goto_status(SWITCH_STATUS_GENERR, err);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] created\n", name);

  	switch_core_new_memory_pool(&pool);

	profile = switch_core_alloc(pool, sizeof(baresip_profile_t));

	profile->pool = pool;
	profile->workers = 1;
	profile->workers_running = 0;
	profile->destroyed = SWITCH_FALSE;
	profile->name = switch_core_strdup(profile->pool, name);
	profile->dialplan = "XML";
	profile->context = "public";
	profile->rtpip = NULL;
	profile->extrtpip = NULL;
	profile->running = true;
	profile->debug = false;

	switch_mutex_init(&(profile->profile_mutex), SWITCH_MUTEX_UNNESTED, baresip_globals.pool);

	/* Process profile params */

	if (sip_alloc(&(profile->sip), NULL, 65536, 65536, 65536, "FreeSWITCH mod_baresip", baresip_profile_exit_handler, profile)){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to allocate sip user agent\n");
		switch_goto_status(SWITCH_STATUS_GENERR, err);
	}

#ifdef HAVE_LIBRE_SIPSETTRACE

	sip_set_trace(profile->sip, baresip_profile_siptrace_handler);
#endif

	/* Generic catch all for all inbound requests */
	// sip_listen(&(profile->sip_listener), profile->sip, true, baresip_profile_request_handler, profile);
	sipsess_listen(&(profile->sipsess_listener), profile->sip, 65536, baresip_profile_sipsess_handler, profile);
	
	/* Start profile worker threads */
	switch_threadattr_create(&(profile->thd_attr), baresip_globals.pool);
	switch_threadattr_priority_set(profile->thd_attr, SWITCH_PRI_REALTIME);
	switch_threadattr_stacksize_set(profile->thd_attr, SWITCH_THREAD_STACKSIZE);

	*new_profile = profile;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Profile[%s] created\n", name);
	return status;
 err:
	baresip_profile_destroy(&profile);
	
	return status;
}

void baresip_profile_exit_handler(void *arg)
{
	baresip_profile_t *profile = arg;

	if (profile->destroyed){
		return;
	}

	profile->destroyed = SWITCH_TRUE;
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] exit handler called\n", profile->name);
	baresip_profile_destroy(&profile);
}

void baresip_profile_destroy(baresip_profile_t **old_profile)
{
	baresip_profile_t *profile = NULL;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	int x = 0, debug = 0;

	if (!old_profile || !*old_profile){
		return;
	} else {
		profile = *old_profile;
	}

	debug = profile->debug;
	switch_core_hash_delete(baresip_globals.profiles, profile->name);

	if ( debug ) {
		mem_debug();
	}

	profile->running = false;

	for (x = 0; x < profile->workers; x++) {
		mqueue_push(profile->worker_queue[x], BARESIP_PROFILE_COMMAND_SHUTDOWN, profile->worker_queue[x]);
	}

	for (x = 0; x < profile->workers; x++) {
		switch_thread_join(&status, profile->thread[x]);
	}

	if (profile->sip_listener) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Baresip profile destroy sip_listener %d\n", (int) mem_nrefs(profile->sip_listener));	
		mem_deref(profile->sip_listener);
	}

	if (profile->sipsess_listener) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Baresip profile destroy sipsess_listener %d\n", (int) mem_nrefs(profile->sipsess_listener));	
		sipsess_close_all(profile->sipsess_listener);
		mem_deref(profile->sipsess_listener);
	}
	
	if (profile->sip) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Baresip profile destroy sip %d\n", (int) mem_nrefs(profile->sip));	
		sip_close(profile->sip, true);
		mem_deref(profile->sip);
	}

	*old_profile = NULL;
	return;
}

static void baresip_profile_worker_thread_destroy(baresip_profile_t *profile)
{
	switch_mutex_lock(profile->profile_mutex);
	profile->workers_running--;
	switch_mutex_unlock(profile->profile_mutex);
}

static int8_t baresip_profile_get_next_id(baresip_profile_t *profile)
{
	int8_t idx = -1;
	int x = 0;
	char *reserved = "UNDEF";

	/* 
	   The worker thread idx is based on the worker queue index -
	   1. If a worker thread shutsdown, then that worker queue will be
	   NULL. If there are no available worker queues to create, then
	   this will return -1. Any result < 0 is considered an error.
	 */
	
	switch_mutex_lock(profile->profile_mutex);
	for ( x = 0; x < profile->workers && idx == -1; x++) {
		if ( profile->worker_queue[x] != NULL ) {
			continue;
		}
		idx = x;
		profile->worker_queue[x] = (void *) reserved;
		profile->workers_running++;
	}
	switch_mutex_unlock(profile->profile_mutex);

	return idx;
}

static void *SWITCH_THREAD_FUNC baresip_profile_thread(switch_thread_t *thread, void *obj)
{
	baresip_profile_t *profile = obj;
	int err = 0;
	int8_t idx = baresip_profile_get_next_id(profile);
	struct le *le;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Profile[%s] starting worker thread %d\n", profile->name, idx);

	/* Create a new instance of struct re, owned by this thread */
	err = re_thread_init();
	if (err) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] worker thread init failed: %d\n", profile->name, err);
		goto out;
	}

	/* the mqueue needs to be allocated from the event thread itself. The allocation is what subscribes the thread. */
	err = mqueue_alloc(&(profile->worker_queue[idx]), baresip_profile_mqueue_handler, profile);

	/* Attach this thread to the shared UDP-socket
	 */

	for (le = profile->sip->transpl.head; le; le = le->next) {
		const struct sip_transport *transp = le->data;

		switch(transp->tp) {
		case SIP_TRANSP_UDP:
			err = udp_thread_attach(transp->sock);
			if (err) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
								  "Profile[%s] attaching worker thread to udp socket failed: %d\n", profile->name, err);
				goto out;
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
								  "Profile[%s] attaching worker thread to udp socket success\n", profile->name);

			}
			break;
		default:
			break;
		}
	}
	

	/* Start the event-loop for this thread.
	 * Call re_cancel() from the same thread to stop it.
	 */
	re_main(NULL);

 out:
	mem_deref(profile->worker_queue[idx]);
	udp_thread_detach(profile->udp_socket);
	re_thread_close();
	baresip_profile_worker_thread_destroy(profile);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Profile[%s] exiting worker thread %d\n", profile->name, idx);
	return NULL;
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
