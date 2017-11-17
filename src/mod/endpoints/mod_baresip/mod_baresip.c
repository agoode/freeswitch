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

SWITCH_MODULE_LOAD_FUNCTION(mod_baresip_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_baresip_shutdown);
SWITCH_MODULE_DEFINITION(mod_baresip, mod_baresip_load, mod_baresip_shutdown, NULL);

mod_baresip_globals_t baresip_globals;
switch_endpoint_interface_t *baresip_endpoint_interface;

static switch_status_t baresip_on_init(switch_core_session_t *session);
static switch_status_t baresip_on_hangup(switch_core_session_t *session);
static switch_status_t baresip_on_destroy(switch_core_session_t *session);
static switch_call_cause_t baresip_outgoing_channel(switch_core_session_t *session,
													switch_event_t *var_event,
													switch_caller_profile_t *outbound_profile,
													switch_core_session_t **new_session, 
													switch_memory_pool_t **pool, 
													switch_originate_flag_t flags,
													switch_call_cause_t *cancel_cause);

switch_io_routines_t baresip_io_routines = {
	/*.outgoing_channel */ baresip_outgoing_channel,
	/*.read_frame */ NULL,
	/*.write_frame */ NULL,
	/*.kill_channel */ NULL,
	/*.send_dtmf */ NULL,
	/*.receive_message */ NULL,
	/*.receive_event */ NULL,
	/*.state_change */ NULL,
	/*.read_video_frame */ NULL,
	/*.write_video_frame */ NULL,
	/*.state_run*/ NULL,
	/*.get_jb*/ NULL
};

switch_state_handler_table_t baresip_state_handlers = {
	/*.on_init */ baresip_on_init,
	/*.on_routing */ NULL,
	/*.on_execute */ NULL,
	/*.on_hangup */ baresip_on_hangup, /* TODO */
	/*.on_exchange_media */ NULL,
	/*.on_soft_execute */ NULL,
	/*.on_consume_media */ NULL,
	/*.on_hibernate */ NULL,
	/*.on_reset */ NULL,
	/*.on_park */ NULL,
	/*.on_reporting */ NULL,
	/*.on_destroy */ baresip_on_destroy /* TODO */
};

static switch_status_t baresip_on_init(switch_core_session_t *session)
{
	(void) session;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Baresip channel init\n");	
	
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t baresip_on_hangup(switch_core_session_t *session)
{
	baresip_techpvt_t *tech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Baresip channel hangup [%p]\n", (void *) tech_pvt->sipsess);

	if ( tech_pvt->sipsess ) {
		tech_pvt->sipsess = mem_deref((void *)tech_pvt->sipsess);
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t baresip_on_destroy(switch_core_session_t *session)
{
	baresip_techpvt_t *tech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);
	(void) tech_pvt;

	return SWITCH_STATUS_SUCCESS;
}

static switch_call_cause_t baresip_outgoing_channel(switch_core_session_t *session,
													switch_event_t *var_event,
													switch_caller_profile_t *outbound_profile,
													switch_core_session_t **new_session, 
													switch_memory_pool_t **pool, 
													switch_originate_flag_t flags,
													switch_call_cause_t *cancel_cause)
{
	switch_call_cause_t cause = SWITCH_CAUSE_CHANNEL_UNACCEPTABLE;
	switch_channel_t *channel;
	struct sipsess *sipsess = NULL;
	switch_caller_profile_t *caller_profile;
	baresip_techpvt_t *tech_pvt = NULL;
	baresip_profile_t *profile = NULL;
	char *dest = NULL, *data = NULL;
	char *str = NULL, *uuid = NULL;
	struct mbuf *sdp_mbuf = NULL;
	char name[256] = {0}, from_uri[256] = {0};
	int err = 0;

	PROTECT_INTERFACE(baresip_endpoint_interface);

	if (!zstr(outbound_profile->destination_number)) {
		dest = strdup(outbound_profile->destination_number);
	}

	if (zstr(dest)) {
		goto end;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Baresip creating outbound channel to [%s]\n", dest);

	data = strchr(dest, '/');
	*data = '\0';
	data++;
	profile = switch_core_hash_find(baresip_globals.profiles, dest);

	if (!profile) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Baresip unable to locate profile [%s] to create outbound channel\n", dest);
		goto end;
	}

	switch_event_serialize(var_event, &str, 0);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Creating channel from event:\n%s\n", str);
	switch_safe_free(str);

	if ((cause = switch_core_session_outgoing_channel(session, var_event, "rtc",
												  outbound_profile, new_session, NULL, SOF_NONE, cancel_cause)) != SWITCH_CAUSE_SUCCESS) {
		goto end;
	}

    channel = switch_core_session_get_channel(*new_session);
	switch_channel_set_direction(channel, SWITCH_CALL_DIRECTION_OUTBOUND);

    tech_pvt = switch_core_session_alloc(*new_session, sizeof(*tech_pvt));
	tech_pvt->session = *new_session;
	tech_pvt->channel = channel;
	tech_pvt->profile = profile;
	tech_pvt->media = 0;
	tech_pvt->smh = switch_core_session_get_media_handle(*new_session);
	tech_pvt->mparams = switch_core_media_get_mparams(tech_pvt->smh);

	tech_pvt->mparams->rtpip = profile->rtpip;
	tech_pvt->mparams->extrtpip = profile->extrtpip ? profile->extrtpip : profile->rtpip;

	//add these to profile
	tech_pvt->mparams->timer_name =  "soft";
	tech_pvt->mparams->local_network = "localnet.auto";
		
	switch_core_session_set_private_class(*new_session, tech_pvt, SWITCH_PVT_SECONDARY);
	
	switch_snprintf(name, sizeof(name), "baresip.rtc/%s", "1234");
	switch_channel_set_name(channel, name);	
	
	switch_channel_add_state_handler(channel, &baresip_state_handlers);
	switch_core_event_hook_add_receive_message(*new_session, baresip_profile_messagehook);

	if ((caller_profile = switch_caller_profile_dup(switch_core_session_get_pool(*new_session), outbound_profile))) {
		switch_channel_set_caller_profile(channel, caller_profile);        
	} 
		
	switch_channel_set_state(channel, CS_INIT);
	uuid = switch_core_session_get_uuid(*new_session);

	if (session) {
		switch_channel_t *ochannel = switch_core_session_get_channel(session);
		baresip_techpvt_t *otech_pvt = switch_core_session_get_private_class(session, SWITCH_PVT_SECONDARY);

		if (switch_true(switch_channel_get_variable(ochannel, SWITCH_BYPASS_MEDIA_VARIABLE))) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "BYPASS_MEDIA ENABLED\n");
			switch_channel_set_flag(channel, CF_PROXY_MODE);
			switch_channel_set_flag(ochannel, CF_PROXY_MODE);
			switch_channel_set_cap(channel, CC_BYPASS_MEDIA);

			/* A-leg to B-leg copy of SDP, then B leg absorb it */
			switch_channel_pass_sdp(otech_pvt->channel, channel, otech_pvt->r_sdp);
			switch_core_media_absorb_sdp(*new_session);
		} else {
			switch_core_media_prepare_codecs(*new_session, SWITCH_TRUE);
			switch_core_media_choose_ports(*new_session, SWITCH_TRUE, SWITCH_FALSE);
			switch_core_media_gen_local_sdp(*new_session, SDP_TYPE_REQUEST, tech_pvt->mparams->extrtpip, 0, NULL, 0);
		}
	}
	
	if (tech_pvt->mparams->local_sdp_str) {
		sdp_mbuf = mbuf_alloc(2048);
		mbuf_printf(sdp_mbuf, "%s", tech_pvt->mparams->local_sdp_str);
		mbuf_set_pos(sdp_mbuf, 0);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Session local SDP[%s]\n", tech_pvt->mparams->local_sdp_str);
	}

	/* TODO: Not the correct way to construct the from uri, but this at least parses properly for now */
	snprintf(from_uri, sizeof(from_uri), "sip:%s@%s", "1234", tech_pvt->mparams->extrtpip);

	/*
	  int  sipsess_connect(struct sipsess **sessp, struct sipsess_sock *sock,
                     const char *to_uri, const char *from_name,
                     const char *from_uri, const char *cuser,
                     const char *routev[], uint32_t routec,
                     const char *ctype, struct mbuf *desc,
                     sip_auth_h *authh, void *aarg, bool aref,
                     sipsess_offer_h *offerh, sipsess_answer_h *answerh,
                     sipsess_progr_h *progrh, sipsess_estab_h *estabh,
                     sipsess_info_h *infoh, sipsess_refer_h *referh,
                     sipsess_close_h *closeh, void *arg, const char *fmt, ...);
	 */
	err = sipsess_connect(&sipsess,
						  profile->sipsess_listener,
						  data,     /* to uri */
						  "from_name", /* from name */
						  from_uri, /* from uri */
						  "mod_baresip",  /* contact username or uri */
						  NULL,     /* route array */
						  0,        /* route count */
						  "application/sdp",  /* content-type */
						  sdp_mbuf,     /* mbuf of content */
						  baresip_profile_session_auth_handler,     /* sip auth handler */
						  uuid,     /* sip auth handler arg */
						  false,    /* mem_ref auth arg */
						  baresip_profile_session_offer_handler,     /* offer_handler */
						  baresip_profile_session_answer_handler,     /* answer_handler */
						  baresip_profile_session_progress_handler, /* progress_handler */
						  baresip_profile_session_establish_handler,     /* established_handler */
						  baresip_profile_session_info_handler,     /* info_handler */
						  baresip_profile_session_refer_handler,     /* refer_handler */
						  baresip_profile_session_close_handler,     /* close_handler */
						  uuid,     /* handler arg */
						  "X-module: mod_bearsip\r\n");  /* Extra sip headers */

	if ( err ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] failed to create sip request[%d][%s] %p\n",
						  profile->name, err, strerror(err), (void *) sipsess);
		cause = SWITCH_CAUSE_CHANNEL_UNACCEPTABLE;
		goto end;
	}

	tech_pvt->sipsess = sipsess;
	tech_pvt->sipsess_listener = profile->sipsess_listener;
	
 end:
	if (cause != SWITCH_CAUSE_SUCCESS) {
		UNPROTECT_INTERFACE(baresip_endpoint_interface);
	}

	if (sdp_mbuf) {
		mem_deref(sdp_mbuf);
	}
	switch_safe_free(dest);

	return cause;
}
/* switch_status_t name (switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_baresip_load)
{
	int re_err = 0;
	
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	
	memset(&baresip_globals, 0, sizeof(mod_baresip_globals_t));
	baresip_globals.pool = pool;
	baresip_globals.debug = 0;
	baresip_globals.running = 1;

	switch_core_hash_init(&(baresip_globals.profiles));
	
	if ( baresip_config() != SWITCH_STATUS_SUCCESS ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to load due to bad configs\n");
		return SWITCH_STATUS_TERM;
	}

	re_err = libre_init();
	if (re_err) {
		return SWITCH_STATUS_GENERR;
	}

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	baresip_endpoint_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_ENDPOINT_INTERFACE);
	baresip_endpoint_interface->interface_name = "baresip";
	baresip_endpoint_interface->io_routines = &baresip_io_routines;
	baresip_endpoint_interface->state_handler = &baresip_state_handlers;
	baresip_endpoint_interface->recover_callback = NULL;

	//	re_main(NULL);
	
	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_baresip_shutdown)
{
	switch_hash_index_t *hi;
	baresip_profile_t *profile = NULL;
	/* loop through profiles, and destroy them */
	/* destroy gateways hash */
	baresip_globals.running = false;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Baresip event thread canceled\n");		
	
	while ((hi = switch_core_hash_first(baresip_globals.profiles))) {
		switch_core_hash_this(hi, NULL, NULL, (void **)&profile);
		baresip_profile_destroy(&profile);
		switch_safe_free(hi);
	}

	switch_core_hash_destroy(&(baresip_globals.profiles));
	libre_close();
	mem_debug();
	
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
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
