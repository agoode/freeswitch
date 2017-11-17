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


switch_status_t baresip_config()
{
	char *conf = "baresip.conf";
	switch_xml_t xml, cfg, profiles, profile, params, param, transports, transport;

	if (!(xml = switch_xml_open_cfg(conf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "open of %s failed\n", conf);
		goto err;
	}

	/* Global module settings */


	/* Profile settings */
	if ( (profiles = switch_xml_child(cfg, "profiles")) != NULL) {
		for (profile = switch_xml_child(profiles, "profile"); profile; profile = profile->next) {		
			baresip_profile_t *new_profile = NULL;
			char *name = (char *)switch_xml_attr_soft(profile, "name");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Parsing baresip profile[%s]\n", name);

			/* Allocate profile */
			if ( baresip_profile_alloc(&new_profile, name) == SWITCH_STATUS_SUCCESS) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Created profile[%s]\n", name);
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create profile[%s]\n", name);
			}

			/* Read and set profile params */
			if ( (params = switch_xml_child(profile, "settings")) != NULL) {
				for (param = switch_xml_child(params, "param"); param; param = param->next) {
					char *var = (char *) switch_xml_attr_soft(param, "name");
					char *val = (char *) switch_xml_attr_soft(param, "value");
					if ( ! strcmp(var, "debug") ) {
						new_profile->debug = switch_true(val);
					} else if ( ! strcmp(var, "dialplan") ) {
						new_profile->dialplan = switch_core_strdup(new_profile->pool, val);
					} else if ( ! strcmp(var, "context") ) {
						new_profile->context = switch_core_strdup(new_profile->pool, val);
					} else if ( ! strcmp(var, "rtpip") ) {
						new_profile->rtpip = switch_core_strdup(new_profile->pool, val);
					} else if ( ! strcmp(var, "extrtpip") ) {
						new_profile->extrtpip = switch_core_strdup(new_profile->pool, val);
					} else {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
										  "Warning profile[%s] unknown param[%s] with value[%s]\n", name, var, val);
					}
				}
			}

			/* Add transports */
			if ( (transports = switch_xml_child(profile, "transports")) != NULL) {
				for (transport = switch_xml_child(transports, "transport"); transport; transport = transport->next) {
					uint16_t port = 0;
					char *ip = NULL, *protocol = NULL;
					for (param = switch_xml_child(transport, "param"); param; param = param->next) {
						char *var = (char *) switch_xml_attr_soft(param, "name");
						char *val = (char *) switch_xml_attr_soft(param, "value");
						if ( ! strcmp(var, "port") ) {
							port = atoi(val);
						} else if ( ! strcmp(var, "ip") ) {
							ip = val;
						} else if ( ! strcmp(var, "protocol") ) {
							protocol = val;
						} else {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
											  "Warning profile[%s] unknown param[%s] with value[%s]\n", name, var, val);
						}
					}
					if ( baresip_profile_transport_add(new_profile, protocol, ip, port) == SWITCH_STATUS_SUCCESS ) {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Profile[%s] added transport on protocol[%s] ip[%s] port[%u]\n", name, protocol, ip, port);
					} else {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] failed to add transport on protocol[%s] ip[%s] port[%u]\n", name, protocol, ip, port);
					}
				}
			}

			/* Start the profile */
			if ( baresip_profile_start(new_profile) == SWITCH_STATUS_SUCCESS ) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Profile[%s] started successfully\n", name);
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile[%s] failed to start\n", name);
			}
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profiles config is missing\n");
		goto err;
	}

	return SWITCH_STATUS_SUCCESS;
	
 err:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Configuration failed\n");
	return SWITCH_STATUS_GENERR;
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
