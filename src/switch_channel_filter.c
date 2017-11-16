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
 * Michael Jerris <mike@jerris.com>
 * Paul D. Tinsley <pdt at jackhammer.org>
 * Marcel Barbulescu <marcelbarbulescu@gmail.com>
 * Joseph Sullivan <jossulli@amazon.com>
 * Seven Du <dujinfang@gmail.com>
 *
 * switch_core.c -- Main Core Library
 *
 */



#include <switch.h>
#include <switch_channel_filter.h>
#include "private/switch_core_pvt.h"

static int channel_event_filters_reloadxml_bound = 0;

SWITCH_DECLARE(switch_channel_filters_p) switch_core_get_channel_event_filters()
{
	return runtime.channel_vars_filters;
}

static void switch_core_channel_event_filters_reload(switch_event_t *_event)
{
	switch_xml_t xml = NULL, x_lists = NULL, x_list = NULL, cfg = NULL;

	if ((xml = switch_xml_open_cfg("switch.conf", &cfg, NULL))) {
		if ((x_lists = switch_xml_child(cfg, "settings"))) {
			for (x_list = switch_xml_child(x_lists, "param"); x_list; x_list = x_list->next) {
				const char *name = switch_xml_attr(x_list, "name");
				const char *value = switch_xml_attr(x_list, "value");

				if (zstr(name)) {
					continue;
				}

				if (zstr(value)) {
					continue;
				}

				if (!strcasecmp(name, "channel-var-filters") && !zstr(value)) {
					switch_core_set_channel_event_filters(value);
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "channel event filters reloaded\n");
					break;
				}
			}
		}

		switch_xml_free(xml);
	}
}

SWITCH_DECLARE(void) switch_core_set_channel_event_filters(const char* val)
{
	int i, argc = 0;
	char *argv[20] = { 0 };
	char* filters = switch_safe_strdup(val);
	switch_channel_filters_p pFilters = NULL;

	if ((argc = switch_separate_string(filters, ',', argv, (sizeof(argv) / sizeof(argv[0]))))) {
		pFilters = malloc(sizeof(switch_channel_filters_t));
		pFilters->original_filter = filters;
		pFilters->len = argc;
		pFilters->prefixes = malloc(sizeof(switch_channel_filter_t) * argc);
		for(i = 0; i < argc; i++) {
			pFilters->prefixes[i].prefix = argv[i];
			pFilters->prefixes[i].len = strlen(argv[i]);
		}
		switch_thread_rwlock_wrlock(runtime.global_var_rwlock);
		if(runtime.channel_vars_filters) {
			switch_safe_free(runtime.channel_vars_filters->original_filter);
			switch_safe_free(runtime.channel_vars_filters->prefixes);
			switch_safe_free(runtime.channel_vars_filters);
		}
		runtime.channel_vars_filters = pFilters;
		if(!channel_event_filters_reloadxml_bound) {
			if ((switch_event_bind("channel_filters", SWITCH_EVENT_RELOADXML, NULL, switch_core_channel_event_filters_reload, NULL) != SWITCH_STATUS_SUCCESS)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind to reloadxml!\n");
			} else {
				channel_event_filters_reloadxml_bound = 1;
			}
		}
		switch_thread_rwlock_unlock(runtime.global_var_rwlock);
	}
}

SWITCH_DECLARE(void) switch_core_free_channel_event_filters()
{
	switch_thread_rwlock_wrlock(runtime.global_var_rwlock);
	if(runtime.channel_vars_filters) {
		switch_safe_free(runtime.channel_vars_filters->original_filter);
		switch_safe_free(runtime.channel_vars_filters->prefixes);
		switch_safe_free(runtime.channel_vars_filters);
	}
	if(channel_event_filters_reloadxml_bound) {
		switch_event_unbind_callback(switch_core_channel_event_filters_reload);
	}
	switch_thread_rwlock_unlock(runtime.global_var_rwlock);
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
