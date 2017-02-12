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
 *
 * switch_channel.h -- Media Channel Interface
 *
 */
/**
 * @file switch_channel_filter.h
 * @brief allows channel vars prefix addition to basic data
 */

#ifndef SWITCH_CHANNEL_FILTER_H
#define SWITCH_CHANNEL_FILTER_H

SWITCH_BEGIN_EXTERN_C

typedef struct switch_channel_filter {
	char* prefix;
	int len;
} switch_channel_filter_t, *switch_channel_filter_p;

typedef struct switch_channel_filters {
	char* original_filter;
	switch_channel_filter_p prefixes;
	int len;
} switch_channel_filters_t, *switch_channel_filters_p;

SWITCH_DECLARE(switch_channel_filters_p) switch_core_get_channel_event_filters();
SWITCH_DECLARE(void) switch_core_set_channel_event_filters(const char*);
SWITCH_DECLARE(void) switch_core_free_channel_event_filters();

SWITCH_END_EXTERN_C
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
