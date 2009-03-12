/**
 * Calls to convert event ids to useful data that can be displayed.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupgui_events.h
 *
 * \author chris@open1x.org
 *
 */

#ifndef __XSUPGUI_EVENTS_H__
#define __XSUPGUI_EVENTS_H__

#include <libxml/parser.h>

#define XSUPGUI_EVENTS_LOG_LEVEL_NORMAL                    1
#define XSUPGUI_EVENTS_LOG_LEVEL_NORMAL_STR                "NORMAL"

typedef struct _tnc_msg_batch {
	uint32_t imcID;
	uint32_t connectionID;
	uint32_t oui;
	uint32_t msgid;
	char *parameter;
} tnc_msg_batch;

int xsupgui_events_generate_log_string(char **, char **);
int xsupgui_events_get_state_change(char **, int *, int *, int *, uint32_t *);
long int xsupgui_events_get_event_num(xmlDocPtr);
int xsupgui_events_get_scan_complete_interface(char **);
int xsupgui_events_get_passwd_challenge(char **, char **, char **, char **);
int xsupgui_events_get_ui_event(int *, char **, char **);
int xsupgui_events_get_tnc_ui_event(uint32_t *, uint32_t *);
int xsupgui_events_get_tnc_ui_request_event(uint32_t *, uint32_t *, uint32_t *,
					    uint32_t *);
int xsupgui_events_get_tnc_ui_batch_request_event(uint32_t *, uint32_t *,
						  uint32_t *, uint32_t *,
						  tnc_msg_batch **);
void xsupgui_events_free_tnc_msg_batch_data(tnc_msg_batch **);
int xsupgui_events_get_error(int *, char **);

#endif				// __XSUPGUI_EVENTS_H__
