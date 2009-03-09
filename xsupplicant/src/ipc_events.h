/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ipc_events.h
 *
 * \author chris@open1x.org
 *
 **/
#ifndef __IPC_EVENTS_H__
#define __IPC_EVENTS_H__

#include <libxml/parser.h>

int ipc_events_statemachine_transition(context *, int, int, int);
void ipc_events_error(context *, unsigned int, char *);
int ipc_events_request_eap_upwd(char *, char *);
void ipc_events_ui(context *, unsigned int, char *);
void ipc_events_imc_event(uint32_t, uint32_t);
void ipc_events_imc_request_event(uint32_t, uint32_t, uint32_t, uint32_t);
int ipc_events_send(xmlDocPtr);
void ipc_events_send_tnc_batch(void *, uint32_t, uint32_t, uint32_t, uint32_t);
int ipc_events_log_msg(char *);
int ipc_events_scan_complete(context *);

// "Quicker" version of the malloc failure error.
#define ipc_events_malloc_failed(ctx) ipc_events_error(ctx, IPC_EVENT_ERROR_MALLOC, (char *)__FUNCTION__)

#endif // __IPC_EVENTS_H__
