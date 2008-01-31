/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupgui.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _XSUPGUI_H_
#define _XSUPGUI_H_

#ifndef WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#include <inttypes.h>
#endif

#include <libxml/parser.h>

int xsupgui_connect();
int xsupgui_connect_event_listener();
int xsupgui_disconnect();
int xsupgui_disconnect_event_listener();
int xsupgui_process(int *);
int xsupgui_send_to_event(unsigned char *, int);
int xsupgui_send(unsigned char *, int, unsigned char **, int *);
xmlDocPtr xsupgui_get_event_doc();
void xsupgui_free_event_doc();

#endif
