/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupgui_ud.h
 *
 * \author chris@open1x.org
 *
 * $Id: xsupgui_ud.h,v 1.4 2007/10/16 08:27:49 galimorerpg Exp $
 * $Date: 2007/10/16 08:27:49 $
 **/
#ifndef __XSUPGUI_UD_H__
#define __XSUPGUI_UD_H__

int xsupgui_connect();
int xsupgui_disconnect();

int xsupgui_ud_connect();
int xsupgui_ud_disconnect();

int xsupgui_ud_connect_event_listener();
int xsupgui_ud_disconnect_event_listener();

int xsupgui_ud_selectable_socket();

long int xsupgui_ud_process(int *evttype);

int xsupgui_ud_send(unsigned char *tosend, int sendsize, unsigned char **result,
		    int *resultsize);
int xsupgui_ud_send_to_event(unsigned char *buffer, int bufsize);

xmlDocPtr xsupgui_ud_get_event_doc();
void xsupgui_ud_free_event_doc();

#endif				// __XSUPGUI_UD_H__
