/**
 * Windows event generation interface.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows_events.h
 *
 * \author chris@open1x.org
 *
 */  
#ifndef _CARDIF_WINDOWS_EVENTS_H_
#define _CARDIF_WINDOWS_EVENTS_H_

void cardif_windows_ip_update_event();

wchar_t * cardif_windows_events_get_ip_guid_str(context * ctx);

void cardif_windows_events_init_iphlpapi();

void cardif_windows_events_deinit_iphlpapi();

char *cardif_windows_event_get_guid(context * ctx);


#endif				// _CARDIF_WINDOWS_EVENTS_H_
    
