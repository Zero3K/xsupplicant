/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file windows_calls.h
 *
 * \author chris@open1x.org
 *
 **/

#ifdef WINDOWS

#ifndef __WINDOWS_CALLS_H__
#define __WINDOWS_CALLS_H__

int windows_calls_wmi_init();
int windows_calls_wmi_deinit();
int windows_calls_wmi_connect();
int supdetect_check_process_list(sup_fingerprints * search);
int supdetect_check_service_list(sup_fingerprints * search);
int os_strange_checks();

#endif				// __WINDOWS_CALLS_H__

#endif				// WINDOWS
