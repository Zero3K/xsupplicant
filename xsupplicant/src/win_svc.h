/**
 * Functions to run as a windows service.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 * 
 * \file win_svc.h
 *
 * \author chris@open1x.org
 *
 **/  
#ifndef _WIN_SVC_H_
#define _WIN_SVC_H_
    
#ifdef BUILD_SERVICE
int win_svc_init();
void win_svc_status_stopping();
void win_svc_error_dup();
void win_svc_basic_init_failed();
void win_svc_running();
void win_svc_init_failed(int retval);

#endif				// BUILD_SERVICE
    
#endif				// _WIN_SVC_H_
