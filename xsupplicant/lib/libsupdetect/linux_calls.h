/**
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file linux_calls.h
 *
 * \author chris@open1x.org
 *
 **/

#ifdef LINUX

#ifndef __LINUX_CALLS_H__
#define __LINUX_CALLS_H__

int supdetect_check_process_list(sup_fingerprints * search);
int os_strange_checks();

#endif				// __LINUX_CALLS_H__

#endif				// LINUX
