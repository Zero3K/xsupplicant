/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file error_prequeue.h
 *
 * \author chris@open1x.org
 *
 * $Id: error_prequeue.h,v 1.3 2007/10/20 09:19:26 galimorerpg Exp $
 * $Date: 2007/10/20 09:19:26 $
 */

#ifndef __ERROR_PREQUEUE_H__
#define __ERROR_PREQUEUE_H__

typedef struct _err_prequeue {
	struct _err_prequeue *next;

	char *errstr;
} err_prequeue;

int error_prequeue_add(char *);
int error_prequeue_flush();
int error_prequeue_data_available();
int error_prequeue_events_available();
err_prequeue *error_prequeue_get_head();


#endif // __ERROR_PREQUEUE_H__
