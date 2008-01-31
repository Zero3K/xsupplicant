/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * $Id: tnc_compliance_callbacks.h,v 1.3 2008/01/23 23:45:10 galimorerpg Exp $
 * $Date: 2008/01/23 23:45:10 $
 **/

#ifndef __TNC_COMPLIANCE_CALLBACKS_H__
#define __TNC_COMPLIANCE_CALLBACKS_H__

#ifdef HAVE_TNC

typedef struct _tnc_callbacks {
	struct _tnc_callbacks *next;
	uint32_t imcID;
	uint32_t connID;
	uint32_t oui;
	uint32_t notification;
	void (*callback)(TNC_IMCID, TNC_ConnectionID, int);
} tnc_callbacks;

int tnc_compliance_callbacks_add(TNC_IMCID, TNC_ConnectionID, uint32_t, uint32_t, void *);
int tnc_compliance_callbacks_call(TNC_IMCID, TNC_ConnectionID, uint32_t, uint32_t, int);
tnc_callbacks *tnc_compliance_callbacks_locate(TNC_IMCID, TNC_ConnectionID, uint32_t, uint32_t);
void tnc_compliance_callbacks_cleanup();

#endif // HAVE_TNC

#endif // __TNC_COMPLIANCE_CALLBACKS_H__