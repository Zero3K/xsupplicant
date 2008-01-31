/*******************************************************************
 * EAPTTLS OSC Proprietary TNC Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file osc_ttls_tnc.h
 *
 * \author mikem@open.com.au
 *******************************************************************/
#ifndef __OSC_TTLS_TNC_H__
#define __OSC_TTLS_TNC_H__

#ifdef HAVE_OSC_TNC
#include <libtnctncc.h>

void ttls_tnc_start(uint8_t *, size_t *);
void ttls_tnc_process(uint8_t *, size_t, uint8_t *, size_t *);
TNC_Result TNC_TNCC_SendBatch(TNC_ConnectionID, const char *, size_t);
#endif  // HAVE_OSC_TNC

#endif
