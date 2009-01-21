/**
 * \file snmp.h
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _XSUP_SNMP_H_
#define _XSUP_SNMP_H_

#include <sys/types.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

/*************************************
 *
 *  This structure contains SNMP related variables for the 802.1X supplicant
 *   as defined in section 9.5 of 802.1X-2001.
 *
 *************************************/
struct snmp_data {
  // The configuration pieces of the SNMP defined in section 9.5.1 are stored
  // in our main structure, and not replicated here.

  // Port number is stored in the main structure, and not replicated here.
  unsigned int dot1xSuppEapolFramesRx;
  unsigned int dot1xSuppEapolFramesTx;
  unsigned int dot1xSuppEapolStartFramesTx;
  unsigned int dot1xSuppEapolLogoffFramesTx;
  unsigned int dot1xSuppEapolRespIdFramesTx;
  unsigned int dot1xSuppEapolRespFramesTx;
  unsigned int dot1xSuppEapolReqIdFramesRx;
  unsigned int dot1xSuppEapolReqFramesRx;
  unsigned int dot1xSuppInvalidEapolFramesRx;
  unsigned int dot1xSuppEapLengthErrorFramesRx;
  unsigned char dot1xSuppLastEapolFrameVersion;
  unsigned char dot1xSuppLastEapolFrameSource[6];

  // These are not defined in the 802.1X-2001 document, but may be interesting
  // anyway.
  unsigned int eapol_success_rx;
  unsigned int eapol_fail_rx;
  unsigned int backend_timeout;
};

void snmp_init();
void snmp_dump_stats(char *);
void snmp_inc_dot1xSuppInvalidEapolFramesRx();
void snmp_dot1xSuppLastEapolFrameVersion(int);
int snmp_get_dot1xSuppLastEapolFrameVersion();
void snmp_dot1xSuppEapolLogoffFramesTx();
void snmp_dot1xSuppEapolStartFramesTx();
void snmp_dot1xSuppEapolReqIdFramesRx();
void snmp_dot1xSuppEapolReqFramesRx();
void snmp_dot1xSuppEapLengthErrorFramesRx();
void snmp_eapol_success_rx();
void snmp_eapol_fail_rx();
void snmp_backend_timeout();
void snmp_dot1xSuppEapolRespIdFramesTx();
void snmp_dot1xSuppEapolRespFramesTx();
void snmp_dot1xSuppEapolFramesTx();
void snmp_dot1xSuppEapolFramesRx();
void snmp_dot1xSuppLastEapolFrameSource(uint8_t *);

#endif
