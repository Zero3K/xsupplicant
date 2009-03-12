/**
 * \file snmp.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file fore more info.)
 *
 * \author chris@open1x.org
 *
 **/

#include <stdlib.h>
#include <string.h>

#ifndef WINDOWS
#include <strings.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "snmp.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

struct snmp_data snmpdata;

void snmp_init()
{
	memset(&snmpdata, 0x00, sizeof(snmpdata));
}

void snmp_dump_stats(char *intname)
{
	if (!xsup_assert((intname != NULL), "intname != NULL", FALSE))
		return;

	debug_printf(DEBUG_SNMP, "\nStats for Interface %s :\n\n", intname);

	debug_printf(DEBUG_SNMP,
		     "EAPOL Frames RX    : %10d   EAPOL Frames TX    : %10d\n",
		     snmpdata.dot1xSuppEapolFramesRx,
		     snmpdata.dot1xSuppEapolFramesTx);
	debug_printf(DEBUG_SNMP,
		     "EAPOL Starts TX    : %10d   EAPOL Logoff TX    : %10d\n",
		     snmpdata.dot1xSuppEapolStartFramesTx,
		     snmpdata.dot1xSuppEapolLogoffFramesTx);
	debug_printf(DEBUG_SNMP,
		     "EAPOL Resp. ID TX  : %10d   EAPOL Resp. TX     : %10d\n",
		     snmpdata.dot1xSuppEapolRespIdFramesTx,
		     snmpdata.dot1xSuppEapolRespFramesTx);
	debug_printf(DEBUG_SNMP,
		     "EAPOL Req. ID RX   : %10d   EAPOL Req. RX      : %10d\n",
		     snmpdata.dot1xSuppEapolReqIdFramesRx,
		     snmpdata.dot1xSuppEapolReqFramesRx);
	debug_printf(DEBUG_SNMP,
		     "EAPOL Invalid Frame: %10d   EAP Length Error   : %10d\n",
		     snmpdata.dot1xSuppInvalidEapolFramesRx,
		     snmpdata.dot1xSuppEapLengthErrorFramesRx);
	debug_printf(DEBUG_SNMP,
		     "Last EAPOL Version : %10d   Last EAPOL Src.    :",
		     snmpdata.dot1xSuppLastEapolFrameVersion);
	debug_hex_printf(DEBUG_SNMP, snmpdata.dot1xSuppLastEapolFrameSource, 6);
	debug_printf(DEBUG_SNMP,
		     "EAPOL Success      : %10d   EAPOL Failure      : %10d\n",
		     snmpdata.eapol_success_rx, snmpdata.eapol_fail_rx);
	debug_printf(DEBUG_SNMP, "Backend Timeouts   : %10d\n\n",
		     snmpdata.backend_timeout);
}

void snmp_inc_dot1xSuppInvalidEapolFramesRx()
{
	snmpdata.dot1xSuppInvalidEapolFramesRx++;
}

void snmp_dot1xSuppLastEapolFrameVersion(int version)
{
	snmpdata.dot1xSuppLastEapolFrameVersion = version;
}

int snmp_get_dot1xSuppLastEapolFrameVersion()
{
	return snmpdata.dot1xSuppLastEapolFrameVersion;
}

void snmp_dot1xSuppEapolLogoffFramesTx()
{
	snmpdata.dot1xSuppEapolLogoffFramesTx++;
}

void snmp_dot1xSuppEapolStartFramesTx()
{
	snmpdata.dot1xSuppEapolStartFramesTx++;
}

void snmp_dot1xSuppEapolReqIdFramesRx()
{
	snmpdata.dot1xSuppEapolReqIdFramesRx++;
}

void snmp_dot1xSuppEapolReqFramesRx()
{
	snmpdata.dot1xSuppEapolReqFramesRx++;
}

void snmp_dot1xSuppEapLengthErrorFramesRx()
{
	snmpdata.dot1xSuppEapLengthErrorFramesRx++;
}

void snmp_eapol_success_rx()
{
	snmpdata.eapol_success_rx++;
}

void snmp_eapol_fail_rx()
{
	snmpdata.eapol_fail_rx++;
}

void snmp_backend_timeout()
{
	snmpdata.backend_timeout++;
}

void snmp_dot1xSuppEapolRespIdFramesTx()
{
	snmpdata.dot1xSuppEapolRespIdFramesTx++;
}

void snmp_dot1xSuppEapolRespFramesTx()
{
	snmpdata.dot1xSuppEapolRespFramesTx++;
}

void snmp_dot1xSuppEapolFramesTx()
{
	snmpdata.dot1xSuppEapolFramesTx++;
}

void snmp_dot1xSuppEapolFramesRx()
{
	snmpdata.dot1xSuppEapolFramesRx++;
}

void snmp_dot1xSuppLastEapolFrameSource(uint8_t * srcmac)
{
	if (!xsup_assert((srcmac != NULL), "srcmac != NULL", FALSE))
		return;

	memcpy(snmpdata.dot1xSuppLastEapolFrameSource, srcmac, 6);
}
