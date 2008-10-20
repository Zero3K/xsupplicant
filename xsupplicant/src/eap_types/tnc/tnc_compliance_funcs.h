/**
 * TNC compliance calls that can be used by IMCs to communicate directly 
 *   with the supplicant.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * $Id: tnc_compliance_funcs.h,v 1.5 2008/01/30 20:24:40 galimorerpg Exp $
 * $Date: 2008/01/30 20:24:40 $
 **/

#ifndef __TNC_COMPLIANCE_FUNCS_H__
#define __TNC_COMPLIANCE_FUNCS_H__

#ifdef HAVE_TNC

#include <libtnc.h>
#include <tncifimc.h>

#ifdef WINDOWS
#ifdef IMC_EXPORTS
#define XSUP_OUI_API __declspec(dllexport)
#else
#define XSUP_OUI_API __declspec(dllimport)
#endif
#else
#define XSUP_OUI_API
#endif

typedef struct _tnc_msg_batch {
	struct _tnc_msg_batch *next;

	uint32_t imcID;
	uint32_t connectionID;
	uint32_t oui;
	uint32_t msgid;
	char *parameter;
} tnc_msg_batch;

typedef void (*callback)(TNC_IMCID, TNC_ConnectionID, int);

XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Get_Posture_Preferences(TNC_IMCID imcID, TNC_ConnectionID connectionID);
XSUP_OUI_API void TNC_28383_TNCC_Send_UI_Notification_by_ID(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui, TNC_UInt32 notification);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Request_Answer_From_UI_by_ID(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui, TNC_UInt32 request, void *callback);
XSUP_OUI_API void TNC_28383_TNCC_debug_log(TNC_IMCID, TNC_UInt32, char *);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Add_To_Batch(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui, TNC_UInt32 msgID, TNC_BufferReference attr);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Send_Batch(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui, TNC_UInt32 msg, callback *cb);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Reset_Connection(TNC_IMCID imcID, TNC_ConnectionID connectionID);
XSUP_OUI_API void TNC_28383_IMC_Reset_Connection(TNC_IMCID imcID, TNC_ConnectionID connectionID);
XSUP_OUI_API void TNC_28383_TNCC_Send_Error_Message(TNC_IMCID imcID, TNC_ConnectionID connectionID, char *errMsg);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Renew_DHCP(TNC_IMCID imcID, TNC_ConnectionID connectionID);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Set_User_Logon_Callback(void *);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Set_Disconnect_Callback(void *);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Single_Shot_Batch(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui,
														 TNC_UInt32 parent_msg, TNC_UInt32 msg, TNC_BufferReference attr, callback *cb);
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Set_UI_Connect_Callback(void *);

// Callbacks from libtnc:

XSUP_OUI_API TNC_Result TNC_9048_LogMessage(
/*in*/ TNC_UInt32 severity,
/*in*/ const char * message);

XSUP_OUI_API TNC_Result TNC_9048_UserMessage(
/*in*/ TNC_IMCID imcID,
/*in*/ TNC_ConnectionID connectionID,
/*in*/ const char * message);

#endif // HAVE_TNC

#endif //__TNC_COMPLIANCE_FUNCS_H__
