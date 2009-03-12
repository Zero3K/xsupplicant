/**
 * Vendor specific calls for TNC implementations to use.
 *
 * \file tnc_compliance_funcs.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifdef HAVE_TNC

#include <stdio.h>
#include <libtnc.h>
#include <tncifimc.h>

#ifdef WINDOWS
#include <windows.h>
#include "../../stdintwin.h"
#else
#include <stdint.h>
#endif

#include "../../xsup_common.h"
#include "../../xsup_debug.h"
#include "tnc_compliance_funcs.h"
#include "tnc_compliance_callbacks.h"

tnc_callbacks *callback_start = NULL;

/**
 * \brief Add a callback that the UI should trigger to the list.
 *
 * @param[in] imcID   The IMC ID that the IMC uses to track state.
 * @param[in] connID   The connection ID that the IMC uses to track state.
 * @param[in] oui   The IANA OUI that requested this callback.
 * @param[in] cmd   The OUI specific call that caused this callback.
 * @param[in] callback   The callback that will be called when the UI tells us too.
 *
 * \retval -1 on error
 * \retval 0 on success
 **/
int tnc_compliance_callbacks_add(TNC_IMCID imcID, TNC_ConnectionID connID,
				 uint32_t oui, uint32_t notification,
				 void *callback)
{
	tnc_callbacks *cur = NULL;

	if (callback == NULL)
		return 0;

	// Make sure the callback isn't already registered.
	if (tnc_compliance_callbacks_locate(imcID, connID, oui, notification) !=
	    NULL) {
		debug_printf(DEBUG_VERBOSE,
			     "IMC callback already registered, ignoring.\n");
		return 0;
	}

	cur = (tnc_callbacks *) Malloc(sizeof(tnc_callbacks));
	if (cur == NULL) {
		return -1;
	}

	cur->callback = callback;
	cur->notification = notification;
	cur->oui = oui;
	cur->connID = connID;
	cur->imcID = imcID;
	cur->next = callback_start;

	callback_start = cur;

	return 0;
}

/**
 * \brief Determine if the callback we need is available.
 *
 * @param[in] imcID   The ID of the IMC that we want to call.
 * @param[in] connID   The ID of the connection that we want to use in the IMC.
 * @param[in] oui   The OUI of the IMC that we want to call.
 * @param[in] notification   The notification that we are looking for the callback for.
 *
 * \retval ptr if the callback is found
 * \retval NULL if the callback is not found
 **/
tnc_callbacks *tnc_compliance_callbacks_locate(TNC_IMCID imcID,
					       TNC_ConnectionID connID,
					       uint32_t oui,
					       uint32_t notification)
{
	tnc_callbacks *cur = NULL;

	cur = callback_start;

	while (cur != NULL) {
		if (cur->connID == connID) {
			if (cur->imcID == imcID) {
				if (cur->oui == oui) {
					if (cur->notification == notification) {
						break;
					}
				}
			}
		}
		cur = cur->next;
	}

	return cur;
}

/**
 * \brief Locate the callback that was already stored, and call it.  (Then, 
 *        remove it from the list.)
 *
 * @param[in] imcID   The ID that the IMC uses to track this instance.
 * @param[in] connID   The connection ID that the IMC uses to track this connection.
 * @param[in] oui   The IANA OUI that should be used to look up the callback.
 * @param[in] notification   The command that caused this callback.
 * @param[in] result   The TRUE/FALSE result value from the yes/no selection.
 *
 * \retval -1 on error
 * \retval 0 on success
 **/
int tnc_compliance_callbacks_call(TNC_IMCID imcID, TNC_ConnectionID connID,
				  uint32_t oui, uint32_t notification,
				  int result)
{
	tnc_callbacks *cur = NULL;
	tnc_callbacks *last = NULL;
	void (*mycall) (TNC_IMCID, TNC_ConnectionID, int);

	cur = callback_start;

	while (cur != NULL) {
		if (cur->connID == connID) {
			if (cur->imcID == imcID) {
				if (cur->oui == oui) {
					if (cur->notification == notification) {
						break;
					}
				}
			}
		}

		debug_printf(DEBUG_VERBOSE, "Checked %d, %d, %d, %d\n",
			     cur->connID, cur->imcID, cur->oui,
			     cur->notification);
		last = cur;
		cur = cur->next;
	}

	if (cur == NULL) {
		debug_printf(DEBUG_VERBOSE,
			     "Unable to locate callback for %d, %d, %d, %d.\n",
			     imcID, connID, oui, notification);
		return -1;
	}

	if (cur->callback != NULL) {
		mycall = cur->callback;
	}

	if (last == NULL) {
		// It was the first node.
		callback_start = cur->next;
		FREE(cur);
	} else {
		last->next = cur->next;
		FREE(cur);
	}

	if (mycall != NULL)
		(mycall) (imcID, connID, result);

	return 0;
}

/**
 * \brief Clean up any callbacks that might be hanging around in memory.
 **/
void tnc_compliance_callbacks_cleanup()
{
	tnc_callbacks *cur = NULL;
	tnc_callbacks *next = NULL;

	cur = callback_start;

	while (cur != NULL) {
		next = cur->next;
		FREE(cur);
		cur = next;
	}

	callback_start = NULL;
}

/**
 * \brief Provide our vendor specific functions to the IMCs.  This function will be
 *        called by libtnc when an IMC requests a bind to a function that libtnc
 *        doesn't provide.
 *
 * @param[in] imcID   The ID of the IMC that is attempting to bind.
 * @param[in] functionName   The name of the function the IMC is attempting to bind.
 * @param[out] pOutfunctionPointer   A pointer to the function that is being requested.
 *
 * \retval TNC_Result A TNC_Result value.
 **/
TNC_Result libtnc_tncc_BindFunction(TNC_IMCID imcID,
				    char *functionName,
				    void **pOutfunctionPointer)
{
	if (!strcmp(functionName, "TNC_28383_TNCC_Get_Posture_Preferences"))
		*pOutfunctionPointer =
		    (void *)TNC_28383_TNCC_Get_Posture_Preferences;
	else if (!strcmp
		 (functionName, "TNC_28383_TNCC_Send_UI_Notification_by_ID"))
		*pOutfunctionPointer =
		    (void *)TNC_28383_TNCC_Send_UI_Notification_by_ID;
	else if (!strcmp
		 (functionName, "TNC_28383_TNCC_Request_Answer_From_UI_by_ID"))
		*pOutfunctionPointer =
		    (void *)TNC_28383_TNCC_Request_Answer_From_UI_by_ID;
	else if (!strcmp(functionName, "TNC_28383_TNCC_debug_log"))
		*pOutfunctionPointer = (void *)TNC_28383_TNCC_debug_log;
	else if (!strcmp(functionName, "TNC_9048_LogMessage"))
		*pOutfunctionPointer = (void *)TNC_9048_LogMessage;
	else if (!strcmp(functionName, "TNC_9048_UserMessage"))
		*pOutfunctionPointer = (void *)TNC_9048_UserMessage;
	else if (!strcmp(functionName, "TNC_28383_TNCC_Add_To_Batch"))
		*pOutfunctionPointer = (void *)TNC_28383_TNCC_Add_To_Batch;
	else if (!strcmp(functionName, "TNC_28383_TNCC_Send_Batch"))
		*pOutfunctionPointer = (void *)TNC_28383_TNCC_Send_Batch;
	else if (!strcmp(functionName, "TNC_28383_TNCC_Reset_Connection"))
		*pOutfunctionPointer = (void *)TNC_28383_TNCC_Reset_Connection;
	else if (!strcmp(functionName, "TNC_28383_TNCC_Renew_DHCP"))
		*pOutfunctionPointer = (void *)TNC_28383_TNCC_Renew_DHCP;
	else if (!strcmp(functionName, "TNC_28383_TNCC_Send_Error_Message"))
		*pOutfunctionPointer =
		    (void *)TNC_28383_TNCC_Send_Error_Message;
	else if (!strcmp
		 (functionName, "TNC_28383_TNCC_Set_User_Logon_Callback"))
		*pOutfunctionPointer =
		    (void *)TNC_28383_TNCC_Set_User_Logon_Callback;
	else if (!strcmp
		 (functionName, "TNC_28383_TNCC_Set_Disconnect_Callback"))
		*pOutfunctionPointer =
		    (void *)TNC_28383_TNCC_Set_Disconnect_Callback;
	else if (!strcmp(functionName, "TNC_28383_TNCC_Single_Shot_Batch"))
		*pOutfunctionPointer = (void *)TNC_28383_TNCC_Single_Shot_Batch;
	else if (!strcmp
		 (functionName, "TNC_28383_TNCC_Set_UI_Connect_Callback"))
		*pOutfunctionPointer =
		    (void *)TNC_28383_TNCC_Set_UI_Connect_Callback;
	else
		return TNC_RESULT_INVALID_PARAMETER;

	return TNC_RESULT_SUCCESS;
}

#endif				// HAVE_TNC
