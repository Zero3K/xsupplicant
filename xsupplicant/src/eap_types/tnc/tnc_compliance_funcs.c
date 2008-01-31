/**
 * Vendor specific calls for TNC implementations to use.
 *
 * \file tnc_compliance_funcs.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * $Id: tnc_compliance_funcs.c,v 1.6 2008/01/30 20:24:40 galimorerpg Exp $
 * $Date: 2008/01/30 20:24:40 $
 **/

#ifdef HAVE_TNC

#include <stdio.h>
#include <libtnc.h>
#include <tncifimc.h>

#ifdef WINDOWS
#include <windows.h>
#include "../../stdintwin.h"
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "liblist/liblist.h"
#include "../../context.h"
#include "../../ipc_events.h"
#include "../../xsup_debug.h"
#include "../../xsup_common.h"
#include "../../ipc_events_index.h"
#include "../../wireless_sm.h"
#include "tnc_compliance_funcs.h"

#ifdef WINDOWS
#include "../../event_core_win.h"
#else
#include "../../event_core.h"
#endif

tnc_msg_batch *batch_ptr = NULL;

/**
 * \brief Determine the posture preferences for the current supplicant context.
 *
 * @param[in] imcID   The ID value that the IMC uses to track this instance.
 * @param[in] connectionID   The connection ID value that the IMC uses to track
 *                           this instance.
 * 
 * \retval uint32_t A 32 bit value that indicates the current settings for the 
 *                  posture set.  The flags are identified in tnc_compliance_options.h.
 **/
TNC_UInt32 TNC_28383_TNCC_Get_Posture_Preferences(TNC_IMCID imcID, TNC_ConnectionID connectionID)
{
	context *ctx = NULL;

	ctx = event_core_get_active_ctx();

	return ctx->prof->compliance;
}

/**
 * \brief Send an event notification to the UI.  These notifications should cause the UI
 *        to display a dialog box that contains the message, and the Ok button.
 *
 * @param[in] imcID   The ID that the IMC uses to track this instance.
 * @param[in] connectionID   The ID that the IMC uses to track this connection.
 * @param[in] oui   The IANA OUI number for the IMC making the call.
 * @param[in] notification   The notification number that will allow the UI to look
 *                           in a message catalog to find the proper string to display.
 **/
void TNC_28383_TNCC_Send_UI_Notification_by_ID(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui, TNC_UInt32 notification)
{
	ipc_events_imc_event(oui, notification);
}

/**
 * \brief Request that the UI display a message, with a set of yes/no buttons displayed.
 *        This will also register the callback that will be called when one of the
 *        yes/no buttons has been clicked.
 *
 * @param[in] imcID   The IMC ID that is used by the IMC to keep track of the connection.
 * @param[in] connectionID   The connectionID used by the IMC to keep track of the connection.
 * @param[in] oui   The OUI of the IMC that is making the request.  This is used by the
 *                  UI to determine which message catalog should be used.
 * @param[in] request   The request ID to use with the OUI to look up the message to display.
 * @param[in] callback   A pointer to the callback that should be called when the UI has
 *                       had a yes or no clicked.
 *
 * \retval 0 on success.
 * \retval !=0 on failure
 **/
TNC_UInt32 TNC_28383_TNCC_Request_Answer_From_UI_by_ID(TNC_IMCID imcID, 
						TNC_ConnectionID connectionID, TNC_UInt32 oui, TNC_UInt32 request, 
						void *callback)
{
	if (tnc_compliance_callbacks_add(imcID, connectionID, oui, request, callback) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't request a TNC answer from the UI!\n");
		return TNC_RESULT_FATAL;
	}

	return TNC_RESULT_SUCCESS;
}

/**
 * \brief Write a log string to the supplicant's log file.  This string will *NOT* be
 *        passed up to the UI, and will *ONLY* be logged if TNC IMC debug logging is
 *        enabled.  As such, it should only be used for IMC debug messages.
 *
 * @param[in] imcID   The ID that the IMC uses to track this instance.
 * @param[in] logline   An ASCII string that will be written to the debug log.
 * @param[in] severity The TNC severity level which is used to determine how to log the message.
 **/
void TNC_28383_TNCC_debug_log(TNC_IMCID imcID, TNC_UInt32 severity, char *logline)
{
	char *temp = NULL;
	char imcn[100];

	sprintf((char *)&imcn, "%d", imcID);

	temp = Malloc(strlen(imcn) + strlen(logline) + 100);
	if (temp == NULL)
	{
		debug_printf(DEBUG_NORMAL, "IMC attempted to send us a log line, but we couldn't "
				"allocate memory to store it!\n");
		return;
	}

	sprintf(temp, "IMC ID : %s  Log Message : %s\n", imcn,
		logline);

	switch(severity)
	{
	case TNC_LOG_SEVERITY_ERR:
		{
			debug_printf(DEBUG_NORMAL | DEBUG_TNC_IMC | DEBUG_VERBOSE, "%s", logline);
		}break;
	case TNC_LOG_SEVERITY_WARNING:
	case TNC_LOG_SEVERITY_NOTICE:
	case TNC_LOG_SEVERITY_INFO:
        {
            // Only send INFO level information into the debug plugins.
            debug_printf(DEBUG_NULL, "%s", logline);
        }break;
	case TNC_LOG_SEVERITY_DEBUG:
	default:
		debug_printf(DEBUG_TNC_IMC | DEBUG_VERBOSE, "%s", logline);
	};

	FREE(temp);
}

/**
 * \brief Add a message to the UI request message queue.
 *
 * @param[in] imcID  The ID of the IMC requesting the addition to the batch.
 * @param[in] connectionID  The connection ID requesting the addition to the batch.
 * @param[in] oui   The OUI of the IMC that is making the request.  (Needed so that the UI knows
 *                  which message catalog to use.
 * @param[in] msgID   The message ID that the UI should use to locate the message in the catalog.
 * @param[in] attr   A string to send to the UI that the UI should just display.
 *
 * \retval 0 on success
 * \retval >0 on failure
 **/
TNC_UInt32 TNC_28383_TNCC_Add_To_Batch(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui, 
									  TNC_UInt32 msgID, TNC_BufferReference attr)
{
	tnc_msg_batch *cur = NULL;

	cur = Malloc(sizeof(tnc_msg_batch));
	if (cur == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store new TNC UI message batch node.\n");
		return TNC_RESULT_FATAL;
	}

	cur->imcID = imcID;
	cur->connectionID = connectionID;
	cur->msgid = msgID;
	cur->oui = oui;
	cur->parameter = _strdup(attr);
	cur->next = NULL;

	liblist_add_to_head((genlist **)&batch_ptr, (genlist *)cur);

	return TNC_RESULT_SUCCESS;
}

/**
 * \brief  The callback that is used to free the memory used by a single node.
 *
 * @param[in] node   The node to free the memory of.
 **/
node_delete_func tnc_compliance_funcs_delete_node(void **node)
{
	tnc_msg_batch *cur = NULL;

	cur = (*node);

	// We only need to free "parameter".  Everything else goes away when we free the node.
	FREE(cur->parameter);

	FREE((*node));
}

/**
 * \brief Actually send the message to the UI.
 * 
 * @param[in] imcID  The ID of the IMC requesting the addition to the batch.
 * @param[in] connectionID   The connection ID requesting that the data be sent.
 * @param[in] oui   The OUI number assigned to the IMC's developer company by IANA.
 * @param[in] msg   A message id provided by the IMC that will let the UI know to expect
 *                  a batch of messages.  (Must be unique!!)
 * @param[in] cb   The callback to call when the UI responds.  (If this is NULL then no callback
 *                 is expected.)
 *
 * \retval 0 on success
 * \retval !=0 on failure
 **/
TNC_UInt32 TNC_28383_TNCC_Send_Batch(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui,
							   TNC_UInt32 msg, callback *cb)
{
	if (tnc_compliance_callbacks_add(imcID, connectionID, oui, msg, cb) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't add the callback needed to get an answer from the TNC "
				"batch message.\n");
		return TNC_RESULT_FATAL;	
	}

	ipc_events_send_tnc_batch(batch_ptr, imcID, connectionID, oui, msg);

	liblist_delete_list((genlist **)&batch_ptr, (node_delete_func)&tnc_compliance_funcs_delete_node);

	return TNC_RESULT_SUCCESS;
}

/**
 * \brief Send a "single-shot" batch.
 * 
 * @param[in] imcID  The ID of the IMC requesting the addition to the batch.
 * @param[in] connectionID   The connection ID requesting that the data be sent.
 * @param[in] oui   The OUI number assigned to the IMC's developer company by IANA.
 * @param[in] parent_msg   The "parent" message type to send to the UI.
 * @param[in] msg   A message id provided by the IMC that will let the UI know to expect
 *                  a batch of messages.  (Must be unique!!)
 * @param[in] cb   The callback to call when the UI responds.  (If this is NULL then no callback
 *                 is expected.)
 *
 * \todo  Clean this up!
 *
 * \retval 0 on success
 * \retval !=0 on failure
 **/
TNC_UInt32 TNC_28383_TNCC_Single_Shot_Batch(TNC_IMCID imcID, TNC_ConnectionID connectionID, TNC_UInt32 oui,
											TNC_UInt32 parent_msg, TNC_UInt32 msg, TNC_BufferReference attr, callback *cb)
{
	tnc_msg_batch *ss_batch = NULL;
	tnc_msg_batch *cur = NULL;

	cur = Malloc(sizeof(tnc_msg_batch));
	if (cur == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store new TNC UI message batch node.\n");
		return TNC_RESULT_FATAL;
	}

	cur->imcID = imcID;
	cur->connectionID = connectionID;
	cur->msgid = msg;
	cur->oui = oui;
	cur->parameter = _strdup(attr);
	cur->next = NULL;

	liblist_add_to_head((genlist **)&ss_batch, (genlist *)cur);

	if (tnc_compliance_callbacks_add(imcID, connectionID, oui, parent_msg, cb) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't add the callback needed to get an answer from the TNC "
				"batch message.\n");
		return TNC_RESULT_FATAL;	
	}

	ipc_events_send_tnc_batch(ss_batch, imcID, connectionID, oui, parent_msg);

	liblist_delete_list((genlist **)&ss_batch, (node_delete_func)&tnc_compliance_funcs_delete_node);

	return TNC_RESULT_SUCCESS;
}

/**
 * \brief Allow the IMC to forward an error message up to the UI.  The IMCs should do
 *        this sparingly, since proper behvaior for the type of message being sent is to
 *        pop up a window to display to the user.
 *
 * @param[in] imcID   The ID of the IMC that is requesting we send an error message.
 * @param[in] connectionID   The ID of the connection that is sending the error message.
 * @param[in] errMsg   A string that contains the error message that we want to pass up to the UI.
 *
 **/
void TNC_28383_TNCC_Send_Error_Message(TNC_IMCID imcID, TNC_ConnectionID connectionID, char *errMsg)
{
	ipc_events_error(NULL, IPC_EVENT_ERROR_TEXT, errMsg);
}

/**
 * \brief Find the context for the given Connection ID/IMC ID
 * @param[out] ctx The context.  NULL if the context wasn't found. 
 * @param[in] imcID The ID of the IMC that the connection belongs to.
 * @param[in] connectionID The ID of the connection in question.
 *
 **/
TNC_UInt32 find_context_for_imc_id_and_connection(context **ctx, TNC_IMCID imcID, TNC_ConnectionID connectionID)
{
	event_core_reset_locator();

	(*ctx) = event_core_get_next_context();
	while ((*ctx) != NULL)
	{
		if ((*ctx)->tnc_connID == connectionID)
		{
			break;
		}
		(*ctx) = event_core_get_next_context();
	}

	if((*ctx) == NULL)
	{
		return TNC_RESULT_OTHER;
	}

	return TNC_RESULT_SUCCESS;
}

/**
 * \brief Allow the IMC to request that the supplicant drop the connection
 *        and reauthenticate.
 *
 * @param[in] imcID  The ID of the IMC that is requesting the connection reset.
 * @param[in] connectionID  The ID of the connection that we are supposed to reset.
 *
 * \retval TNC_UInt32 success/failure of the request to reset.
 **/
TNC_UInt32 TNC_28383_TNCC_Reset_Connection(TNC_IMCID imcID, TNC_ConnectionID connectionID)
{
	context *ctx = NULL;

	debug_printf(DEBUG_NORMAL, "IMC %d has requested that we reset the connection for ID %d.\n", imcID, connectionID);

	if(find_context_for_imc_id_and_connection(&ctx, imcID, connectionID) == TNC_RESULT_SUCCESS)
	{
		// We found it!
		if (ctx->intType == ETH_802_11_INT)
		{
			// Send a logoff, and disassociate.
			txLogoff(ctx);
			cardif_disassociate(ctx, 0);  

			debug_printf(DEBUG_PHYSICAL_STATE, "!!!!! Bypassing scanning phase!\n");
			wireless_sm_change_state(ASSOCIATING, ctx);
		}
		else
		{
			// It is wired, so just send a logoff.
			txLogoff(ctx);
		}

		// Set the authentication counter back to 0.
		// This causes a DHCP release/renew to happen
		// on the next successful authentication
		// Which is probably what is desired since
		// the user is likely to be placed on a new VLAN
		// in the cases where a TNC IMC requests a connection reset
		ctx->auths = 0;
	}
	else
	{
		debug_printf(DEBUG_NORMAL, "Unable to reset connection because we couldn't find the context!\n");
		return TNC_RESULT_OTHER;
	}

	return TNC_RESULT_SUCCESS;
}

/**
 * \brief Allow the IMC to request that the supplicant renew DHCP for the connection specified.
 *
 * @param[in] imcID  The ID of the IMC that is requesting the connection renewal.
 * @param[in] connectionID  The ID of the connection that we are supposed to renew.
 *
 * \retval TNC_UInt32 success/failure of the request to renew DHCP.
 **/
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Renew_DHCP(TNC_IMCID imcID, TNC_ConnectionID connectionID)
{
	context *ctx = NULL;

	debug_printf(DEBUG_NORMAL, "IMC %d has requested DHCP renew for connection ID %d.\n", imcID, connectionID);

	if(find_context_for_imc_id_and_connection(&ctx, imcID, connectionID) == TNC_RESULT_SUCCESS)
	{
		// Set the authentication counter back to 0.
		// This causes a DHCP release/renew to happen
		// on the next successful authentication
		// Which is probably what is desired since
		// the user is likely to be placed on a new VLAN
		// in the cases where a TNC IMC requests a DHCP renew
		ctx->auths = 0;
	}
	else
	{
		debug_printf(DEBUG_NORMAL, "Unable to renew DHCP because we couldn't find the context!\n");
		return TNC_RESULT_OTHER;
	}

	return TNC_RESULT_SUCCESS;
}

/**
 * \brief Allow the IMC to register a call to be notified when a user logs in.
 *        
 *
 * @param[in] callback The callback to register.
 *
 * \retval TNC_UInt32 success/failure of the registration request.
 **/
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Set_User_Logon_Callback(void *callback)
{
	//debug_printf(DEBUG_NORMAL, ">>* Setting user callback function!\n");
	if (callback == NULL) debug_printf(DEBUG_NORMAL, "An IMC attempted to set a NULL callback function in %s!\n", __FUNCTION__);
	return event_core_register_imc_logon_callback(callback);
}

/**
 * \brief Allow the IMC to register a call to be notified when a connection changes from authenticated state.
 *        
 *
 * @param[in] callback The callback to register.
 *
 * \retval TNC_UInt32 success/failure of the registration request.
 **/
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Set_Disconnect_Callback(void *callback)
{
	//debug_printf(DEBUG_NORMAL, ">>* Setting user callback function!\n");
	if (callback == NULL) debug_printf(DEBUG_NORMAL, "An IMC attempted to set a NULL callback function in %s!\n", __FUNCTION__);
	return event_core_register_disconnect_callback(callback);
}

/**
 * \brief Allow the IMC to register a call to be notified when the UI connects to the engine.
 *        
 *
 * @param[in] callback The callback to register.
 *
 * \retval TNC_UInt32 success/failure of the registration request.
 **/
XSUP_OUI_API TNC_UInt32 TNC_28383_TNCC_Set_UI_Connect_Callback(void *callback)
{
	debug_printf(DEBUG_NORMAL, ">>* Setting UI Connect function!\n");
	if (callback == NULL) debug_printf(DEBUG_NORMAL, "An IMC attempted to set a NULL callback function in %s!\n", __FUNCTION__);
	return event_core_register_ui_connect_callback(callback);
}

#endif //HAVE_TNC

