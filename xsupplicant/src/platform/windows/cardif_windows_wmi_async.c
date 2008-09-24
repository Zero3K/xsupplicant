/**
 * Interface to Windows WMI to check for WMI method calls completion status.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows_wmi_async.c
 *
 * \author chris@open1x.org
 *
 * \todo Implement calls to get the list of DNS servers.
 **/

#define _WIN32_DCOM

// We need to define COBJMACROS so that we can make the C calls
// to the IWbem* interfaces.
#ifndef COBJMACROS
#define COBJMACROS
#endif 

#include <wbemidl.h>

#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "cardif_windows.h"
#include "../../event_core_win.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"
#include "cardif_windows_wmi.h"
#include "cardif_windows_wmi_async.h"


#define STALE_REQUEST   0x01

typedef struct _execmethod_check {
	char *name;                ///< The name of the command we are waiting for completion on.
	context *ctx;              ///< The context that triggered this event.
	IWbemCallResult *rescheck; ///< The handle to check the result of the call.
	void (*callback)(char *name, context *ctx, int err);   ///< A call to make when the call completes.
	uint8_t flags;             ///< Flags for this instance of the call.

	struct _execmethod_check *next;
} execmethod_check;

execmethod_check *method_head = NULL;

/**
 * \brief Dump a list of all of the async callbacks that are currently enqueued.
 **/
void cardif_windows_wmi_async_dump()
{
	execmethod_check *cur = NULL;

	cur = method_head;

	debug_printf(DEBUG_INT, "------------  WMI Callbacks --------------\n");
	while (cur != NULL)
	{
		debug_printf(DEBUG_INT, "Name = %s (0x%x)\n", cur->name, &cur);
		cur = cur->next;
	}

	debug_printf(DEBUG_INT, "------------------------------------------\n");
}

/**
 * \brief Add an execmethod_check node to the list.
 *
 * @param[in] name   A text name for the method that we are checking, used only in 
 *                   debugging and logging output.
 * @param[in] intname   The OS specific interface name that this call is operating against.
 *                      If the call doesn't operate on an interface, this should be NULL.
 * @param[in] rescheck   A IWbemCallResult value that contains the information we need to use
 *                       in order to verify that we are attempting to get an IP address.
 * @param[in] callback   A callback that can be used to generate an event when the call completes.
 *                       An error code is passed in so that the callback can also generate an
 *                       error if needed.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
int cardif_windows_wmi_async(char *name, context *ctx, IWbemCallResult *rescheck, 
							 void *callback)
{
	execmethod_check *cur = NULL, *temp = NULL;

	cur = Malloc(sizeof(execmethod_check));
	if (cur == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to create WMI async check funcion!\n");
		return -1;
	}

	cur->name = strdup(name);
	cur->ctx = ctx;
	cur->rescheck = rescheck;
	cur->callback = callback;
	cur->flags = 0x00;
	cur->next = NULL;

	if (method_head == NULL)
	{
		method_head = cur;
	}
	else
	{
		temp = method_head;

		while (temp->next != NULL)
		{
			temp = temp->next;
		}

		temp->next = cur;
	}

	return 0;  // Success!
}

/**
 * \brief Remove a node from the check list.
 *
 * @param[in] rm   The node that we want to locate and remove from the list.
 **/
static void cardif_windows_wmi_async_remove_node(execmethod_check **rm)
{
	execmethod_check *cur = NULL;

	if (method_head == NULL)
	{
		debug_printf(DEBUG_INT, "Attempt to remove a node from the WMI check list when "
				"there are currently no nodes in the list!?\n");
		return;
	}

	// The line below can be useful in debugging this code.  But, leave it commented out if you don't need it.
//	cardif_windows_wmi_async_dump();

	if (method_head == (*rm))
	{
		method_head = method_head->next;
	}
	else
	{
		cur = method_head;

		while ((cur != NULL) && (cur->next != (*rm)))
			cur = cur->next;

		if (cur == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Unable to locate the WMI check list node we were asked to delete!?\n");
			return;
		}

		// Otherwise, remove it.
		cur->next = cur->next->next;
	}

	FREE((*rm)->name);
	IWbemCallResult_Release((*rm)->rescheck);
	FREE((*rm));
	rm = NULL;
}

/**
 * \brief Check all of the existing commands in the list to see if any have completed.
 **/
void cardif_windows_wmi_async_check()
{
	LONG result;
	execmethod_check *cur = NULL, *temp = NULL;
	HRESULT hr;
	VARIANT varReturnValue;
	IWbemClassObject *pclsobj = NULL;

	cur = method_head;

	while (cur != NULL)
	{
		temp = cur->next;

		if ((cur != NULL) && (cur->rescheck != NULL))
		{
			hr = IWbemCallResult_GetCallStatus(cur->rescheck, 0, &result);
			if (FAILED(hr))
			{
				if (hr != WBEM_S_TIMEDOUT)
				{
					// ACK!  We failed in a bad way!
					debug_printf(DEBUG_NORMAL, "Execution of method '%s' failed! (Result : %x)\n", 
							cur->name, hr);	

					ipc_events_error(NULL, IPC_EVENT_ERROR_WMI_ASYNC_FAILED, cur->name);
					return;
				}

				// Otherwise, it just means we aren't ready yet.
			}
			else
			{
				if (hr == WBEM_S_NO_ERROR)
				{
					debug_printf(DEBUG_INT, "Call %s completed!  Return value : %d\n", 
						cur->name, result);

					hr = IWbemCallResult_GetResultObject(cur->rescheck, 0, &pclsobj);
					if (FAILED(hr))
					{
						printf("Couldn't get result object!\n");
						cardif_windows_wmi_async_remove_node(&cur);
						return;
					}

					if (pclsobj == NULL)
					{
						debug_printf(DEBUG_INT, "No return object.  Trying later!\n");
						cardif_windows_wmi_async_remove_node(&cur);
						return;
					}

					hr = IWbemClassObject_Get(pclsobj, L"ReturnValue", 0, 
						&varReturnValue, NULL, 0);  
					if (FAILED(hr))
					{
						debug_printf(DEBUG_NORMAL, "%s result object didn't have a valid value!\n", cur->name);
						cardif_windows_wmi_async_remove_node(&cur);
						return;
					}

					if (cur->callback != NULL)
					{
						if (cur->flags == 0x01) debug_printf(DEBUG_INT, "!!!!!! Stale Response !!!!!!\n");
						cur->callback(cur->name, cur->ctx, varReturnValue.intVal);
					}	

					VariantClear(&varReturnValue);

					cardif_windows_wmi_async_remove_node(&cur);
				}
			}
		}
		cur = temp;
	}
}

/**
 * \brief Clean up any calls that might be hanging around in memory when the supplicant 
 *        terminates.
 **/
void cardif_windows_wmi_async_cleanup()
{
	execmethod_check *cur = NULL, *next = NULL;

	if (method_head == NULL) return;  // Everything is clean.

	cur = method_head;

	while (cur != NULL)
	{
		next = cur->next;

		cardif_windows_wmi_async_remove_node(&cur);

		cur = next;
	}
}

/**
 * \brief The callback that will be called when a DHCP release call completes.
 *
 * @param[in] name   The description of the call that triggered this callback.
 * @param[in] ctx   The context that caused this event.
 * @param[in] err   The error code that was returned from the call.
 **/
void cardif_windows_wmi_async_dhcp_release_renew_callback(char *name, context *ctx, int err)
{
	if (err != 0)
	{
		debug_printf(DEBUG_NORMAL, "Error attempting to release the current DHCP address.\n");
	}

	cardif_windows_wmi_renew_dhcp(ctx);
}

/**
 * \brief The callback that will be called when a DHCP renew call completes.
 *
 * If we have static DNS values set, we need to attempt to set them here.  We 
 * should also trigger an event to let the UI know that DHCP has completed, and
 * an IP address should be available now.
 *
 * @param[in] name   The description of the call that triggered this callback.
 * @param[in] ctx   The context that caused this event.
 * @param[in] err   The error code that was returned from the call.
 **/
void cardif_windows_wmi_async_dhcp_renew_callback(char *name, context *ctx, int err)
{
	int retval = 0;
	char *ipaddr = NULL;

	if (err == 82)
	{
		// If we get an error 82, then it means that Windows "couldn't renew" the DHCP
		// address.  But, it isn't necessarily an indication that getting an IP address failed.
		//  It is possible that there was an existing lease already available, or that a new
		// lease was acquired.  So, we want to check the IP address that we have, and see if
		// if is 0.0.0.0, or one of the link local addresses 169.254/16.  If it is, then we will
		// throw an error.
		ipaddr = cardif_windows_wmi_get_ip_utf8(ctx);
		if (ipaddr == NULL)
		{
			debug_printf(DEBUG_NORMAL, "No IP address is set!  DHCP failed!\n");
			ipc_events_ui(ctx, IPC_EVENT_ERROR_CANT_RENEW_DHCP, NULL);
			return;
		}

		if ((strcmp(ipaddr, "0.0.0.0") == 0) || (strncmp(ipaddr, "169.254", 7) == 0))
		{
			debug_printf(DEBUG_NORMAL, "Unable to acquire an IP address via DHCP.  (Address is %s.)\n", ipaddr);
			ipc_events_ui(ctx, IPC_EVENT_ERROR_CANT_RENEW_DHCP, NULL);
			FREE(ipaddr);
			return;
		}

		FREE(ipaddr);

		// Otherwise, we have a valid address, but log a message so the user has an idea of what is going on.
		debug_printf(DEBUG_NORMAL, "The attempt to renew the DHCP lease for interface '%s' generated an error.  However, you have a valid IP address.  Windows is probably using an address that was cached and still indicated it had time available on its lease.\n", ctx->desc);
	}
	else if (err != 0)
	{
		debug_printf(DEBUG_NORMAL, "Failed to renew DHCP address. (Error : %d)\n", err);
		ipc_events_ui(ctx, IPC_EVENT_ERROR_CANT_RENEW_DHCP, NULL);
	}
	else
	{
		// Notify the UI that we changed IP addresses.
		ipc_events_ui(ctx, IPC_EVENT_UI_IP_ADDRESS_SET, NULL);

		debug_printf(DEBUG_NORMAL, "Interface '%s' had it's IP address set.\n", ctx->desc);
	}

	// We want to set this stuff no matter what.  It is possible the stuff above got foobared, and the address is still
	// valid even when it claims not to be.  So, make sure we do an update.

	// Check and see if we have static DNS values to set.
	if ((ctx->conn != NULL) && ((ctx->conn->ip.dns1 != NULL) || (ctx->conn->ip.dns2 != NULL) ||
		(ctx->conn->ip.dns3 != NULL)))
	{
		retval = cardif_windows_wmi_set_dns_servers(ctx, ctx->conn->ip.dns1, ctx->conn->ip.dns2,
													ctx->conn->ip.dns3);
		if (retval == 94)
		{
			debug_printf(DEBUG_INT, "Failed on first attempt to set static DNS servers, trying again.\n");

			retval = cardif_windows_wmi_set_dns_servers(ctx, ctx->conn->ip.dns1, ctx->conn->ip.dns2,
				ctx->conn->ip.dns3);
			if (retval != 0)
			{
				debug_printf(DEBUG_NORMAL, "Failed to set static DNS servers.  Error was %d.\n", retval);
				return;
			}
		}
	}

	if ((ctx->conn != NULL) && (ctx->conn->ip.search_domain != NULL))
	{
		debug_printf(DEBUG_INT, "Setting search domain.\n");
		retval = cardif_windows_wmi_set_dns_domain(ctx, ctx->conn->ip.search_domain);
		if (retval == 94)
		{
			debug_printf(DEBUG_INT, "First attempt failed, trying again.\n");
			retval = cardif_windows_wmi_set_dns_domain(ctx, ctx->conn->ip.search_domain);
			if (retval != 0)
			{
				debug_printf(DEBUG_NORMAL, "Couldn't set search domain.  Error was %d.\n", retval);
				return;
			}
		} else if (retval != 0)
		{
			debug_printf(DEBUG_NORMAL, "Unable to set DNS search domain.  Error was %d.\n", retval);
			return;
		}
	}
}

/**
 * \brief The callback that will be called when a set static IP call completes.
 *
 * @param[in] name   The description of the call that triggered this callback.
 * @param[in] ctx   The context that caused this event.
 * @param[in] err   The error code that was returned from the call.
 **/
void cardif_windows_wmi_async_static_ip_callback(char *name, context *ctx, int err)
{
	int retval = 0;

	if (err != 0)
	{
		debug_printf(DEBUG_NORMAL, "Failed to set static IP address.\n");
		return;
	}

	// Notify the UI that we changed IP addresses.
	ipc_events_ui(ctx, IPC_EVENT_UI_IP_ADDRESS_SET, NULL);

	debug_printf(DEBUG_INT, "Setting DNS server(s).\n");
	retval = cardif_windows_wmi_set_dns_servers(ctx, ctx->conn->ip.dns1, ctx->conn->ip.dns2,
				ctx->conn->ip.dns3);
	if (retval == 94)
	{
		debug_printf(DEBUG_INT, "First attempt failed, trying again.\n");
		retval = cardif_windows_wmi_set_dns_servers(ctx, ctx->conn->ip.dns1, ctx->conn->ip.dns2,
			ctx->conn->ip.dns3);
		if (retval != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set DNS servers!  Error was %d.\n", retval);
			return;
		}
	}
	else if (retval != 0)
	{
		debug_printf(DEBUG_NORMAL, "Unable to set DNS servers!  Error was %d.\n", retval);
		return;
	}

	debug_printf(DEBUG_INT, "Setting search domain.\n");
	retval = cardif_windows_wmi_set_dns_domain(ctx, ctx->conn->ip.search_domain);
	if (retval == 94)
	{
		debug_printf(DEBUG_INT, "First attempt failed, trying again.\n");
		retval = cardif_windows_wmi_set_dns_domain(ctx, ctx->conn->ip.search_domain);
		if (retval != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set search domain.  Error was %d.\n", retval);
			return;
		}
	} else if (retval != 0)
	{
		debug_printf(DEBUG_NORMAL, "Unable to set DNS search domain.  Error was %d.\n", retval);
		return;
	}

	debug_printf(DEBUG_INT, "Setting default GW.\n");
	retval = cardif_windows_wmi_set_static_gw(ctx, ctx->conn->ip.gateway);
	if (retval == 94)
	{
		debug_printf(DEBUG_INT, "First attempt failed, trying again.\n");
		retval = cardif_windows_wmi_set_static_gw(ctx, ctx->conn->ip.gateway);
		if (retval != 0)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't set GW.  Error was %d.\n", retval);
			return;
		}
	} else if (retval != 0)
	{	
		debug_printf(DEBUG_NORMAL, "Unable to set default GW.  Error was %d.\n", retval);
		return;
	}
}

/**
 * \brief Clear out any waiting events in our list.  
 *
 * @param[in] ctx   The context that we want to clear events for.
 **/
void cardif_windows_wmi_async_clear_by_ctx(context *ctx)
{
	execmethod_check *cur = NULL, *prev = NULL;

	if (method_head == NULL) return;  // Everything is clean.

	cur = method_head;
	prev = NULL;

	while (cur != NULL)
	{
		if (cur->ctx == ctx)
		{
			if (cur == method_head) 
			{
				prev = method_head->next;
				cardif_windows_wmi_async_remove_node(&cur);
				method_head = prev;
				cur = prev;
			}
			else
			{
				prev->next = cur->next;
				cardif_windows_wmi_async_remove_node(&cur);
				cur = prev->next;
			}
		}
		else
		{
			prev = cur;
			cur = cur->next;
		}
	}
}
