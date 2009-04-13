/**
*
* Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
*
* \file win_ip_manip.c
*
* \author chris@open1x.org
*
**/  

#include <windows.h>
#include <iphlpapi.h>

#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "cardif_windows.h"
#include "cardif_windows_wmi.h"
#include "../../event_core_win.h"
#include "../../ipc_events_index.h"
#include "../../eap_sm.h"
#include "../../error_prequeue.h"
#include "cardif_windows_events.h"
#include "../../ipaddr_common.h"

typedef int (CALLBACK * DNSFLUSHPROC) ();

typedef int (CALLBACK * DHCPNOTIFYPROC) (LPWSTR, LPWSTR, BOOL, DWORD, DWORD,
										 DWORD, int);


#define MAX_OUTSTANDING_DHCP_THREADS	2

struct tmpAddrStruct {
	char *guid;
	char *addr;
	char *netmask;
	char *gateway;
	context * ctx;
};


///< A couple of APIs we need aren't normally exported.  So we need to handle that.
HMODULE hIPHlpApiMod;	///< The handle to the IPHLPAPI DLL.

typedef DWORD(WINAPI * IpHlpSetStatic) (char *adapterGUID, DWORD dwDHCPEnable,
										DWORD dwIP, DWORD dwMask,
										DWORD dwGateway);


IpHlpSetStatic SetAdapterIpAddress;


int win_ip_manip_init_iphlpapi() 
{
	hIPHlpApiMod = LoadLibraryA("iphlpapi.dll");
	if (hIPHlpApiMod == NULL)
		return -1;

	SetAdapterIpAddress = (IpHlpSetStatic) GetProcAddress(hIPHlpApiMod,
		"SetAdapterIpAddress");

	if (SetAdapterIpAddress == NULL)
		return -2;

	return 0;
}


void win_ip_manip_deinit_iphlpapi() 
{
	//if (hIPHlpApiMod != NULL) CloseHandle(hIPHlpApiMod);
} 

/**
* \brief Set the DNS registry keys.
*
* @param[in] lpszAdapterName   The GUID of the interface we want to work with.
* @param[in] pDNS   A pointer to a comma seperated list of DNS entries.
*
* \retval TRUE on success
* \retval FALSE on failure
**/ 
int RegSetDNS(LPCTSTR lpszAdapterName, LPCTSTR pDNS) 
{
	HKEY hKey;
	char *strKeyPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
	char *strKeyName = NULL;
	char mszDNS[100];
	int nDNS;

	debug_printf(DEBUG_INT,
		"Setting DNS servers for interface '%s'.  (Setting to '%s')\n",
		lpszAdapterName, pDNS);

	strKeyName = Malloc(strlen(strKeyPath) + strlen(lpszAdapterName) + 2);
	if (strKeyName == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory in %s()!\n",
			__FUNCTION__);
		return FALSE;
	}

	strcpy(strKeyName, strKeyPath);
	strcat(strKeyName, lpszAdapterName);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
		strKeyName, 
		0, 
		KEY_WRITE,
		&hKey) != ERROR_SUCCESS)
		return FALSE;

	FREE(strKeyName);

	strncpy(mszDNS, pDNS, 98);

	nDNS = strlen(mszDNS);

	*(mszDNS + nDNS + 1) = 0x00;	// REG_MULTI_SZ need add one more 0
	nDNS += 2;

	RegSetValueEx(hKey, "NameServer", 0, REG_SZ, (unsigned char *)mszDNS,
		nDNS);

	RegCloseKey(hKey);

	return TRUE;
}


/**
* \brief Set the DNS domain registry keys.
*
* @param[in] lpszAdapterName   The GUID of the interface we want to work with.
* @param[in] pDomain   A pointer to the DNS domain name for this connection.
*
* \retval TRUE on success
* \retval FALSE on failure
**/ 
int RegSetDomain(LPCTSTR lpszAdapterName, LPCTSTR pDomain) 
{
	HKEY hKey;
	char *strKeyPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
	char *strKeyName = NULL;
	char mszDomain[100];
	int nDomain;
	int bufsize = 0;

	debug_printf(DEBUG_INT,
		"Attempting to set the DNS domain for interface '%s'!  (Setting to '%s')\n",
		lpszAdapterName, pDomain);

	bufsize = strlen(strKeyPath) + strlen(lpszAdapterName) + 2;
	strKeyName = Malloc(bufsize);
	if (strKeyName == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory in %s()!\n",
			__FUNCTION__);
		return FALSE;
	}

	strcpy(strKeyName, strKeyPath);
	Strcat(strKeyName, bufsize, (char *)lpszAdapterName);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
		strKeyName, 
		0, 
		KEY_WRITE,
		&hKey) != ERROR_SUCCESS)
		return FALSE;

	FREE(strKeyName);

	strncpy(mszDomain, pDomain, 98);

	nDomain = strlen(mszDomain);

	*(mszDomain + nDomain + 1) = 0x00;	// REG_MULTI_SZ need add one more 0
	nDomain += 2;

	RegSetValueEx(hKey, "Domain", 0, REG_SZ, (unsigned char *)mszDomain,
		nDomain);

	RegCloseKey(hKey);

	return TRUE;
}


/**
* \brief Issue an event to Windows to let it know that it needs up date the DNS information
*        for the adapter GUID specified by \ref lpszAdapterName.
*
* @param[in] lpszAdapterName   The GUID of the adapter that we want to notify Windows has been
*								updated.
*
* \retval TRUE on success.
**/ 
int NotifyDNSChange(LPCTSTR lpszAdapterName) 
{
	BOOL bResult = FALSE;
	HINSTANCE hDhcpDll;
	DHCPNOTIFYPROC pDhcpNotifyProc;
	WCHAR wcAdapterName[256];

	MultiByteToWideChar(CP_ACP, 0, lpszAdapterName, -1, wcAdapterName,
		256);

	if ((hDhcpDll = LoadLibrary("dhcpcsvc")) == NULL)
		return FALSE;

	if ((pDhcpNotifyProc = (DHCPNOTIFYPROC) GetProcAddress(hDhcpDll, "DhcpNotifyConfigChange")) != NULL)
		if ((pDhcpNotifyProc) (NULL, wcAdapterName, FALSE, 0, 0, 0, 0) == ERROR_SUCCESS)
			bResult = TRUE;

	FreeLibrary(hDhcpDll);

	return bResult;
}


/**
* \brief Flush the DNS resolver cache.
*
* \retval FALSE on failure.
* \retval TRUE on success.
**/ 
int FlushDNS() 
{
	int bResult = TRUE;
	HINSTANCE hDnsDll;
	DNSFLUSHPROC pDnsFlushProc;

	if ((hDnsDll = LoadLibrary("dnsapi")) == NULL)
		return FALSE;

	if ((pDnsFlushProc = (DNSFLUSHPROC) GetProcAddress(hDnsDll,
		"DnsFlushResolverCache")) != NULL)
	{
		if ((pDnsFlushProc) () == ERROR_SUCCESS)
		{
			bResult = FALSE;
		}
	}

	FreeLibrary(hDnsDll);

	return bResult;
}


/** 
* \brief Delete the DNS servers listed for the interface pointed to by \ref ctx.
*
* @param[in] ctx   The context for the interface that we want to delete the DNS servers on.
*
* \note You need to call NotifyDNSChange() to get Windows to recognize the change has been made.
*
* \retval TRUE on success.
* \retval FALSE on failure.
**/ 
int win_ip_manip_delete_dns_servers(context * ctx) 
{
	char *dnsList = NULL;
	char *guid = NULL;
	int retval = TRUE;
	int bufsize = 0;
	HKEY hKey;
	char *strKeyPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
	char *strKeyName = NULL;
	ULONG result;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return FALSE;

	guid = cardif_windows_event_get_guid(ctx);

	debug_printf(DEBUG_INT,
		"Attempting to delete the DNS servers for interface '%s'!\n",
		guid);

	bufsize = strlen(strKeyPath) + strlen(guid) + 2;

	strKeyName = Malloc(bufsize);
	if (strKeyName == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory in %s()!\n",
			__FUNCTION__);
		FREE(guid);
		return FALSE;
	}

	strcpy(strKeyName, strKeyPath);
	Strcat(strKeyName, bufsize, guid);

	FREE(guid);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
		strKeyName, 
		0, 
		KEY_WRITE,
		&hKey) != ERROR_SUCCESS)
		return FALSE;

	FREE(strKeyName);

	result = RegDeleteValue(hKey, "NameServer");
	if ((result != NO_ERROR) && (result != 2))
	{
		debug_printf(DEBUG_NORMAL,
			"Delete key failed with error %d!\n", result);
		RegCloseKey(hKey);
		return FALSE;
	}

	RegCloseKey(hKey);

	NotifyDNSChange(guid);

	return TRUE;
}


/**
* \brief Set three DNS server entries for the interface pointed to by \ref ctx.
*
* @param[in] ctx   The context of the interface that we want to set the DNS addresses
*					for.
* @param[in] dns1   A string that represents the IP address of the primary DNS server.
* @param[in] dns2   A string that represents the IP address of the secondary DNS server.
* @param[in] dns3   A string that represents the IP address of the ternary DNS server.
*
* \retval TRUE on success
* \retval FALSE on failure.
**/ 
int win_ip_manip_set_dns_servers(context * ctx, char *dns1, char *dns2,
								 char *dns3) 
{
	char *dnsList = NULL;
	char *guid = NULL;
	int retval = TRUE;
	int bufsize = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return FALSE;

	if ((dns1 != NULL) && (ipaddr_common_ip_is_valid(dns1) != TRUE))
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to set DNS address 1 for interface %s, because it is invalid.\n",
			ctx->desc);
		return FALSE;
	}

	if ((dns2 != NULL) && (ipaddr_common_ip_is_valid(dns2) != TRUE))
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to set DNS address 2 for interface %s, because it is invalid.\n",
			ctx->desc);
		return FALSE;
	}

	if ((dns3 != NULL) && (ipaddr_common_ip_is_valid(dns3) != TRUE))
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to set DNS address 3 for interface %s, because it is invalid.\n",
			ctx->desc);
		return FALSE;
	}

	guid = cardif_windows_event_get_guid(ctx);

	bufsize = Strlen(dns1) + Strlen(dns2) + Strlen(dns3) + 5;

	dnsList = Malloc(bufsize);	// Pad it with 5 for commas and NULLs.
	if (dnsList == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory in %s()!\n",
			__FUNCTION__);
		return FALSE;
	}

	memset(dnsList, 0x00, bufsize);

	if (dns1 != NULL)
	{
		xsup_common_strcpy(dnsList, bufsize, dns1);
	}

	if ((dns2 != NULL) && (strlen(dnsList) != 0))	// Only add a comma if there is already something there.
	{
		Strcat(dnsList, bufsize, ",");	// There should be *NO* spaces between the DNS server addresses!
	}

	if (dns2 != NULL)
	{
		Strcat(dnsList, bufsize, dns2);
	}

	if ((dns3 != NULL) && (strlen(dnsList) != 0))	// Only add a comma if there is already something there.
	{
		Strcat(dnsList, bufsize, ",");	// There should be *NO* spaces between the DNS server addresses!
	}

	if (dns3 != NULL)
	{
		Strcat(dnsList, bufsize, dns3);
	}

	// We should now have a valid DNS string to write to the registry.
	if (RegSetDNS(guid, dnsList) != TRUE)
	{
		retval = FALSE;
	}
	else
	{
		NotifyDNSChange(guid);
	}

	FREE(dnsList);
	FREE(guid);

	return retval;
}


/**
* \brief Set the DNS search domain for the interface specified by \ref ctx.
* 
* @param[in] ctx   The context of the interface that we want to set the DNS search
*					domain for.
* @param[in] newdomain   The new domain that we want to be set as the search domain.
*
* \retval TRUE on success
* \retval FALSE on error.
**/ 
int win_ip_manip_set_dns_domain(context * ctx, char *newdomain) 
{
	char *guid = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return FALSE;

	guid = cardif_windows_event_get_guid(ctx);

	if (RegSetDomain(guid, newdomain) != TRUE)
	{
		FREE(guid);
		return FALSE;
	}
	else
	{
		NotifyDNSChange(guid);
	}

	FREE(guid);
	return TRUE;
}


/**
* \brief This function is used as a thread to release an IP address.
*
* @param[in] ctxptr   A pointer to a context typedef that identifies the interface
*                     that we want to release the IP address on.
**/ 
void win_ip_manip_release_ip_thread(void *ctxptr) 
{
	ULONG idx = 0;
	DWORD dwRetVal = 0;
	context * ctx = NULL;
	wchar_t * ippath = NULL;
	IP_ADAPTER_INDEX_MAP addrMap;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	ctx = (context *) ctxptr;

	ippath = cardif_windows_events_get_ip_guid_str(ctx);

	if (ippath == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine the interface GUID for interface '%s'!\n",
			ctx->desc);
		_endthread();
		return;
	}

	if ((dwRetVal = GetAdapterIndex(ippath, &idx)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine interface index for interface '%ws'.  (Error : %d)\n",
			ippath, dwRetVal);
		FREE(ippath);
		_endthread();
		return;
	}

	addrMap.Index = idx;
	wcscpy((wchar_t *) & addrMap.Name, ippath);
	FREE(ippath);

	if ((dwRetVal = IpReleaseAddress(&addrMap)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL,
			"IP release failed on interface '%s'.  (Error : %d)\n",
			ctx->desc, dwRetVal);
	}
#if 0
	else
	{
		debug_printf(DEBUG_NORMAL, "IP release success.\n");
	}
#endif	
	// Notify the UI that we changed IP addresses.
	ipc_events_ui(ctx, IPC_EVENT_UI_IP_ADDRESS_SET, NULL);

	_endthread();
}


/**
* \brief Release an IP address for the interface bound to this context.
*
* @param[in] ctx   The context that we want to release the IP from.
**/ 
void win_ip_manip_release_ip(context * ctx) 
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	_beginthread(win_ip_manip_release_ip_thread, 0, ctx);
}



DWORD win_ip_manip_lock_mutex(PHANDLE mutexHandle, int mutexNum)
{
	DWORD dwWaitResult;
	DWORD lastError = 0;

	if (((*mutexHandle) == 0) || ((*mutexHandle) == INVALID_HANDLE_VALUE))
	{
		// This is the first time we have attempted to use the mutex, so init it.
		(*mutexHandle) = CreateMutex(NULL, FALSE, NULL);
		if (((*mutexHandle) == 0) || ((*mutexHandle) == INVALID_HANDLE_VALUE))
		{
			debug_printf(DEBUG_NORMAL,
				"Unable to create a new mutex for mutex number %d!\n",
				mutexNum);

			return -1;	// We failed to create the mutex.
		}
	}

	// Wait for our mutex to be available!
	dwWaitResult = WaitForSingleObject((*mutexHandle), INFINITE);

	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
#ifdef LOCK_DEBUG
		debug_printf(DEBUG_IPC,
			"Acquired mutex lock number %d.  (Thread ID : %d)\n",
			mutexNum, GetCurrentThreadId());
#endif	
		return 0;
		break;

	default:
		lastError = GetLastError();

		if (lastError != 0)
		{
			debug_printf(DEBUG_IPC,
				"!!!!!!!!!!!! Error acquiring mutex lock number %d!  (Error %d -- wait result %d)\n",
				mutexNum, GetLastError(), dwWaitResult);
		}
		else
		{
			// We can get in to a situation where a thread may have terminated without releasing
			// a lock.  In these cases, Windows may tell us there was an error, but 
			// GetLastError() indicates that the log was obtained correctly.
			debug_printf(DEBUG_NORMAL,
				"Windows indicated an error obtaining mutex lock number %d.  But, the lock was obtained successfully.  This is usually a bug in the code.  Please report it!\n",
				mutexNum);
			return 0;
		}
		break;
	}

	return -1;
}


DWORD win_ip_manip_unlock_mutex(PHANDLE mutexHandle, int mutexNum)
{
	if (!ReleaseMutex((*mutexHandle)))
	{
		debug_printf(DEBUG_IPC,
			"!!!!!!!!!!!! Error releasing mutex lock number %d!  (Error %d) (Thread id : %d)\n",
			mutexNum, GetLastError(), GetCurrentThreadId());
		return -1;
	}

#ifdef LOCK_DEBUG
	debug_printf(DEBUG_IPC,
		"Released mutex lock number %d.  (Thread ID : %d)\n",
		mutexNum, GetCurrentThreadId());
#endif	
	return 0;
}


/**
* \brief See if this thread is allowed to run.
*
* @param[in] sockData   The socket data structure from the interface context
*
* \retval TRUE if we are allowed to run.
* \retval FALSE if we should terminate the thread.
**/ 
int win_ip_manip_check_dhcp_thread_allowed(struct win_sock_data *sockData) 
{
	// Lock a mutex so we can safely deal with our socket counter.
	if (win_ip_manip_lock_mutex(&sockData->mutexDhcpOutstanding, 1) != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to obtain the DHCP thread counter mutex!\n");
		return FALSE;
	}

	debug_printf(DEBUG_INT, "dhcpOutstanding = %d\n",
		sockData->dhcpOutstanding);

	if (sockData->dhcpOutstanding >= MAX_OUTSTANDING_DHCP_THREADS)
	{
		// Too many DHCP threads outstanding.
		debug_printf(DEBUG_INT,
			"Already two DHCP threads on this interface, terminating.\n");

		if (win_ip_manip_unlock_mutex(&sockData->mutexDhcpOutstanding, 1) != 0)
		{
			debug_printf(DEBUG_NORMAL,
				"Unable to unlock the DHCP mutex!  DHCP will be broken on this interface.\n");
		}

		return FALSE;
	}

	// Add one to our counter.
	sockData->dhcpOutstanding++;

	if (win_ip_manip_unlock_mutex(&sockData->mutexDhcpOutstanding, 1) != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to release the DHCP counter mutex!\n");
		sockData->dhcpOutstanding--;
		return FALSE;
	}

	return TRUE;
}


/**
* \brief Clear the counter for this thread, because the thread is terminating.
*
* @param[in] sockData   The sockData structure from the interface context.
*
* \retval TRUE if the thread counter was decremented.
* \retval FALSE if the thread counter decrement failed.
**/ 
int win_ip_manip_clear_thread_counter(struct win_sock_data *sockData) 
{
	if (win_ip_manip_lock_mutex(&sockData->mutexDhcpOutstanding, 1) != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to obtain the DHCP thread counter mutex!\n");
		return FALSE;
	}

	sockData->dhcpOutstanding--;

	if (win_ip_manip_unlock_mutex(&sockData->mutexDhcpOutstanding, 1) != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to release the DHCP counter mutex!\n");
		return FALSE;
	}

	return TRUE;
}


/**
* \brief This function is used as a thread to renew an IP address.
*
* @param[in] ctxptr   A pointer to a context typedef that identifies the interface
*                     that we want to renew the IP address on.
**/ 
void win_ip_manip_renew_ip_thread(void *ctxptr) 
{
	ULONG idx = 0;
	DWORD dwRetVal = 0;
	context * ctx = NULL;
	wchar_t * ippath = NULL;
	IP_ADAPTER_INDEX_MAP addrMap;
	int tries = 0;
	int retry = TRUE;
	struct win_sock_data *sockData = NULL;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	ctx = (context *) ctxptr;

	if (ctx == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Invalid interface context passed in to DHCP renew thread.  DHCP service will be unavailable.\n");
		_endthread();
		return;
	}

	ippath = cardif_windows_events_get_ip_guid_str(ctx);

	if (ippath == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine the interface GUID for interface '%s'!\n",
			ctx->desc);
		_endthread();
		return;
	}

	if ((dwRetVal = GetAdapterIndex(ippath, &idx)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine interface index for interface '%ws'.  (Error : %d)\n",
			ippath, dwRetVal);
		FREE(ippath);
		_endthread();
		return;
	}

	addrMap.Index = idx;
	wcscpy((wchar_t *) & addrMap.Name, ippath);

	FREE(ippath);

	sockData = ctx->sockData;

	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Invalid socket data for interface '%s'.\n",
			ctx->desc);
		_endthread();
		return;
	}

	if (win_ip_manip_check_dhcp_thread_allowed(sockData) == FALSE)
	{
		debug_printf(DEBUG_INT,
			"Too many DHCP threads waiting to run.  Terminating this instance.\n");
		_endthread();
		return;
	}

	if (win_ip_manip_lock_mutex(&sockData->mutexDhcpRunning, 2) != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to obtain DHCP lock.  DHCP will fail.\n");
		_endthread();
		return;
	}

	if (sockData->needTerminate == TRUE)
	{
		win_ip_manip_unlock_mutex(&sockData->mutexDhcpRunning, 2);
		win_ip_manip_clear_thread_counter(sockData);
		_endthread();
		return;
	}

	while (retry == TRUE)
	{
		if (sockData->needTerminate == TRUE)
		{
			win_ip_manip_unlock_mutex(&sockData->mutexDhcpRunning, 2);
			win_ip_manip_clear_thread_counter(sockData);
			_endthread();
			return;
		}

		if ((dwRetVal = IpRenewAddress(&addrMap)) != NO_ERROR)
		{
			tries++;

			if (tries >= 5)
			{
				debug_printf(DEBUG_NORMAL,
					"IP renew failed on interface '%s'.  (Error : %d)\n",
					ctx->desc, dwRetVal);
				retry = FALSE;
			}
			else
			{
				if (dwRetVal == ERROR_SEM_TIMEOUT)
				{
					if (win_ip_manip_do_release_renew_ip(ctx) != TRUE)
					{
						debug_printf(DEBUG_NORMAL,
							"Unable to aquire an address via DHCP for interface '%s'.\n",
							ctx->desc);
					}

					retry = FALSE;	// Jump out of the loop.
				}
				else
				{
					debug_printf(DEBUG_NORMAL,
						"IP renew failed on interface '%s'.  (Error : %d)  Trying again...\n",
						ctx->desc, dwRetVal);

					Sleep(1000);	// Wait 1 second, and try again  (this is running in a thread, so blocking it is okay.)

					if (sockData->needTerminate == TRUE)
					{
						win_ip_manip_unlock_mutex(&sockData->mutexDhcpRunning, 2);
						_endthread();
					}
				}
			}
		}
		else
		{
			retry = FALSE;
#if 0
			debug_printf(DEBUG_NORMAL, "IP renew success.\n");
#endif	
		}
	}

	if (win_ip_manip_clear_thread_counter(sockData) != TRUE)
	{
		// Ouch!  Bad stuff could happen if we end up with more than one thread in this state.
		debug_printf(DEBUG_NORMAL,
			"Unable to clear thread counter for interface '%s'.\n",
			ctx->desc);

		// Fall through and try to unlock the main mutex.
	}

	if (win_ip_manip_unlock_mutex(&sockData->mutexDhcpRunning, 2) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't release DHCP lock!\n");
	}

	_endthread();
}


/**
* \brief Renew (or request) an IP address for the interface bound to this context.
*
* @param[in] ctx   The context that we want to renew (or request) an IP address for.
**/ 
void win_ip_manip_renew_ip(context * ctx) 
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	_beginthread(win_ip_manip_renew_ip_thread, 0, ctx);
}


/**
* \brief Do an IP address release/renew.
*
* @param[in] ctx   A pointer to the context that we want to do the release/renew on.
*
* \warning This function *WILL* block.  So, it should be run in a thread outside the main thread.
*
* \retval TRUE if the release/renew was successful.
* \retval FALSE if the release/renew failed.
**/ 
int win_ip_manip_do_release_renew_ip(context * ctx) 
{
	ULONG idx = 0;
	DWORD dwRetVal = 0xfffffff;
	DWORD attempts = 0;
	int success = FALSE;
	wchar_t * ippath = NULL;
	IP_ADAPTER_INDEX_MAP addrMap;
	int retval = 0;
	struct win_sock_data *sockData = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
	{
		return FALSE;
	}

	sockData = ctx->sockData;

	if (sockData == NULL)
		return FALSE;

	retval = win_ip_manip_delete_dns_servers(ctx);
	if (retval == FALSE)
	{
		// Display an error message, but continue on.
		debug_printf(DEBUG_NORMAL,
			"Unable to clear DNS servers on interface '%s'!\n",
			ctx->desc);
	}

	retval = win_ip_manip_set_dns_domain(ctx, "");
	if (retval == FALSE)
	{
		// Display an error message, but continue on.
		debug_printf(DEBUG_NORMAL,
			"Failed to set DNS domain on interface '%s'!\n",
			ctx->desc);
	}

	ippath = cardif_windows_events_get_ip_guid_str(ctx);

	if (ippath == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine the interface GUID for interface '%s'!\n",
			ctx->desc);
		return FALSE;
	}

	if ((dwRetVal = GetAdapterIndex(ippath, &idx)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine interface index for interface '%ws'.  (Error : %d)\n",
			ippath, dwRetVal);
		FREE(ippath);
		return FALSE;
	}

	addrMap.Index = idx;
	wcscpy((wchar_t *) & addrMap.Name, ippath);
	FREE(ippath);
	success = FALSE;

	while ((attempts < 10) && (success == FALSE))
	{
		if (sockData->needTerminate == TRUE)
			return FALSE;

		if ((dwRetVal = IpReleaseAddress(&addrMap)) == NO_ERROR)
		{
			success = TRUE;
		}
		else
		{
			debug_printf(DEBUG_INT,
				"IP release failed on interface '%s'.  (Error : %d)\n",
				ctx->desc, dwRetVal);

			Sleep(1000);

			if (sockData->needTerminate == TRUE)
				return FALSE;
		}

		attempts++;
	}

	if (success == FALSE)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to release existing IP address on interface '%s'.\n",
			ctx->desc);
	}

	// NOTE : In the release case above we attempt the release several times.  We don't need to do that here since the second
	//        attempt in the release case should have gotten us in to a good state with the interface.  As a result
	//        if we get a failure here, it is probably a real failure.
	if ((dwRetVal = IpRenewAddress(&addrMap)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL,
			"IP renew failed on interface '%s'.  (Error : %d)\n",
			ctx->desc, dwRetVal);
	}
	else
	{
#if 0
		debug_printf(DEBUG_NORMAL,
			"Interface '%s' had it's IP address set.\n",
			ctx->desc);
#endif	
	}

	if ((ctx->conn != NULL)
		&& ((ctx->conn->ip.dns1 != NULL) || (ctx->conn->ip.dns2 != NULL)
		|| (ctx->conn->ip.dns3 != NULL)))
	{
		retval = win_ip_manip_set_dns_servers(ctx, ctx->conn->ip.dns1,
			ctx->conn->ip.dns2,
			ctx->conn->ip.dns3);
		if (retval == FALSE)
		{
			// Display an error message, but continue on.
			debug_printf(DEBUG_NORMAL,
				"Failed to set DNS servers on interface '%s'!\n",
				ctx->desc);
		}
	}

	if ((ctx->conn != NULL) && (ctx->conn->ip.search_domain != NULL))
	{
		retval = win_ip_manip_set_dns_domain(ctx, ctx->conn->ip.search_domain);
		if (retval == FALSE)
		{
			// Display an error message, but continue on.
			debug_printf(DEBUG_NORMAL,
				"Failed to set DNS domain on interface '%s'!\n",
				ctx->desc);
		}
	}

	return TRUE;
}


/**
* \brief The worked thread that will do the release/renew.
*
* @param[in] ctxptr   A pointer to the context that we want to do a release renew on.
**/ 
void win_ip_manip_release_renew_ip_thread(void *ctxptr) 
{
	ULONG idx = 0;
	DWORD dwRetVal = 0;
	context * ctx = NULL;
	wchar_t * ippath = NULL;
	IP_ADAPTER_INDEX_MAP addrMap;
	int tries = 0;
	int retry = TRUE;
	struct win_sock_data *sockData = NULL;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	ctx = (context *) ctxptr;
	if (ctx == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Invalid interface context passed in to DHCP renew thread.  DHCP service will be unavailable.\n");
		_endthread();
		return;
	}

	ippath = cardif_windows_events_get_ip_guid_str(ctx);
	if (ippath == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine the interface GUID for interface '%s'!\n",
			ctx->desc);
		_endthread();
		return;
	}

	if ((dwRetVal = GetAdapterIndex(ippath, &idx)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine interface index for interface '%ws'.  (Error : %d)\n",
			ippath, dwRetVal);
		FREE(ippath);
		_endthread();

		return;
	}

	addrMap.Index = idx;
	wcscpy((wchar_t *) & addrMap.Name, ippath);

	FREE(ippath);

	sockData = ctx->sockData;

	if (sockData == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Invalid socket data for interface '%s'.\n",
			ctx->desc);
		_endthread();
		return;
	}

	if (win_ip_manip_check_dhcp_thread_allowed(sockData) == FALSE)
	{
		debug_printf(DEBUG_INT,
			"Too many DHCP threads waiting to run.  Terminating this instance.\n");
		_endthread();
		return;
	}

	if (win_ip_manip_lock_mutex(&sockData->mutexDhcpRunning, 2) != 0)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to obtain DHCP lock.  DHCP will fail.\n");
		win_ip_manip_clear_thread_counter(sockData);
		_endthread();
		return;
	}

	if (sockData->needTerminate == TRUE)
	{
		win_ip_manip_unlock_mutex(&sockData->mutexDhcpRunning, 2);
		win_ip_manip_clear_thread_counter(sockData);
		_endthread();
		return;
	}

	win_ip_manip_do_release_renew_ip(ctx);

	if (win_ip_manip_clear_thread_counter(sockData) != TRUE)
	{
		// Ouch!  Bad stuff could happen if we end up with more than one thread in this state.
		debug_printf(DEBUG_NORMAL,
			"Unable to clear thread counter for interface '%s'.\n",
			ctx->desc);

		// Fall through and try to unlock the main mutex.
	}

	if (win_ip_manip_unlock_mutex(&sockData->mutexDhcpRunning, 2) != 0)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't release DHCP lock!\n");
	}

	UNSET_FLAG(ctx->flags, DHCP_RELEASE_RENEW);
	_endthread();
}


/**
* \brief Do a release/renew of the IP address for the context specified.
*
* @param[in] ctx   Do a release/renew of the IP address for the interface this context
*                  points to.
**/ 
void win_ip_manip_release_renew_ip(context * ctx) 
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	_beginthread(win_ip_manip_release_renew_ip_thread, 0, ctx);
}


/**
* \brief Enable DHCP on an interface that is currently set to use a static IP address.
*
* @param[in] ctx   The context for the interface that we want to enable DHCP on.
*
* \retval 0 on success
**/ 
int win_ip_manip_enable_dhcp(context * ctx) 
{
	char *guid = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	guid = cardif_windows_event_get_guid(ctx);

	if (SetAdapterIpAddress(guid, 1, 0, 0, 0) != NO_ERROR)
	{
		FREE(guid);
		return -1;
	}

	FREE(guid);

	return 0;
}


/**
* \brief Set the default gateway using IP Helper calls.
*
* @param[in] ctx   The context for the interface that we want to set that gateway on.
* @param[in] gw   A string that represents the IP address of the default gateway.
**/ 
void win_ip_manip_set_gw(context * ctx, char *gw) 
{
	MIB_IPFORWARDROW row;
	DWORD retval = 0;
	wchar_t * ippath = NULL;
	ULONG ifIndex = 0;
	DWORD dwRetVal = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((gw != NULL), "gw != NULL", FALSE))
		return;

	ippath = cardif_windows_events_get_ip_guid_str(ctx);

	if (ippath == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine the interface GUID for interface '%s'!\n",
			ctx->desc);
		_endthread();
		return;
	}

	if ((dwRetVal = GetAdapterIndex(ippath, &ifIndex)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to determine interface index for interface '%ws'.  (Error : %d)\n",
			ippath, dwRetVal);
		_endthread();
		return;
	}

	memset(&row, 0x00, sizeof(row));

	row.dwForwardDest = 0;
	row.dwForwardMask = 0;
	row.dwForwardPolicy = 0;
	row.dwForwardNextHop = inet_addr(gw);
	row.dwForwardIfIndex = ifIndex;
	row.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
	row.dwForwardProto = MIB_IPPROTO_NETMGMT;
	row.dwForwardAge = 0;
	row.dwForwardNextHopAS = 0;

	if (ctx->intType == ETH_802_11_INT)
	{
		row.dwForwardMetric1 = 25;
	}
	else
	{
		row.dwForwardMetric1 = 10;
	}

	row.dwForwardMetric2 = -1;
	row.dwForwardMetric3 = -1;
	row.dwForwardMetric4 = -1;
	row.dwForwardMetric5 = -1;

	retval = CreateIpForwardEntry(&row);
	if (retval != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL,
			"Error setting default route for interface '%s'. (Error : %d).\n",
			ctx->desc, retval);
	}
}


/**
* \brief Setting a static IP address can sometimes take a little time.  So we spawn a thread
*        to let it do it's thing.
*
* @param[in] dataPtr   A pointer to a blob that is formatted as a tmpAddrStruct
**/ 
void win_ip_manip_set_static_ip_thread(void *dataPtr) 
{
	struct tmpAddrStruct *addrData = NULL;
	int error = 0;

	if (!xsup_assert((dataPtr != NULL), "dataPtr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	addrData = (struct tmpAddrStruct *)dataPtr;

	if (ipaddr_common_ip_is_valid(addrData->addr) == FALSE)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to set IP address for interface %s, because it isn't a valid address.\n",
			addrData->ctx->desc);
		_endthread();
		return;
	}

	if (ipaddr_common_ip_is_valid(addrData->gateway) == FALSE)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to set the gateway address for interface %s, because it isn't a valid address.\n",
			addrData->ctx->desc);
		_endthread();
		return;
	}

	if (ipaddr_common_is_netmask_valid(addrData->netmask) == FALSE)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to use the netmask configured for interface %s, because it isn't a valid netmask.\n",
			addrData->ctx->desc);
		_endthread();
		return;
	}

	if (ipaddr_common_is_gw_in_subnet(addrData->addr, addrData->netmask, addrData->gateway) == FALSE)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to user the gateway configured for interface %s.  It is not in the same subnet as the network addrss!\n",
			addrData->ctx->desc);
		_endthread();
		return;
	}

	if (ipaddr_common_is_broadcast(addrData->addr, addrData->netmask) == TRUE)
	{
		debug_printf(DEBUG_NORMAL,
			"IP address configured on '%s' is a broadcast address, and not allowed.\n",
			addrData->ctx->desc);
		_endthread();
		return;
	}

	// As of XP SP 3, this will always return an error.  But, it still does the right thing. :-/
	SetAdapterIpAddress(addrData->guid, 0, inet_addr(addrData->addr),
		inet_addr(addrData->netmask), 0);

	NotifyDNSChange(addrData->guid);

	// Set the gateway using IP Helper calls, since SetAdapterIpAddress is broken in XP SP3.
	win_ip_manip_set_gw(addrData->ctx, addrData->gateway);

	FREE(addrData->addr);
	FREE(addrData->guid);
	FREE(addrData->netmask);
	FREE(addrData->gateway);
	FREE(addrData);

	if (error == 0)
	{
		// Notify the UI that we changed IP addresses.
		ipc_events_ui(NULL, IPC_EVENT_UI_IP_ADDRESS_SET, NULL);
	}

	_endthread();
}


/**
* \brief Set a static IP address on an interface.
*
* @param[in] ctx   The context for the interface we want to set the static IP on.
* @param[in] addr   The IP address that we want to set on this interface.
* @param[in] netmask   The netmask that we want to set on this interface.
* @param[in] gateway   The gateway that we want to set for this interface.
*
* \retval 0 on success  (success only indicates that the thread spawned!)
* \retval -1 on failure
**/ 
int win_ip_manip_set_static_ip(context * ctx, char *addr, char *netmask,
							   char *gateway) 
{
	char *guid = NULL;
	struct tmpAddrStruct *addrData = NULL;

	guid = cardif_windows_event_get_guid(ctx);

	addrData = Malloc(sizeof(struct tmpAddrStruct));
	if (addrData == NULL)
	{
		debug_printf(DEBUG_NORMAL,
			"Unable to allocate memory in %s()!\n",
			__FUNCTION__);
		return -1;
	}

	addrData->guid = guid;
	addrData->addr = _strdup(addr);
	addrData->netmask = _strdup(netmask);
	addrData->gateway = _strdup(gateway);
	addrData->ctx = ctx;

	_beginthread(win_ip_manip_set_static_ip_thread, 0, addrData);

	return 0;
}


/**
* \brief Issue the calls needed to enable DHCP on the interface specified by ctx.
*
* @param[in] ctx   The context of the interface we want to enable DHCP on.
*
* \retval 0 on success.
**/ 
int cardif_windows_events_enable_dhcp(context * ctx) 
{
	char *guid = NULL;

	guid = cardif_windows_event_get_guid(ctx);

	if (guid == NULL)
		return -1;

	if (SetAdapterIpAddress(guid, 1, inet_addr("1.1.1.1"), inet_addr("255.255.255.0"),
		inet_addr("1.1.1.1")) != NO_ERROR)
		return -1;

	FREE(guid);

	return 0;
}



