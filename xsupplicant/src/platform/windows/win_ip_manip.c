/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_windows_events.c
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

typedef int (CALLBACK* DNSFLUSHPROC)();
typedef int (CALLBACK* DHCPNOTIFYPROC)(LPWSTR, LPWSTR, BOOL, DWORD, DWORD, DWORD, int);

struct tmpAddrStruct {
	char *guid;
	char *addr;
	char *netmask;
	char *gateway;
};

///< A couple of APIs we need aren't normally exported.  So we need to handle that.
HMODULE hIPHlpApiMod;                       ///< The handle to the IPHLPAPI DLL.

typedef DWORD (WINAPI* IpHlpSetStatic)(char *adapterGUID, DWORD dwDHCPEnable, DWORD dwIP, DWORD dwMask, DWORD dwGateway);

IpHlpSetStatic SetAdapterIpAddress;

int win_ip_manip_init_iphlpapi()
{
	hIPHlpApiMod = LoadLibraryA("iphlpapi.dll");
	if (hIPHlpApiMod == NULL) return -1;

	SetAdapterIpAddress = (IpHlpSetStatic) GetProcAddress(hIPHlpApiMod, "SetAdapterIpAddress");
	if (SetAdapterIpAddress == NULL) return -2;

	return 0;
}

void win_ip_manip_deinit_iphlpapi()
{
	if (hIPHlpApiMod != NULL) CloseHandle(hIPHlpApiMod);
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

	debug_printf(DEBUG_INT, "Setting DNS servers for interface '%s'.  (Setting to '%s')\n", lpszAdapterName, pDNS);
	strKeyName = Malloc(strlen(strKeyPath)+strlen(lpszAdapterName)+2);
	if (strKeyName == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory in %s()!\n", __FUNCTION__);
		return FALSE;
	}

	strcpy(strKeyName, strKeyPath);
	strcat(strKeyName, lpszAdapterName);

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				strKeyName,
				0,
				KEY_WRITE,
				&hKey) != ERROR_SUCCESS)
		return FALSE;
	
	strncpy(mszDNS, pDNS, 98);

	nDNS = strlen(mszDNS);

	*(mszDNS + nDNS + 1) = 0x00;	// REG_MULTI_SZ need add one more 0
	nDNS += 2;

	RegSetValueEx(hKey, "NameServer", 0, REG_SZ, (unsigned char*)mszDNS, nDNS);

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

	debug_printf(DEBUG_INT, "Attempting to set the DNS domain for interface '%s'!  (Setting to '%s')\n", lpszAdapterName, pDomain);
	bufsize = strlen(strKeyPath)+strlen(lpszAdapterName)+2;
	strKeyName = Malloc(bufsize);
	if (strKeyName == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory in %s()!\n", __FUNCTION__);
		return FALSE;
	}

	strcpy(strKeyName, strKeyPath);
	Strcat(strKeyName, bufsize, lpszAdapterName);

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				strKeyName,
				0,
				KEY_WRITE,
				&hKey) != ERROR_SUCCESS)
		return FALSE;
	
	strncpy(mszDomain, pDomain, 98);

	nDomain = strlen(mszDomain);

	*(mszDomain + nDomain + 1) = 0x00;	// REG_MULTI_SZ need add one more 0
	nDomain += 2;

	RegSetValueEx(hKey, "Domain", 0, REG_SZ, (unsigned char*)mszDomain, nDomain);

	RegCloseKey(hKey);

	return TRUE;
}

int NotifyDNSChange(LPCTSTR lpszAdapterName)
{
	BOOL			bResult = FALSE;
	HINSTANCE		hDhcpDll;
	DHCPNOTIFYPROC	pDhcpNotifyProc;
	WCHAR wcAdapterName[256];
	
	MultiByteToWideChar(CP_ACP, 0, lpszAdapterName, -1, wcAdapterName,256);

	if((hDhcpDll = LoadLibrary("dhcpcsvc")) == NULL)
		return FALSE;

	if((pDhcpNotifyProc = (DHCPNOTIFYPROC)GetProcAddress(hDhcpDll, "DhcpNotifyConfigChange")) != NULL)
		if((pDhcpNotifyProc)(NULL, wcAdapterName, FALSE, 0, NULL,NULL, 0) == ERROR_SUCCESS)
			bResult = TRUE;

	FreeLibrary(hDhcpDll);
	return bResult;
}

int FlushDNS()
{
	int 			bResult = TRUE;
	HINSTANCE		hDnsDll;
	DNSFLUSHPROC	pDnsFlushProc;

	if((hDnsDll = LoadLibrary("dnsapi")) == NULL)
		return FALSE;

	if((pDnsFlushProc = (DNSFLUSHPROC)GetProcAddress(hDnsDll, "DnsFlushResolverCache")) != NULL)
	{
		if ( (pDnsFlushProc)() == ERROR_SUCCESS)
		{
			bResult = FALSE;
		}
	}
	
	FreeLibrary(hDnsDll);
	return bResult;
}

int win_ip_manip_delete_dns_servers(context *ctx)
{
	char *dnsList = NULL;
	char *guid = NULL;
	int retval = TRUE;
	int bufsize = 0;
	HKEY hKey;
	char *strKeyPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
	char *strKeyName = NULL;
	ULONG result;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return FALSE;

	guid = cardif_windows_event_get_guid(ctx);

	debug_printf(DEBUG_INT, "Attempting to delete the DNS servers for interface '%s'!\n", guid);
	bufsize = strlen(strKeyPath)+strlen(guid)+2;
	strKeyName = Malloc(bufsize);
	if (strKeyName == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory in %s()!\n", __FUNCTION__);
		return FALSE;
	}

	strcpy(strKeyName, strKeyPath);
	Strcat(strKeyName, bufsize, guid);

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				strKeyName,
				0,
				KEY_WRITE,
				&hKey) != ERROR_SUCCESS)
		return FALSE;

	result = RegDeleteValue(hKey, "NameServer");
	if ((result != NO_ERROR) && (result != 2))
	{
		debug_printf(DEBUG_NORMAL, "Delete key failed with error %d!\n", result);
		RegCloseKey(hKey);
		return FALSE;
	}

	RegCloseKey(hKey);

	NotifyDNSChange(guid);

	return TRUE;
}

int win_ip_manip_set_dns_servers(context *ctx, char *dns1, char *dns2, char *dns3)
{
	char *dnsList = NULL;
	char *guid = NULL;
	int retval = TRUE;
	int bufsize = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return FALSE;

	guid = cardif_windows_event_get_guid(ctx);

	bufsize = Strlen(dns1)+Strlen(dns2)+Strlen(dns3)+5;
	dnsList = Malloc(bufsize);  // Pad it with 5 for commas and NULLs.
	if (dnsList == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory in %s()!\n", __FUNCTION__);
		return FALSE;
	}

	memset(dnsList, 0x00, bufsize);

	if (dns1 != NULL)
	{
		xsup_common_strcpy(dnsList, bufsize, dns1);
	}

	if ((dns2 != NULL) && (strlen(dnsList) != 0))   // Only add a comma if there is already something there.
	{
		Strcat(dnsList, bufsize, ",");    // There should be *NO* spaces between the DNS server addresses!
	}

	if (dns2 != NULL)
	{
		Strcat(dnsList, bufsize, dns2);
	}

	if ((dns3 != NULL) && (strlen(dnsList) != 0))   // Only add a comma if there is already something there.
	{
		Strcat(dnsList, bufsize, ",");    // There should be *NO* spaces between the DNS server addresses!
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

int win_ip_manip_set_dns_domain(context *ctx, char *newdomain)
{
	char *guid = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return FALSE;

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
	context *ctx = NULL;
	wchar_t *ippath = NULL;
	IP_ADAPTER_INDEX_MAP addrMap;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	ctx = (context *)ctxptr;

	ippath = cardif_windows_events_get_ip_guid_str(ctx);

	if (ippath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine the interface GUID for interface '%s'!\n", ctx->desc);
		_endthread();
		return;
	}

	if ((dwRetVal = GetAdapterIndex(ippath, &idx)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine interface index for interface '%ws'.  (Error : %d)\n", ippath, dwRetVal);
		_endthread();
		return;
	}

	addrMap.Index = idx;
	wcscpy((wchar_t *)&addrMap.Name, ippath); 

    if ((dwRetVal = IpReleaseAddress(&addrMap)) != NO_ERROR) 
	{
		debug_printf(DEBUG_NORMAL, "IP release failed on interface '%s'.  (Error : %d)\n", ctx->desc, dwRetVal);
    }
#if 0
	else
	{
		debug_printf(DEBUG_NORMAL, "IP release success.\n");
	}
#endif

	_endthread();
}

/**
 * \brief Release an IP address for the interface bound to this context.
 *
 * @param[in] ctx   The context that we want to release the IP from.
 **/
void win_ip_manip_release_ip(context *ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	_beginthread(win_ip_manip_release_ip_thread, 0, ctx);
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
	context *ctx = NULL;
	wchar_t *ippath = NULL;
	IP_ADAPTER_INDEX_MAP addrMap;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	ctx = (context *)ctxptr;

	ippath = cardif_windows_events_get_ip_guid_str(ctx);

	if (ippath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine the interface GUID for interface '%s'!\n", ctx->desc);
		_endthread();
		return;
	}

	if ((dwRetVal = GetAdapterIndex(ippath, &idx)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine interface index for interface '%ws'.  (Error : %d)\n", ippath, dwRetVal);
		_endthread();
		return;
	}

	addrMap.Index = idx;
	wcscpy((wchar_t *)&addrMap.Name, ippath); 

    if ((dwRetVal = IpRenewAddress(&addrMap)) != NO_ERROR) 
	{
		debug_printf(DEBUG_NORMAL, "IP renew failed on interface '%s'.  (Error : %d)\n", ctx->desc, dwRetVal);
    }
#if 0
	else
	{
		debug_printf(DEBUG_NORMAL, "IP renew success.\n");
	}
#endif

	_endthread();
}

/**
 * \brief Renew (or request) an IP address for the interface bound to this context.
 *
 * @param[in] ctx   The context that we want to renew (or request) an IP address for.
 **/
void win_ip_manip_renew_ip(context *ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	_beginthread(win_ip_manip_renew_ip_thread, 0, ctx);
}

/**
 * \brief Do an IP address release/renew.
 *
 * @param[in] ctxptr   A pointer to the context that we want to do the release/renew on.
 **/
void win_ip_manip_release_renew_ip_thread(void *ctxptr)
{
	ULONG idx = 0;
	DWORD dwRetVal = 0;
	context *ctx = NULL;
	wchar_t *ippath = NULL;
	IP_ADAPTER_INDEX_MAP addrMap;
	int retval = 0;

	if (!xsup_assert((ctxptr != NULL), "ctxptr != NULL", FALSE))
	{
		_endthread();
		return;
	}

	ctx = (context *)ctxptr;

	retval = win_ip_manip_delete_dns_servers(ctx);
	if (retval == FALSE)
	{
		// Display an error message, but continue on.
		debug_printf(DEBUG_NORMAL, "Unable to clear DNS servers on interface '%s'!\n", ctx->desc);
	}

	retval = win_ip_manip_set_dns_domain(ctx, "");
	if (retval == FALSE)
	{
		// Display an error message, but continue on.
		debug_printf(DEBUG_NORMAL, "Failed to set DNS domain on interface '%s'!\n", ctx->desc);
	}

	ippath = cardif_windows_events_get_ip_guid_str(ctx);

	if (ippath == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine the interface GUID for interface '%s'!\n", ctx->desc);
		_endthread();
		return;
	}

	if ((dwRetVal = GetAdapterIndex(ippath, &idx)) != NO_ERROR)
	{
		debug_printf(DEBUG_NORMAL, "Unable to determine interface index for interface '%ws'.  (Error : %d)\n", ippath, dwRetVal);
		_endthread();
		return;
	}

	addrMap.Index = idx;
	wcscpy((wchar_t *)&addrMap.Name, ippath); 

    if ((dwRetVal = IpReleaseAddress(&addrMap)) != NO_ERROR) 
	{
		if (dwRetVal == 2)
		{
			// Sometimes we get here before Windows is ready.  So sleep for a few seconds and try again.
			// NOTE : It is safe to sleep here because we are in a thread!
			Sleep(3000);

			dwRetVal = IpReleaseAddress(&addrMap);
		}

		if (dwRetVal != NO_ERROR)
			debug_printf(DEBUG_NORMAL, "IP release failed on interface '%s'.  (Error : %d)\n", ctx->desc, dwRetVal);
    }
#if 0
	else
	{
		debug_printf(DEBUG_NORMAL, "IP release success.\n");
	}
#endif

	// NOTE : In the release case above we attempt the release twice.  We don't need to do that here since the second
	//        attempt in the release case should have gotten us in to a good state with the interface.  As a result
	//        if we get a failure here, it is probably a real failure.
    if ((dwRetVal = IpRenewAddress(&addrMap)) != NO_ERROR) 
	{
		debug_printf(DEBUG_NORMAL, "IP renew failed on interface '%s'.  (Error : %d)\n", ctx->desc, dwRetVal);
    }
	else
	{
		// Notify the UI that we changed IP addresses.
		ipc_events_ui(ctx, IPC_EVENT_UI_IP_ADDRESS_SET, NULL);

		debug_printf(DEBUG_NORMAL, "Interface '%s' had it's IP address set.\n", ctx->desc);
	}

	if ((ctx->conn != NULL) && ((ctx->conn->ip.dns1 != NULL) || (ctx->conn->ip.dns2 != NULL) ||
		(ctx->conn->ip.dns3 != NULL)))
	{
		retval = win_ip_manip_set_dns_servers(ctx, ctx->conn->ip.dns1, ctx->conn->ip.dns2,
											ctx->conn->ip.dns3);
		if (retval == FALSE)
		{
			// Display an error message, but continue on.
			debug_printf(DEBUG_NORMAL, "Failed to set DNS servers on interface '%s'!\n", ctx->desc);
		}
	}

	if ((ctx->conn != NULL) && (ctx->conn->ip.search_domain != NULL))
	{
		retval = win_ip_manip_set_dns_domain(ctx, ctx->conn->ip.search_domain);
		if (retval == FALSE)
		{
			// Display an error message, but continue on.
			debug_printf(DEBUG_NORMAL, "Failed to set DNS domain on interface '%s'!\n", ctx->desc);
		}
	}

	_endthread();
}

/**
 * \brief Do a release/renew of the IP address for the context specified.
 *
 * @param[in] ctx   Do a release/renew of the IP address for the interface this context
 *                  points to.
 **/
void win_ip_manip_release_renew_ip(context *ctx)
{
	int retval = 0;
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE)) return;

	_beginthread(win_ip_manip_release_renew_ip_thread, 0, ctx);
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

	if (!xsup_assert((dataPtr != NULL), "dataPtr != NULL", FALSE)) return;

	addrData = (struct tmpAddrStruct *)dataPtr;

	if (SetAdapterIpAddress(addrData->guid, 0, inet_addr(addrData->addr), inet_addr(addrData->netmask), 
		inet_addr(addrData->gateway)) != NO_ERROR) return -1;
 
	FREE(addrData->addr);
	FREE(addrData->guid);
	FREE(addrData->netmask);
	FREE(addrData->gateway);
	FREE(addrData);

	// Notify the UI that we changed IP addresses.
	ipc_events_ui(NULL, IPC_EVENT_UI_IP_ADDRESS_SET, NULL);

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
int win_ip_manip_set_static_ip(context *ctx, char *addr, char *netmask, char *gateway)
{
	char *guid = NULL;
	struct tmpAddrStruct *addrData = NULL;

	guid = cardif_windows_event_get_guid(ctx);

	addrData = Malloc(sizeof(struct tmpAddrStruct));
	if (addrData == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory in %s()!\n", __FUNCTION__);
		return -1;
	}

	addrData->guid = guid;
	addrData->addr = _strdup(addr);
	addrData->netmask = _strdup(netmask);
	addrData->gateway = _strdup(gateway);

	_beginthread(win_ip_manip_set_static_ip_thread, 0, addrData);

	return 0;
}
