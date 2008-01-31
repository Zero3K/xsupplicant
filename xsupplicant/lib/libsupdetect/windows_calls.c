/**
 *  Library to attempt to detect other supplicants that may be running.
 *
 *  \file windows_calls.c
 *
 *  \author chris@open1x.org
 *
 * $Id: windows_calls.c,v 1.4 2008/01/23 23:45:08 galimorerpg Exp $
 * $Date: 2008/01/23 23:45:08 $
 **/
#ifdef WINDOWS


#define _WIN32_DCOM

// We need to define COBJMACROS so that we can make the C calls
// to the IWbem* interfaces.
#ifndef COBJMACROS
#define COBJMACROS
#endif 

#include <stdio.h>

#include <wbemidl.h>

#include "..\..\src\xsup_debug.h"
#include "supdetect_private.h"

IWbemLocator *wcLoc = NULL;
IWbemServices *wSvc = NULL;


/**
 * \brief Initialize WMI so that we can use it.
 *
 * \retval 0 on success.
 **/
int windows_calls_wmi_init()
{
	HRESULT hr;

	wcLoc = NULL;
	wSvc = NULL;

	hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED); 
	if ((hr != S_OK) && (hr != S_FALSE))
	{
		if (hr == RPC_E_CHANGED_MODE)
		{
			debug_printf(DEBUG_NORMAL, "Couldn't change threading mode.  Trying to continue with current threading model.\n");
		}
		else if (FAILED(hr)) 
		{ 
			debug_printf(DEBUG_NORMAL, "Failed to initialize COM library. Error code = 0x%x\n", hr);
			return -1;
		}
	}

	hr =  CoInitializeSecurity(
	    NULL,                      // Security descriptor    
	    -1,                        // COM negotiates authentication service
	    NULL,                      // Authentication services
		NULL,                      // Reserved
	    RPC_C_AUTHN_LEVEL_DEFAULT, // Default authentication level for proxies
	    RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation level for proxies
	    NULL,                        // Authentication info
	    EOAC_NONE,                   // Additional capabilities of the client or server
	    NULL);                       // Reserved

	if (hr != S_OK && hr != RPC_E_TOO_LATE)
	{
		debug_printf(DEBUG_NORMAL, "Failed to initialize COM security. Error code = 0x%02x\n", hr);
		CoUninitialize();
		return -1;
	}

	hr = CoCreateInstance(&CLSID_WbemLocator, 0, 
        CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *) &wcLoc);
 
    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Failed to create IWbemLocator object. Err code = 0x%02x\n", hr);
        CoUninitialize();
        return -1;
    }

	return 0;
}

/**
 * \brief Clean up the WMI hooks we used.
 *
 * \retval 0 on success
 **/
int windows_calls_wmi_deinit()
{
	if(wcLoc != NULL)
		IWbemLocator_Release(wcLoc);   

	if (wSvc != NULL)
		IWbemLocator_Release(wSvc);

    CoUninitialize();

	return 0;
}

/**
 * \brief Establish a connection to WMI for future requests.
 *
 *  In general, this will only be called when the program starts up.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int windows_calls_wmi_connect()
{
	HRESULT hr;

	if (wcLoc == NULL)
	{
		printf("Couldn't connect to IWbemLocator because wcLoc was NULL!\n");
		return -1;
	}

  // Connect to the root\default namespace with the current user.
    hr = IWbemLocator_ConnectServer(wcLoc,
            L"ROOT\\CIMV2", 
            NULL, NULL, NULL, 0, NULL, NULL, &wSvc);

    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Could not connect. Error code = 0x%x\n", hr);
        return -1;
    }

	if (wSvc == NULL)
	{
		printf("Couldn't connect to IWbemLocator service!\n");
		return -1;
	}

    hr = CoSetProxyBlanket(
       (IUnknown *)wSvc,                        // Indicates the proxy to set
       RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
       NULL,                        // Server principal name 
       RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
       RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
       NULL,                        // client identity
       EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hr))
    {
        debug_printf(DEBUG_NORMAL, "Could not set proxy blanket. Error code = 0x%02x\n", hr);
        return -1;
    }

	return 0;
}

/**
 * \brief Look in the windows process list to see if a process is running.
 *
 * @param[in] search   The fingerprint record to search for.
 *
 * \retval >0 number of times the fingerprint was matched.
 * \retval 0 process not found.
 **/
int supdetect_check_process_list(sup_fingerprints *search)
{
	HRESULT hr;
	IEnumWbemClassObject *pEnumerator = NULL;
	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 1;
	VARIANT vtProp;
	int found = 0;
	char utf8result[1000];
	char *matchstr = NULL;

	if (wSvc == NULL)
	{
		return -1;
	}

    hr = IWbemServices_ExecQuery(wSvc,
         L"WQL", L"select * from Win32_Process",
         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
         NULL,
         &pEnumerator);

    if (FAILED(hr)) return -1;

	matchstr = _strdup(search->match_string);
	if (matchstr == NULL) return -1;

	toupper_str(matchstr);

	while ((SUCCEEDED(IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1, 
         &pclsObj, &uReturn)) && (uReturn != 0)))
	{
			hr = IWbemClassObject_Get(pclsObj, L"Caption", 0, &vtProp, 0, 0);
			if (SUCCEEDED(hr))
			{
				sprintf(utf8result, "%ws", vtProp.bstrVal);

				VariantClear(&vtProp);

				IWbemClassObject_Release(pclsObj);

				toupper_str((char *)&utf8result);

				if (strcmp(utf8result, matchstr) == 0) found++;
			}
	}

	IWbemClassObject_Release(pEnumerator);

	free(matchstr);
	
	return found;
}

/**
 * \brief Look in the windows service list to see if a process is running.
 *
 * @param[in] search   The fingerprint record to search for.
 *
 * \retval >0 number of times the fingerprint was matched.
 * \retval 0 process not found.
 **/
int supdetect_check_service_list(sup_fingerprints *search)
{
	HRESULT hr;
	IEnumWbemClassObject *pEnumerator = NULL;
	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 1;
	VARIANT vtProp;
	int found = 0;
	char utf8result[1000];
	char *matchstr = NULL;

	if (wSvc == NULL)
	{
		return -1;
	}

    hr = IWbemServices_ExecQuery(wSvc,
         L"WQL", L"select * from Win32_Service",
         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
         NULL,
         &pEnumerator);

    if (FAILED(hr)) return -1;

	matchstr = _strdup(search->match_string);
	if (matchstr == NULL) return -1;

	toupper_str(matchstr);

	while ((SUCCEEDED(IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1, 
         &pclsObj, &uReturn)) && (uReturn != 0)))
	{
			hr = IWbemClassObject_Get(pclsObj, L"Caption", 0, &vtProp, 0, 0);
			if (SUCCEEDED(hr))
			{
				sprintf(utf8result, "%ws", vtProp.bstrVal);

				VariantClear(&vtProp);

				toupper_str((char *)&utf8result);

				if (strcmp(utf8result, matchstr) == 0)
				{
					// It was found, now see if it is running.
					hr = IWbemClassObject_Get(pclsObj, L"State", 0, &vtProp, 0, 0);
					if (SUCCEEDED(hr))
					{
						sprintf(utf8result, "%ws", vtProp.bstrVal);

						VariantClear(&vtProp);

						toupper_str((char *)&utf8result);

						if (strcmp(utf8result, "RUNNING") == 0) 
							found++;
					}
				}

				IWbemClassObject_Release(pclsObj);
			}
	}

	IWbemClassObject_Release(pEnumerator);

	free(matchstr);
	
	return found;
}

/**
 * \brief This call is provided so that we can run checks against anything
 *        special that the OS does that we might care about.  (i.e. Windows
 *        Zero Config.)
 *
 * \retval >0 the number of OS specific checks that failed.
 * \retval 0 no OS specific checks failed.
 **/
int os_strange_checks()
{
	return 0;
}


#endif // WINDOWS
