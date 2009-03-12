/**
 * Windows WLAN API interfaces
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file wlanapi_interface.h
 *
 * \author chris@open1x.org
 *
 **/  
    
#ifndef _WLANAPI_INTERFACE_H_
#define _WLANAPI_INTERFACE_H_
    
// Define some return codes.
#define WLANAPI_OK					 0	///< The function completed successfully.
#define WLANAPI_NOT_AVAILABLE		-1	///< The wlan API isn't available on this system.
#define WLANAPI_CANT_MAP			-2	///< The needed wlan API functions couldn't be mapped.
#define WLANAPI_NOT_CONNECTED		-3	///< The wlanapi.dll has not been loaded.
#define WLANAPI_CALL_FAILED	        -4	///< A call to the wlan API failed.
#define WLANAPI_INT_NOT_FOUND       -5	///< The desired interface wasn't found.
#define WLANAPI_ALREADY_SET			 1	///< The desired state is already set on the interface.
#define WLANAPI_DIDNT_TAKE          -6	///< We successfully set the state, but it didn't take.
int wlanapi_interface_disconnect();
int wlanapi_interface_connect();
int wlanapi_interface_disable_wzc(char *desc);
int wlanapi_interface_enable_wzc(char *desc);

#endif				// _WLANAPI_INTERFACE_H_
    
