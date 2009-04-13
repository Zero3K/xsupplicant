/**
* Windows code to establish the supplicant as a service.
*
* Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
*
* \file win_svc.c
*
* \authors chris@open1x.org
*
*/  

#ifdef BUILD_SERVICE
#include <windows.h>

#include <dbt.h>
#include <devguid.h>

#include "xsup_debug.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;
HDEVNOTIFY hDevStatus;

// Some service specific error codes.
#define SERVICE_ERROR_STOP_REQUESTED       1
#define SERVICE_ERROR_DUPLICATE_INSTANCE   2
#define SERVICE_ERROR_GLOBAL_DEINIT_CALLED 3
#define SERVICE_ERROR_FAILED_TO_INIT       4
#define SERVICE_ERROR_FAILED_TO_START_IPC  5
#define SERVICE_ERROR_BASIC_INIT_FAILED    6

// Used to determine when a network interface is plugged in.
DEFINE_GUID(GUID_NDIS_LAN_CLASS, 0xad498944, 0x762f, 0x11d0, 0x8d, 0xcb, 0x00,
			0xc0, 0x4f, 0xc3, 0x35, 0x8c);


DWORD WINAPI ControlHandler(DWORD request, DWORD dwEventType,
							LPVOID lpEventData, LPVOID lpContext);


/**
* \brief Handle device insertion/removal events that are coming in on the service
*        event handler.
*
* \note Because we filter by the class of events we want, we don't need to do any extra
*       checking in here.  (Unless someone messes with our filter. ;)
*
* @param[in] dwEventType   The event type that triggered this call.
* @param[in] lpEventData   The data blob that came with the event.
**/ 
void ProcessDeviceEvent(DWORD dwEventType, LPVOID lpEventData) 
{
	PDEV_BROADCAST_DEVICEINTERFACE lpdb = (PDEV_BROADCAST_DEVICEINTERFACE) lpEventData;

	switch (dwEventType)
	{
	case DBT_DEVICEARRIVAL:
		// This check is largely pointless, but leave it here just to make sure nothing weird
		// happens.
		if (lpdb->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
		{
			// The device name we care about will start with something like this :
			//    \\?\Root#MS_PSCHEDMP#0008#
			debug_printf(DEBUG_INT,
				"Got a device insertion event for '%ws'.\n",
				lpdb->dbcc_name);

			// If it is the one we want, then process it, otherwise ignore it.
			if (_wcsnicmp((wchar_t *) lpdb->dbcc_name,
				L"\\\\?\\Root#MS_PSCHEDMP#", 21) == 0)
			{
				debug_printf(DEBUG_INT,
					"Processing interface insertion!\n");
				cardif_windows_events_add_remove_interface(lpdb->dbcc_name, TRUE);
			}
		}
		break;

	case DBT_DEVICEREMOVECOMPLETE:
		// This check is largely pointless, but leave it here just to make sure nothing weird
		// happens.
		if (lpdb->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
		{
			// The device name we care about will start with something like this :
			//    \\?\Root#MS_PSCHEDMP#0008#
			debug_printf(DEBUG_INT,
				"Got a device removal event for '%ws'.\n",
				lpdb->dbcc_name);

			// If it is the one we want, then process it, otherwise ignore it.
			if (_wcsnicmp((wchar_t *) lpdb->dbcc_name, L"\\\\?\\Root#MS_PSCHEDMP#", 21) == 0)
			{
				debug_printf(DEBUG_INT,
					"Processing interface removal!\n");
				cardif_windows_events_add_remove_interface(lpdb->dbcc_name, FALSE);
			}
		}
		break;

	default:
		debug_printf(DEBUG_INT, "Got event %x on device handler.\n",
			dwEventType);
		break;
	}
}


DWORD WINAPI ControlHandler(DWORD request, DWORD dwEventType,
							LPVOID lpEventData, LPVOID lpContext) 
{
	switch (request)
	{
	case SERVICE_CONTROL_STOP:
		ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(hStatus, &ServiceStatus);
		event_core_terminate();
		return NO_ERROR;

	case SERVICE_CONTROL_SHUTDOWN:
		ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(hStatus, &ServiceStatus);
		event_core_terminate();
		return NO_ERROR;

	case SERVICE_CONTROL_DEVICEEVENT:
		ProcessDeviceEvent(dwEventType, lpEventData);
		return NO_ERROR;

	case SERVICE_CONTROL_SESSIONCHANGE:
		switch (dwEventType)
		{
		case WTS_CONSOLE_CONNECT:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>> Console connect. (Session : %d  Size : %d)\n",
				((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId,
				((PWTSSESSION_NOTIFICATION)lpEventData)->cbSize);

			if (((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId == 0)
			{
				event_core_user_logged_on();
			}
			break;

		case WTS_CONSOLE_DISCONNECT:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>> Console disconnect.(Session : %d  Size : %d)\n",
				((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId,
				((PWTSSESSION_NOTIFICATION)lpEventData)->cbSize);

			if (((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId == 0)
			{
				event_core_user_logged_off();
			}
			break;

		case WTS_SESSION_LOGON:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>>  User logged on!  (Session : %d  Size : %d)\n",
				((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId,
				((PWTSSESSION_NOTIFICATION)lpEventData)->cbSize);

			if (((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId == 0)
			{
				event_core_user_logged_on();
			}
			break;

		case WTS_SESSION_LOGOFF:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>>  User logged off! (Session : %d  Size : %d)\n",
				((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId,
				((PWTSSESSION_NOTIFICATION)lpEventData)->cbSize);

			if (((PWTSSESSION_NOTIFICATION)lpEventData)->dwSessionId == 0)
			{
				event_core_user_logged_off();
			}
			break;

		case WTS_REMOTE_CONNECT:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>> Remote connect.\n");
			break;

		case WTS_REMOTE_DISCONNECT:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>> Remote disconnect.\n");
			break;

		case WTS_SESSION_LOCK:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>> Session Lock\n");
			break;

		case WTS_SESSION_UNLOCK:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>> Session Unlock\n");
			break;

		case WTS_SESSION_REMOTE_CONTROL:
			debug_printf(DEBUG_EVENT_CORE,
				">>>>>>>>>>>>>>>>>>>>>>>>>>> Session is under remote control.\n");
			break;

		default:
			debug_printf(DEBUG_EVENT_CORE,
				"Unknown event type %d.\n", dwEventType);
			break;
		}
		break;

	case SERVICE_CONTROL_POWEREVENT:
		// There are a whole bunch of different states that can be signaled.  The ones
		// below represent the ones that we either care about now, or might care about
		// in the future.
		//
		//  If we don't process an event, we need to be sure to return NO_ERROR, to avoid
		// running in to a situation where the OS believes that we want to block it from
		// suspending.
		switch ((int)dwEventType)
		{
		case PBT_APMPOWERSTATUSCHANGE:
			// We don't care about this one right now.
			return NO_ERROR;

		case PBT_APMRESUMEAUTOMATIC:
			// This signal should be generated whenever we resume (sleep or hibernate)
			event_core_waking_up_thread_ctrl();
			return NO_ERROR;

		case PBT_APMRESUMESUSPEND:
			// This signal gets triggered right before PBT_APMRESUMEAUTOMATIC.  So, we don't
			// want to deal with it right now.
			return NO_ERROR;

		case PBT_APMQUERYSUSPEND:
			// This is the first indication that we are going in to suspend mode.  Most of the
			// time it means that we are going to complete going in to suspend mode, however, if
			// PBT_APMQUERYSUSPENDFAILD is triggered, then we won't suspend, so we need to kick
			// everything back up.
			event_core_going_to_sleep_thread_ctrl();
			return NO_ERROR;

		case PBT_APMQUERYSUSPENDFAILED:
			// Suspend failed, so turn everything back on.
			event_core_cancel_sleep_thread_ctrl();
			return NO_ERROR;

		case PBT_APMSUSPEND:
			// We get this signal when the system is starting to go in to a suspend state.
			// By the time we get here, it is probably too late to do much of anything.
			return NO_ERROR;

			// case PBT_WhatEver and so on.
		}
		debug_printf(DEBUG_NORMAL, "Power state event : %x\n",
			((int)dwEventType));
		return NO_ERROR;
		break;

	default:
		break;
	}

	// Report current status
	SetServiceStatus(hStatus, &ServiceStatus);

	return NO_ERROR;
}

extern int ServiceMain(int argc, char *argv[]);


void main() 
{
	SERVICE_TABLE_ENTRY ServiceTable[2];

	ServiceTable[0].lpServiceName = "Xsupplicant";
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION) ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;

	// Start the control dispatcher thread for our service
	StartServiceCtrlDispatcher(ServiceTable);
} 

void win_svc_run(context * intiface) 
{
	while (ServiceStatus.dwCurrentState == 
		SERVICE_RUNNING)
	{
		event_core(intiface);
	}

	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	ServiceStatus.dwWin32ExitCode = NO_ERROR;

	SetServiceStatus(hStatus, &ServiceStatus);
}


void win_svc_status_stopping() 
{
	ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
	ServiceStatus.dwWin32ExitCode = NO_ERROR;
	ServiceStatus.dwCheckPoint++;

	SetServiceStatus(hStatus, &ServiceStatus);
}

void win_svc_deinit() 
{
	UnregisterDeviceNotification(hDevStatus);
} 

void win_svc_error_dup() 
{
	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
	ServiceStatus.dwServiceSpecificExitCode =
		SERVICE_ERROR_DUPLICATE_INSTANCE;
	SetServiceStatus(hStatus, &ServiceStatus);
} 

void win_svc_basic_init_failed() 
{
	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
	ServiceStatus.dwServiceSpecificExitCode =
		SERVICE_ERROR_BASIC_INIT_FAILED;

	SetServiceStatus(hStatus, &ServiceStatus);
} 

void win_svc_init_failed(int retval) 
{
	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;

	if (retval == 2)
	{
		ServiceStatus.dwServiceSpecificExitCode =
			SERVICE_ERROR_FAILED_TO_START_IPC;
	}
	else
	{
		ServiceStatus.dwServiceSpecificExitCode =
			SERVICE_ERROR_FAILED_TO_INIT;
	}

	SetServiceStatus(hStatus, &ServiceStatus);
}


void win_svc_running() 
{
	// The next part of the startup could see some lag that can confuse
	// Windows about the state of the service.  So, we need to report the
	// state earlier.  Technically we are in a fully running state here, 
	// even though no interfaces are operational and no IPC channel is 
	// available.
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &ServiceStatus);
} 

int win_svc_init() 
{
	DEV_BROADCAST_DEVICEINTERFACE devBcInterface;

	ServiceStatus.dwServiceType = 
		SERVICE_WIN32;

	ServiceStatus.dwCurrentState = 
		SERVICE_START_PENDING;

	ServiceStatus.dwControlsAccepted =
		SERVICE_ACCEPT_STOP | 
		SERVICE_ACCEPT_SHUTDOWN |
		SERVICE_ACCEPT_POWEREVENT | 
		SERVICE_ACCEPT_SESSIONCHANGE;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandlerEx(
		"XSupplicant", 
		(LPHANDLER_FUNCTION_EX)
		ControlHandler, 
		NULL);
	if (hStatus == (SERVICE_STATUS_HANDLE) 0)
	{
		// Registering Control Handler failed
		return -1;
	}

	// Register for device insert/remove notifications.
	ZeroMemory(&devBcInterface, sizeof(devBcInterface));
	devBcInterface.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
	devBcInterface.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	memcpy(&(devBcInterface.dbcc_classguid), 
		&(GUID_NDIS_LAN_CLASS),
		sizeof(struct _GUID));

	hDevStatus = RegisterDeviceNotification(hStatus, &devBcInterface,
		DEVICE_NOTIFY_SERVICE_HANDLE);

	return 0;
}



#endif				// BUILD_SERVICE
