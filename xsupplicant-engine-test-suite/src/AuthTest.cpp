#include <windows.h>
#include <process.h>
#include <iostream>

#include "Util.h"
#include "AuthTest.h"

extern "C" {
#include "xsupgui_events.h"
};

AuthTest::AuthTest()
{
}

AuthTest::~AuthTest()
{
}

bool AuthTest::executeTest()
{
	if (buildConnectionList() == false)
	{
		innerError("Unable to establish a connection to the event handle!\n");
		return false;
	}

	if (runConnectionTests() == false)  return false;		// runConnectionTests() should have already screamed.

	return true;
}

bool AuthTest::buildConnectionList()
{
	conn_enum *myEnum = NULL;
	int i = 0;

	if (xsupgui_request_enum_connections((CONFIG_LOAD_GLOBAL | CONFIG_LOAD_USER), &myEnum) != REQUEST_SUCCESS)
	{
		return false;
	}

	while (myEnum[i].name != NULL)
	{
		connections.push_back(string(myEnum[i].name));
		i++;
	}

	xsupgui_request_free_conn_enum(&myEnum);

	return true;
}

bool AuthTest::establishEventListener()
{
	if (xsupgui_connect_event_listener() != 0)
	{
		cout << "Failed to connect event listener!\n";
		return false;
	}

	return true;
}

bool AuthTest::teardownEventListener()
{
	if (xsupgui_disconnect_event_listener() != 0)
	{
		cout << "Failed to disconnect event listener!\n";
		return false;
	}

	return true;
}

void AuthTest::processEvent()
{
	int evttype = 0;
	int result = 0;
	int uievt = 0;
	unsigned int tncconnectionid;
	int newstate, oldstate, sm;
	char *logline, *ints, *arg;

		result = xsupgui_process(&evttype);

		if (result != REQUEST_SUCCESS)
		{
			printf("Error getting data : %ld\n", result);
		}

		if (result == REQUEST_SUCCESS)
		{
			// We got an event.  So we need to look at the type it is, and
			// request that it be processed properly.
			switch (evttype)
			{
			case IPC_EVENT_LOG:
				// Process a log message.
				result = xsupgui_events_generate_log_string(&ints, &logline);
				if (log == 1)
				{
					cout << "Log : " + string(logline) + "\n";
				}

				if (ints != NULL) free(ints);
				if (logline != NULL) free(logline);			
				break;

			case IPC_EVENT_ERROR:
				// Process an error message.
				result = xsupgui_events_get_error(&uievt, &logline);
				if (result == 0)
				{
					printf("Error (%d) : %s\n", uievt, logline);
					free(logline);
				}
				break;

			case IPC_EVENT_UI:
				// Process a UI event.
				result = xsupgui_events_get_ui_event(&uievt, &ints, &arg); 
				if (result == 0)
				{
					cout << "Got a UI event : " + Util::itos(uievt) + "\n";

					if (ints != NULL) free(ints);
					if (arg != NULL) free(arg);
				}
				else
				{
					printf("Couldn't parse UI event!\n");
				}
				break;

			case IPC_EVENT_STATEMACHINE:
				// Process a state machine message.
				result = xsupgui_events_get_state_change(&ints, &sm, &oldstate, &newstate, &tncconnectionid);
				state = newstate;
				free(ints);
				ints = NULL;
				break;

			case IPC_EVENT_SCAN_COMPLETE:
				// Process a scan complete event.
				break;

			case IPC_EVENT_REQUEST_PWD:
				// Process a password request event.
				pwdrequest = 1;
				break;

			case IPC_EVENT_TNC_UI:
				break;

			case IPC_EVENT_TNC_UI_REQUEST:
				break;

			case IPC_EVENT_TNC_UI_BATCH_REQUEST:
				break;

			case IPC_EVENT_COM_BROKEN:
				// The xsupgui library notified us that it's event connection
				// has been broken.  This is the right way to determine when the
				// supplicant isn't going to send us more data, since it isn't
				// platform specific.
				printf("Communication with the supplicant has been broken.\n");
				failure = 1;
				break;

			default:
				printf("Unknown event received!  (Event : %ld)\n", result);
				break;
			}

			// Always free the event doc when you are done working with it.  
			// Otherwise, you might end up leaking lots of memory.
			xsupgui_free_event_doc();
		}
}

bool AuthTest::runConnectionTests()
{
	for (vector<string>::iterator i = connections.begin(); i != connections.end(); ++i)
	{
		if (doTest((*i)) == false) return false;
	}

	return true;
}

bool AuthTest::doTest(string connName)
{
	int retval = 0;
	config_connection *myconnection = NULL;

	log = 1;

	cout << "Attempting to connect to : " << connName << endl;

	retval = xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, const_cast<char *>(connName.c_str()), &myconnection);
	if (retval != REQUEST_SUCCESS)
	{
		cout << "Couldn't get the connection configuration!\n";
		return false;
	}

	// XXX Fix!
	/*
	retval = xsupgui_request_set_connection(myconnection->device, const_cast<char *>(connName.c_str()));
	if (retval != REQUEST_SUCCESS)
	{
		cout << "Failed to request a change of connection to " + connName + "!  (Error : " + Util::itos(retval) + ")\n";
		if (retval == 310)
		{
			cout << "It seems the desired interface isn't in the machine?\n";
			return true;
		}

		return false;
	}
*/
	state = DISCONNECTED;

	while ((state != AUTHENTICATED) && (failure == 0) && (pwdrequest == 0))
	{
		processEvent();
	}

	// XXX Fix!
/*	if (xsupgui_request_disconnect_connection(myconnection->device) != REQUEST_SUCCESS)
	{
		cout << "Unable to disconnect connection " + connName + "!\n";
		return false;
	}*/

	xsupgui_request_free_connection_config(&myconnection);

	log = 0;

	return true;
}