/**
 *  Simple IPC connection test.
 **/
#include <windows.h>

#include <iostream>
#include "IPCConnectTest.h"
#include "Util.h"

extern "C" {
#include "xsupgui.h"
#include "xsupgui_request.h"
}

using namespace std;

IPCConnectTest::IPCConnectTest()
{
	all_tests_success = true;
}

bool IPCConnectTest::setupTest()
{
	int result = 0;
	int i = 0;
	bool connected = true;
	char *verstring = NULL;

	for (i = 0; i<30; i++)
	{
		result = xsupgui_connect();
		if (result != 0)
		{
			innerError("Unable to establish IPC connection with the supplicant engine!\n");
			connected = false;
		}
		else if (result == IPC_ERROR_EVT_ALREADY_CONNECTED)
		{
			innerError("Connection was already established.");
		}
		else
		{
			connected = true;
			break;
		}

		Sleep(1000);
	}

	if (i > 0)
	{
		innerError("It took the test program " + Util::itos(i) + " seconds to reconnect.\n");
	}

	if (connected == false)
	{
		all_tests_success = false;
		return false;
	}

	result = xsupgui_request_version_string(&verstring);
	if (result == REQUEST_SUCCESS)
	{
		cout << "Connected to " << string(verstring) << ".\n";
	}
	else
	{
		cout << "Unable to determine the version!\n";
	}

	return true;
}

bool IPCConnectTest::teardownTest()
{
	int result = 0;

	result = xsupgui_disconnect();
	if (result != 0)
	{
		innerError("Unable to terminate IPC connection with the supplicant engine!\n");
		all_tests_success = false;
		return false;
	}

	return true;
}


