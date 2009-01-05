#ifndef _AUTHTEST_H_
#define _AUTHTEST_H_

#include <windows.h>
#include <string>
#include "TestBase.h"
#include "IPCConnectTest.h"

extern "C" {
#include "xsupgui.h"
#include "xsupconfig.h"
#include "xsupgui_request.h"
}

class AuthTest : public IPCConnectTest
{
public:
	AuthTest();
	~AuthTest();

	string getTestName() { return "Authentication Tests"; }
	bool executeTest();
	bool terminal_error() { return false; }

private:
	bool buildConnectionList();
	bool establishEventListener();
	bool teardownEventListener();
	void processEvent();
	bool runConnectionTests();
	bool doTest(string connName);

	vector<string> connections;

	int state;
	int log;
	int failure;
	int pwdrequest;
};

#endif
