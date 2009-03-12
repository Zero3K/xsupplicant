/**
 * Simple test to verify that we can connect to the supplicant on the IPC channel.
 *
 * \author chris@open1x.org
 **/  
    
#ifndef _IPCCONNECTTEST_H_
#define _IPCCONNECTTEST_H_
    
#include <string>
#include "TestBase.h"
 class IPCConnectTest:public TestBase  {
 public:IPCConnectTest();
	virtual string getTestName() {
		return "Simple IPC Connection";
	}
	virtual bool setupTest();
	virtual bool teardownTest();
	virtual bool executeTest() {
		return true;
	}
	virtual bool terminal_error() {
		return true;
	}
};


#endif				// _IPCCONNECTTEST_H_
