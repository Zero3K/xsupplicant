/**
 * Test non-network related IPC calls
 *
 * \author chris@open1x.org
 **/  
    
#ifndef _NNIPC_TESTS_H_
#define _NNIPC_TESTS_H_
    
#include <string>
#include "TestBase.h"
#include "IPCConnectTest.h"
extern "C" {
	
#include "xsupgui.h"
#include "xsupconfig.h"
#include "xsupgui_request.h"
}   class nnIPCTests:public IPCConnectTest  {
 public:nnIPCTests();
	~nnIPCTests();
	string getTestName() {
		return "non-network IPC";
	}
	bool executeTest();
	bool terminal_error() {
		return false;
	}
 protected:bool doPing();
	bool enumLiveInts();
	bool enumEAPmethods();
	bool checkVersionString();
	bool checkCertificates();
	bool checkCreateTT();
	bool checkUserCertificates();
	bool enumSmartCardReaders();
};


#endif				// _NNIPC_TESTS_H_
