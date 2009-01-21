/**
 * Test add/change/remove in both system and user level configuration data.  Also verify that
 * data survives a restart of the supplicant.
 *
 * \author chris@open1x.org
 **/

#ifndef _TRUSTEDSERVER_CONFIG_TESTS_H_
#define _TRUSTEDSERVER_CONFIG_TESTS_H_

#include <string>
#include "TestBase.h"
#include "IPCConnectTest.h"

extern "C" {
#include "xsupgui.h"
#include "xsupconfig.h"
#include "xsupgui_request.h"
}

class TrustedServerConfigTests : public IPCConnectTest
{
public:
	TrustedServerConfigTests();
	~TrustedServerConfigTests();

	string getTestName() { return "Trusted Server Configuration"; }
	bool executeTest();
	bool terminal_error() { return false; }

protected:
	bool createSystemTrustedServerConfig();
	bool createUserTrustedServerConfig();
	bool checkSystemTrustedServerConfig();
	bool checkUserTrustedServerConfig();
	bool createVolatileSystemTrustedServerConfig();
	bool createVolatileUserTrustedServerConfig();
	bool checkVolatileSystemTrustedServerConfig(bool expected);
	bool checkVolatileUserTrustedServerConfig(bool expected);
	bool checkRenameToVolatile();
	bool checkSystemSwitchToVolatile();
	bool checkUserSwitchToVolatile();
	bool checkFlagsRange();
	bool checkTSEnum();
	bool checkBadDelete();
	bool checkDeleteSystemTrustedServerConfig();
	bool checkDeleteUserTrustedServerConfig();
	bool writeConfigs();
	bool checkRename();
	bool checkInvalidRename();
	bool checkInvalidConfigDest();
	bool checkInvalidServerName();

	struct config_trusted_server *createFullTrustedServerConfig(char *name, char *stype, char *location);

private:
	bool foundInEnum(trusted_servers_enum *tsenum, char *tofind);
};

#endif  // _TRUSTEDSERVER_CONFIG_TESTS_H_