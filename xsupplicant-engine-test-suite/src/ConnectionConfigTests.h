/**
 * Test add/change/remove in both system and user level configuration data.  Also verify that
 * data survives a restart of the supplicant.
 *
 * \author chris@open1x.org
 **/

#ifndef _CONNECTION_CONFIG_TESTS_H_
#define _CONNECTION_CONFIG_TESTS_H_

#include <string>
#include "TestBase.h"
#include "IPCConnectTest.h"

extern "C" {
#include "xsupgui.h"
#include "xsupconfig.h"
#include "xsupgui_request.h"
}

class ConnectionConfigTests : public IPCConnectTest
{
public:
	ConnectionConfigTests();
	~ConnectionConfigTests();

	string getTestName() { return "Connection Configuration"; }
	bool executeTest();
	bool terminal_error() { return false; }

protected:
	config_connection *createValidNonDefaultConfig(char *name);
	bool createSystemConfig();
	bool createUserConfig();
	bool createVolatileSystemConfig();
	bool createVolatileUserConfig();
	bool checkConfigState();
	bool checkUserConfigState();
	bool checkVolatileSystemConfig(bool shouldBeAvail);
	bool checkVolatileUserConfig(bool shouldBeAvail);
	bool checkFlagSettings();
	bool checkPriorityRange();
	bool checkForceEAPoLVerRange();
	bool checkAssociationTypeRange();
	bool checkAuthenticationTypeRange();
	bool checkGroupKeyRange();
	bool checkPairwiseKeyRange();
	bool checkTxKeyRange();
	bool checkWEPKeyRange();
	bool checkPSKValues();
	bool checkPSKHexValues();
	bool checkIPTypeValues();
	bool checkReauthRenewValues();
	bool checkRenameSystemConnection();
	bool checkRenameUserConnection();
	bool checkDeleteSystemConnection();
	bool checkDeleteUserConnection();
	bool checkInvalidDeleteConnections();
	bool checkVolatileOnStored();
	bool checkEnumConnections();
	bool checkInvalidConnectionName();
	bool checkInvalidConfigDest();
	bool configsMatch(config_connection *original, config_connection *testval);
	bool writeConfigs();
	bool checkRenameNotExist();

private:
	config_connection *system_config;
	config_connection *user_config;
	config_connection *volatile_system_config;
	config_connection *volatile_user_config;

	bool connectionIsInEnum(conn_enum *enumdata, uint8_t config_type, char *name);
};

#endif  // _CONNECTION_CONFIG_TESTS_H_