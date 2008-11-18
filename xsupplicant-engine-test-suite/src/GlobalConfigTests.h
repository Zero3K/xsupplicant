/**
 * Test add/change/remove in both system and user level configuration data.  Also verify that
 * data survives a restart of the supplicant.
 *
 * \author chris@open1x.org
 **/

#ifndef _GLOBAL_CONFIG_TESTS_H_
#define _GLOBAL_CONFIG_TESTS_H_

#include <string>
#include "TestBase.h"
#include "IPCConnectTest.h"

extern "C" {
#include "xsupgui.h"
#include "xsupconfig.h"
#include "xsupgui_request.h"
}

class GlobalConfigTests : public IPCConnectTest
{
public:
	GlobalConfigTests();
	~GlobalConfigTests();

	string getTestName() { return "Global Configuration"; }
	bool executeTest();
	bool terminal_error() { return false; }

protected:
	bool checkSettingsSurviveRestart();
	bool checkLogFileLocation();
	bool checkLogLevelRange();
	bool checkLogsToKeepRange();
	bool checkSizeToRollRange();
	bool checkLogTypeRange();
	bool checkLogFacility();
	bool checkIPCGroupName();
	bool checkFlags();
	bool checkDestinationRange();
	bool checkAuthPeriodRange();
	bool checkHeldPeriodRange();
	bool checkMaxStartsRange();
	bool checkStaleKeyTimeoutRange();
	bool checkAssocTimeoutRange();
	bool checkPassiveTimeoutRange();
	bool checkActiveTimeoutRange();
	bool checkIdleWhileTimeoutRange();
	bool checkPMKSAAgeOutRange();
	bool checkPMKSACacheCheckRange();
	bool checkDeadConnectionTimeoutRange();

private:
	bool globalConfigsMatch(struct config_globals *g1, struct config_globals *g2);
	bool writeConfigs();
};

#endif  // _GLOBAL_CONFIG_TESTS_H_