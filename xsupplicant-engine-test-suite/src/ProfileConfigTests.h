/**
 * Test add/change/remove in both system and user level configuration data.  Also verify that
 * data survives a restart of the supplicant.
 *
 * \author chris@open1x.org
 **/

#ifndef _PROFILE_CONFIG_TESTS_H_
#define _PROFILE_CONFIG_TESTS_H_

#include <string>
#include "TestBase.h"
#include "IPCConnectTest.h"

extern "C" {
#include "xsupgui.h"
#include "xsupconfig.h"
#include "xsupgui_request.h"
}

class ProfileConfigTests : public IPCConnectTest
{
public:
	ProfileConfigTests();
	~ProfileConfigTests();

	string getTestName() { return "Profile Configuration"; }
	bool executeTest();
	bool terminal_error() { return false; }

protected:
	bool createSystemProfileConfig();
	bool createUserProfileConfig();
	bool checkSystemProfileConfig();
	bool checkUserProfileConfig();
	bool createVolatileSystemProfileConfig();
	bool createVolatileUserProfileConfig();
	bool checkVolatileSystemProfileConfig(bool expected);
	bool checkVolatileUserProfileConfig(bool expected);
	bool checkRenameToVolatile();
	bool checkSystemSwitchToVolatile();
	bool checkUserSwitchToVolatile();
	bool checkBadDelete();
	bool checkDeleteSystemProfileConfig();
	bool checkDeleteUserProfileConfig();
	bool writeConfigs();
	bool checkRename();
	bool checkInvalidRename();
	bool checkInvalidConfigDest();
	bool checkProfileEnum();
	bool checkEAPMD5Config();
	bool checkEAPMSCHAPv2Config();
	bool checkEAPAKAConfig();
	bool checkEAPSIMConfig();
	bool checkEAPGTCConfig();
	bool checkEAPOTPConfig();
	bool checkEAPTLSConfig();

	// EAP-MD5 helper functions
	struct config_eap_method *createEAPMD5Test();
	bool checkEAPMD5Test(struct config_eap_method *eapmd5);
	bool freeEAPMD5Test(struct config_eap_method **eapmd5);

	// EAP-MSCHAPv2 helper functions
	struct config_eap_method *createEAPMSCHAPv2Test();
	bool checkEAPMSCHAPv2Test(struct config_eap_method *eapmscv2);
	bool freeEAPMSCHAPv2Test(struct config_eap_method **eapmscv2);

	// EAP-AKA helper functions
	struct config_eap_method *createEAPAKATest();
	bool checkEAPAKATest(struct config_eap_method *eapaka);
	bool freeEAPAKATest(struct config_eap_method **eapaka);

	// EAP-SIM helper functions
	struct config_eap_method *createEAPSIMTest();
	bool checkEAPSIMTest(struct config_eap_method *eapsim);
	bool freeEAPSIMTest(struct config_eap_method **eapsim);

	// EAP-GTC helper functions
	struct config_eap_method *createEAPGTCTest();
	bool checkEAPGTCTest(struct config_eap_method *eapgtc);
	bool freeEAPGTCTest(struct config_eap_method **eapgtc);

	// EAP-OTP helper functions
	struct config_eap_method *createEAPOTPTest();
	bool checkEAPOTPTest(struct config_eap_method *eapotp);
	bool freeEAPOTPTest(struct config_eap_method **eapotp);

	// EAP-TLS helper functions
	struct config_eap_method *createEAPTLSTest();
	bool checkEAPTLSTest(struct config_eap_method *eaptls);
	bool freeEAPTLSTest(struct config_eap_method **eaptls);

private:
	bool foundInEnum(profile_enum *profenum, char *tofind);
};

#endif  // _PROFILE_CONFIG_TESTS_H_