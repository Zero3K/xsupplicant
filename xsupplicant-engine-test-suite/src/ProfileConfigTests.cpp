#include <iostream>

#include "Util.h"
#include "ProfileConfigTests.h"

ProfileConfigTests::ProfileConfigTests()
{
}

ProfileConfigTests::~ProfileConfigTests()
{
}

bool ProfileConfigTests::executeTest()
{
	runInnerTest("1 createSystemProfileConfig()", createSystemProfileConfig());

	runInnerTest("1 createUserProfileConfig()", createUserProfileConfig());

	runInnerTest("1 checkSystemProfileConfig()", checkSystemProfileConfig());

	runInnerTest("1 checkUserProfileConfig()", checkUserProfileConfig());

	runInnerTest("1 createVolatileSystemProfileConfig()", createVolatileSystemProfileConfig());

	runInnerTest("1 createVolatileUserProfileConfig()", createVolatileUserProfileConfig());

	runInnerTest("1 checkVolatileSystemProfileConfig()", checkVolatileSystemProfileConfig(true));

	runInnerTest("1 checkVolatileUserProfileConfig()", checkVolatileUserProfileConfig(true));

	runInnerTest("1 checkRenameToVolatile()", checkRenameToVolatile());

	// Make sure we can write it to the disk.
	if (runInnerTest("1 writeConfigs()", writeConfigs()) == false) return false;

	// Cleanly disconnect before we restart the engine.
	if (runInnerTest("1 IPCConnectTest::teardownTest()", IPCConnectTest::teardownTest()) == false) return false;

	// Restart the engine.
	Util::restartEngine(30);		// Wait 30 seconds.

	// Establish a new IPC connection to the engine.
	if (runInnerTest("1 IPCConnectTest::setupTest()", IPCConnectTest::setupTest()) == false) return false;

	runInnerTest("2 checkVolatileSystemProfileConfig()", checkVolatileSystemProfileConfig(false));

	runInnerTest("2 checkVolatileUserProfileConfig()", checkVolatileUserProfileConfig(false));

	runInnerTest("1 checkInvalidRename()", checkInvalidRename());

	runInnerTest("1 checkInvalidConfigTest()", checkInvalidConfigDest());

	runInnerTest("1 checkProfileEnum()", checkProfileEnum());

	// Check EAP methods here.
	runInnerTest("1 checkEAPMD5Config()", checkEAPMD5Config());

	runInnerTest("1 checkEAPMSCHAPv2Config()", checkEAPMSCHAPv2Config());

	runInnerTest("1 checkEAPAKAConfig()", checkEAPAKAConfig());

	runInnerTest("1 checkEAPSIMConfig()", checkEAPSIMConfig());

	runInnerTest("1 checkEAPGTCConfig()", checkEAPGTCConfig());

	runInnerTest("1 checkEAPOTPConfig()", checkEAPOTPConfig());

	runInnerTest("1 checkEAPTLSConfig()", checkEAPTLSConfig());

	runInnerTest("1 checkEAPFASTConfig()", checkEAPFASTConfig());

//	runInnerTest("1 checkSystemSwitchToVolatile()", checkSystemSwitchToVolatile());

//	runInnerTest("1 checkUserSwitchToVolatile()", checkUserSwitchToVolatile());

	runInnerTest("1 checkBadDelete()", checkBadDelete());

	runInnerTest("1 checkRename()", checkRename());

	runInnerTest("1 checkDeleteSystemProfileConfig()", checkDeleteSystemProfileConfig());

	runInnerTest("1 checkDeleteUserProfileConfig()", checkDeleteUserProfileConfig());

	if (runInnerTest("2 writeConfigs()", writeConfigs()) == false) return false;

	cout << "Finish implementation!!  (Need to test settings for all EAP methods)\n";
	return true;
}

#define SYSTEM_CONF_NAME   "System Level Profile Configuration"
#define USER_CONF_NAME    "User Level Profile Configuration"

bool ProfileConfigTests::createSystemProfileConfig()
{
	struct config_profiles *system_profile = NULL;
	int result = 0;

	system_profile = (struct config_profiles *)malloc(sizeof(struct config_profiles));
	if (system_profile == NULL)
	{
		innerError("Unable to allocate memory needed to create a test profile.\n");
		return false;
	}

	system_profile->name = _strdup(SYSTEM_CONF_NAME);
	system_profile->identity = _strdup("non-anonymous id");
	system_profile->flags = 0;
	system_profile->compliance = 0;
	system_profile->temp_password = NULL;
	system_profile->temp_username = NULL;

	// Create a simple method to test with.
	system_profile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (system_profile->method == NULL)
	{
		innerError("Unable to allocate memory to create an EAP method configuration.\n");
		return false;
	}

	system_profile->method->method_num = EAP_TYPE_MD5;
	system_profile->method->method_data = malloc(sizeof(struct config_pwd_only));
	if (system_profile->method->method_data == NULL)
	{
		innerError("Unable to allocate memory to store EAP type.\n");
		return false;
	}

	memset(system_profile->method->method_data, 0x00, sizeof(struct config_pwd_only));

	system_profile->next = NULL;

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, system_profile)) != REQUEST_SUCCESS)
	{
		innerError("Error creating new system level profile!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::createUserProfileConfig()
{
	struct config_profiles *user_profile = NULL;
	int result = 0;

	user_profile = (struct config_profiles *)malloc(sizeof(struct config_profiles));
	if (user_profile == NULL)
	{
		innerError("Unable to allocate memory needed to create a test profile.\n");
		return false;
	}

	user_profile->name = _strdup(USER_CONF_NAME);
	user_profile->identity = _strdup("user non-anonymous id");
	user_profile->flags = 0;
	user_profile->compliance = 0;
	user_profile->temp_password = NULL;
	user_profile->temp_username = NULL;

	// Create a simple method to test with.
	user_profile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (user_profile->method == NULL)
	{
		innerError("Unable to allocate memory to create an EAP method configuration.\n");
		return false;
	}

	user_profile->method->method_num = EAP_TYPE_MD5;
	user_profile->method->method_data = malloc(sizeof(struct config_pwd_only));
	if (user_profile->method->method_data == NULL)
	{
		innerError("Unable to allocate memory to store EAP type.\n");
		return false;
	}

	memset(user_profile->method->method_data, 0x00, sizeof(struct config_pwd_only));
	user_profile->next = NULL;

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_USER, user_profile)) != REQUEST_SUCCESS)
	{
		innerError("Error creating new profile!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkSystemProfileConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Error reading system configuration test profile!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if ((prof->name == NULL) || (strcmp(prof->name, SYSTEM_CONF_NAME) != 0))
	{
		innerError("The profile name was invalid.\n");
		return false;
	}

	if (strcmp(prof->identity, "non-anonymous id") != 0)
	{
		innerError("Identity read back didn't match!\n");
		return false;
	}

	if (prof->flags != 0)
	{
		innerError("Flags weren't 0 when they should have been!\n");
		return false;
	}

	if (prof->compliance != 0xffffff00)
	{
		innerError("Compliance isn't -256 when it should have been!\n");
		return false;
	}

	if (prof->temp_password != NULL)
	{
		innerError("temp_password was non-NULL!  (Shouldn't be possible!)\n");
		return false;
	}

	if (prof->temp_username != NULL)
	{
		innerError("temp_username was non-NULL!  (Shouldn't be possible!)\n");
		return false;
	}

	if (prof->method->method_num != EAP_TYPE_MD5)
	{
		innerError("Method type wasn't stored properly!\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Couldn't free memory from the profile.\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkUserProfileConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_USER, USER_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Error reading user configuration test profile!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if ((prof->name == NULL) || (strcmp(prof->name, USER_CONF_NAME) != 0))
	{
		innerError("The profile name was invalid.\n");
		return false;
	}

	if (strcmp(prof->identity, "user non-anonymous id") != 0)
	{
		innerError("Identity read back didn't match!\n");
		return false;
	}

	if (prof->flags != 0)
	{
		innerError("Flags weren't 0 when they should have been!\n");
		return false;
	}

	if (prof->compliance != 0xffffff00)
	{
		innerError("Compliance isn't -256 when it should have been!\n");
		return false;
	}

	if (prof->temp_password != NULL)
	{
		innerError("temp_password was non-NULL!  (Shouldn't be possible!)\n");
		return false;
	}

	if (prof->temp_username != NULL)
	{
		innerError("temp_username was non-NULL!  (Shouldn't be possible!)\n");
		return false;
	}

	if (prof->method->method_num != EAP_TYPE_MD5)
	{
		innerError("Method type wasn't stored properly!\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Couldn't free memory from the profile.\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::writeConfigs()
{
	if (xsupgui_request_write_config(CONFIG_LOAD_GLOBAL, NULL) != REQUEST_SUCCESS)
	{
		innerError("Couldn't write the global configuration!\n");
		return false;
	}

	if (xsupgui_request_write_config(CONFIG_LOAD_USER, NULL) != REQUEST_SUCCESS)
	{
		innerError("Couldn't write the user configuration!\n");
		return false;
	}

	return true;
}

#define SYSTEM_VOLATILE_CONF_NAME   "System Level Volatile Profile Configuration"
#define USER_VOLATILE_CONF_NAME    "User Level Volatile Profile Configuration"

bool ProfileConfigTests::createVolatileSystemProfileConfig()
{
	struct config_profiles *system_profile = NULL;
	int result = 0;

	system_profile = (struct config_profiles *)malloc(sizeof(struct config_profiles));
	if (system_profile == NULL)
	{
		innerError("Unable to allocate memory needed to create a test profile.\n");
		return false;
	}

	system_profile->name = _strdup(SYSTEM_VOLATILE_CONF_NAME);
	system_profile->identity = _strdup("non-anonymous id");
	system_profile->flags = CONFIG_VOLATILE_PROFILE;
	system_profile->compliance = 0;
	system_profile->temp_password = NULL;
	system_profile->temp_username = NULL;

	// Create a simple method to test with.
	system_profile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (system_profile->method == NULL)
	{
		innerError("Unable to allocate memory to create an EAP method configuration.\n");
		return false;
	}

	system_profile->method->method_num = EAP_TYPE_MD5;
	system_profile->method->method_data = malloc(sizeof(struct config_pwd_only));
	if (system_profile->method->method_data == NULL)
	{
		innerError("Unable to allocate memory to store EAP type.\n");
		return false;
	}

	memset(system_profile->method->method_data, 0x00, sizeof(struct config_pwd_only));

	system_profile->next = NULL;

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, system_profile)) != REQUEST_SUCCESS)
	{
		innerError("Error creating new system level profile!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::createVolatileUserProfileConfig()
{
	struct config_profiles *user_profile = NULL;
	int result = 0;

	user_profile = (struct config_profiles *)malloc(sizeof(struct config_profiles));
	if (user_profile == NULL)
	{
		innerError("Unable to allocate memory needed to create a test profile.\n");
		return false;
	}

	user_profile->name = _strdup(USER_VOLATILE_CONF_NAME);
	user_profile->identity = _strdup("user non-anonymous id");
	user_profile->flags = CONFIG_VOLATILE_PROFILE;
	user_profile->compliance = 0;
	user_profile->temp_password = NULL;
	user_profile->temp_username = NULL;

	// Create a simple method to test with.
	user_profile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (user_profile->method == NULL)
	{
		innerError("Unable to allocate memory to create an EAP method configuration.\n");
		return false;
	}

	user_profile->method->method_num = EAP_TYPE_MD5;
	user_profile->method->method_data = malloc(sizeof(struct config_pwd_only));
	if (user_profile->method->method_data == NULL)
	{
		innerError("Unable to allocate memory to store EAP type.\n");
		return false;
	}

	memset(user_profile->method->method_data, 0x00, sizeof(struct config_pwd_only));

	user_profile->next = NULL;

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_USER, user_profile)) != REQUEST_SUCCESS)
	{
		innerError("Error creating new system level profile!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkVolatileSystemProfileConfig(bool expected)
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_VOLATILE_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		if (expected == true)
		{
			innerError("Error reading user configuration test profile!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}
		else
		{
			return true;
		}
	}

	if ((prof->name == NULL) || (strcmp(prof->name, SYSTEM_VOLATILE_CONF_NAME) != 0))
	{
		innerError("The profile name was invalid.\n");
		return false;
	}

	if (strcmp(prof->identity, "non-anonymous id") != 0)
	{
		innerError("Identity read back didn't match!\n");
		return false;
	}

	if (prof->flags != CONFIG_VOLATILE_PROFILE)
	{
		innerError("Flags weren't set to volatile when they should have been!\n");
		return false;
	}

	if (prof->compliance != 0xffffff00)
	{
		innerError("Compliance isn't -256 when it should have been! (Value = " + Util::itos(prof->compliance) + ")\n");
		return false;
	}

	if (prof->temp_password != NULL)
	{
		innerError("temp_password was non-NULL!  (Shouldn't be possible!)\n");
		return false;
	}

	if (prof->temp_username != NULL)
	{
		innerError("temp_username was non-NULL!  (Shouldn't be possible!)\n");
		return false;
	}

	if (prof->method->method_num != EAP_TYPE_MD5)
	{
		innerError("Method type wasn't stored properly!\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Couldn't free memory from the profile.\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkVolatileUserProfileConfig(bool expected)
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_USER, USER_VOLATILE_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		if (expected == true)
		{
			innerError("Error reading user configuration test profile!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}
		else
		{
			return true;
		}
	}

	if ((prof->name == NULL) || (strcmp(prof->name, USER_VOLATILE_CONF_NAME) != 0))
	{
		innerError("The profile name was invalid.\n");
		return false;
	}

	if (strcmp(prof->identity, "user non-anonymous id") != 0)
	{
		innerError("Identity read back didn't match!\n");
		return false;
	}

	if (prof->flags != CONFIG_VOLATILE_PROFILE)
	{
		innerError("Flags weren't set to volatile when they should have been!\n");
		return false;
	}

	if (prof->compliance != 0xffffff00)
	{
		innerError("Compliance isn't -256 when it should have been!\n");
		return false;
	}

	if (prof->temp_password != NULL)
	{
		innerError("temp_password was non-NULL!  (Shouldn't be possible!)\n");
		return false;
	}

	if (prof->temp_username != NULL)
	{
		innerError("temp_username was non-NULL!  (Shouldn't be possible!)\n");
		return false;
	}

	if (prof->method->method_num != EAP_TYPE_MD5)
	{
		innerError("Method type wasn't stored properly!\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Couldn't free memory from the profile.\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkRenameToVolatile()
{
	if (xsupgui_request_rename_profile(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, SYSTEM_VOLATILE_CONF_NAME) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed a volatile config to be renamed to the name of a static config!\n");
		return false;
	}

	if (xsupgui_request_rename_profile(CONFIG_LOAD_GLOBAL, SYSTEM_VOLATILE_CONF_NAME, SYSTEM_CONF_NAME) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed a static config to be renamed to the name of a volatile config!\n");
		return false;
	}

	if (xsupgui_request_rename_profile(CONFIG_LOAD_USER, USER_CONF_NAME, USER_VOLATILE_CONF_NAME) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed a volatile user config to be renamed to the name of a static config!\n");
		return false;
	}

	if (xsupgui_request_rename_profile(CONFIG_LOAD_USER, USER_VOLATILE_CONF_NAME, USER_CONF_NAME) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed a static user config to be renamed to the name of a volatile config!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkSystemSwitchToVolatile()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	prof->flags = CONFIG_VOLATILE_PROFILE;

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to change a static configuration to volatile!\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkUserSwitchToVolatile()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_USER, USER_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	prof->flags = CONFIG_VOLATILE_PROFILE;

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_USER, prof)) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to change a static configuration to volatile!\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkBadDelete()
{
	if (xsupgui_request_delete_profile_config(CONFIG_LOAD_GLOBAL, USER_CONF_NAME, 1) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to delete a user level config with the system level flag!?\n");
		return false;
	}

	if (xsupgui_request_delete_profile_config(CONFIG_LOAD_USER, SYSTEM_CONF_NAME, 1) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to delete a system level config with the user level flag!?\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkDeleteSystemProfileConfig()
{
	int result = 0;

	if ((result = xsupgui_request_delete_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, 1)) != REQUEST_SUCCESS)
	{
		innerError("Unable to delete the profile we created for testing.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkDeleteUserProfileConfig()
{
	int result = 0;

	if ((result = xsupgui_request_delete_profile_config(CONFIG_LOAD_USER, USER_CONF_NAME, 1)) != REQUEST_SUCCESS)
	{
		innerError("Unable to delete the profile we created for testing.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

#define SYSTEM_RENAME_CONF_NAME   "System Level Renamed Profile Configuration"
#define USER_RENAME_CONF_NAME    "User Level Renamed Profile Configuration"

bool ProfileConfigTests::checkRename()
{
	int result = 0;

	if ((result = xsupgui_request_rename_profile(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, SYSTEM_RENAME_CONF_NAME)) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the profile!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if ((result = xsupgui_request_rename_profile(CONFIG_LOAD_GLOBAL, SYSTEM_RENAME_CONF_NAME, SYSTEM_CONF_NAME)) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the profile back to its original name!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if ((result = xsupgui_request_rename_profile(CONFIG_LOAD_USER, USER_CONF_NAME, USER_RENAME_CONF_NAME)) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the user profile!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if ((result = xsupgui_request_rename_profile(CONFIG_LOAD_USER, USER_RENAME_CONF_NAME, USER_CONF_NAME)) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the user profile back to its original name!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkProfileEnum()
{
	profile_enum *profenum = NULL;
	int result = 0;

	if ((result = xsupgui_request_enum_profiles(CONFIG_LOAD_GLOBAL, &profenum)) != REQUEST_SUCCESS)
	{
		innerError("Unable to enumerate global profiles.\n");
		return false;
	}

	if (foundInEnum(profenum, SYSTEM_CONF_NAME) == false)
	{
		innerError("System profile not found in enumeration!\n");
		return false;
	}

	if (xsupgui_request_free_profile_enum(&profenum) != 0)
	{
		innerError("Unable to free profile enumeration.\n");
		return false;
	}

	if ((result = xsupgui_request_enum_profiles(CONFIG_LOAD_USER, &profenum)) != REQUEST_SUCCESS)
	{
		innerError("Unable to enumerate user profiles.\n");
		return false;
	}

	if (foundInEnum(profenum, USER_CONF_NAME) == false)
	{
		innerError("User profile not found in enumeration!\n");
		return false;
	}

	if (xsupgui_request_free_profile_enum(&profenum) != 0)
	{
		innerError("Unable to free profile enumeration.\n");
		return false;
	}

	if ((result = xsupgui_request_enum_profiles((CONFIG_LOAD_USER | CONFIG_LOAD_GLOBAL), &profenum)) != REQUEST_SUCCESS)
	{
		innerError("Unable to enumerate all profiles.\n");
		return false;
	}

	if ((foundInEnum(profenum, USER_CONF_NAME) == false) || (foundInEnum(profenum, SYSTEM_CONF_NAME) == false))
	{
		innerError("User profile not found in enumeration!\n");
		return false;
	}

	if (xsupgui_request_free_profile_enum(&profenum) != 0)
	{
		innerError("Unable to free profile enumeration.\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::foundInEnum(profile_enum *profenum, char *tofind)
{
	int i = 0;

	while (profenum[i].name != NULL)
	{
		if ((profenum[i].name != NULL) && (strcmp(profenum[i].name, tofind) == 0)) return true;
		i++;
	}

	return false;
}

struct config_eap_method *ProfileConfigTests::createEAPMD5Test()
{
	struct config_eap_method *eapdata = NULL;
	struct config_pwd_only *pwddata = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_MD5;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_pwd_only));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-MD5 configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	pwddata = (struct config_pwd_only *)eapdata->method_data;

	pwddata->password = _strdup("mytestpassword");

	return eapdata;
}

bool ProfileConfigTests::checkEAPMD5Test(struct config_eap_method *eapmd5)
{
	struct config_pwd_only *pwddata = NULL;

	if (eapmd5->method_num != EAP_TYPE_MD5)
	{
		innerError("EAP type wasn't set to MD5!\n");
		return false;
	}

	if (eapmd5->method_data == NULL)
	{
		innerError("No EAP-MD5 configuration data was found in memory!\n");
		return false;
	}

	pwddata = (config_pwd_only *)eapmd5->method_data;

	if (pwddata->password == NULL)
	{
		innerError("No EAP-MD5 password was found!\n");
		return false;
	}

	if (strcmp(pwddata->password, "mytestpassword") != 0)
	{
		innerError("EAP-MD5 password didn't match!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPMD5Test(struct config_eap_method **eapmd5)
{
	struct config_eap_method *eapdata = NULL;
	struct config_pwd_only *pwddata = NULL;
	bool retval = true;

	eapdata = (*eapmd5);

	if (eapdata == NULL) 
	{
		innerError("Invalid MD5 data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	pwddata = (struct config_pwd_only *)eapdata->method_data;

	if (pwddata->password == NULL)
	{
		innerError("No password to free!\n");
		retval = false;
	}
	else
	{
		free(pwddata->password);
	}

	free(eapdata->method_data);
	free(eapdata);
	(*eapmd5) = NULL;

	return retval;
}

bool ProfileConfigTests::checkEAPMD5Config()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPMD5Test();
	if (prof->method == NULL) return false;		// createEAPMD5Test() should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write EAP-MD5 config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPMD5Test(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPMD5Test(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

bool ProfileConfigTests::checkInvalidRename()
{
	if (xsupgui_request_rename_profile(CONFIG_LOAD_GLOBAL, "dsflkjsdlkfjsldfkj", "This is bad") == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a nonexistant configuration at the system level!\n");
		return false;
	}

	if (xsupgui_request_rename_profile(CONFIG_LOAD_USER, "dsflkjsdlkfjsldfkj", "This is bad") == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a nonexistant configuration at the user level!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkInvalidConfigDest()
{
	unsigned char i = 0;
	config_profiles *read_back_config = NULL;
	config_profiles *temp = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &read_back_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system profile that was written earlier. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	for (i = 0; i < 0xff; i++)
	{
		if ((i == CONFIG_LOAD_GLOBAL) || (i == CONFIG_LOAD_USER)) continue;

		if ((result = xsupgui_request_get_profile_config(i, SYSTEM_CONF_NAME, &temp)) != IPC_ERROR_INVALID_CONFIG)
		{
			innerError("Attempt to read an invalid config didn't fail properly! (Error : " + Util::itos(result) + "  Iteration : " + Util::itos(i) + ")\n");
			return false;
		}

		if (temp != NULL)
		{
			innerError("Failure to read an invalid config did not return a NULL value!\n");
			return false;
		}

		if ((result = xsupgui_request_set_profile_config(i, read_back_config)) != IPC_ERROR_INVALID_CONFIG)
		{
			innerError("Attempt to write an invalid config didn't fail properly!  (Error : " + Util::itos(result) + "  Iteration : " + Util::itos(i) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_profile_config(&read_back_config) != 0)
	{
		innerError("Unable to free connection configuration.\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::checkEAPMSCHAPv2Config()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPMSCHAPv2Test();
	if (prof->method == NULL) return false;		// createEAPMSCHAPv2Test() should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPMSCHAPv2Test(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPMSCHAPv2Test(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

struct config_eap_method *ProfileConfigTests::createEAPMSCHAPv2Test()
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_mschapv2 *mscv2data = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_MSCHAPV2;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_eap_mschapv2));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-MSCHAPv2 configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	mscv2data = (struct config_eap_mschapv2 *)eapdata->method_data;

	mscv2data->password = _strdup("mytestpassword");

	mscv2data->flags = (FLAGS_EAP_MSCHAPV2_VOLATILE | FLAGS_EAP_MSCHAPV2_IAS_QUIRK);
	mscv2data->nthash = _strdup("000102030405060708090a0b0c0d0e0f");

	return eapdata;
}

bool ProfileConfigTests::checkEAPMSCHAPv2Test(struct config_eap_method *eapmscv2)
{
	struct config_eap_mschapv2 *mscv2data = NULL;

	if (eapmscv2->method_num != EAP_TYPE_MSCHAPV2)
	{
		innerError("EAP type wasn't set to MSCHAPv2!\n");
		return false;
	}

	if (eapmscv2->method_data == NULL)
	{
		innerError("No EAP-MSCHAPv2 configuration data was found in memory!\n");
		return false;
	}

	mscv2data = (config_eap_mschapv2 *)eapmscv2->method_data;

	if (mscv2data->password == NULL)
	{
		innerError("No EAP-MSCHAPv2 password was found!\n");
		return false;
	}

	if (strcmp(mscv2data->password, "mytestpassword") != 0)
	{
		innerError("EAP-MSCHAPv2 password didn't match!\n");
		return false;
	}

	if (mscv2data->nthash == NULL)
	{
		innerError("No EAP-MSCHAPv2 NT hash was found!\n");
		return false;
	}

	if (strcmp(mscv2data->nthash, "000102030405060708090a0b0c0d0e0f") != 0)
	{
		innerError("EAP-MSCHAPv2 NT hash didn't match!\n");
		return false;
	}
 
	if (mscv2data->flags != (FLAGS_EAP_MSCHAPV2_VOLATILE | FLAGS_EAP_MSCHAPV2_IAS_QUIRK))
	{
		innerError("Flags were invalid!  (Expected : " + Util::itos((FLAGS_EAP_MSCHAPV2_VOLATILE | FLAGS_EAP_MSCHAPV2_IAS_QUIRK)) + "  Got : " + Util::itos(mscv2data->flags) + ")\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPMSCHAPv2Test(struct config_eap_method **eapmscv2)
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_mschapv2 *mscv2data = NULL;
	bool retval = true;

	eapdata = (*eapmscv2);

	if (eapdata == NULL) 
	{
		innerError("Invalid MSCHAPv2 data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	mscv2data = (struct config_eap_mschapv2 *)eapdata->method_data;

	if (mscv2data->password == NULL)
	{
		innerError("No password to free!\n");
		retval = false;
	}
	else
	{
		free(mscv2data->password);
	}

	if (mscv2data->nthash == NULL)
	{
		innerError("No NT hash to free!\n");
		retval = false;
	}
	else
	{
		free(mscv2data->nthash);
	}

	free(eapdata->method_data);
	free(eapdata);
	(*eapmscv2) = NULL;

	return true;
}

bool ProfileConfigTests::checkEAPAKAConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPAKATest();
	if (prof->method == NULL) return false;		// createEAPAKATest() should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPAKATest(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPAKATest(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

struct config_eap_method *ProfileConfigTests::createEAPAKATest()
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_aka *akadata = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_AKA;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_eap_aka));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-AKA configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	akadata = (struct config_eap_aka *)eapdata->method_data;

	akadata->password = _strdup("12345678");
	akadata->auto_realm = 1;
	akadata->reader = _strdup("Invalid Reader Name");

	return eapdata;
}

bool ProfileConfigTests::checkEAPAKATest(struct config_eap_method *eapaka)
{
	struct config_eap_aka *akadata = NULL;

	if (eapaka->method_num != EAP_TYPE_AKA)
	{
		innerError("EAP type wasn't set to AKA!\n");
		return false;
	}

	if (eapaka->method_data == NULL)
	{
		innerError("No EAP-AKA configuration data was found in memory!\n");
		return false;
	}

	akadata = (config_eap_aka *)eapaka->method_data;

	if (akadata->password == NULL)
	{
		innerError("No EAP-AKA password was found!\n");
		return false;
	}

	if (strcmp(akadata->password, "12345678") != 0)
	{
		innerError("EAP-AKA password didn't match!\n");
		return false;
	}

	if (akadata->reader == NULL)
	{
		innerError("No EAP-AKA reader was found!\n");
		return false;
	}

	if (strcmp(akadata->reader, "Invalid Reader Name") != 0)
	{
		innerError("EAP-AKA reader didn't match!\n");
		return false;
	}

	if (akadata->auto_realm != 1)
	{
		innerError("EAP-AKA auto realm wasn't set to 1.\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPAKATest(struct config_eap_method **eapaka)
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_aka *akadata = NULL;
	bool retval = true;

	eapdata = (*eapaka);

	if (eapdata == NULL) 
	{
		innerError("Invalid AKA data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	akadata = (struct config_eap_aka *)eapdata->method_data;

	if (akadata->password == NULL)
	{
		innerError("No password to free!\n");
		retval = false;
	}
	else
	{
		free(akadata->password);
	}

	free(eapdata->method_data);
	free(eapdata);
	(*eapaka) = NULL;

	return true;
}

bool ProfileConfigTests::checkEAPSIMConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPSIMTest();
	if (prof->method == NULL) return false;		// should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPSIMTest(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPSIMTest(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

struct config_eap_method *ProfileConfigTests::createEAPSIMTest()
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_sim *simdata = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_SIM;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_eap_sim));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-SIM configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	simdata = (struct config_eap_sim *)eapdata->method_data;

	simdata->password = _strdup("12345678");
	simdata->auto_realm = 1;
	simdata->reader = _strdup("Invalid Reader Name");

	return eapdata;
}

bool ProfileConfigTests::checkEAPSIMTest(struct config_eap_method *eapsim)
{
	struct config_eap_sim *simdata = NULL;

	if (eapsim->method_num != EAP_TYPE_SIM)
	{
		innerError("EAP type wasn't set to SIM!\n");
		return false;
	}

	if (eapsim->method_data == NULL)
	{
		innerError("No EAP-SIM configuration data was found in memory!\n");
		return false;
	}

	simdata = (config_eap_sim *)eapsim->method_data;

	if (simdata->password == NULL)
	{
		innerError("No EAP-SIM password was found!\n");
		return false;
	}

	if (strcmp(simdata->password, "12345678") != 0)
	{
		innerError("EAP-SIM password didn't match!\n");
		return false;
	}

	if (simdata->reader == NULL)
	{
		innerError("No EAP-SIM reader was found!\n");
		return false;
	}

	if (strcmp(simdata->reader, "Invalid Reader Name") != 0)
	{
		innerError("EAP-SIM reader didn't match!\n");
		return false;
	}

	if (simdata->auto_realm != 1)
	{
		innerError("EAP-SIM auto realm wasn't set to 1.\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPSIMTest(struct config_eap_method **eapsim)
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_sim *simdata = NULL;
	bool retval = true;

	eapdata = (*eapsim);

	if (eapdata == NULL) 
	{
		innerError("Invalid SIM data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	simdata = (struct config_eap_sim *)eapdata->method_data;

	if (simdata->password == NULL)
	{
		innerError("No password to free!\n");
		retval = false;
	}
	else
	{
		free(simdata->password);
	}

	free(eapdata->method_data);
	free(eapdata);
	(*eapsim) = NULL;

	return true;
}

bool ProfileConfigTests::checkEAPGTCConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPGTCTest();
	if (prof->method == NULL) return false;		// should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPGTCTest(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPGTCTest(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

struct config_eap_method *ProfileConfigTests::createEAPGTCTest()
{
	struct config_eap_method *eapdata = NULL;
	struct config_pwd_only *gtcdata = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_GTC;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_pwd_only));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-GTC configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	gtcdata = (struct config_pwd_only *)eapdata->method_data;

	gtcdata->password = _strdup("mytestpassword");

	return eapdata;
}

bool ProfileConfigTests::checkEAPGTCTest(struct config_eap_method *eapgtc)
{
	struct config_pwd_only *gtcdata = NULL;

	if (eapgtc->method_num != EAP_TYPE_GTC)
	{
		innerError("EAP type wasn't set to GTC!\n");
		return false;
	}

	if (eapgtc->method_data == NULL)
	{
		innerError("No EAP-GTC configuration data was found in memory!\n");
		return false;
	}

	gtcdata = (config_pwd_only *)eapgtc->method_data;

	if (gtcdata->password == NULL)
	{
		innerError("No EAP-GTC password was found!\n");
		return false;
	}

	if (strcmp(gtcdata->password, "mytestpassword") != 0)
	{
		innerError("EAP-GTC password didn't match!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPGTCTest(struct config_eap_method **eapgtc)
{
	struct config_eap_method *eapdata = NULL;
	struct config_pwd_only *gtcdata = NULL;
	bool retval = true;

	eapdata = (*eapgtc);

	if (eapdata == NULL) 
	{
		innerError("Invalid GTC data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	gtcdata = (struct config_pwd_only *)eapdata->method_data;

	if (gtcdata->password == NULL)
	{
		innerError("No password to free!\n");
		retval = false;
	}
	else
	{
		free(gtcdata->password);
	}

	free(eapdata->method_data);
	free(eapdata);
	(*eapgtc) = NULL;

	return true;
}

bool ProfileConfigTests::checkEAPOTPConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPOTPTest();
	if (prof->method == NULL) return false;		// should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPOTPTest(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPOTPTest(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

struct config_eap_method *ProfileConfigTests::createEAPOTPTest()
{
	struct config_eap_method *eapdata = NULL;
	struct config_pwd_only *otpdata = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_OTP;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_pwd_only));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-OTP configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	otpdata = (struct config_pwd_only *)eapdata->method_data;

	otpdata->password = _strdup("mytestpassword");

	return eapdata;
}

bool ProfileConfigTests::checkEAPOTPTest(struct config_eap_method *eapotp)
{
	struct config_pwd_only *otpdata = NULL;

	if (eapotp->method_num != EAP_TYPE_OTP)
	{
		innerError("EAP type wasn't set to OTP!\n");
		return false;
	}

	if (eapotp->method_data == NULL)
	{
		innerError("No EAP-OTP configuration data was found in memory!\n");
		return false;
	}

	otpdata = (config_pwd_only *)eapotp->method_data;

	if (otpdata->password != NULL)
	{
		innerError("EAP-OTP password was found when it shouldn't have been!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPOTPTest(struct config_eap_method **eapotp)
{
	struct config_eap_method *eapdata = NULL;
	struct config_pwd_only *otpdata = NULL;
	bool retval = true;

	eapdata = (*eapotp);

	if (eapdata == NULL) 
	{
		innerError("Invalid OTP data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	otpdata = (struct config_pwd_only *)eapdata->method_data;

	if (otpdata->password != NULL)
	{
		free(otpdata->password);
		retval = false;
	}

	free(eapdata->method_data);
	free(eapdata);
	(*eapotp) = NULL;

	return true;
}

bool ProfileConfigTests::checkEAPTLSConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPTLSTest();
	if (prof->method == NULL) return false;		// should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPTLSTest(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPTLSTest(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

struct config_eap_method *ProfileConfigTests::createEAPTLSTest()
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_tls *tlsdata = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_TLS;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_eap_tls));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-TLS configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	tlsdata = (struct config_eap_tls *)eapdata->method_data;

	tlsdata->chunk_size = 1069;
	tlsdata->store_type = _strdup("WINDOWS");
	tlsdata->crl_dir = _strdup("my_test_crl\\dir");
	tlsdata->random_file = _strdup("mytest_random.fil");
	tlsdata->session_resume = RES_YES;
	tlsdata->trusted_server = _strdup("My Trusted Server Test");
	tlsdata->user_cert = _strdup("my_user_cert_path");
	tlsdata->user_key = _strdup("my_user_key_path");
	tlsdata->user_key_pass = _strdup("my user key password");
	
	// The tlsdata->sc struct isn't tested right now.

	return eapdata;
}

bool ProfileConfigTests::checkEAPTLSTest(struct config_eap_method *eaptls)
{
	struct config_eap_tls *tlsdata = NULL;

	if (eaptls->method_num != EAP_TYPE_TLS)
	{
		innerError("EAP type wasn't set to TLS!\n");
		return false;
	}

	if (eaptls->method_data == NULL)
	{
		innerError("No EAP-TLS configuration data was found in memory!\n");
		return false;
	}

	tlsdata = (config_eap_tls *)eaptls->method_data;

	if (tlsdata->chunk_size != 1069)
	{
		innerError("TLS chunk size didn't match!\n");
		return false;
	}

	if (tlsdata->store_type == NULL)
	{
		innerError("TLS store type isn't defined!\n");
		return false;
	}

	if (strcmp(tlsdata->store_type, "WINDOWS") != 0)
	{
		innerError("Invalid store type returned!\n");
		return false;
	}

	if (tlsdata->crl_dir == NULL)
	{
		innerError("CRL dir isn't defined!\n");
		return false;
	}

	if (strcmp(tlsdata->crl_dir, "my_test_crl\\dir") != 0)
	{
		innerError("CRL dir path didn't match!\n");
		return false;
	}

	if (tlsdata->random_file == NULL)
	{
		innerError("Random file isn't defined!\n");
		return false;
	}

	if (strcmp(tlsdata->random_file, "mytest_random.fil") != 0)
	{
		innerError("Random file didn't match!\n");
		return false;
	}

	if (tlsdata->session_resume != RES_YES)
	{
		innerError("Session resume didn't match!\n");
		return false;
	}

	if (tlsdata->trusted_server == NULL)
	{
		innerError("Trusted server wasn't set!\n");
		return false;
	}

	if (strcmp(tlsdata->trusted_server, "My Trusted Server Test") != 0)
	{
		innerError("Trusted server name didn't match!\n");
		return false;
	}

	if (tlsdata->user_cert == NULL)
	{
		innerError("User certificate wasn't set!\n");
		return false;
	}

	if (strcmp(tlsdata->user_cert, "my_user_cert_path") != 0)
	{
		innerError("User certificate information was invalid.\n");
		return false;
	}

	if (tlsdata->user_key == NULL)
	{
		innerError("User key wasn't set!\n");
		return false;
	}

	if (strcmp(tlsdata->user_key, "my_user_key_path") != 0)
	{
		innerError("User key path was invalid!\n");
		return false;
	}

	if (tlsdata->user_key_pass == NULL)
	{
		innerError("User key pass wasn't set!\n");
		return false;
	}

	if (strcmp(tlsdata->user_key_pass, "my user key password") != 0)
	{
		innerError("User key pass didn't match!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPTLSTest(struct config_eap_method **eaptls)
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_tls *tlsdata = NULL;
	bool retval = true;

	eapdata = (*eaptls);

	if (eapdata == NULL) 
	{
		innerError("Invalid TLS data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	tlsdata = (struct config_eap_tls *)eapdata->method_data;

	if (tlsdata->store_type == NULL)
	{
		innerError("No Store_type to free!\n");
		retval = false;
	}
	else
	{
		free(tlsdata->store_type);
	}

	if (tlsdata->crl_dir == NULL)
	{
		innerError("No crl_dir to free!\n");
		retval = false;
	}
	else
	{
		free(tlsdata->crl_dir);
	}

	if (tlsdata->random_file == NULL)
	{
		innerError("No random file to free!\n");
		retval = false;
	}
	else
	{
		free(tlsdata->random_file);
	}

	if (tlsdata->trusted_server == NULL)
	{
		innerError("No trusted server to free!\n");
		retval = false;
	}
	else
	{
		free(tlsdata->trusted_server);
	}

	if (tlsdata->user_cert == NULL)
	{
		innerError("No user cert to free!\n");
		retval = false;
	}
	else
	{
		free(tlsdata->user_cert);
	}

	if (tlsdata->user_key == NULL)
	{
		innerError("No user key to free!\n");
		retval = false;
	}
	else
	{
		free(tlsdata->user_key);
	}

	if (tlsdata->user_key_pass == NULL)
	{
		innerError("No user key pass!\n");
		retval = false;
	}
	else
	{
		free(tlsdata->user_key_pass);
	}

	free(eapdata->method_data);
	free(eapdata);
	(*eaptls) = NULL;

	return true;
}

bool ProfileConfigTests::checkEAPFASTConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPFASTTest();
	if (prof->method == NULL) return false;		// should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPFASTTest(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPFASTTest(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

struct config_eap_method *ProfileConfigTests::createEAPFASTTest()
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_fast *fastdata = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_FAST;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_eap_fast));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-FAST configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	fastdata = (struct config_eap_fast *)eapdata->method_data;

	fastdata->chunk_size = 1069;
	fastdata->innerid = _strdup("my inner id test");
	fastdata->pac_location = _strdup("my_pac_path\\is\\here");
	fastdata->phase2 = NULL;
	fastdata->provision_flags = 0xff;
	fastdata->trusted_server = _strdup("my trusted server string");
	fastdata->validate_cert = FALSE;

	return eapdata;
}

bool ProfileConfigTests::checkEAPFASTTest(struct config_eap_method *eapfast)
{
	struct config_eap_fast *fastdata = NULL;

	if (eapfast->method_num != EAP_TYPE_FAST)
	{
		innerError("EAP type wasn't set to FAST!\n");
		return false;
	}

	if (eapfast->method_data == NULL)
	{
		innerError("No EAP-FAST configuration data was found in memory!\n");
		return false;
	}

	fastdata = (config_eap_fast *)eapfast->method_data;

	if (fastdata->chunk_size != 1069)
	{
		innerError("TLS chunk size didn't match!\n");
		return false;
	}

	if (fastdata->innerid == NULL)
	{
		innerError("Inner id isn't defined!\n");
		return false;
	}

	if (strcmp(fastdata->innerid, "my inner id test") != 0)
	{
		innerError("Invalid inner id returned!\n");
		return false;
	}

	if (fastdata->pac_location == NULL)
	{
		innerError("PAC location isn't defined!\n");
		return false;
	}

	if (strcmp(fastdata->pac_location, "my_pac_path\\is\\here") != 0)
	{
		innerError("PAC location path didn't match!\n");
		return false;
	}

	if (fastdata->trusted_server == NULL)
	{
		innerError("Trusted server wasn't set!\n");
		return false;
	}

	if (strcmp(fastdata->trusted_server, "my trusted server string") != 0)
	{
		innerError("Trusted server name didn't match!\n");
		return false;
	}

	if (fastdata->validate_cert != FALSE)
	{
		innerError("Validate cert setting didn't match!\n");
		return false;
	}

	if (fastdata->provision_flags != 7)
	{
		innerError("Invalid provision flags were returned!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPFASTTest(struct config_eap_method **eapfast)
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_fast *fastdata = NULL;
	bool retval = true;

	eapdata = (*eapfast);

	if (eapdata == NULL) 
	{
		innerError("Invalid FAST data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	fastdata = (struct config_eap_fast *)eapdata->method_data;

	if (fastdata->innerid == NULL)
	{
		innerError("No inner id to free!\n");
		retval = false;
	}
	else
	{
		free(fastdata->innerid);
	}

	if (fastdata->pac_location == NULL)
	{
		innerError("No pac_location to free!\n");
		retval = false;
	}
	else
	{
		free(fastdata->pac_location);
	}

	if (fastdata->trusted_server == NULL)
	{
		innerError("No trusted server to free!\n");
		retval = false;
	}
	else
	{
		free(fastdata->trusted_server);
	}

	free(eapdata->method_data);
	free(eapdata);
	(*eapfast) = NULL;

	return true;
}

bool ProfileConfigTests::checkEAPPEAPConfig()
{
	struct config_profiles *prof = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system configuration test profile. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	// Clear the data that is already there.
	delete_config_eap_method(&prof->method);

	prof->method = createEAPPEAPTest();
	if (prof->method == NULL) return false;		// should have already screamed.

	if ((result = xsupgui_request_set_profile_config(CONFIG_LOAD_GLOBAL, prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write config to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_profile_config(&prof) != 0)
	{
		innerError("Unable to free profile configuration memory!\n");
		return false;
	}

	if ((result = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &prof)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the profile.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (checkEAPPEAPTest(prof->method) == false) return false;	// The check should have screamed.

	if (freeEAPPEAPTest(&prof->method) == false) return false;  // The check should have screamed.
	return true;
}

struct config_eap_method *ProfileConfigTests::createEAPPEAPTest()
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_peap *peapdata = NULL;

	eapdata = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
	if (eapdata == NULL)
	{
		innerError("Couldn't allocate memory to store EAP configuration structure.\n");
		return NULL;
	}

	eapdata->method_num = EAP_TYPE_PEAP;
	eapdata->next = NULL;

	eapdata->method_data = malloc(sizeof(struct config_eap_peap));
	if (eapdata->method_data == NULL)
	{
		innerError("Couldn't allocate memory to store EAP-PEAP configuration structure.\n");
		free(eapdata);
		return NULL;
	}

	peapdata = (struct config_eap_peap *)eapdata->method_data;

	peapdata->chunk_size = 1069;
	peapdata->crl_dir = _strdup("my_test_crl\\dir");
	peapdata->random_file = _strdup("mytest_random.fil");
	peapdata->session_resume = RES_YES;
	peapdata->trusted_server = _strdup("My Trusted Server Test");
	peapdata->user_cert = _strdup("my_user_cert_path");
	peapdata->user_key = _strdup("my_user_key_path");
	peapdata->user_key_pass = _strdup("my user key password");
	peapdata->proper_peapv1 = TRUE;
	peapdata->force_peap_version = 2;
	peapdata->identity = _strdup("my inner id");
	peapdata->validate_cert = FALSE;

	return eapdata;
}

bool ProfileConfigTests::checkEAPPEAPTest(struct config_eap_method *eappeap)
{
	struct config_eap_peap *peapdata = NULL;

	if (eappeap->method_num != EAP_TYPE_PEAP)
	{
		innerError("EAP type wasn't set to PEAP!\n");
		return false;
	}

	if (eappeap->method_data == NULL)
	{
		innerError("No EAP-PEAP configuration data was found in memory!\n");
		return false;
	}

	peapdata = (config_eap_peap *)eappeap->method_data;

	if (peapdata->chunk_size != 1069)
	{
		innerError("TLS chunk size didn't match!\n");
		return false;
	}

	if (peapdata->crl_dir == NULL)
	{
		innerError("CRL dir isn't defined!\n");
		return false;
	}

	if (strcmp(peapdata->crl_dir, "my_test_crl\\dir") != 0)
	{
		innerError("CRL dir path didn't match!\n");
		return false;
	}

	if (peapdata->random_file == NULL)
	{
		innerError("Random file isn't defined!\n");
		return false;
	}

	if (strcmp(peapdata->random_file, "mytest_random.fil") != 0)
	{
		innerError("Random file didn't match!\n");
		return false;
	}

	if (peapdata->session_resume != RES_YES)
	{
		innerError("Session resume didn't match!\n");
		return false;
	}

	if (peapdata->trusted_server == NULL)
	{
		innerError("Trusted server wasn't set!\n");
		return false;
	}

	if (strcmp(peapdata->trusted_server, "My Trusted Server Test") != 0)
	{
		innerError("Trusted server name didn't match!\n");
		return false;
	}

	if (peapdata->user_cert == NULL)
	{
		innerError("User certificate wasn't set!\n");
		return false;
	}

	if (strcmp(peapdata->user_cert, "my_user_cert_path") != 0)
	{
		innerError("User certificate information was invalid.\n");
		return false;
	}

	if (peapdata->user_key == NULL)
	{
		innerError("User key wasn't set!\n");
		return false;
	}

	if (strcmp(peapdata->user_key, "my_user_key_path") != 0)
	{
		innerError("User key path was invalid!\n");
		return false;
	}

	if (peapdata->user_key_pass == NULL)
	{
		innerError("User key pass wasn't set!\n");
		return false;
	}

	if (strcmp(peapdata->user_key_pass, "my user key password") != 0)
	{
		innerError("User key pass didn't match!\n");
		return false;
	}

	if (peapdata->proper_peapv1 != TRUE)
	{
		innerError("Proper PEAPv1 keying value was incorrect!\n");
		return false;
	}

	if (peapdata->force_peap_version != 2)
	{
		innerError("Force PEAP version wasn't 2!\n");
		return false;
	}

	if (peapdata->identity == NULL)
	{
		innerError("No inner identity set!\n");
		return false;
	}
	
	if (strcmp(peapdata->identity, "my inner id") != 0)
	{
		innerError("Inner ID wasn't valid!\n");
		return false;
	}

	if (peapdata->validate_cert != FALSE)
	{
		innerError("Validate cert wasn't FALSE!\n");
		return false;
	}

	return true;
}

bool ProfileConfigTests::freeEAPPEAPTest(struct config_eap_method **eappeap)
{
	struct config_eap_method *eapdata = NULL;
	struct config_eap_peap *peapdata = NULL;
	bool retval = true;

	eapdata = (*eappeap);

	if (eapdata == NULL) 
	{
		innerError("Invalid PEAP data passed in to free!\n");
		return false;
	}

	if (eapdata->method_data == NULL)
	{
		innerError("Invalid method_Data passed in to free!\n");
		return false;
	}

	peapdata = (struct config_eap_peap *)eapdata->method_data;

	if (peapdata->crl_dir == NULL)
	{
		innerError("No crl_dir to free!\n");
		retval = false;
	}
	else
	{
		free(peapdata->crl_dir);
	}

	if (peapdata->random_file == NULL)
	{
		innerError("No random file to free!\n");
		retval = false;
	}
	else
	{
		free(peapdata->random_file);
	}

	if (peapdata->trusted_server == NULL)
	{
		innerError("No trusted server to free!\n");
		retval = false;
	}
	else
	{
		free(peapdata->trusted_server);
	}

	if (peapdata->user_cert == NULL)
	{
		innerError("No user cert to free!\n");
		retval = false;
	}
	else
	{
		free(peapdata->user_cert);
	}

	if (peapdata->user_key == NULL)
	{
		innerError("No user key to free!\n");
		retval = false;
	}
	else
	{
		free(peapdata->user_key);
	}

	if (peapdata->user_key_pass == NULL)
	{
		innerError("No user key pass!\n");
		retval = false;
	}
	else
	{
		free(peapdata->user_key_pass);
	}

	if (peapdata->identity == NULL)
	{
		innerError("No identify to free!\n");
		retval = false;
	}
	else
	{
		free(peapdata->identity);
	}
	
	free(eapdata->method_data);
	free(eapdata);
	(*eappeap) = NULL;

	return true;
}

