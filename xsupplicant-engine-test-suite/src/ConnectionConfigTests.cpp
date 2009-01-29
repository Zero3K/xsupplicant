
#include <iostream>
#include <sstream>
#include "ConnectionConfigTests.h"
#include "Util.h"

extern "C" {
#include "xsupgui_request.h"
}

ConnectionConfigTests::ConnectionConfigTests()
{
	all_tests_success = true;
	system_config = NULL;
	user_config = NULL;
	volatile_system_config = NULL;
	volatile_user_config = NULL;
}

ConnectionConfigTests::~ConnectionConfigTests()
{
	if (system_config != NULL)
		xsupgui_request_free_connection_config(&system_config);
	
	if (user_config != NULL)
		xsupgui_request_free_connection_config(&user_config);

	if (volatile_system_config != NULL)
		xsupgui_request_free_connection_config(&volatile_system_config);

	if (volatile_user_config != NULL)
		xsupgui_request_free_connection_config(&volatile_user_config);
}

bool ConnectionConfigTests::writeConfigs()
{
	if (xsupgui_request_write_config(CONFIG_LOAD_GLOBAL, NULL) != REQUEST_SUCCESS)
	{
		innerError("Couldn't write the global configuration!\n");
		all_tests_success = false;
		return false;
	}

	if (xsupgui_request_write_config(CONFIG_LOAD_USER, NULL) != REQUEST_SUCCESS)
	{
		innerError("Couldn't write the user configuration!\n");
		all_tests_success = false;
		return false;
	}

	return true;
}

bool ConnectionConfigTests::executeTest()
{
	// Build a known configuration in memory, and apply it to the engine.
	runInnerTest("1 createSystemConfig()", createSystemConfig());

	// Verify that we can read it back, and do the right things with it.
	runInnerTest("1 checkConfigState()", checkConfigState());

	// Build a known user configuration in memory, and apply it to the engine.
	runInnerTest("1 createUserConfig()", createUserConfig());

	runInnerTest("1 checkUserConfigState()", checkUserConfigState());

	runInnerTest("1 checkInvalidConfigDest()", checkInvalidConfigDest());

	runInnerTest("2 createSystemConfig()", createSystemConfig());

	runInnerTest("2 createUserConfig()", createUserConfig());

	runInnerTest("1 createVolatileSystemConfig()", createVolatileSystemConfig());

	runInnerTest("1 createVolatileUserConfig()", createVolatileUserConfig());

	runInnerTest("1 checkVolatileSystemConfig()", checkVolatileSystemConfig(true));

	runInnerTest("1 checkVolatileUserConfig()", checkVolatileUserConfig(true));

	// Make sure we can write it to the disk.
	if (runInnerTest("1 writeConfigs()", writeConfigs()) == false) return false;

	// Cleanly disconnect before we restart the engine.
	if (runInnerTest("1 IPCConnectTest::teardownTest()", IPCConnectTest::teardownTest()) == false) return false;

	// Restart the engine.
	Util::restartEngine(30);		// Wait 30 seconds.

	// Establish a new IPC connection to the engine.
	if (runInnerTest("1 IPCConnectTest::setupTest()", IPCConnectTest::setupTest()) == false) return false;

	// Verify the state that we were in when the engine went away stuck around.
	if (runInnerTest("2 checkConfigState()", checkConfigState()) == false) return false;

	if (runInnerTest("2 checkUserConfigState()", checkUserConfigState()) == false) return false;

	runInnerTest("2 checkVolatileSystemConfig()", checkVolatileSystemConfig(false));

	runInnerTest("2 checkVolatileUserConfig()", checkVolatileUserConfig(false));

	runInnerTest("1 checkEnumConnections()", checkEnumConnections());

	runInnerTest("1 checkFlagSettings()", checkFlagSettings());

	runInnerTest("1 checkPriorityRange()", checkPriorityRange());

	runInnerTest("1 checkForceEAPoLVerRange()", checkForceEAPoLVerRange());

	runInnerTest("1 checkAssociationTypeRange()", checkAssociationTypeRange());

	runInnerTest("1 checkAuthenticationTypeRange()", checkAuthenticationTypeRange());

	runInnerTest("1 checkGroupKeyRange()", checkGroupKeyRange());

	runInnerTest("1 checkPairwiseKeyRange()", checkPairwiseKeyRange());

	runInnerTest("1 checkTxKeyRange()", checkTxKeyRange());

	runInnerTest("1 checkWEPKeyRange()", checkWEPKeyRange());

	runInnerTest("1 checkPSKValues()", checkPSKValues());

	runInnerTest("1 checkPSKHexValues()", checkPSKHexValues());

	runInnerTest("1 checkIPTypeValues()", checkIPTypeValues());

	runInnerTest("1 checkReauthRenewValues()", checkReauthRenewValues());

//	runInnerTest("1 checkVolatileOnStored()", checkVolatileOnStored());				// Is this test of any value?

	runInnerTest("1 checkRenameSystemConnection()", checkRenameSystemConnection());

	runInnerTest("1 checkRenameUserConnection()", checkRenameUserConnection());

	runInnerTest("1 checkInvalidDeleteConnections()", checkInvalidDeleteConnections());

	runInnerTest("1 checkDeleteSystemConnection()", checkDeleteSystemConnection());

	runInnerTest("1 checkDeleteUserConnection()", checkDeleteUserConnection());

	runInnerTest("1 checkInvalidConnectionName()", checkInvalidConnectionName());

	runInnerTest("1 checkRenameNotExist()", checkRenameNotExist());

	if (runInnerTest("2 writeConfigs()", writeConfigs()) == false) return false;

	return true;
}

config_connection *ConnectionConfigTests::createValidNonDefaultConfig(char *name)
{
	config_connection *config = NULL;

	config = (config_connection *)malloc(sizeof(config_connection));
	if (config == NULL)
	{
		innerError("Couldn't allocate memory to create a valid connection configuration!\n");
		return NULL;
	}

	memset(config, 0x00, sizeof(config_connection));

	config->name = _strdup(name);
	config->association.association_type = ASSOC_WPA2;
	config->association.auth_type = AUTH_EAP;
	config->association.group_keys = CRYPT_TKIP;
	config->association.keys[1] = _strdup("1111111111");
	config->association.keys[2] = _strdup("22222222222222222222222222");
	config->association.keys[3] = _strdup("3333333333");
	config->association.keys[4] = _strdup("4444444444");
	config->association.pairwise_keys = CRYPT_FLAGS_TKIP;
	config->association.psk = _strdup("thisisatestpskkey");
	config->association.psk_hex = _strdup("1234567890123456789012345678901234567890123456789012345678901234");
	config->association.txkey = 3;
	memcpy(config->dest_mac, "\xab\xcd\xef\xfe\xdc\xba", 6);
	config->flags = (CONFIG_NET_DEST_MAC | CONFIG_NET_IS_HIDDEN);   // Don't set 0xff here or the connection gets flagged as volatile! ;)
	config->force_eapol_ver = 1;
	config->ip.dns1 = _strdup("1.1.1.1");
	config->ip.dns2 = _strdup("2.2.2.2");
	config->ip.dns3 = _strdup("3.3.3.3");
	config->ip.gateway = _strdup("11.11.11.11");
	config->ip.ipaddr = _strdup("22.22.22.22");
	config->ip.netmask = _strdup("255.255.255.0");
	config->ip.renew_on_reauth = 1;
	config->ip.search_domain = _strdup("Test search domain");
	config->ip.type = CONFIG_IP_USE_NONE;
	config->next = NULL;
	config->priority = 69;
	config->profile = "Undefined profile";
	config->ssid = "Undefined SSID";

	return config;
}

bool ConnectionConfigTests::configsMatch(config_connection *original, config_connection *testval)
{
	int i = 0;
	bool success = true;

	if (strcmp(original->name, testval->name) != 0)
	{
		string temp;

		temp = "Connection Config match failed because names didn't match!  (Got " + string(original->name) + " expected " + string(testval->name) + ")\n";
		innerError(temp);
		success = false;
	}

	if (original->association.association_type != testval->association.association_type)
	{
		innerError("Connection Config match failed because association types didn't match!\n");
		success = false;
	}

	if (original->association.auth_type != testval->association.auth_type)
	{
		innerError("Connection Config match failed because authentication types didn't match!\n");
		success = false;
	}

	if (original->association.group_keys != testval->association.group_keys)
	{
		innerError("Connection Config match failed because group key types didn't match!\n");
		success = false;
	}

	if (original->association.keys[0] != NULL)
	{
		innerError("Connection Config match failed because original config didn't have keys[0] set to NULL!\n");
		success = false;
	}

	if (testval->association.keys[0] != NULL)
	{
		innerError("Connection Config match failed because testval config didn't have keys[0] set to NULL!\n");
		success = false;
	}

	if (strcmp(original->association.keys[1], testval->association.keys[1]) != 0)
	{
		innerError("Connection Config match failed because WEP key 1 didn't match!\n");
		success = false;
	}

	if (strcmp(original->association.keys[2], testval->association.keys[2]) != 0)
	{
		innerError("Connection Config match failed because WEP key 2 didn't match!\n");
		success = false;
	}

	if (strcmp(original->association.keys[3], testval->association.keys[3]) != 0)
	{
		innerError("Connection Config match failed because WEP key 3 didn't match!\n");
		success = false;
	}

	if (strcmp(original->association.keys[4], testval->association.keys[4]) != 0)
	{
		innerError("Connection Config match failed because WEP key 4 didn't match!\n");
		success = false;
	}

	if (original->association.pairwise_keys != testval->association.pairwise_keys)
	{
		innerError("Connection Config match failed because pairwise keys didn't match!\n");
		success = false;
	}

	if ((original->association.psk != NULL) && (testval->association.psk == NULL))
	{
		innerError("Connection Config match failed because read back PSK was NULL when it shouldn't have been!\n");
		success = false;
	}
	else if (strcmp(original->association.psk, testval->association.psk) != 0)
	{
		innerError("Connection Config match failed because WPA(2)-PSKs didn't match!\n");
		success = false;
	}

	if (strcmp(original->association.psk_hex, testval->association.psk_hex) != 0)
	{
		innerError("Connection Config match failed because WPA(2)-PSK hex keys didn't match!\n");
		success = false;
	}

	if (original->association.txkey != testval->association.txkey)
	{
		innerError("Connection Config match failed because TX keys didn't match!\n");
		success = false;
	}

	if (memcmp(original->dest_mac, testval->dest_mac, 6) != 0)
	{
		innerError("Connection Config match failed because destination MACs didn't match!\n");
		success = false;
	}

	if (original->flags != testval->flags)
	{
		string temp;
	
		temp = "Connection Config match failed because flags don't match! (Expected " + Util::itos(original->flags) + " got " + Util::itos(testval->flags) + ")\n";
		innerError(temp);
		success = false;
	}

	if (original->force_eapol_ver != testval->force_eapol_ver)
	{
		innerError("Connection Config match failed because EAPoL version flags don't match!\n");
		success = false;
	}

	if (strcmp(original->ip.dns1, testval->ip.dns1) != 0)
	{
		innerError("Connection Config match failed because DNS1 settings don't match!\n");
		success = false;
	}

	if (strcmp(original->ip.dns2, testval->ip.dns2) != 0)
	{
		innerError("Connection Config match failed because DNS2 settings don't match!\n");
		success = false;
	}

	if (strcmp(original->ip.dns3, testval->ip.dns3) != 0)
	{
		innerError("Connection Config match failed because DNS3 settings don't match!\n");
		success = false;
	}

	if (strcmp(original->ip.gateway, testval->ip.gateway) != 0)
	{
		innerError("Connection Config match failed because gateways didn't match!\n");
		success = false;
	}

	if (strcmp(original->ip.ipaddr, testval->ip.ipaddr) != 0)
	{
		innerError("Connection Config match failed because IP addresses didn't match!\n");
		success = false;
	}

	if (original->ip.netmask == NULL)
	{
		innerError("Netmask is NULL!\n");
		success = false;
	}

	if (strcmp(original->ip.netmask, testval->ip.netmask) != 0)
	{
		innerError("Connection Config match failed because netmask didn't match!\n");
		success = false;
	}

	if (original->ip.renew_on_reauth != testval->ip.renew_on_reauth)
	{
		innerError("Connection Config match failed because 'Renew on Reauth' settings didn't match!\n");
		success = false;
	}

	if (strcmp(original->ip.search_domain, testval->ip.search_domain) != 0)
	{
		innerError("Connection Config match failed because search domain didn't match!\n");
		success = false;
	}

	if (original->ip.type != testval->ip.type)
	{
		innerError("Connection Config match failed because IP address type didn't match!\n");
		success = false;
	}

	if (original->priority != testval->priority)
	{
		innerError("Connection Config match failed because priorities didn't match!\n");
		success = false;
	}

	if (strcmp(original->profile, testval->profile) != 0)
	{
		innerError("Connection Config match failed because profile names didn't match!\n");
		success = false;
	}

	if (strcmp(original->ssid, testval->ssid) != 0)
	{
		innerError("Connection Config match failed because SSIDs didn't match!\n");
		success = false;
	}

	return success;
}

#define VALID_CONF_STR  "Valid Config Test"

bool ConnectionConfigTests::createSystemConfig()
{
	int result = 0;

	system_config = createValidNonDefaultConfig(VALID_CONF_STR);
	
	if ((result = xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, system_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to add 'Valid Config Test' to the system level config!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkConfigState()
{
	int result = 0;
	config_connection *read_back_config = NULL;

	if ((result = xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read 'Valid Config Test' back from the engine! (Error : " + Util::itos(result) + ")\n");

		if (read_back_config != NULL)
		{
			innerError("AND the result pointer wasn't NULL like it should have been!\n");
		}
		return false;
	}

	if (configsMatch(system_config, read_back_config) != true)
		return false;

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the configuration we read back!\n");
		return false;
	}

	// See if we can read the connection for the user config. (Should fail.)
	if (xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("The engine returned a configuration from user space when it shouldn't have!\n");

		if (configsMatch(system_config, read_back_config) == true)
		{
			innerError("AND it was valid!\n");
		}
		return false;
	}

	// Attempt to write our config to the user config file. (Should fail.)
	if (xsupgui_request_set_connection_config(CONFIG_LOAD_USER, system_config) == REQUEST_SUCCESS)
	{
		innerError("The engine allowed us to write a configuration to the user config that matched the name of an existing configuration in the system config!\n");
		return false;
	}

	// Try to read back the invalid config from the user config file. (Should fail.)
	if (xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Even though the engine claimed it didn't write to the user config space, it returned a configuration!\n");

		if (configsMatch(system_config, read_back_config) == true)
		{
			innerError("AND the configuration matched! (ACK!)\n");
		}

		return false;
	}

	if (read_back_config != NULL)
	{
		innerError("Even though the engine claimed it failed to read the data, the pointer wasn't NULL!\n");
		return false;
	}

	return true;
}


#define VALID_USER_CONF_STR  "Valid User Config Test"

bool ConnectionConfigTests::createUserConfig()
{
	int result = 0;

	user_config = createValidNonDefaultConfig(VALID_USER_CONF_STR);
	
	if ((result = xsupgui_request_set_connection_config(CONFIG_LOAD_USER, user_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to add 'Valid Config Test' to the user level config! (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkUserConfigState()
{
	config_connection *read_back_config = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_USER_CONF_STR, &read_back_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read 'Valid Config User Test' back from the engine! (Error : " + Util::itos(result) + ")\n");

		if (read_back_config != NULL)
		{
			innerError("AND the result pointer wasn't NULL like it should have been!\n");
		}
		return false;
	}

	if (configsMatch(user_config, read_back_config) != true)
		return false;

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the user configuration we read back!\n");
		return false;
	}

	// See if we can read the connection for the global config. (Should fail.)
	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_USER_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("The engine returned a configuration from system space when it shouldn't have!\n");

		if (configsMatch(user_config, read_back_config) == true)
		{
			innerError("AND it was valid!\n");
		}
		return false;
	}

	// Attempt to write our config to the user config file. (Should fail.)
	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, user_config) == REQUEST_SUCCESS)
	{
		innerError("The engine allowed us to write a configuration to the system config that matched the name of an existing configuration in the system config!\n");
		return false;
	}

	// Try to read back the invalid config from the user config file. (Should fail.)
	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_USER_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Even though the engine claimed it didn't write to the system config space, it returned a configuration!\n");

		if (configsMatch(user_config, read_back_config) == true)
		{
			innerError("AND the configuration matched! (ACK!)\n");
		}

		return false;
	}

	if (read_back_config != NULL)
	{
		innerError("Even though the engine claimed it failed to read the data, the pointer wasn't NULL!\n");
		return false;
	}

	return true;
}

#define VALID_VOLATILE_CONF_STR		"Valid Volatile Configuration"

bool ConnectionConfigTests::createVolatileSystemConfig()
{
	int result = 0;

	volatile_system_config = createValidNonDefaultConfig(VALID_VOLATILE_CONF_STR);

	SET_FLAG(volatile_system_config->flags, CONFIG_VOLATILE_CONN);
	
	if ((result = xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, volatile_system_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to add 'Valid Volatile Config Test' to the system level config!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

#define VALID_VOLATILE_USER_CONF_STR  "Valid Volatile User Connection"

bool ConnectionConfigTests::createVolatileUserConfig()
{
	int result = 0;

	volatile_user_config = createValidNonDefaultConfig(VALID_VOLATILE_USER_CONF_STR);

	SET_FLAG(volatile_user_config->flags, CONFIG_VOLATILE_CONN);

	if ((result = xsupgui_request_set_connection_config(CONFIG_LOAD_USER, volatile_user_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to add 'Valid Volatile Config Test' to the user level config!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkVolatileSystemConfig(bool shouldBeAvail)
{
	config_connection *read_back_config = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_VOLATILE_CONF_STR, &read_back_config)) != REQUEST_SUCCESS)
	{
		if (shouldBeAvail == false)
		{
			if (read_back_config != NULL)
			{
				innerError("Volatile connection didn't exist (as expected), but configuration pointer wasn't NULL!\n");
				return false;
			}

			// If it shouldn't be available, then this test is done.
			return true;
		}

		innerError("Unable to read 'Valid Volatile Config Test' back from the engine!\n");

		if (read_back_config != NULL)
		{
			innerError("AND the result pointer wasn't NULL like it should have been!\n");
		}
		return false;
	}

	if (configsMatch(volatile_system_config, read_back_config) != true)
		return false;

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the configuration we read back!\n");
		return false;
	}

	// See if we can read the connection for the user config. (Should fail.)
	if (xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_VOLATILE_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("The engine returned a configuration from user space when it shouldn't have!\n");

		if (configsMatch(volatile_system_config, read_back_config) == true)
		{
			innerError("AND it was valid!\n");
		}
		return false;
	}

	// Attempt to write our config to the user config file. (Should fail.)
	if (xsupgui_request_set_connection_config(CONFIG_LOAD_USER, volatile_system_config) == REQUEST_SUCCESS)
	{
		innerError("The engine allowed us to write a configuration to the user config that matched the name of an existing configuration in the system config!\n");
		return false;
	}

	// Try to read back the invalid config from the user config file. (Should fail.)
	if (xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_VOLATILE_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Even though the engine claimed it didn't write to the user config space, it returned a configuration!\n");

		if (configsMatch(volatile_system_config, read_back_config) == true)
		{
			innerError("AND the configuration matched! (ACK!)\n");
		}

		return false;
	}

	if (read_back_config != NULL)
	{
		innerError("Even though the engine claimed it failed to read the data, the pointer wasn't NULL!\n");
		return false;
	}


	return true;
}

bool ConnectionConfigTests::checkVolatileUserConfig(bool shouldBeAvail)
{
	config_connection *read_back_config = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_VOLATILE_USER_CONF_STR, &read_back_config)) != REQUEST_SUCCESS)
	{
		if (shouldBeAvail == false)
		{
			if (read_back_config != NULL)
			{
				innerError("User's volatile connection wasn't returned (as expected), but the pointer wasn't NULL!\n");
				return false;
			}

			return true;
		}

		innerError("Unable to read 'Valid Volatile Config User Test' back from the engine!  (Error : " + Util::itos(result) + ")\n");

		if (read_back_config != NULL)
		{
			innerError("AND the result pointer wasn't NULL like it should have been!\n");
		}
		return false;
	}

	if (configsMatch(volatile_user_config, read_back_config) != true)
		return false;

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the user configuration we read back!\n");
		return false;
	}

	// See if we can read the connection for the global config. (Should fail.)
	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_VOLATILE_USER_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("The engine returned a configuration from system space when it shouldn't have!\n");

		if (configsMatch(volatile_user_config, read_back_config) == true)
		{
			innerError("AND it was valid!\n");
		}
		return false;
	}

	// Attempt to write our config to the user config file. (Should fail.)
	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, volatile_user_config) == REQUEST_SUCCESS)
	{
		innerError("The engine allowed us to write a configuration to the system config that matched the name of an existing configuration in the system config!\n");
		return false;
	}

	// Try to read back the invalid config from the user config file. (Should fail.)
	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_VOLATILE_USER_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Even though the engine claimed it didn't write to the system config space, it returned a configuration!\n");

		if (configsMatch(volatile_user_config, read_back_config) == true)
		{
			innerError("AND the configuration matched! (ACK!)\n");
		}

		return false;
	}

	if (read_back_config != NULL)
	{
		innerError("Even though the engine claimed it failed to read the data, the pointer wasn't NULL!\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkFlagSettings()
{
	config_connection *read_back_config = NULL;
	string temp;

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config'.\n");
		return false;
	}

	// Set the flags to be all 1s except the volatile flag.  When we write it, and read it back, we
	// should only get back flags that are known.
	read_back_config->flags = 0xff;
	UNSET_FLAG(read_back_config->flags, CONFIG_VOLATILE_CONN);

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to write flags changes back to the configuration.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the temporary connection data!\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config' for final verification.\n");
		return false;
	}

	if (read_back_config->flags != (CONFIG_NET_DEST_MAC | CONFIG_NET_IS_HIDDEN))
	{
		temp = "Flags byte returned a value other than what was expected.  (Expected : " + Util::itos((CONFIG_NET_DEST_MAC | CONFIG_NET_IS_HIDDEN)) +
			"  Got : " + Util::itos(read_back_config->flags) + ")\n";
		innerError(temp);
		xsupgui_request_free_connection_config(&read_back_config);
		return false;
	}

	xsupgui_request_free_connection_config(&read_back_config);

	return true;
}

bool ConnectionConfigTests::checkPriorityRange()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if (xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->priority = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if (read_back_config->priority != altered_config->priority)
			{
				temp = "Priority values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
					
				return false;
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

bool ConnectionConfigTests::checkForceEAPoLVerRange()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->force_eapol_ver = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if ((values >= 0) && (values <= 2))
			{
				if (read_back_config->force_eapol_ver != altered_config->force_eapol_ver)
				{
					temp = "EAPoL version values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}
			else
			{
				if (altered_config->force_eapol_ver != 0)
				{
					temp = "Invalid type values written didn't return as a default setting!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

bool ConnectionConfigTests::checkAssociationTypeRange()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->association.association_type = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if ((values >= 0) && (values <= 5))
			{
				if (read_back_config->association.association_type != altered_config->association.association_type)
				{
					temp = "Association Type values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}
			else
			{
				if (altered_config->association.association_type != 0)
				{
					temp = "Association Type values written didn't return as a default setting!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

bool ConnectionConfigTests::checkAuthenticationTypeRange()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->association.auth_type = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (altered_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if ((values >= 1) && (values <= 3))
			{
				if (read_back_config->association.auth_type != altered_config->association.auth_type)
				{
					innerError("Authentication values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ", written = " + Util::itos(read_back_config->association.auth_type) + ", read = " + Util::itos(altered_config->association.auth_type) + ")\n");
					
					return false;
				}
			}
			else
			{
				if (altered_config->association.auth_type != 3)  // EAP is our default auth type.
				{
					innerError("Invalid invalid authentication type values written didn't return as a default setting!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n");
					
					return false;
				}
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

bool ConnectionConfigTests::checkGroupKeyRange()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->association.group_keys = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if ((values >= 0) && (values <= 5))
			{
				if (read_back_config->association.group_keys != altered_config->association.group_keys)
				{
					temp = "Group key values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}
			else
			{
				if (altered_config->association.group_keys != 0)
				{
					temp = "Invalid group key values written didn't return as a default setting!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

bool ConnectionConfigTests::checkPairwiseKeyRange()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->association.pairwise_keys = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if ((values >= 0) && (values <= 31))
			{
				if (read_back_config->association.pairwise_keys != altered_config->association.pairwise_keys)
				{
					temp = "TX key values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}
			else
			{
				if (altered_config->association.pairwise_keys != 31)		// This should be 31 because that is the last valid value we set.  New settings should get ignored.
				{
					temp = "Invalid pairwise key values written didn't return as a default setting!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

bool ConnectionConfigTests::checkTxKeyRange()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->association.txkey = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if ((values >= 0) && (values <= 4))
			{
				if (read_back_config->association.txkey != altered_config->association.txkey)
				{
					temp = "TX key values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}
			else
			{
				if (altered_config->association.txkey != 0)
				{
					temp = "Invalid TX key values written didn't return as a default setting!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

bool ConnectionConfigTests::checkIPTypeValues()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->ip.type = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if ((values >= 0) && (values <= 2))
			{
				if (read_back_config->ip.type != altered_config->ip.type)
				{
					temp = "Type values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}
			else
			{
				if (altered_config->ip.type != CONFIG_IP_USE_DHCP)
				{
					temp = "Invalid type values written didn't return as a default setting!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

bool ConnectionConfigTests::checkReauthRenewValues()
{
	config_connection *read_back_config = NULL;
	config_connection *altered_config = NULL;
	uint8_t values = 0;
	uint8_t config_type = CONFIG_LOAD_GLOBAL;
	char *conn_name = NULL;
	string temp;
	int result = 0;

	conn_name = _strdup(VALID_CONF_STR);  // Start with the global config.

	for (int i = 0; i < 2; i++)
	{
		if (i == 1) 
		{
			config_type = CONFIG_LOAD_USER;
			free(conn_name);
			conn_name = _strdup(VALID_USER_CONF_STR);
		}

		for (values = 0; values < 0xff; values++)
		{
			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			read_back_config->ip.renew_on_reauth = values;

			if ((result = xsupgui_request_set_connection_config(config_type, read_back_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to write '";
				temp += conn_name;
				temp += "' to the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		
				
				return false;
			}

			if ((result = xsupgui_request_get_connection_config(config_type, conn_name, &altered_config)) != REQUEST_SUCCESS)
			{
				temp = "Unable to read modified '";
				temp += conn_name;
				temp += "' back from the engine!  (err = " + Util::itos(result) + " i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
				innerError(temp);		

				if (read_back_config != NULL)
				{
					innerError("AND the result pointer wasn't NULL like it should have been!\n");
				}
				return false;
			}

			if ((values == 1) || (values == 0))
			{
				if (read_back_config->ip.renew_on_reauth != altered_config->ip.renew_on_reauth)
				{
					temp = "Renew values written didn't match when read!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}
			else
			{
				if (altered_config->ip.renew_on_reauth != 0)		// FALSE is the default.
				{
					temp = "Invalid type values written didn't return as a default setting!  (i = " + Util::itos(i) + ", values = " + Util::itos(values) + ")\n";
					innerError(temp);		
					
					return false;
				}
			}

			xsupgui_request_free_connection_config(&read_back_config);
			xsupgui_request_free_connection_config(&altered_config);
		}
	}

	return true;
}

#define VALID_RENAMED_CONF_STR  "Renamed System Level Configuration"
#define VALID_USER_RENAMED_CONF_STR  "Renamed User Level Configuration"

bool ConnectionConfigTests::checkRenameSystemConnection()
{
	config_connection *read_back_config = NULL;

	// Try to rename a user config, but tell the engine it is a system config.  (Should fail.)
	if (xsupgui_request_rename_connection(CONFIG_LOAD_GLOBAL, VALID_USER_CONF_STR, VALID_USER_RENAMED_CONF_STR) == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a user config when we flagged the message as being a system level config.\n");
		return false;
	}

	// Attempt to rename a system config to the same name as a user config.  (Should fail.)
	if (xsupgui_request_rename_connection(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, VALID_USER_CONF_STR) == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a system config to the same name as a user config!\n");
		return false;
	}

	if (xsupgui_request_rename_connection(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, VALID_RENAMED_CONF_STR) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the configuration.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Managed to read back a configuration that shouldn't exist anymore!\n");
		return false;
	}

	if (read_back_config != NULL)
	{
		innerError("Our read back configuration pointer wasn't NULL when it should have been!\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_RENAMED_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Our renamed connection couldn't be read back!\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration data!\n");
		return false;
	}

	if (xsupgui_request_rename_connection(CONFIG_LOAD_GLOBAL, VALID_RENAMED_CONF_STR, VALID_CONF_STR) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename our connection back to it's original name!\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_RENAMED_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Managed to read back a configuration that should no longer exist!  (It was renamed back to its original name!)\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the configuration that was renamed back to the original name!\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the memory used to read back a configuration!\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkRenameUserConnection()
{
	config_connection *read_back_config = NULL;

	// Try to rename a system config, but tell the engine it is a user config.  (Should fail.)
	if (xsupgui_request_rename_connection(CONFIG_LOAD_USER, VALID_CONF_STR, VALID_RENAMED_CONF_STR) == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a system config when we flagged the message as being a user level config.\n");
		return false;
	}

	// Attempt to rename a user config to the same name as a system config.  (Should fail.)
	if (xsupgui_request_rename_connection(CONFIG_LOAD_USER, VALID_USER_CONF_STR, VALID_CONF_STR) == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a user config to the same name as a system config!\n");
		return false;
	}

	if (xsupgui_request_rename_connection(CONFIG_LOAD_USER, VALID_USER_CONF_STR, VALID_USER_RENAMED_CONF_STR) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the configuration.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_USER_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Managed to read back a configuration that shouldn't exist anymore!\n");
		return false;
	}

	if (read_back_config != NULL)
	{
		innerError("Our read back configuration pointer wasn't NULL when it should have been!\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_USER_RENAMED_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Our renamed connection couldn't be read back!\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration data!\n");
		return false;
	}

	if (xsupgui_request_rename_connection(CONFIG_LOAD_USER, VALID_USER_RENAMED_CONF_STR, VALID_USER_CONF_STR) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename our connection back to it's original name!\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_USER_RENAMED_CONF_STR, &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Managed to read back a configuration that should no longer exist!  (It was renamed back to its original name!)\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_USER, VALID_USER_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the configuration that was renamed back to the original name!\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the memory used to read back a configuration!\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkInvalidDeleteConnections()
{
	if (xsupgui_request_delete_connection_config(CONFIG_LOAD_GLOBAL, VALID_USER_CONF_STR) == REQUEST_SUCCESS)
	{
		// This should have failed.
		innerError("Attempt to delete connection with a name from a user's config out of the system config was a success!  (This is bad.)\n");
		return false;
	}

	if (xsupgui_request_delete_connection_config(CONFIG_LOAD_USER, VALID_CONF_STR) == REQUEST_SUCCESS)
	{
		// This should have failed.
		innerError("Attempt to delete connection with a name from the system's config out of the user's config was a sucess!  (This is bad.)\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkDeleteSystemConnection()
{
	if (xsupgui_request_delete_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR) != REQUEST_SUCCESS)
	{
		// This should have failed.
		innerError("Failed to delete the 'Valid System Config' from the system configuration!\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkDeleteUserConnection()
{
	if (xsupgui_request_delete_connection_config(CONFIG_LOAD_USER, VALID_USER_CONF_STR) != REQUEST_SUCCESS)
	{
		// This should have failed.
		innerError("Failed to delete the 'Valid User Config' from the configuration!\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::connectionIsInEnum(conn_enum *enumdata, uint8_t config_type, char *name)
{
	unsigned int i = 0;

	while ((enumdata[i].name != NULL) && (strcmp(enumdata[i].name, name) != 0))
	{
		i++;
	}

	if (enumdata[i].name == NULL) return false;

	if (enumdata[i].config_type != config_type) return false;

	return true;
}

bool ConnectionConfigTests::checkEnumConnections()
{
	conn_enum *enumdata = NULL;
	int result = 0;

	if ((result = xsupgui_request_enum_connections(CONFIG_LOAD_GLOBAL, &enumdata)) != REQUEST_SUCCESS)
	{
		innerError("Couldn't enumerate global connections! (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (!connectionIsInEnum(enumdata, CONFIG_LOAD_GLOBAL, VALID_CONF_STR))
	{
		innerError("'Valid System Config' was not found in the system level configuration enumeration!\n");
		return false;
	}

	if (connectionIsInEnum(enumdata, CONFIG_LOAD_GLOBAL, VALID_USER_CONF_STR))   // Should fail.
	{
		innerError("'Valid User System Config' was found in the system level configuration enumeration!\n");
		return false;
	}

	if (xsupgui_request_free_conn_enum(&enumdata) != 0)
	{
		innerError("Failed to free connections enumeration.\n");
		return false;
	}

	if ((result = xsupgui_request_enum_connections(CONFIG_LOAD_USER, &enumdata)) != REQUEST_SUCCESS)
	{
		innerError("Couldn't enumerate user connections! (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (connectionIsInEnum(enumdata, CONFIG_LOAD_USER, VALID_CONF_STR))
	{
		innerError("'Valid System Config' was found in the user configuration when it shouldn't be!\n");
		return false;
	}

	if (!connectionIsInEnum(enumdata, CONFIG_LOAD_USER, VALID_USER_CONF_STR))
	{
		innerError("'Valid User Config' was NOT found in the user configuration when it should be!\n");
		return false;
	}

	if (xsupgui_request_free_conn_enum(&enumdata) != 0)
	{
		innerError("Failed to free connections enumeration!\n");
		return false;
	}

	if ((result = xsupgui_request_enum_connections((CONFIG_LOAD_USER | CONFIG_LOAD_GLOBAL), &enumdata)) != REQUEST_SUCCESS)
	{
		innerError("Couldn't enumerate all connections! (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (!connectionIsInEnum(enumdata, CONFIG_LOAD_GLOBAL, VALID_CONF_STR))
	{
		innerError("'Valid System Config' was NOT found in the 'all connections' enumeration!\n");
		return false;
	}

	if (!connectionIsInEnum(enumdata, CONFIG_LOAD_USER, VALID_USER_CONF_STR))
	{
		innerError("'Valid User Config' was NOT found in the 'all connections' enumeration!\n");
		return false;
	}

	if (xsupgui_request_free_conn_enum(&enumdata) != 0)
	{
		innerError("Failed to free connections enumeration!!\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkPSKValues()
{
	config_connection *read_back_config = NULL;

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the 'Valid System Config' configuration!\n");
		return false;
	}

	if (read_back_config->association.psk != NULL)
	{
		free(read_back_config->association.psk);
	}

	read_back_config->association.psk = _strdup("short");

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to write back the configuration with a short PSK.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the configuration information in memory.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config' configuration!\n");
		return false;
	}
	
	if (read_back_config->association.psk != NULL)
	{
		innerError("Engine allowed a short PSK to be saved!\n");
		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free configuration structure.\n");
			return false;
		}

		return false;
	}

	read_back_config->association.psk = _strdup("1234567890123456789012345678901234567890123456789012345678901234567890");

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to update the configuration for 'Valid System Config'.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration structure.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config' configuration!\n");
		return false;
	}

	if (read_back_config->association.psk != NULL)
	{
		innerError("Engine allowed us to write a PSK longer than 63 characters.\n");
		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free configuration structure.\n");
			return false;
		}

		return false;
	}

	read_back_config->association.psk = _strdup("validkeypsk");

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to update the configuration for 'Valid System Config'.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration structure.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config' configuration!\n");
		return false;
	}

	if ((read_back_config->association.psk == NULL) || (strcmp(read_back_config->association.psk, "validkeypsk") != 0))
	{
		innerError("Valid PSK wasn't saved!\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration structure.\n");
		return false;
	}

	return true;
}

/**
 * \brief If we set the volatile flag on a connection that exists, but wasn't
 *			previously volatile, we should get an error.
 **/
bool ConnectionConfigTests::checkVolatileOnStored()
{
	config_connection *read_back_config = NULL;

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read 'Valid Config Test' back from the engine!\n");

		if (read_back_config != NULL)
		{
			innerError("AND the result pointer wasn't NULL like it should have been!\n");
		}
		return false;
	}

	SET_FLAG(read_back_config->flags, CONFIG_VOLATILE_CONN);

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to set 'Valid Config Test' to volatile.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free connection structure!\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read 'Valid Config Test' back from the engine!\n");

		if (read_back_config != NULL)
		{
			innerError("AND the result pointer wasn't NULL like it should have been!\n");
		}
		return false;
	}

	if (TEST_FLAG(read_back_config->flags, CONFIG_VOLATILE_CONN))
	{
		innerError("Engine allowed an existing configuration to be changed to volatile!!!\n");
		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free connection structure!\n");
			return false;
		}

		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free connection structure!\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkPSKHexValues()
{
	config_connection *read_back_config = NULL;

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the 'Valid System Config' configuration!\n");
		return false;
	}

	if (read_back_config->association.psk_hex != NULL)
	{
		free(read_back_config->association.psk_hex);
	}

	read_back_config->association.psk_hex = _strdup("0001020304");

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to write back the configuration with a short PSK HEX.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free the configuration information in memory.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config' configuration!\n");
		return false;
	}
	
	if (read_back_config->association.psk_hex != NULL)
	{
		innerError("Engine allowed a short PSK HEX to be saved!\n");
		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free configuration structure.\n");
			return false;
		}

		return false;
	}

	read_back_config->association.psk_hex = _strdup("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to update the configuration for 'Valid System Config'.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration structure.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config' configuration!\n");
		return false;
	}

	if (read_back_config->association.psk_hex != NULL)
	{
		innerError("Engine allowed us to write a PSK HEX longer than 64 bytes. (128 characters)\n");
		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free configuration structure.\n");
			return false;
		}

		return false;
	}

	read_back_config->association.psk_hex = _strdup("invalidPSKHEXkey");

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to update the configuration for 'Valid System Config'.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration structure.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config' configuration!\n");
		return false;
	}

	if (read_back_config->association.psk_hex != NULL)
	{
		innerError("Engine allowed us to write a PSK HEX that isn't HEX!\n");
		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free configuration structure.\n");
			return false;
		}

		return false;
	}

	read_back_config->association.psk_hex = _strdup("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678");

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to update the configuration for 'Valid System Config'.\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration structure.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read back the 'Valid System Config' configuration!\n");
		return false;
	}

	if (strcmp(read_back_config->association.psk_hex, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678") != 0)
	{
		innerError("Unable to save valid PSK HEX value!\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free configuration structure.\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkWEPKeyRange()
{
	config_connection *read_back_config = NULL;
	int i = 0;
	string temp;

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the 'Valid System Config' configuration!\n");
		return false;
	}

	if (read_back_config->association.keys[0] != NULL)
	{
		innerError("keys[0] was not NULL!  (It should ALWAYS be NULL!)\n");
		return false;
	}

	read_back_config->association.txkey = 0;
	read_back_config->association.keys[0] = _strdup("1111111111");

	if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to write 'Valid System Config' configuration!\n");
		return false;
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free connection configuration.\n");
		return false;
	}

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the 'Valid System Config' configuration!\n");
		return false;
	}

	if (read_back_config->association.keys[0] != NULL)
	{
		innerError("keys[0] was not NULL!  (The engine allowed us to store an invalid value!)\n");
		return false;
	}

	// Do these tests for each key slot!
	for (i = 1; i <= 4; i++)
	{
		if (read_back_config->association.keys[i] != NULL) 
		{
			free(read_back_config->association.keys[i]);
			read_back_config->association.keys[i] = NULL;
		}

		read_back_config->association.txkey = i;
		read_back_config->association.keys[i] = _strdup("3333322222");

		if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
		{
			innerError("Unable to write 'Valid System Config' configuration!\n");
			return false;
		}

		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free connection configuration.\n");
			return false;
		}

		if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
		{
			innerError("Unable to read the 'Valid System Config' configuration!\n");
			return false;
		}

		if (read_back_config->association.keys[i] == NULL)
		{
			innerError("Writing a valid key resulted in a NULL value when read back. (Slot : " + Util::itos(i) + ")\n");
			return false;
		}

		if (strcmp(read_back_config->association.keys[i], "3333322222") != 0)
		{
			innerError("Valid 40 bit key couldn't be saved in slot " + Util::itos(i) + "!\n");
			return false;
		}

		free(read_back_config->association.keys[i]);

		read_back_config->association.keys[i] = _strdup("33333222224444455555666661");

		if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
		{
			innerError("Unable to write 'Valid System Config' configuration!\n");
			return false;
		}

		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free connection configuration.\n");
			return false;
		}

		if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
		{
			innerError("Unable to read the 'Valid System Config' configuration!\n");
			return false;
		}

		if ((read_back_config->association.keys[i] == NULL) || (strcmp(read_back_config->association.keys[i], "33333222224444455555666661") != 0))
		{
			temp = "Valid 104 bit key couldn't be saved in slot " + Util::itos(i) + "!\n";
			innerError(temp);
			return false;
		}

		free(read_back_config->association.keys[i]);

		read_back_config->association.keys[i] = _strdup("333332222255555666661");

		if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
		{
			innerError("Unable to write 'Valid System Config' configuration!\n");
			return false;
		}

		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free connection configuration.\n");
			return false;
		}

		if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
		{
			innerError("Unable to read the 'Valid System Config' configuration!\n");
			return false;
		}

		if (read_back_config->association.keys[i] != NULL)
		{
			temp = "Invalid length key was saved in slot " + Util::itos(i) + "!\n";
			innerError(temp);
			return false;
		}

		free(read_back_config->association.keys[i]);

		read_back_config->association.keys[i] = _strdup("3333322222qqqqq55555666661");

		if (xsupgui_request_set_connection_config(CONFIG_LOAD_GLOBAL, read_back_config) != REQUEST_SUCCESS)
		{
			innerError("Unable to write 'Valid System Config' configuration!\n");
			return false;
		}

		if (xsupgui_request_free_connection_config(&read_back_config) != 0)
		{
			innerError("Unable to free connection configuration.\n");
			return false;
		}

		if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config) != REQUEST_SUCCESS)
		{
			innerError("Unable to read the 'Valid System Config' configuration!\n");
			return false;
		}

		if (read_back_config->association.keys[i] != NULL)
		{
			temp = "Invalid 104 bit key was saved in slot " + Util::itos(i) + "!\n";
			innerError(temp);
			return false;
		}
	}
	
	return true;
}

bool ConnectionConfigTests::checkInvalidConnectionName()
{
	config_connection *read_back_config = NULL;

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, "sdlkgfjs;ldkjfgs;lkgtjsl;kertgj", &read_back_config) == REQUEST_SUCCESS)
	{
		innerError("Attempt to read an invalid connection configuration was a success?!\n");
		return false;
	}

	if (read_back_config != NULL)
	{
		innerError("Invalid connection request returned a non-NULL configuration pointer!\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkInvalidConfigDest()
{
	unsigned char i = 0;
	config_connection *read_back_config = NULL;
	config_connection *temp = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, VALID_CONF_STR, &read_back_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read previously created config! (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	for (i = 0; i < 0xff; i++)
	{
		if ((i == CONFIG_LOAD_GLOBAL) || (i == CONFIG_LOAD_USER)) continue;

		if ((result = xsupgui_request_get_connection_config(i, VALID_CONF_STR, &temp)) != IPC_ERROR_INVALID_CONFIG)
		{
			innerError("Attempt to read an invalid connection config didn't fail properly! (Error : " + Util::itos(result) + "  Iteration : " + Util::itos(i) + ")\n");
			return false;
		}

		if (temp != NULL)
		{
			innerError("Failed attempt to read a connection resulted in a non-NULL string!\n");
			return false;
		}

		result = xsupgui_request_set_connection_config(i, read_back_config);
		if ((result != IPC_ERROR_INVALID_CONFIG) && (result != IPC_ERROR_PARSING))
		{
			innerError("Attempt to write an invalid connection config didn't fail properly!  (Error : " + Util::itos(result) + "  Iteration : " + Util::itos(i) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_connection_config(&read_back_config) != 0)
	{
		innerError("Unable to free connection configuration.\n");
		return false;
	}

	return true;
}

bool ConnectionConfigTests::checkRenameNotExist()
{
	if (xsupgui_request_rename_connection(CONFIG_LOAD_GLOBAL, "dsflkjsdlkfjsldfkj", "This is bad") == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a nonexistant configuration at the system level!\n");
		return false;
	}

	if (xsupgui_request_rename_connection(CONFIG_LOAD_USER, "dsflkjsdlkfjsldfkj", "This is bad") == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a nonexistant configuration at the user level!\n");
		return false;
	}

	return true;
}

