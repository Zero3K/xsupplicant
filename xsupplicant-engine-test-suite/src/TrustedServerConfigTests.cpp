#include <iostream>

#include "TrustedServerConfigTests.h"
#include "Util.h"

TrustedServerConfigTests::TrustedServerConfigTests()
{
}

TrustedServerConfigTests::~TrustedServerConfigTests()
{
}

/**
 * \brief Helper function to create trusted server types.
 **/
struct config_trusted_server *TrustedServerConfigTests::createFullTrustedServerConfig(char *name, char *stype, char *location)
{
	struct config_trusted_server *tempServer = NULL;

	tempServer = (struct config_trusted_server *)malloc(sizeof(struct config_trusted_server));
	if (tempServer == NULL)
	{
		innerError("Unable to allocate memory to store temp trusted server config!\n");
		return NULL;
	}

	tempServer->name = _strdup(name);
	tempServer->location = (char **)malloc(sizeof(char *));
	memset(tempServer->location, 0x00, sizeof(char *));
	tempServer->num_locations = 1;

	tempServer->location[0] = _strdup(location);
	tempServer->store_type = _strdup(stype);

	return tempServer;
}

bool TrustedServerConfigTests::executeTest()
{
	runInnerTest("1 createSystemTrustedServerConfig()", createSystemTrustedServerConfig());

	runInnerTest("1 createUserTrustedServerConfig()", createUserTrustedServerConfig());

	runInnerTest("1 checkSystemTrustedServerConfig()", checkSystemTrustedServerConfig());

	runInnerTest("1 checkUserTrustedServerConfig()", checkUserTrustedServerConfig());

	runInnerTest("1 createVolatileSystemTrustedServerConfig()", createVolatileSystemTrustedServerConfig());

	runInnerTest("1 createVolatileUserTrustedServerConfig()", createVolatileUserTrustedServerConfig());

	runInnerTest("1 checkVolatileSystemTrustedServerConfig()", checkVolatileSystemTrustedServerConfig(true));

	runInnerTest("1 checkVolatileUserTrustedServerConfig()", checkVolatileUserTrustedServerConfig(true));

	runInnerTest("1 checkRenameToVolatile()", checkRenameToVolatile());

	// Make sure we can write it to the disk.
	if (runInnerTest("1 writeConfigs()", writeConfigs()) == false) return false;

	// Cleanly disconnect before we restart the engine.
	if (runInnerTest("1 IPCConnectTest::teardownTest()", IPCConnectTest::teardownTest()) == false) return false;

	// Restart the engine.
	Util::restartEngine(30);		// Wait 30 seconds.

	// Establish a new IPC connection to the engine.
	if (runInnerTest("1 IPCConnectTest::setupTest()", IPCConnectTest::setupTest()) == false) return false;

	runInnerTest("2 checkVolatileSystemTrustedServerConfig()", checkVolatileSystemTrustedServerConfig(false));

	runInnerTest("2 checkVolatileUserTrustedServerConfig()", checkVolatileUserTrustedServerConfig(false));

//	runInnerTest("1 checkSystemSwitchToVolatile()", checkSystemSwitchToVolatile());

//	runInnerTest("1 checkUserSwitchToVolatile()", checkUserSwitchToVolatile());

	runInnerTest("1 checkExactCommonNameRange()", checkExactCommonNameRange());

	runInnerTest("1 checkFlagsRange()", checkFlagsRange());

	runInnerTest("1 checkTSEnum()", checkTSEnum());

	runInnerTest("1 checkBadDelete()", checkBadDelete());

	runInnerTest("1 checkRename()", checkRename());

	runInnerTest("1 checkInvalidServerName()", checkInvalidServerName());

	runInnerTest("1 checkInvalidRename()", checkInvalidRename());

	runInnerTest("1 checkInvalidConfigDest()", checkInvalidConfigDest());

	runInnerTest("1 checkDeleteSystemTrustedServerConfig()", checkDeleteSystemTrustedServerConfig());

	runInnerTest("1 checkDeleteUserTrustedServerConfig()", checkDeleteUserTrustedServerConfig());

	if (runInnerTest("2 writeConfigs()", writeConfigs()) == false) return false;

	return true;
}

bool TrustedServerConfigTests::writeConfigs()
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

#define SYSTEM_CONF_NAME  "System Trusted Server Name"
#define USER_CONF_NAME "User Trusted Server Name"

bool TrustedServerConfigTests::createSystemTrustedServerConfig()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	ts = createFullTrustedServerConfig(SYSTEM_CONF_NAME, "WINDOWS", "000102030405060708");
	ts->common_name = _strdup("Some common name");
	ts->exact_common_name = TRUE;
	ts->flags = 0;

	if ((result = xsupgui_request_set_trusted_server_config(CONFIG_LOAD_GLOBAL, ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write trusted server configuration to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_trusted_server_config(&ts) != 0)
	{
		innerError("Unable to free trusted server configuration!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkSystemTrustedServerConfig()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read system trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (ts == NULL)
	{
		innerError("System level trusted server configuration claimed to have been read back, but it was NULL!\n");
		return false;
	}

	if ((ts->name == NULL) || (strcmp(ts->name, SYSTEM_CONF_NAME) != 0))
	{
		innerError("System level trusted server configuration claimed to have been read back, but the name didn't match!\n");
		return false;
	}

	if ((ts->store_type == NULL) || (strcmp(ts->store_type, "WINDOWS") != 0))
	{
		innerError("System level trusted server configuration store type name changed or was invalid.\n");
		return false;
	}

	if ((ts->location == NULL) || (strcmp(ts->location[0], "000102030405060708") != 0))
	{
		innerError("System level trusted server configuration 'location' value changed or was invalid!\n");
		return false;
	}

	if ((ts->common_name == NULL) || (strcmp(ts->common_name, "Some common name") != 0))
	{
		innerError("System level common name configuration was invalid or changed!\n");
		return false;
	}

	if (ts->exact_common_name != TRUE)
	{
		innerError("Valid for exact_common_name changed!\n");
		return false;
	}

	if (ts->flags != 0)
	{
		innerError("Some flag values were returned even though we didn't set them!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::createUserTrustedServerConfig()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	ts = createFullTrustedServerConfig(USER_CONF_NAME, "WINDOWS", "000102030405060708");
	ts->common_name = _strdup("Some common name");
	ts->exact_common_name = TRUE;
	ts->flags = 0;

	if ((result = xsupgui_request_set_trusted_server_config(CONFIG_LOAD_USER, ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write trusted server configuration to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_trusted_server_config(&ts) != 0)
	{
		innerError("Unable to free trusted server configuration!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkUserTrustedServerConfig()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_USER, USER_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (ts == NULL)
	{
		innerError("Trusted server configuration claimed to have been read back, but it was NULL!\n");
		return false;
	}

	if ((ts->name == NULL) || (strcmp(ts->name, USER_CONF_NAME) != 0))
	{
		innerError("Trusted server configuration claimed to have been read back, but the name didn't match!\n");
		return false;
	}

	if ((ts->store_type == NULL) || (strcmp(ts->store_type, "WINDOWS") != 0))
	{
		innerError("Trusted server configuration store type name changed or was invalid.\n");
		return false;
	}

	if ((ts->location == NULL) || (strcmp(ts->location[0], "000102030405060708") != 0))
	{
		innerError("Trusted server configuration 'location' value changed or was invalid!\n");
		return false;
	}

	if ((ts->common_name == NULL) || (strcmp(ts->common_name, "Some common name") != 0))
	{
		innerError("Common name configuration was invalid or changed!\n");
		return false;
	}

	if (ts->exact_common_name != TRUE)
	{
		innerError("Valid for exact_common_name changed!\n");
		return false;
	}

	if (ts->flags != 0)
	{
		innerError("Some flag values were returned even though we didn't set them!\n");
		return false;
	}

	return true;
}

#define SYSTEM_VOLATILE_CONF_NAME  "System Volatile Trusted Server Name"
#define USER_VOLATILE_CONF_NAME "User Volatile Trusted Server Name"

bool TrustedServerConfigTests::createVolatileSystemTrustedServerConfig()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	ts = createFullTrustedServerConfig(SYSTEM_VOLATILE_CONF_NAME, "WINDOWS", "000102030405060708");
	ts->common_name = _strdup("Some common name");
	ts->exact_common_name = TRUE;
	ts->flags = 0;
	SET_FLAG(ts->flags, CONFIG_VOLATILE_SERVER);

	if ((result = xsupgui_request_set_trusted_server_config(CONFIG_LOAD_GLOBAL, ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write trusted server configuration to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_trusted_server_config(&ts) != 0)
	{
		innerError("Unable to free trusted server configuration!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::createVolatileUserTrustedServerConfig()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	ts = createFullTrustedServerConfig(USER_VOLATILE_CONF_NAME, "WINDOWS", "000102030405060708");
	ts->common_name = _strdup("Some common name");
	ts->exact_common_name = TRUE;
	ts->flags = 0;
	SET_FLAG(ts->flags, CONFIG_VOLATILE_SERVER);

	if ((result = xsupgui_request_set_trusted_server_config(CONFIG_LOAD_USER, ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to write trusted server configuration to engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_trusted_server_config(&ts) != 0)
	{
		innerError("Unable to free trusted server configuration!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkVolatileSystemTrustedServerConfig(bool expected)
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_VOLATILE_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		if (expected == true)
		{
			innerError("Unable to read system trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
			return false;
		}
		else
		{
			return true;
		}
	}

	if (ts == NULL)
	{
		if (expected == true)
		{
			innerError("System volatile connection wasn't returned when we expected it to be!\n");
			return false;
		}
		else
		{
			return true;
		}
	}

	if ((ts->name == NULL) || (strcmp(ts->name, SYSTEM_VOLATILE_CONF_NAME) != 0))
	{
		innerError("System level trusted server configuration claimed to have been read back, but the name didn't match!\n");
		return false;
	}

	if ((ts->store_type == NULL) || (strcmp(ts->store_type, "WINDOWS") != 0))
	{
		innerError("System level trusted server configuration store type name changed or was invalid.\n");
		return false;
	}

	if ((ts->location == NULL) || (strcmp(ts->location[0], "000102030405060708") != 0))
	{
		innerError("System level trusted server configuration 'location' value changed or was invalid!\n");
		return false;
	}

	if ((ts->common_name == NULL) || (strcmp(ts->common_name, "Some common name") != 0))
	{
		innerError("System level common name configuration was invalid or changed!\n");
		return false;
	}

	if (ts->exact_common_name != TRUE)
	{
		innerError("Valid for exact_common_name changed!\n");
		return false;
	}

	if (TEST_FLAG(ts->flags, CONFIG_VOLATILE_SERVER) != CONFIG_VOLATILE_SERVER)
	{
		innerError("Some flag values were returned even though we didn't set them!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkVolatileUserTrustedServerConfig(bool expected)
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_USER, USER_VOLATILE_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		if (expected == true)
		{
			innerError("Unable to read trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
			return false;
		}
		else
		{
			return true;
		}
	}

	if (ts == NULL)
	{
		if (expected == true)
		{
			innerError("User volatile connection wasn't returned when we expected it to be!\n");
			return false;
		}
		else
		{
			return true;
		}
	}

	if ((ts->name == NULL) || (strcmp(ts->name, USER_VOLATILE_CONF_NAME) != 0))
	{
		innerError("Trusted server configuration claimed to have been read back, but the name didn't match!\n");
		return false;
	}

	if ((ts->store_type == NULL) || (strcmp(ts->store_type, "WINDOWS") != 0))
	{
		innerError("Trusted server configuration store type name changed or was invalid.\n");
		return false;
	}

	if ((ts->location == NULL) || (strcmp(ts->location[0], "000102030405060708") != 0))
	{
		innerError("Trusted server configuration 'location' value changed or was invalid!\n");
		return false;
	}

	if ((ts->common_name == NULL) || (strcmp(ts->common_name, "Some common name") != 0))
	{
		innerError("Common name configuration was invalid or changed!\n");
		return false;
	}

	if (ts->exact_common_name != TRUE)
	{
		innerError("Valid for exact_common_name changed!\n");
		return false;
	}

	if (TEST_FLAG(ts->flags, CONFIG_VOLATILE_SERVER) != CONFIG_VOLATILE_SERVER)
	{
		innerError("Some flag values were returned even though we didn't set them!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkRenameToVolatile()
{
	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, SYSTEM_VOLATILE_CONF_NAME) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to rename a static config to a volatile config that already existed!\n");
		return false;
	}

	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_GLOBAL, SYSTEM_VOLATILE_CONF_NAME, SYSTEM_CONF_NAME) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to rename a volatile config to a static config that already existed!\n");
		return false;
	}

	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_USER, USER_CONF_NAME, USER_VOLATILE_CONF_NAME) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to rename a static user config to a volatile user config that already existed!\n");
		return false;
	}

	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_USER, USER_VOLATILE_CONF_NAME, USER_CONF_NAME) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to rename a volatile user config to a static user config that already existed!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkSystemSwitchToVolatile()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read system trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (ts == NULL)
	{
		innerError("System level trusted server configuration claimed to have been read back, but it was NULL!\n");
		return false;
	}

	SET_FLAG(ts->flags, CONFIG_VOLATILE_SERVER);

	if ((result = xsupgui_request_set_trusted_server_config(CONFIG_LOAD_GLOBAL, ts)) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to switch a static config to volatile.\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkUserSwitchToVolatile()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_USER, USER_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read system trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (ts == NULL)
	{
		innerError("System level trusted server configuration claimed to have been read back, but it was NULL!\n");
		return false;
	}

	SET_FLAG(ts->flags, CONFIG_VOLATILE_SERVER);

	if ((result = xsupgui_request_set_trusted_server_config(CONFIG_LOAD_GLOBAL, ts)) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to switch a static config to volatile.\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkExactCommonNameRange()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;
	uint8_t value = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read system trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (ts == NULL)
	{
		innerError("System level trusted server configuration claimed to have been read back, but it was NULL!\n");
		return false;
	}

	for (value = 0; value < 0xff; value++)
	{
		ts->exact_common_name = value;

		if (result = xsupgui_request_set_trusted_server_config(CONFIG_LOAD_GLOBAL, ts) != REQUEST_SUCCESS)
		{
			innerError("Unable to update the system configuration.  (Value : " + Util::itos(value) + ")\n");
			return false;
		}

		if (xsupgui_request_free_trusted_server_config(&ts) != 0)
		{
			innerError("Unable to free the trusted server configuration in memory!\n");
			return false;
		}

		if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &ts)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read system trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (value == 1)
		{
			if (ts->exact_common_name != 1)
			{
				innerError("Configuration didn't save a value of TRUE like we expected!\n");
				return false;
			}
		}
		else
		{
			if (ts->exact_common_name != 0)
			{
				innerError("Value wasn't 0 as expected!  (Value : " + Util::itos(value) + "  Common Name Value : " + Util::itos(ts->exact_common_name) + ")\n");
				return false;
			}
		}
	}

	return true;
}

bool TrustedServerConfigTests::checkFlagsRange()
{
	struct config_trusted_server *ts = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read system trusted server configuration from the engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (ts == NULL)
	{
		innerError("System level trusted server configuration claimed to have been read back, but it was NULL!\n");
		return false;
	}

	ts->flags = 0xff;
	UNSET_FLAG(ts->flags, CONFIG_VOLATILE_SERVER);	// Make sure we don't try to do something that should fail!

	if ((result = xsupgui_request_set_trusted_server_config(CONFIG_LOAD_GLOBAL, ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to update the configuration.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_trusted_server_config(&ts) != 0)
	{
		innerError("Failed to free the trusted server configuration.\n");
		return false;
	}

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &ts)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read system trusted server configuration back from the engine.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}
	
	if (ts->flags != 0)  // We don't have any flags except VOLATILE for trusted servers right now
	{
		innerError("Trusted server flags came back set in an invalid way!\n");
		return false;
	}

	if (xsupgui_request_free_trusted_server_config(&ts) != 0)
	{
		innerError("Failed to free the trusted server configuration.\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::foundInEnum(trusted_servers_enum *tsenum, char *tofind)
{
	int i = 0;

	while (tsenum[i].name != NULL)
	{
		if ((tsenum[i].name != NULL) && (strcmp(tsenum[i].name, tofind) == 0)) return true;
		i++;
	}

	return false;
}

bool TrustedServerConfigTests::checkTSEnum()
{
	trusted_servers_enum *tsenum = NULL;
	int result = 0;

	if ((result = xsupgui_request_enum_trusted_servers(CONFIG_LOAD_GLOBAL, &tsenum)) != REQUEST_SUCCESS)
	{
		innerError("Unable to enumerate global trusted servers.  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (foundInEnum(tsenum, SYSTEM_CONF_NAME) == false)
	{
		innerError("System trusted server not found in enumeration!\n");
		return false;
	}

	if (xsupgui_request_free_trusted_servers_enum(&tsenum) != 0)
	{
		innerError("Unable to free trusted server enumeration.\n");
		return false;
	}

	if ((result = xsupgui_request_enum_trusted_servers(CONFIG_LOAD_USER, &tsenum)) != REQUEST_SUCCESS)
	{
		innerError("Unable to enumerate user trusted servers.\n");
		return false;
	}

	if (foundInEnum(tsenum, USER_CONF_NAME) == false)
	{
		innerError("User trusted server not found in enumeration!\n");
		return false;
	}

	if (xsupgui_request_free_trusted_servers_enum(&tsenum) != 0)
	{
		innerError("Unable to free trusted server enumeration.\n");
		return false;
	}

	if ((result = xsupgui_request_enum_trusted_servers((CONFIG_LOAD_USER | CONFIG_LOAD_GLOBAL), &tsenum)) != REQUEST_SUCCESS)
	{
		innerError("Unable to enumerate all trusted servers.\n");
		return false;
	}

	if ((foundInEnum(tsenum, USER_CONF_NAME) == false) || (foundInEnum(tsenum, SYSTEM_CONF_NAME) == false))
	{
		innerError("Both user and system trusted server were not found in enumeration!\n");
		return false;
	}

	if (xsupgui_request_free_trusted_servers_enum(&tsenum) != 0)
	{
		innerError("Unable to free trusted server enumeration.\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkBadDelete()
{
	if (xsupgui_request_delete_trusted_server_config(CONFIG_LOAD_GLOBAL, USER_CONF_NAME, 1) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to delete the user configuration from the system configuration space!\n");
		return false;
	}

	if (xsupgui_request_delete_trusted_server_config(CONFIG_LOAD_USER, SYSTEM_CONF_NAME, 1) == REQUEST_SUCCESS)
	{
		innerError("Engine allowed us to delete the system configuration from the user configuration space!\n");
		return false;
	}

	return true;
}

#define SYSTEM_RENAMED_CONF_NAME  "Renamed System Trusted Server Configuration"
#define USER_RENAMED_CONF_NAME  "Renamed User Trusted Server Configuration"

bool TrustedServerConfigTests::checkRename()
{
	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, SYSTEM_RENAMED_CONF_NAME) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the system trusted server config.\n");
		return false;
	}

	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_GLOBAL, SYSTEM_RENAMED_CONF_NAME, SYSTEM_CONF_NAME) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the system trusted server config back to its original name!\n");
		return false;
	}

	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_USER, USER_CONF_NAME, USER_RENAMED_CONF_NAME) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the user trusted server config.\n");
		return false;
	}

	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_USER, USER_RENAMED_CONF_NAME, USER_CONF_NAME) != REQUEST_SUCCESS)
	{
		innerError("Unable to rename the user trusted server config back to its original name!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkDeleteSystemTrustedServerConfig()
{
	if (xsupgui_request_delete_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, 1) != REQUEST_SUCCESS)
	{
		innerError("Unable to delete the system trusted server config.\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkDeleteUserTrustedServerConfig()
{
	if (xsupgui_request_delete_trusted_server_config(CONFIG_LOAD_USER, USER_CONF_NAME, 1) != REQUEST_SUCCESS)
	{
		innerError("Unable to delete the user trusted server config.\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkInvalidServerName()
{
	struct config_trusted_server *ts = NULL;

	if (xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, "sdlkfjhs;ldfkgjhdsl;kgjhsdfkhjf", &ts) == REQUEST_SUCCESS)
	{
		innerError("Engine returned something valid for an invalid server name request!?\n");
		return false;
	}

	if (ts != NULL)
	{
		innerError("Invalid request resulted in a valid pointer being returned!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkInvalidRename()
{
	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_GLOBAL, "dsflkjsdlkfjsldfkj", "This is bad") == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a nonexistant configuration at the system level!\n");
		return false;
	}

	if (xsupgui_request_rename_trusted_server(CONFIG_LOAD_USER, "dsflkjsdlkfjsldfkj", "This is bad") == REQUEST_SUCCESS)
	{
		innerError("Managed to rename a nonexistant configuration at the user level!\n");
		return false;
	}

	return true;
}

bool TrustedServerConfigTests::checkInvalidConfigDest()
{
	unsigned char i = 0;
	config_trusted_server *read_back_config = NULL;
	config_trusted_server *temp = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, SYSTEM_CONF_NAME, &read_back_config)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read the system profile that was written earlier. (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	for (i = 0; i < 0xff; i++)
	{
		if ((i == CONFIG_LOAD_GLOBAL) || (i == CONFIG_LOAD_USER)) continue;

		if ((result = xsupgui_request_get_trusted_server_config(i, SYSTEM_CONF_NAME, &temp)) != IPC_ERROR_INVALID_CONFIG)
		{
			innerError("Attempt to read an invalid config didn't fail properly! (Error : " + Util::itos(result) + "  Iteration : " + Util::itos(i) + ")\n");
			return false;
		}

		if (temp != NULL)
		{
			innerError("Failure to read an invalid config did not result in a NULL value!\n");
			return false;
		}

		if ((result = xsupgui_request_set_trusted_server_config(i, read_back_config)) != IPC_ERROR_INVALID_CONFIG)
		{
			innerError("Attempt to write an invalid config didn't fail properly!  (Error : " + Util::itos(result) + "  Iteration : " + Util::itos(i) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_trusted_server_config(&read_back_config) != 0)
	{
		innerError("Unable to free connection configuration.\n");
		return false;
	}

	return true;
}
