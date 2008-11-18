#include <iostream>
#include <direct.h>

#include "GlobalConfigTests.h"
#include "Util.h"

GlobalConfigTests::GlobalConfigTests()
{
}

GlobalConfigTests::~GlobalConfigTests()
{
}

bool GlobalConfigTests::executeTest()
{
	runInnerTest("checkSettingsSurviveRestart()", checkSettingsSurviveRestart());

	runInnerTest("checkLogFileLocation()", checkLogFileLocation());

	runInnerTest("checkLogLevelRange()", checkLogLevelRange());

	runInnerTest("checkLogsToKeepRange()", checkLogsToKeepRange());

	runInnerTest("checkSizeToRollRange()", checkSizeToRollRange());

	runInnerTest("checkLogTypeRange()", checkLogTypeRange());

	runInnerTest("checkLogFacility()", checkLogFacility());

	runInnerTest("checkIPCGroupName()", checkIPCGroupName());

	runInnerTest("checkFlags()", checkFlags());

	runInnerTest("checkDestinationRange()", checkDestinationRange());

	runInnerTest("checkAuthPeriodRange()", checkAuthPeriodRange());

	runInnerTest("checkHeldPeriodRange()", checkHeldPeriodRange());

	runInnerTest("checkMaxStartsRange()", checkMaxStartsRange());

	runInnerTest("checkStaleKeyTimeoutRange()", checkStaleKeyTimeoutRange());

	runInnerTest("checkAssocTimeoutRange()", checkAssocTimeoutRange());

	runInnerTest("checkPassiveTimeoutRange()", checkPassiveTimeoutRange());

	runInnerTest("checkActiveTimeoutRange()", checkActiveTimeoutRange());

	runInnerTest("checkIdleWhileTimeoutRange()", checkIdleWhileTimeoutRange());

	runInnerTest("checkPMKSAAgeOutRange()", checkPMKSAAgeOutRange());

	runInnerTest("checkPMKSACacheCheckRange()", checkPMKSACacheCheckRange());

	runInnerTest("checkDeadConnectionTimeoutRange()", checkDeadConnectionTimeoutRange());

	return true;
}

bool GlobalConfigTests::checkLogsToKeepRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint8_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xff; value++)
	{
		globals->logs_to_keep = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->logs_to_keep != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->logs_to_keep) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkSizeToRollRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->size_to_roll = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->size_to_roll != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->size_to_roll) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkLogTypeRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint8_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xff; value++)
	{
		globals->logtype = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (value > 2)
		{
			if (globals->logtype != 0)
			{
				innerError("Value returned wasn't what was expected!  (Got : " + Util::itos(globals->logtype) + "  Expected : 0  Value : " + Util::itos(value) + ")\n");
				return false;
			}
		}
		else
		{
			if (globals->logtype != value)
			{
				innerError("Value returned wasn't what was expected!  (Got : " + Util::itos(globals->logtype) + "  Value : " + Util::itos(value) + ")\n");
				return false;
			}
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkAuthPeriodRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->auth_period = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->auth_period != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->auth_period) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkHeldPeriodRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->held_period = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->held_period != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->held_period) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkMaxStartsRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->max_starts = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->max_starts != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->max_starts) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkStaleKeyTimeoutRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->stale_key_timeout = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->stale_key_timeout != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->stale_key_timeout) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkAssocTimeoutRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->assoc_timeout = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->assoc_timeout != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->assoc_timeout) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkPassiveTimeoutRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->passive_timeout = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->passive_timeout != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->passive_timeout) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkActiveTimeoutRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->active_timeout = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->active_timeout != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->active_timeout) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkPMKSAAgeOutRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint16_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffff; value++)
	{
		globals->pmksa_age_out = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->pmksa_age_out != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->pmksa_age_out) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkPMKSACacheCheckRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint8_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xff; value++)
	{
		globals->pmksa_cache_check = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->pmksa_cache_check != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->pmksa_cache_check) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkDeadConnectionTimeoutRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint8_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xff; value++)
	{
		globals->dead_connection_timeout = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->dead_connection_timeout != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->dead_connection_timeout) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkIdleWhileTimeoutRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint8_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xff; value++)
	{
		globals->idleWhile_timeout = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (globals->idleWhile_timeout != value)
		{
			innerError("Value passed to the engine wasn't returned when reread!  (Got : " + Util::itos(globals->idleWhile_timeout) + "  Expected : " + Util::itos(value) + ")\n");
			return false;
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkDestinationRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint8_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xff; value++)
	{
		globals->destination = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (value > 3)
		{
			if (globals->destination != 0)
			{
				innerError("Value returned wasn't what was expected!  (Got : " + Util::itos(globals->destination) + "  Expected : 0  Value : " + Util::itos(value) + ")\n");
				return false;
			}
		}
		else
		{
			if (globals->destination != value)
			{
				innerError("Value returned wasn't what was expected!  (Got : " + Util::itos(globals->destination) + "  Value : " + Util::itos(value) + ")\n");
				return false;
			}
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkLogLevelRange()
{
	struct config_globals *globals = NULL;
	int result = 0;
	uint32_t value = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	for (value = 0; value < 0xffffffff; value++)
	{
		globals->loglevel = value;

		if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
			return false;
		}

		if (xsupgui_request_free_config_globals(&globals) != 0)
		{
			innerError("Unable to free configuration globals!\n");
			return false;
		}

		if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
		{
			innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

			if (globals != NULL)
			{
				innerError("AND globals pointer wasn't NULL!\n");
			}

			return false;
		}

		if (value > 0x01FFFFFF)  // All known flags set. (Except the NULL flag, which shouldn't be written to our config.)
		{
			if (globals->loglevel != 0)
			{
				innerError("Value returned wasn't what was expected!  (Got : " + Util::itos(globals->loglevel) + "  Expected : 0  Value : " + Util::itos(value) + ")\n");
				return false;
			}
		}
		else
		{
			if (globals->loglevel != value)
			{
				innerError("Value returned wasn't what was expected!  (Got : " + Util::itos(globals->loglevel) + "  Value : " + Util::itos(value) + ")\n");
				return false;
			}
		}
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

#define KNOWN_CONFIG_FLAGS   (CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS | CONFIG_GLOBALS_ALLMULTI | CONFIG_GLOBALS_ASSOC_AUTO | CONFIG_GLOBALS_FIRMWARE_ROAM | CONFIG_GLOBALS_PASSIVE_SCAN | CONFIG_GLOBALS_NO_EAP_HINTS | CONFIG_GLOBALS_DETECT_ON_STARTUP | CONFIG_GLOBALS_ROLL_LOGS | CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF | CONFIG_GLOBALS_WIRELESS_ONLY | CONFIG_GLOBALS_NO_INT_CTRL)

bool GlobalConfigTests::checkFlags()
{
	struct config_globals *globals = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	globals->flags = 0xffff;

	if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	if (globals->flags != KNOWN_CONFIG_FLAGS)
	{
		innerError("Flags read back don't match flags passed in!  (Expected : " + Util::itos(KNOWN_CONFIG_FLAGS) + "  Got : " + Util::itos(globals->flags) + ")\n");
		return false;
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkLogFileLocation()
{
	struct config_globals *globals = NULL;
	int result = 0;
	char *saved = NULL;
	FILE *fh = NULL;

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	if (globals->logpath != NULL)
	{
		saved = _strdup(globals->logpath);
	}

	if ((result = _chdir("\\xsup_test_dir")) != 0)
	{
		switch (_mkdir("\\xsup_test_dir"))
		{
		case ENOENT:
			innerError("Attempt to create a temporary directory failed because it already existed!?\n");
			return false;
			break;

		case EEXIST:
			innerError("Attempted to create a directory that already exists.\n");
			return false;
			break;

		case 0:
			break;

		default:
			innerError("Unable to create a directory for an unknown reason.\n");
			return false;
			break;
		}
	}

	free(globals->logpath);
	globals->logpath = _strdup("\\xsup_test_dir");

	if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	fh = fopen("\\xsup_test_dir\\xsupplicant.log", "r");
	if (fh == NULL)
	{
		innerError("Unable to change log file location!\n");
		return false;
	}

	fclose(fh);

	free(globals->logpath);
	if (saved == NULL)
	{
		globals->logpath = NULL;
	}
	else
	{
		globals->logpath = _strdup(saved);
		free(saved);
	}

	if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::globalConfigsMatch(struct config_globals *g1, struct config_globals *g2)
{
	if (g1->logpath != NULL)
	{
		if (g2->logpath == NULL) 
		{
			innerError("g1->logpath was not NULL, but g2->logpath was.\n");
			return false;
		}
	}
	else
	{
		if (g2->logpath != NULL) 
		{
			innerError("g1->logpath was NULL, but g2->logpath was not!\n");
			return false;
		}
	}

	if (strcmp(g1->logpath, g2->logpath) != 0) 
	{
		innerError("Log paths didn't match.  (Got : " + string(g1->logpath) + "  Expected : " + string(g2->logpath) + ")\n");
		return false;
	}

	if (g1->loglevel != g2->loglevel)
	{
		innerError("Log levels didn't match.\n");
		return false;
	}

	if (g1->logs_to_keep != g2->logs_to_keep)
	{
		innerError("Logs to keep didn't match!\n");
		return false;
	}

	if (g1->size_to_roll != g2->size_to_roll)
	{
		innerError("Sizes to roll didn't match!\n");
		return false;
	}

	if (g1->logtype != g2->logtype)
	{
		innerError("Log types didn't match!\n");
		return false;
	}

	if (g1->log_facility == NULL)
	{
		if (g2->log_facility != NULL)
		{
			innerError("g1->log_facility was NULL, but g2->log_facility wasn't!\n");
			return false;
		}
	}
	else
	{
		if (g2->log_facility == NULL)
		{
			innerError("g2->log_facility was NULL, but g1->log_facility wasn't!\n");
			return false;
		}
	}

	if (strcmp(g1->log_facility, g2->log_facility) != 0)
	{
		innerError("Log facilities don't match!\n");
		return false;
	}

	if (g1->ipc_group_name == NULL)
	{
		if (g2->ipc_group_name != NULL)
		{
			innerError("g1->ipc_group_name was NULL, but g2->ipc_group_name wasn't!\n");
			return false;
		}
	}
	else
	{
		if (g2->ipc_group_name == NULL)
		{
			innerError("g2->ipc_group_name was NULL, but g1->ipc_group_name wasn't!\n");
			return false;
		}
	}

	if (strcmp(g1->ipc_group_name, g2->ipc_group_name) != 0)
	{
		innerError("IPC Group names didn't match!\n");
		return false;
	}

	if (g1->flags != g2->flags)
	{
		innerError("Flags didn't match!\n");
		return false;
	}

	if (g1->destination != g2->destination)
	{
		innerError("Destinations didn't match!\n");
		return false;
	}

	if (g1->auth_period != g2->auth_period)
	{
		innerError("Auth Periods didn't match!\n");
		return false;
	}

	if (g1->held_period != g2->held_period)
	{
		innerError("Held periods didn't match!\n");
		return false;
	}

	if (g1->max_starts != g2->max_starts)
	{
		innerError("Max starts didn't match!\n");
		return false;
	}

	if (g1->stale_key_timeout != g2->stale_key_timeout)
	{
		innerError("Stale key timeouts didn't match!\n");
		return false;
	}

	if (g1->assoc_timeout != g2->assoc_timeout)
	{
		innerError("Assoc Timeouts didn't match!\n");
		return false;
	}

	if (g1->passive_timeout != g2->passive_timeout)
	{
		innerError("Passive timeouts didn't match!\n");
		return false;
	}

	if (g1->active_timeout != g2->active_timeout)
	{
		innerError("Active timeouts didn't match!\n");
		return false;
	}

	if (g1->idleWhile_timeout != g2->idleWhile_timeout)
	{
		innerError("Idle while timeouts didn't match!\n");
		return false;
	}

	if (g1->pmksa_age_out != g2->pmksa_age_out)
	{
		innerError("PMKSA age out timers didn't match!\n");
		return false;
	}

	if (g1->pmksa_cache_check != g2->pmksa_cache_check)
	{
		innerError("PMKSA cache check freqency didn't match!\n");
		return false;
	}

	if (g1->dead_connection_timeout != g2->dead_connection_timeout)
	{
		innerError("Dead connection timeouts didn't match!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::checkSettingsSurviveRestart()
{
	struct config_globals *globals = NULL;
	struct config_globals *saved_globals = NULL;
	struct config_globals *reread_globals = NULL;
	int result = 0;

	if ((result = xsupgui_request_get_globals_config(&saved_globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	if ((result = xsupgui_request_get_globals_config(&globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	if (globals->logpath != NULL) free(globals->logpath);
	globals->logpath = _strdup("\\");

	// Bit 0 may not get set by the engine since it is assumed on all the time.
	globals->loglevel = 68;

	globals->logs_to_keep = 96;
	globals->size_to_roll = 169;
	globals->logtype = 1;
	globals->log_facility = _strdup("LOCAL");
	globals->ipc_group_name = _strdup("mygroup");
	globals->flags = 6;
	globals->destination = 2;
	globals->auth_period = (rand() % 0xffff);
	globals->held_period = (rand() % 0xffff);
	globals->max_starts = (rand() % 0xffff);
	globals->stale_key_timeout = (rand() % 0xffff);
	globals->assoc_timeout = (rand() % 0xffff);
	globals->passive_timeout = (rand() % 0xffff);
	globals->active_timeout = (rand() % 0xffff);
	globals->idleWhile_timeout = (rand() % 0xff);
	globals->pmksa_age_out = (rand() % 0xffff);
	globals->pmksa_cache_check = (rand() % 0xff);
	globals->dead_connection_timeout = (rand() % 0xff);

	if ((result = xsupgui_request_set_globals_config(globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	writeConfigs();

	if (IPCConnectTest::teardownTest() == false)
	{
		innerError("Unable to tear down connection to the engine!\n");
		return false;
	}

	Util::restartEngine(30);

	if (IPCConnectTest::setupTest() == false)
	{
		innerError("Unable to reconnect to the engine!\n");
		return false;
	}

	if ((result = xsupgui_request_get_globals_config(&reread_globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to read configuration globals!  (Error : " + Util::itos(result) + ")\n");

		if (globals != NULL)
		{
			innerError("AND globals pointer wasn't NULL!\n");
		}

		return false;
	}

	if ((result = xsupgui_request_set_globals_config(saved_globals)) != REQUEST_SUCCESS)
	{
		innerError("Unable to set configuration globals!  (Error : " + Util::itos(result) + ")\n");
		return false;
	}

	if (xsupgui_request_free_config_globals(&saved_globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	if (globalConfigsMatch(globals, reread_globals) == false) return false;

	if (xsupgui_request_free_config_globals(&globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	if (xsupgui_request_free_config_globals(&reread_globals) != 0)
	{
		innerError("Unable to free configuration globals!\n");
		return false;
	}

	return true;
}

bool GlobalConfigTests::writeConfigs()
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

bool GlobalConfigTests::checkLogFacility()
{
	// XXX Not on Windows, implement later.
	return true;
}

bool GlobalConfigTests::checkIPCGroupName()
{
	// XXX Not on Windows, implement later.
	return true;
}

