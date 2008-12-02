/**
 * A Software emulated 3G SIM card.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file main.c
 *
 * \author chris@open1x.org
 *
 **/

#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../plugin_includes.h"

#include <xsupplugin_types.h>

// Supplicant entrypoint
uint32_t DLLMAGIC initialize()
{
	return PLUGIN_TYPE_SIM_INTERFACE;
}

// Supplicant entrypoint
void DLLMAGIC cleanup()
{
}

