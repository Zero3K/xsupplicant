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
#include "config_manager.h"

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

void DLLMAGIC sim_hook_update_reader_list(char **readerlist)
{
}

int DLLMAGIC sim_hook_reader_gs_supported(void *card_hdl)
{
}

int DLLMAGIC sim_hook_get_3g_imsi(void *cardhdl, char reader_mode, char *pin, char **imsi)
{
}

int DLLMAGIC sim_hook_3g_pin_needed(void *card_hdl, char reader_mode)
{
}

int DLLMAGIC sim_hook_card_connect(void *card_ctx, void *card_hdl, char *cardreader)
{
}

int DLLMAGIC sim_hook_card_disconnect(void *card_hdl)
{
}

int DLLMAGIC sim_hook_do_3g_auth(void *card_hdl, char reader_mode, unsigned char *Rand, unsigned char *autn,
		unsigned char *c_auts, char *res_len, unsigned char *c_sres, unsigned char *c_ck,
		unsigned char *c_ik, unsigned char *c_kc)
{
}
