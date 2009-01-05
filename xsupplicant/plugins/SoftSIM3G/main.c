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
#include "sim.h"

#include <xsupplugin_types.h>

#define READER_NAME  "3G Soft SIM Emulator"
#define SUPPORT_3G_SIM			0x02

unsigned long reader_handle_value = 1;			// A global counter to deal with multiple simultanious attempts to use the virtual reader.

// Supplicant entrypoint
uint32_t DLLMAGIC initialize()
{
	printf("%s()\n", __FUNCTION__);
	return PLUGIN_TYPE_SIM_INTERFACE;
}

// Supplicant entrypoint
void DLLMAGIC cleanup()
{
	printf("%s()\n", __FUNCTION__);
}

void DLLMAGIC sim_hook_update_reader_list(char **readerlist)
{
	unsigned int listsize = 0;
	unsigned int totallist = 0;
	char *pReader = NULL;
	char *newReaderList = NULL;

	printf("%s()\n", __FUNCTION__);

	pReader = (*readerlist);

	if (pReader != NULL)
	{
		while ( '\0' != (*pReader))
		{
			listsize = strlen(pReader)+1;
			totallist += listsize;
			pReader += listsize;
		}
		totallist++;  // Pick up the last NULL character.
	}

	newReaderList = malloc(totallist+strlen(READER_NAME)+2);
	if (newReaderList == NULL) return;   // Can't add ours. :-(

	memset(newReaderList, 0x00, (strlen(READER_NAME)+totallist+2));
	strcpy(newReaderList, READER_NAME);

	memcpy(&newReaderList[strlen(READER_NAME)+1], (*readerlist), totallist);

	pReader = (*readerlist);
	free(pReader);

	(*readerlist) = newReaderList;
}

int DLLMAGIC sim_hook_reader_gs_supported(void **card_hdl)
{
	printf("%s()\n", __FUNCTION__);
	return SUPPORT_3G_SIM;
}

int DLLMAGIC sim_hook_get_3g_imsi(void *cardhdl, char reader_mode, char *pin, char **imsi)
{
	printf("%s()\n", __FUNCTION__);
	return get_imsi(imsi);
}

int DLLMAGIC sim_hook_3g_pin_needed(void **card_hdl, char reader_mode)
{
	printf("%s()\n", __FUNCTION__);
	if ((*card_hdl) != 1) return -2;

	return -1;			//  No PIN needed right now.
}

int DLLMAGIC sim_hook_card_connect(void *card_ctx, void **card_hdl, char *cardreader)
{
	printf("%s()\n", __FUNCTION__);

	if (strcmp(cardreader, READER_NAME) != 0) return -3;		// Not for us. ;)

	(*card_hdl) = 1;
	return load_sim_config();
}

int DLLMAGIC sim_hook_card_disconnect(void *card_hdl)
{
	printf("%s()\n", __FUNCTION__);
	free_sim_config();

	return 0;
}

int DLLMAGIC sim_hook_do_3g_auth(void **card_hdl, char reader_mode, unsigned char *Rand, unsigned char *autn,
		unsigned char *c_auts, char *res_len, unsigned char *c_sres, unsigned char *c_ck,
		unsigned char *c_ik, unsigned char *c_kc)
{
	printf("%s()\n", __FUNCTION__);

	// Reject if it isn't for us.
	if ((*card_hdl) != 1) return -1;
	return sim_do_3g_auth(Rand, autn, c_auts, res_len, c_sres, c_ck, c_ik, c_kc);
}

int DLLMAGIC sim_hook_wait_card_ready(void **card_hdl, int waittime)
{
	if ((*card_hdl) != 1) 
	{
		printf("Not a Soft SIM!\n");
		return -1;
	}

	return 0;
}
