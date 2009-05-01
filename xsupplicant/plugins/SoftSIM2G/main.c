/**
 * A Software emulated 2G SIM card.  (Triplets read from a file, not a full emulation.)
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
#include "sim.h"
#include <stdintwin.h>

#include <xsupplugin_types.h>

#define READER_NAME  "2G Soft SIM Emulator"
#define SUPPORT_2G_SIM			0x01

unsigned long reader_handle_value = 1;			// A global counter to deal with multiple simultanious attempts to use the virtual reader.

// Supplicant entrypoint
#ifdef WIN32
unsigned __int32 DLLMAGIC initialize()
#else
uint32_t DLLMAGIC initialize()
#endif
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
	return SUPPORT_2G_SIM;
}

int DLLMAGIC sim_hook_get_2g_imsi(void *cardhdl, char reader_mode, char *pin, char **imsi)
{
	printf("%s()\n", __FUNCTION__);
	return sim_get_imsi(imsi);
}

int DLLMAGIC sim_hook_2g_pin_needed(void **card_hdl, char reader_mode)
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
	return 0;
}

int DLLMAGIC sim_hook_card_disconnect(void *card_hdl)
{
	printf("%s()\n", __FUNCTION__);

	return 0;
}

int DLLMAGIC sim_hook_do_2g_auth(void **card_hdl, char reader_mode, unsigned char *challenge,
								 unsigned char *response, unsigned char *ckey)
{
	printf("%s()\n", __FUNCTION__);

	// Reject if it isn't for us.
	if ((*card_hdl) != 1) return -1;
	return sim_do_2g_auth(challenge, response, ckey);
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
