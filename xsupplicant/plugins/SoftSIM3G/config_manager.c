/**
 * Config manager for software emulated 3G SIM card.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file config_manager.c
 *
 * \author chris@open1x.org
 *
 **/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_manager.h"

struct aka_config {
	char *imsi;
	char *k;
	char *sqn;
	char *amf;
	char *oc;
};

struct aka_config *myconfig = NULL;

int load_config_from_path(char *path)
{
}

int write_config_to_path(char *path)
{
}

int load_sim_config()
{
	if (myconfig != NULL) free_sim_config();

#ifdef WIN32
#else
#warning Implement config paths for your OS!
	return -1;
#endif
}

int get_imsi(char **imsi)
{
	if (myconfig == NULL) return -1;

	if (myconfig->imsi == NULL) 
	{
		(*imsi) = NULL;
		return -1;
	}

	(*imsi) = _strdup(myconfig->imsi);

	return 0;
}

int get_k(char **k)
{
	if (myconfig == NULL) return -1;

	if (myconfig->k == NULL) 
	{
		(*k) = NULL;
		return -1;
	}

	(*k) = _strdup(myconfig->k);

	return 0;
}

int get_sqn(char **sqn)
{
	if (myconfig == NULL) return -1;

	if (myconfig->sqn == NULL) 
	{
		(*sqn) = NULL;
		return -1;
	}

	(*sqn) = _strdup(myconfig->sqn);

	return 0;
}

int get_amf(char **amf)
{
	if (myconfig == NULL) return -1;

	if (myconfig->amf == NULL) 
	{
		(*amf) = NULL;
		return -1;
	}

	(*amf) = _strdup(myconfig->amf);

	return 0;
}

int get_oc(char **oc)
{
	if (myconfig == NULL) return -1;

	if (myconfig->oc == NULL) 
	{
		(*oc) = NULL;
		return -1;
	}

	(*oc) = _strdup(myconfig->oc);

	return 0;
}

int write_sim_config()
{
}

int set_sqn(char *sqn)
{
	if (sqn == NULL) return -1;

	if (myconfig->sqn != NULL)
	{
		free(myconfig->sqn);
		myconfig->sqn = NULL;
	}

	myconfig->sqn = _strdup(sqn);

	return 0;
}

int free_sim_config()
{
	free(myconfig->amf);
	free(myconfig->imsi);
	free(myconfig->k);
	free(myconfig->oc);
	free(myconfig->sqn);

	free(myconfig);
	myconfig = NULL;
}


