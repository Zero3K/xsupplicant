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

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#endif

#include "config_manager.h"

struct aka_config {
	char *imsi;
	char *k;
	char *sqn;
	char *amf;
	char *oc;
};

struct aka_config *myconfig = NULL;

void process_line(char *line)
{
	char *key = NULL, *value = NULL;
	unsigned int i = 0;

	if (myconfig == NULL) 
	{
		printf("myconfig is NULL!\n");
		return;
	}

	if (line[0] == '#') return;

	key = line;
	while ((i < strlen(line)) && (line[i] != '=')) i++;

	line[i] = 0x00;

	value = (char *)&line[i+1];

	if (_stricmp("imsi", key) == 0)
	{
		// It is an imsi.
		myconfig->imsi = _strdup(value);
	}
	else if (_stricmp("k", key) == 0)
	{
		// It is a K
		myconfig->k = _strdup(value);
	}
	else if (_stricmp("sqn", key) == 0)
	{
		myconfig->sqn = _strdup(value);
	}
	else if (_stricmp("amf", key) == 0)
	{
		myconfig->amf = _strdup(value);
	}
	else if (_stricmp("oc", key) == 0)
	{
		myconfig->oc = _strdup(value);
	}
}

int load_config_from_path(char *path)
{
	FILE *fp = NULL;
	char line[1000];

	fp = fopen(path, "r");
	if (fp == NULL) return -30;

	while (fscanf(fp, "%s", &line) != EOF)
	{
		process_line(line);
	}

	fclose(fp);

	return 0;
}

int write_config_to_path(char *path)
{
	FILE *fp = NULL;

	fp = fopen(path, "w");
	if (fp == NULL) return -1;

	fprintf(fp, "IMSI=%s\n", myconfig->imsi);
	fprintf(fp, "K=%s\n", myconfig->k);
	fprintf(fp, "AMF=%s\n", myconfig->amf);
	fprintf(fp, "OC=%s\n", myconfig->oc);
	fprintf(fp, "SQN=%s\n", myconfig->sqn);

	fclose(fp);

	return 0;
}

int load_sim_config()
{
#ifdef WIN32
	TCHAR szMyPath[MAX_PATH];
	char *path = NULL;
#endif

	if (myconfig != NULL) free_sim_config();

	myconfig = malloc(sizeof(struct aka_config));
	if (myconfig == NULL) return -10;

	memset(myconfig, 0x00, sizeof(struct aka_config));

#ifdef WIN32
	if (FAILED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szMyPath)))
	  {
		  printf("Couldn't determine the path to the local common app data.\n");
		  return -30;
	  }

	path = malloc(strlen(szMyPath)+strlen("usim.txt")+3);
	if (path == NULL) return -20;

	memset(path, 0x00, strlen(szMyPath)+strlen("usim.txt")+3);

	strcpy(path, szMyPath);
	strcat(path, "\\usim.txt");

	return load_config_from_path(path);
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
	if (myconfig == NULL) 
	{
		load_sim_config();
		if (myconfig == NULL) return -1;
	}

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
#ifdef WIN32
	TCHAR szMyPath[MAX_PATH];
	char *path = NULL;

	if (FAILED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szMyPath)))
	  {
		  printf("Couldn't determine the path to the local common app data.\n");
		  return NULL;
	  }

	path = malloc(strlen(szMyPath)+strlen("usim.txt")+3);
	if (path == NULL) return -1;

	memset(path, 0x00, strlen(szMyPath)+strlen("usim.txt")+3);

	strcpy(path, szMyPath);
	strcat(path, "\\usim.txt");

	return write_config_to_path(path);
#else
#warning Implement config paths for your OS!
	return -1;
#endif
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
	if (myconfig == NULL) return 0;

	if (myconfig->amf != NULL) free(myconfig->amf);
	if (myconfig->imsi != NULL) free(myconfig->imsi);
	if (myconfig->k != NULL) free(myconfig->k);
	if (myconfig->oc != NULL) free(myconfig->oc);
	if (myconfig->sqn != NULL) free(myconfig->sqn);

	free(myconfig);
	myconfig = NULL;

	return 0;
}


