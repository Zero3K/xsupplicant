/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file sim.c
 *
 * \author chris@open1x.org
 */

#define _CRT_SECURE_NO_WARNINGS

#ifdef WIN32
#include <windows.h>
#include <stdio.h>
#include <shlobj.h>

#include <stdintwin.h>
#else
#include <stdio.h>
#include <string.h>
#endif

#include "sim.h"

char ctonibble(char cnib)
{
  char retVal=0x00;
  char testval=0x00;

  if ((cnib>='0') && (cnib<='9'))
    {
      retVal = cnib - '0';
    } else {
      testval = toupper(cnib);
      if ((testval>='A') && (testval<='F'))
	{
	  retVal = ((testval - 'A') +10);
	} else {
	  printf("Error in conversion!  (Check ctonibble()) -- %02x\n",testval);
	}
    }
  return retVal;
}

// Convert an ASCII hex string to it's binary version.
void process_hex(char *instr, int size, char *outstr)
{
  int i;

  // Make sure we don't try to convert something that isn't byte aligned.
  if ((size % 2) != 0)
    {
      printf("Hex string isn't an even number of chars!!!\n");
      return;
    }

  for (i=0;i<(size/2);i++)
    {
      if (instr[i*2] != 0x00)
	{
	  outstr[i] = (ctonibble(instr[i*2]) << 4) + ctonibble(instr[(i*2)+1]);
	}
    }
}

FILE *sim_open_config()
{
  char *path = NULL;
#ifdef WIN32
	TCHAR szMyPath[MAX_PATH];


	if (FAILED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szMyPath)))
	  {
		  printf("Couldn't determine the path to the local common app data.\n");
		  return NULL;
	  }

	path = malloc(strlen(szMyPath)+strlen("2Gsim.txt")+3);
	if (path == NULL) return NULL;

	memset(path, 0x00, strlen(szMyPath)+strlen("2Gsim.txt")+3);

	strcpy(path, szMyPath);
	strcat(path, "\\2Gsim.txt");
#else

	path = _strdup("/etc/2Gsim.txt");
#endif

	return fopen(path, "r");
}

/**
 * \brief Spilt a file line of the format IMSI:KC:SRES:RAND in to its component parts.
 **/
void sim_split_line(char *line_in, char *imsi, char *kc, char *sres, char *rand)
{
	char *temp = NULL;
	char *prev = NULL;

	if (line_in == NULL)
	{
		// Our line_in was invalid, so return NULL results.
		imsi[0] = 0x00;
		kc[0] = 0x00;
		sres[0] = 0x00;
		rand[0] = 0x00;

		return;
	}

	prev = line_in;
	temp = strstr(line_in, ":");

	if (temp == NULL)
	{
		// Our first value wasn't found.
		imsi[0] = 0x00;
		kc[0] = 0x00;
		sres[0] = 0x00;
		rand[0] = 0x00;

		return;
	}

	temp[0] = 0x00; // NULL terminate the IMSI.

	strcpy(imsi, prev);

	prev = temp+1;

	temp = strstr(prev, ":");

	if (temp == NULL)
	{
		// Our first value wasn't found.
		imsi[0] = 0x00;
		kc[0] = 0x00;
		sres[0] = 0x00;
		rand[0] = 0x00;

		return;
	}

	temp[0] = 0x00;

	strcpy(kc, prev);

	prev = temp+1;

	temp = strstr(prev, ":");

	if (temp == NULL)
	{
		// Our first value wasn't found.
		imsi[0] = 0x00;
		kc[0] = 0x00;
		sres[0] = 0x00;
		rand[0] = 0x00;

		return;
	}

	temp[0] = 0x00;

	strcpy(sres, prev);

	prev = temp+1;

	// Everything left should be the RAND.
	strcpy(rand, prev);
	rand[strlen(rand)] = 0x00;  // Strip the \n.
}

int sim_get_imsi(char **imsi)
{
	FILE *fh = NULL;
	char line[1024];
	char imsi_str[64], kc[64], sres[64], rand[64];

	fh = sim_open_config();
	if (fh == NULL) return -1;

	while (fgets(line, 1024, fh) != NULL)
	{
		if ((line[0] != '#') && (line[0] != '\n') && (line[0] != ' '))
		{
			sim_split_line(line, (char *)&imsi_str, (char *)&kc, (char *)&sres, (char *)&rand);

			// The IMSI is returned as a string, so this is okay.
			(*imsi) = _strdup(imsi_str);

			fclose(fh);
			return 0;
		}
	}

	fclose(fh);
	return -1;
}

int sim_do_2g_auth(unsigned char *challenge, unsigned char *response, unsigned char *ckey)
{
	FILE *fh = NULL;
	char line[1024];
	char imsi[64], kc[64], sres[64], rand[64];
	char challenge_str[33];
	char temp[3];
	int i = 0;
	int found = 0;

	// Convert the challenge to a string so we don't have to convert each random back to binary
	// to compare it.  (The challenge is 16 bytes, so we need 16*2 bytes for the characters, and
	// one extra for the NULL terminator.
	memset(&challenge_str[0], 0x00, 33);

	for (i = 0; i < 16; i++)
	{
		sprintf(&temp[0], "%02X", challenge[i]);
		strcat(challenge_str, temp);
	}

	fh = sim_open_config();
	if (fh == NULL) return -1;

	while (fgets(line, 1024, fh) != NULL)
	{
		if ((line[0] != '#') && (line[0] != '\n') && (line[0] != ' '))
		{
			sim_split_line(line, (char *)&imsi, (char *)&kc, (char *)&sres, (char *)&rand);

			// See if this is the line we want.
			if ((rand != NULL) && (strncmp(rand, challenge_str, strlen(challenge_str)) == 0))
			{
				found = 1;
				break;
			}
		}
	}

	fclose(fh);

	if (found == 0) return -1;

	process_hex(sres, strlen(sres), response);
	process_hex(kc, strlen(kc), ckey);

	return 0;
}

