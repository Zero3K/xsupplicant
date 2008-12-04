/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file sim.c
 *
 * \author chris@open1x.org
 */

#include <windows.h>
#include <stdio.h>

#include <stdintwin.h>

#include "config_manager.h"
#include "milenage.h"
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

void comp_sqn(uint8_t seqn[6], uint64_t *lseq, int ind)
{  
  (*lseq)++;			/* just increment by 1 for now, ignore IND etc */

  seqn[0] = (uint8_t) (((*lseq) >> 40) & 0x00000000000000ff);
  seqn[1] = (uint8_t) (((*lseq) >> 32) & 0x00000000000000ff);
  seqn[2] = (uint8_t) (((*lseq) >> 24) & 0x00000000000000ff);
  seqn[3] = (uint8_t) (((*lseq) >> 16) & 0x00000000000000ff);
  seqn[4] = (uint8_t) (((*lseq) >> 8 ) & 0x00000000000000ff);
  seqn[5] = (uint8_t) (((*lseq) ) & 0x00000000000000ff);
}

void comp_autn(uint8_t seqn[6], uint8_t ak[6], uint8_t amf[2], uint8_t mac_a[8], uint8_t autn[16])
{
  int i;
  for (i = 0; i < 6; i++) {
      autn[i] = seqn[i] ^ ak[i];
  };
  autn[6] = amf[0];
  autn[7] = amf[1];
  for (i = 0; i < 8; i++) {
    autn[i+8] = mac_a[i];
  }
}

void sim_dump_data(char *tag, unsigned char *data, int datalen)
{
	int i = 0;

	printf("%s : ", tag);
	for (i = 0; i < datalen; i++)
	{
		printf("%02X ", data[i]);
	}
	printf("\n");
}

void sim_inc_sqn(unsigned char *sqn)
{
	int i = 0;
	int plus_one = 1;
	int next = 0;

	for (i = 6; i >= 0; i--)
	{
		if (sqn[i] == 0xff) 
			next = 1;
		else
			next = 0;

		if (plus_one == 1) sqn[i]++;

		plus_one = next;
	}
}

char *hex2str(unsigned char *data, int len)
{
	char *temp = NULL;
	int i = 0;
	char conv[5];

	temp = (char *)malloc((len + 1) * 2);
	if (temp == NULL) return NULL;

	memset(temp, 0x00, ((len + 1) * 2));

	for (i = 0; i < len; i++)
	{
		sprintf(&conv, "%02X", data[i]);
		strcat(temp, conv);
	}

	return temp;
}

int sim_do_3g_auth(unsigned char *Rand, unsigned char *autn, unsigned char *c_auts, unsigned char *res_len, unsigned char *c_sres, unsigned char *c_ck, unsigned char *c_ik, unsigned char *c_kc)
{
	unsigned char *seqn = NULL, *k = NULL, *amf = NULL, *op_c = NULL;
	char *temp;
	int retval = 0;

	// Get SQN and convert it to binary.
	if (get_sqn(&temp) != 0) return -1;

	seqn = malloc((strlen(temp)/2)+1);
	if (seqn == NULL) return -1;

	process_hex(temp, strlen(temp), seqn);
	free(temp);

	// need key (in binary) and amf (also binary)
	if (get_k(&temp) != 0) 
	{
		free(seqn);
		return -1;
	}

	k = malloc((strlen(temp)/2)+1);
	if (k == NULL)
	{
		free(seqn);
		return -1;
	}

	process_hex(temp, strlen(temp), k);
	free(temp);

	if (get_amf(&temp) != 0) 
	{
		free(seqn);
		free(k);
		return -1;
	}

	amf = malloc((strlen(temp)/2)+1);
	if (amf == NULL)
	{
		free(seqn);
		free(k);
		return -1;
	}

	process_hex(temp, strlen(temp), amf);
	free(temp);

	if (get_oc(&temp) != 0)
	{
		free(seqn);
		free(k);
		free(amf);
		return -1;
	}

	op_c = malloc((strlen(temp)/2)+2);
	if (op_c == NULL)
	{
		free(seqn);
		free(k);
		free(amf);
		return -1;
	}

	process_hex(temp, strlen(temp), op_c);
	free(temp);

	retval = milenage_check(op_c, k, seqn, Rand, autn, c_ik, c_ck, c_sres, res_len, c_auts);

	sim_inc_sqn(seqn);

	temp = hex2str(seqn, 6);
	if (temp != NULL)
	{
		set_sqn(temp);
		write_sim_config();
	}

	free(seqn);
	free(k);
	free(amf);
	free(op_c);

	return retval;
}

