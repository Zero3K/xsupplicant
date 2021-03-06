/**
 * EAPMSCHAPv2 Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file mschapv2.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _MSCHAPV2_H_
#define _MSCHAPV2_H_

#define USING_ASCII_PWD		0
#define USING_NTPWD_PWD		1
#define USING_MAUTH_PWD		2

void GenerateNTResponse(char *, char *, char *, char *, char *, int);
void ChallengeResponse(char *, char *, char *);
void NtChallengeResponse(char *, char *, char *, int);
void CheckAuthenticatorResponse(char *, char *, char *, char *, char *, char *,
				int *, int);
void GetAsymetricStartKey(char *, char *, int, int, int);
void GetMasterKey(char *, char *, char *);
void GetMasterLEAPKey(char *, char *, char *, char *, char *, char *);
void HashNtPasswordHash(char *, char *);
void NtPasswordHash(char *, char *, int);
char ctonibble(char);
void process_hex(char *, int, char *);
#endif
