/**
 *
 * Licensed under a dual GPL/BSD license. (See LICENSE file for more info.)
 *
 * \file ntpwdhash_main.c
 *
 * \author chris@open1x.org
 *
 **/
#include <openssl/ssl.h>
#include <string.h>

#ifndef WINDOWS
#include <strings.h>
#include <stdint.h>
#else
#define uint8_t unsigned char
#define u_int unsigned int
#endif

/**
 *  \brief  Take a character string, and put null characters in it to create a unicode
 *          string.
 *
 *  @param[in] non_uni   The non-unicode string that will be converted.
 *  
 *  \retval ptr   A pointer to the newly converted unicode string.
 *  \retval NULL   An error.
 **/
char *to_unicode(char *non_uni)
{
	char *retUni;
	int i;

	if (!non_uni) {
		printf("Invalid value passed in to to_unicode()! (%s:%d)\n",
		       __FUNCTION__, __LINE__);
		return NULL;
	}

	retUni = (char *)malloc((strlen(non_uni) + 1) * 2);
	if (retUni == NULL) {
		printf("Error with MALLOC in to_unicode()! (%s:%d)\n",
		       __FUNCTION__, __LINE__);
		return NULL;
	}
	memset(retUni, 0x00, ((strlen(non_uni) + 1) * 2));

	for (i = 0; i < strlen(non_uni); i++) {
		retUni[(2 * i)] = non_uni[i];
	}
	return retUni;
}

/**
 * \brief Create the first hash needed to create an "NT password hash".
 *
 * @param[in] Password   A pointer to the ascii password to be hashed.
 * @param[out] PasswordHash   A pointer to a 16 byte buffer that will contain the resulting
 *                            password hash.
 **/
void NtPasswordHash(char *Password, char *PasswordHash)
{
	EVP_MD_CTX cntx;
	char retVal[20];
	int i, len;
	char *uniPassword;

	if ((!Password) || (!PasswordHash)) {
		printf("Invalid data passed in to NtPasswordHash()! (%s:%d)\n",
		       __FUNCTION__, __LINE__);
		return;
	}

	memset(retVal, 0x00, 20);
	uniPassword = to_unicode(Password);
	len = (strlen(Password)) * 2;

	EVP_DigestInit(&cntx, EVP_md4());
	EVP_DigestUpdate(&cntx, uniPassword, len);
	EVP_DigestFinal(&cntx, (uint8_t *) & retVal, (u_int *) & i);
	memcpy(PasswordHash, &retVal, 16);
	free(uniPassword);
}

int main(int argc, char *argv[])
{
	char pwd_hash[16];
	int i;

	if (argc <= 1) {
		printf("ntpwdhash <password>\n");
		return 255;
	}

	NtPasswordHash(argv[1], (char *)&pwd_hash);

	printf
	    ("Resulting hash value (copy and paste to Xsupplicant configuration)"
	     " :\n");

	for (i = 0; i < 16; i++) {
		printf("%02X", (unsigned char)pwd_hash[i]);
	}
	printf("\n");

	return 0;
}
