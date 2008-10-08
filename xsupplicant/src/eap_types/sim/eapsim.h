/*******************************************************************
 * EAPSIM Header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapsim.h
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/

#ifndef _EAP_SIM_H_
#define _EAP_SIM_H_

#ifdef EAP_SIM_ENABLE

// These are defined in section 18 of Haverinen-08
// EAP-SIM Subtype values.
#define SIM_START            10
#define SIM_CHALLENGE        11
#define SIM_NOTIFICATION     12
#define SIM_REAUTHENTICATION 13

// EAP-SIM Subtype Attribute values
#define AT_RAND               1
#define AT_PADDING            6
#define AT_NONCE_MT           7
#define AT_MAC_SRES           9
#define AT_PERMANENT_ID_REQ  10
#define AT_MAC               11
#define AT_NOTIFICATION      12
#define AT_ANY_ID_REQ        13
#define AT_IDENTITY          14
#define AT_VERSION_LIST      15
#define AT_SELECTED_VERSION  16
#define AT_FULLAUTH_ID_REQ   17
#define AT_COUNTER           19
#define AT_COUNTER_TOO_SMALL 20
#define AT_NONCE_S           21

#define AT_IV               129
#define AT_ENCR_DATA        130
#define AT_NEXT_PSEUDONYM   132
#define AT_NEXT_REAUTH_ID   133

// These are values that can be returned by AT_NOTIFICATION// They are defined in section 16. (Section says 1024 has been defined too,
//  but I can't located the definition. ;)
#define USER_DENIED          1026
#define USER_NO_SUBSCRIPTION 1031

// The highest version of SIM we support...
#define EAPSIM_MAX_SUPPORTED_VER     1

struct triplets {
  unsigned char random[16];
  unsigned char response[4];
  unsigned char ckey[8];
};

struct eaptypedata {
  int workingversion;
  int numrands;
  char *nonce_mt;
  char *verlist;
  int verlistlen;
  struct triplets triplet[3];
  char *keyingMaterial;
  SCARDCONTEXT scntx;
  SCARDHANDLE shdl;
  char card_mode;
  char *readers;
  uint8_t *response_data;
  uint16_t response_size;
};  

#ifdef WINDOWS
#pragma pack(1)

struct typelength {
  uint8_t type;
  uint8_t length;
};

struct typelengthres {
  uint8_t type;
  uint8_t length;
  uint16_t reserved;
};

#pragma pack()
#else

struct typelength {
  uint8_t type;
  uint8_t length;
}  __attribute__((__packed__));

struct typelengthres {
  uint8_t type;
  uint8_t length;
  uint16_t reserved;
}  __attribute__((__packed__));

#endif

// Get the IMSI as the username.
int eapsim_get_username(context *ctx);

void eapsim_check(eap_type_data *);
void eapsim_process(eap_type_data *);
uint8_t *eapsim_buildResp(eap_type_data *);
uint8_t eapsim_isKeyAvailable(eap_type_data *);
uint8_t *eapsim_getKey(eap_type_data *);
void eapsim_deinit(eap_type_data *);

#endif
#endif
