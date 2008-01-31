/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapleap.h
 **/
#ifndef EAPLEAP_H
#define EAPLEAP_H

#ifndef WINDOWS
#include <netinet/in.h>
#endif

#include "../../context.h"

struct leap_requests {
  uint8_t version;
  uint8_t reserved;  //unused field
  uint8_t count;  
  uint8_t randval[8];
  uint8_t name[5];   
};

struct leap_responses {
  uint8_t version;
  uint8_t reserved;  //unused field
  uint8_t count;
  uint8_t randval[24];
  uint8_t name[5];
};

struct leap_challenges {
  uint8_t pc[8];
  uint8_t pr[24];
  uint8_t apc[8];
  uint8_t apr[24];
};  

struct leap_data {
  char *keyingMaterial;
  struct leap_requests *leaprequest;
  struct leap_challenges *leapchallenges;
  int eapsuccess;
  char *password;
  uint8_t *result;
  uint16_t result_size;
  uint8_t eaptype;
};

  
void eapleap_check(eap_type_data *);
void eapleap_process(eap_type_data *);
uint8_t *eapleap_buildResp(eap_type_data *);
uint8_t eapleap_isKeyAvailable(eap_type_data *);
uint8_t *eapleap_getKey(eap_type_data *);
uint8_t eapleap_getKey_len(eap_type_data *);
void eapleap_deinit(eap_type_data *);

#endif
