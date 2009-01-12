/**
 * EAP layer implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eap_sm.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __EAP_SM_H__
#define __EAP_SM_H__

#define EAP_UNKNOWN        0
#define EAP_DISABLED       1
#define EAP_INITIALIZE     2
#define EAP_IDLE           3
#define EAP_RECEIVED       4
#define EAP_GET_METHOD     5
#define EAP_METHOD         6
#define EAP_SEND_RESPONSE  7
#define EAP_DISCARD        8
#define EAP_IDENTITY       9
#define EAP_NOTIFICATION   10
#define EAP_RETRANSMIT     11
#define EAP_SUCCESS        12
#define EAP_FAILURE        13

#define NONE           0
#define EAP_FAIL       2
#define UNCOND_SUCC    3
#define COND_SUCC      4

// EAP method states
#define DONE           1
#define INIT           5
#define CONT           6
#define MAY_CONT       7

// A special state for EAP-FAST
#define PAC_EXPIRED	   8

typedef struct eap_type_data {
  void *eap_conf_data;       // Pointer to the configuration information for
                             // the EAP type we are going to use.

  void *eap_data;            // Pointer to EAP type specific state data.

  uint8_t methodState;
  uint8_t decision;
  uint8_t *eapReqData;
  uint8_t ignore;
  uint8_t eapKeyAvailable;
  uint8_t altAccept;
  uint8_t altReject;
  uint8_t credsSent;
  char *ident;
} eap_type_data;


// State machine variables defined by RFC 4137
typedef struct eap_sm_vars {

  // The state that our state machine is currently in.
  uint8_t eap_sm_state;

  // Variables from 4.1.1 (Lower Layer to Peer)

  uint8_t eapReq;
  uint8_t *eapReqData;
  uint8_t portEnabled; 
  uint8_t idleWhile;
  uint8_t eapRestart;
  uint8_t altAccept;
  uint8_t altReject;

  // Variables from 4.1.2 (Peer to Lower Layer)
  uint8_t eapResp;
  uint8_t eapNoResp;
  uint8_t eapSuccess;
  uint8_t eapFail;
  uint8_t *eapRespData;
  uint8_t *eapKeyData;
  uint8_t eapKeyAvailable;

  // "Constants" from 4.1.3
  //  uint8_t clientTimeout;

  // Peer State Machine Local Variables (4.3.1)
  uint8_t selectedMethod;
  uint8_t allowNotifications;
  uint8_t methodState;
  uint8_t lastId;
  uint8_t *lastRespData;
  uint8_t decision;

  // Short term variables (4.3.2)
  uint8_t rxReq;
  uint8_t rxSuccess;
  uint8_t rxFailure;
  uint8_t reqId;
  uint8_t reqMethod;
  uint8_t ignore;

  // The rest are not part of the defined state machine, but are useful
  // anyway.

  // Save the active EAP method data here.
  eap_type_data *active;
  char *ident;               // The EAP identity value we returned.
  struct config_eap_method *curMethods;  // Currently allowed methods.
  uint8_t phase;             // Set the phase we are using, so we can
                             // weed out EAP types that should only be run
                             // in certain phases.
  uint8_t lastMethod;
  uint8_t eapKeyLen;

  // credsSent should be set to TRUE once an EAP method has sent the actual
  // user's credentials.  (In two phase EAP methods, this would mean that
  // it would be set to TRUE by the inner method.)  When credsSent is set 
  // TRUE, an EAP-Failure will result in the memory cached credentials being
  // flushed, and the user being prompted for a password again.
  uint8_t credsSent;

} eap_sm;

// Different types of credentials that an EAP method might require.
//   The main purpose of these values is to allow the supplicant to determine
//	 if some set of existing stored credentials can be used for an authentication.
#define EAP_REQUIRES_USERNAME	BIT(0)
#define EAP_REQUIRES_PASSWORD	BIT(1)
#define EAP_REQUIRES_PIN		BIT(2)
#define EAP_REQUIRES_TOKEN_CODE	BIT(3)

struct rfc4137_eap_handler {
  int eap_type_handler;
  char *eapname;
  void (*eap_check)(eap_type_data *);
  void (*eap_process)(eap_type_data *);
  uint8_t *(*eap_buildResp)(eap_type_data *);
  uint8_t (*eap_isKeyAvailable)(eap_type_data *);
  uint8_t *(*eap_getKey)(eap_type_data *);
  uint8_t (*eap_getKeyLen)(eap_type_data *);
  int (*eap_cred_requirements)(void *);
  char *(*eap_get_special_username)(void *);		// Allow an EAP method to return a username that we will force to be used.
  void (*eap_deinit)(eap_type_data *);
};

#define EAP_REQUEST_PKT       1
#define EAP_RESPONSE_PKT      2
#define EAP_SUCCESS_PKT       3
#define EAP_FAILURE_PKT       4

#define EAP_TYPE_IDENTITY 1
#define EAP_TYPE_NOTIFY   2
#define EAP_TYPE_NAK      3

#define EAP_REQUEST_ID     1
#define EAP_REQUEST_AUTH   2
#define EAP_REQUEST_NOTIFY 3

#define NO_EAP_AUTH      -1

int eap_sm_init(eap_sm **);
int eap_sm_run(eap_sm *);
void eap_sm_deinit(eap_sm **);
void eap_sm_cleanup(eap_sm *);
void eap_sm_force_init(eap_sm *);
void eap_sm_dump_state(eap_sm *);
int eap_sm_find_method(uint8_t);
int eap_sm_creds_required(uint8_t, void *);

#endif
