/**
 * Hold information about each interface, state machine, and others.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file profile.h
 *
 * \author Chris.Hessing@utah.edu
 *
 */

#ifndef _PROFILE_H_
#define _PROFILE_H_

#include <sys/types.h>
#include <stdint.h>

// Define some things to make the code more readable.
#define TRUE  1
#define FALSE 0

// Define our supplicant status values
#define UNAUTHORIZED 0
#define AUTHORIZED   1
#define AUTO         2

#define FORCE_AUTHORIZED   0
#define FORCE_UNAUTHORIZED 1

typedef unsigned int FDEPTH;

struct dot1x_state {
	// These variables are per the 802.1x documentation.
	/* These are defined as constants, but don't have to be.  We may want */
	/* the option of changing them in the future. */
	char authPeriod;
	char heldPeriod;
	char startPeriod;
	char maxStart;

	/* per 802.1x-REV-d11 section 8.2.2.1 */
	char authWhile;
	char aWhile;
	char heldWhile;
	char quietWhile;
	char reAuthWhen;
	char startWhen;

	/* per 802.1x-REV-d11 section 8.2.2.2 */
	char eapFail;
	char eapolEap;
	char eapSuccess;
	char keyAvailable;
	char keyDone;
	char keyRun;
	char keyTxEnabled;
	char portControl;
	char suppPortStatus;
	char portValid;
	char suppAbort;
	char suppFail;
	char suppStart;
	char suppSuccess;
	char suppTimeout;
	char initialize;
	char portEnabled;

	/* per 802.1x-REV-d11 section 8.2.11.1.1 */
	char eapRestart;
	char logoffSent;
	char sPortMode;
	char startCount;
	char userLogoff;

	/* per 802.1X-REV-d11 section 8.2.12.1.1 */
	char eapNoResp;
	char eapReq;
	char eapResp;

	/* per 802.1x-REV-d11 section 8.2.3.1.1 port timers */
	char tick;

	/* per 802.1x-REV-d11 section 8.2.7.1.1 Key recieve */
	char rxKey;

	// This isn't in the spec, but is useful.
	char curState;
	char beCurState;
	char wpaCurState;
	char wpaLastState;

  /** This is to contain the last type of EAP packet we saw.  It's only
   *  functional purpose is to allow us to give the user some sort of error
   *  message about what might be wrong with the connection.  (i.e. If the
   *  last EAP message we got was a Request ID, and we get a TIMEOUT, it means
   *  we attempted to send a Response ID, and for some reason the AP ignored
   *  us.)
   */
	char lastEapType;

  /** Keep track of the key length that is used in dynamic WEP.  (Basically,
   *  we want to know the shortest unicast and shortest broadcast keys the
   *  AP sent.)  This servers no functional purpose, but will allow us to warn
   *  the user that some cards/drivers/APs are not happy using different length
   *  WEP keys.
   */
	char unicastKeyLen;

  /** \copydoc unicastKeyLen */
	char broadcastKeyLen;

	/* per 802.11i-D3 section 8.5.5.2 */
	char DeauthenticationRequest;
	char AuthenticationRequest;
	char AuthenticationFailed;
	char EAPOLKeyReceived;
	char IntegrityFailed;
	char MICVerified;
	char Counter;
	char *SNonce;
	char *PTK;
	char *TPTK;
	char *GTK;
	char *PMK;

  /** This contains the number of MIC failures the driver has reported.
   *  Once it reaches 2, we should enable countermeasures.
   */
	char MICfailures;

	uint8_t replay_counter[8];
};

/**
 *  Structure to store data of a specific interface
 */
struct interface_data {
  /** The name of this interface.
   */
	char *intName;

	int intIndex;

  /** This is a global tick, not a state machine tick!
   */
	uint8_t tick;

  /**
   * Some drivers behave weirdly, so we need to keep track of which one
   * we are using, in case it ends up causing us problems.
   */
	char driver_in_use;

  /** 
   * A pointer to some data that the OS specific frame handler will
   * use.  (Such as a socket.)
   */
	void *sockData;

  /**
   * Bitmap of true/false values. (For the interface.)
   */
	FDEPTH flags;

  /**
   * Encryption/authentication methods supported by the interface.
   */
	uint32_t enc_capa;

	// Values for flags defined above.  If you add/remove/change any of them
	// update profile_dump_flags in profile.c!
#define IS_WIRELESS   0x0001   /**< Interface is a wireless interface. */
#define WAS_DOWN      0x0002
#define SCANNING      0x0004   /**< Interface is scanning for an access
                                 * point 
				 */
#define ALLMULTI      0x0008

#define ROAMED        0x0040	/**< Have the keys been reset to all 0s?    */
#define ONEDOWN       0x0080	/**< Support for drivers where events come in 
                                 * with a different interface index than the 
                                 * one for the interface we are working with. 
                                 * (i.e. hostap)
				 */

#define TERM_ON_FAIL  0x0200	/**< Terminate when we reach a failure.    */
#define DONT_USE_TEMP 0x0400	/**< Disable use of the TEMP flag in key 
                                 *   requests.
				 */
#define DONT_KEY      0x0800	/**< This flag indicates that we shouldn't 
                                 * attempt to set keys.  It should be used
                                 * when the configuration indicates that we
                                 * are using either static, or no encryption.
				 */
#define CLEAR_IPC     0x1000	/**< Clear the unix domain socket if -s was
                                 * passed.
				 */
#define PASV_SCANNING 0x2000	/**< Are we doing a passive scan. */
#define SSID_SET      0x4000	/**< Did we initiate the SSID set? */

  /** Source MAC address. */
	char source_mac[6];

  /** Destination MAC address. */
	char dest_mac[6];

  /** The current SSID we are using. */
	char *cur_essid;

  /** State machine info */
	struct dot1x_state *statemachine;

  /**
   * Hold any keying material generated by an EAP type.  Should be NULL
   * if there isn't any!
   */
	uint8_t *keyingMaterial;

  /**
   * Normal EAP methods will return 32 bytes of keying material.  Goofy
   * EAP methods like LEAP use less material.
   */
	char keyingLength;

  /** Temporary password. */
	char *tempPassword;

#define SUPP_WEP     0x01
#define SUPP_WPA     0x02
#define SUPP_RSN     0x04

  /** The WPA IE for this AP. */
	uint8_t *wpa_ie;

  /** The RSN IE for this AP. */
	uint8_t *rsn_ie;

	uint8_t sendframe[1520], recvframe[1520];
	int send_size, recv_size;
};

int init_interface_struct(struct interface_data *, char *);
void destroy_interface_struct(struct interface_data *);
void profile_dump_flags(struct interface_data *);
char config_build(struct interface_data *, char *);
int config_set_globals(struct interface_data *);

#endif
