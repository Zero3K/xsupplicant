/**
 * Hold information about each interface, state machine, and others.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file context.h
 *
 * \author chris@open1x.org
 */

#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#ifndef SMARTPHONE
#include <sys/types.h>
#endif

#ifndef WINDOWS
#include <stdint.h>
#else
#include "xsup_common.h"
#endif

#include "libxsupconfig/xsupconfig_structs.h"

#ifdef HAVE_TNC
#include "libtnctncc.h"
#endif

// Define our supplicant status values
#define UNAUTHORIZED 0
#define AUTHORIZED   1
#define AUTO         2

#define FORCE_AUTHORIZED   0
#define FORCE_UNAUTHORIZED 1

typedef uint8_t FDEPTH;

///< A PMKSA is made up of the following elements.  (Defined in section 8.4.1.1 of the 802.11 standard.)
typedef struct _pmksa_cache_element {
	struct _pmksa_cache_element *next;	///< The next PMKSA in the list.

	uint8_t pmkid[16];	///< According to section 8.5.1.2 of the 802.11 standard, a PMKID is 128 bits.
	uint8_t authenticator_mac[6];	///< The MAC address of the authenticator this PMKID is tied to.
	uint8_t *pmk;		///< The PMK for this SA.
	uint16_t lifetime;	///< Lifetime (in seconds) of a key that we have not seen the AP beacon for.
	uint8_t akmp;		///< The authentication and key management protocol used for this PMKSA.
	char *ssid;		///< The SSID this PMKSA is valid for.
} pmksa_cache_element;

typedef struct dot1x_state {
	// These variables are per the 802.1x documentation.
	/* These are defined as constants, but don't have to be.  We may want */
	/* the option of changing them in the future. */
	uint8_t authPeriod;
	uint8_t heldPeriod;
	uint8_t startPeriod;
	uint8_t maxStart;

	/* per 802.1x-REV-d11 section 8.2.2.1 */
	uint8_t authWhile;
	uint8_t aWhile;
	uint8_t heldWhile;
	uint8_t quietWhile;
	uint8_t reAuthWhen;
	uint8_t startWhen;

	/* per 802.1x-REV-d11 section 8.2.2.2 */
	uint8_t eapFail;
	uint8_t eapolEap;
	uint8_t eapSuccess;
	uint8_t keyAvailable;
	uint8_t keyDone;
	uint8_t keyRun;
	uint8_t keyTxEnabled;
	uint8_t portControl;
	uint8_t suppPortStatus;
	uint8_t portValid;
	uint8_t suppAbort;
	uint8_t suppFail;
	uint8_t suppStart;
	uint8_t suppSuccess;
	uint8_t suppTimeout;
	uint8_t initialize;
	uint8_t portEnabled;	// This represents the OPERATIONAL state of the MAC.

	/* per 802.1x-REV-d11 section 8.2.11.1.1 */
	uint8_t eapRestart;
	uint8_t logoffSent;
	uint8_t sPortMode;
	uint8_t startCount;
	uint8_t userLogoff;

	/* per 802.1X-REV-d11 section 8.2.12.1.1 */
	uint8_t eapNoResp;
	uint8_t eapReq;
	uint8_t eapResp;

	/* per 802.1x-REV-d11 section 8.2.3.1.1 port timers */
	uint8_t tick;

	/* per 802.1x-REV-d11 section 8.2.7.1.1 Key recieve */
	uint8_t rxKey;

	/* This isn't in the spec, but is useful. */
	uint8_t curState;
	uint8_t beCurState;

  /** This is to contain the last type of EAP packet we saw.  It's only
   * functional purpose is to allow us to give the user some sort of error
   * message about what might be wrong with the connection.  (i.e. If the
   * last EAP message we got was a Request ID, and we get a TIMEOUT, it means
   * we attempted to send a Response ID, and for some reason the AP ignored
   * us.)
   */
	uint8_t lastEapType;

	/* per 802.11i-D3 section 8.5.5.2 */
	uint8_t DeauthenticationRequest;
	uint8_t AuthenticationRequest;
	uint8_t AuthenticationFailed;
	uint8_t EAPOLKeyReceived;
	uint8_t IntegrityFailed;
	uint8_t MICVerified;
	uint8_t Counter;
	uint8_t *SNonce;
	uint8_t *PTK;
	uint8_t *TPTK;
	uint8_t *GTK;
	uint8_t *PMK;

  /** Not defined in the standard for the state machine.  This value tracks
   *  the uptime that the interface changed to AUTHENTICATED state.  If the
   *  value is 0, then you should check the current state to see if we are
   *  actually authenticated or not.
   */
	uint64_t to_authenticated;
	uint64_t last_reauth;

} eapol_sm;

/** NOTE : The WIRELESS_ flags, and WIRELESS_SM_ flags live in the same flags bytes!  Make
    sure they don't overlap, or you will end up with weird results!  **/

// The WIRELESS_ flags belong in the first 8 bits.
#define WIRELESS_SCANNING      BIT(0)	/**< Interface is scanning for an access point. */
#define WIRELESS_PASV_SCANNING BIT(1)	/**< Are we doing a passive scan. */
#define WIRELESS_ROAMED        BIT(2)	/**< We moved to a new AP. */
#define WIRELESS_ONEDOWN       BIT(3)	/**< Support for drivers where events come in 
										 * with a different interface index than the 
										 * one for the interface we are working with. 
										 * (i.e. hostap)
										 */
#define WIRELESS_DONT_USE_TEMP BIT(4)	/**< Disable use of the TEMP flag in key 
										 * requests.
										 */
#define WIRELESS_ZEROS_ON_ROAM BIT(5)	/**< Do we need to reset keys to 0s when we
										 * roam?
										 */
#define WIRELESS_CHECKED       BIT(6)	/**< We have checked the available scan list to see
										 * if there were any usable SSIDs.  If there weren't 
										 * this flag will keep us from looping and doing the
										 * checks all over again.
										 */

 /**
  *  Flags that are used in the wireless state machine.
  **/
// The WIRELESS_SM_ flags belong in the second 8 bits.
#define WIRELESS_SM_INIT               BIT(7)
#define WIRELESS_SM_PORT_ACTIVE        BIT(10)	// Is the port alive, and ready to go?
#define WIRELESS_SM_SSID_CHANGE        BIT(11)	// Did we just change SSIDs?
#define WIRELESS_SM_DOING_PSK		   BIT(12)	// We are doing WPA(2)-PSK.  This can be used on OSes that
												//    don't return a reason code in a disassociate event.
#define WIRELESS_SM_DISCONNECT_REQ     BIT(13)	// We set this when the user has requested a disconnect.  (So that we don't start the timer to prompt them to connect.)
#define WIRELESS_SM_ASSOCIATED         BIT(14)
#define WIRELESS_AP_DROPSOUT_CONNECT_TO_SAME_ESSID BIT(15) // this flag is set when ap drops the connection and trying to connect to same essid

/**
 * Different values for the type of association that was used to connect to a 
 *  wireless network.
 **/
#define ASSOC_TYPE_UNKNOWN      0
#define ASSOC_TYPE_OPEN         1
#define ASSOC_TYPE_SHARED       2
#define ASSOC_TYPE_LEAP         3
#define ASSOC_TYPE_WPA1         4
#define ASSOC_TYPE_WPA2         5

/**
 * Linux specific WPA defines
 **/
#define WPA2_IE_LENGTH_WITH_PMKID 40
#define ASSOCREQIE_LENGTH_WITH_PMKID 54
#define SIOCSIWPMKSA_NOT_SUPPORTED 95

/**
 * Information needed if this interface is wireless.
 **/
typedef struct {
	uint8_t state;
	uint8_t driver_in_use;	// Will depend on the OS in use.  0 == default.
	uint32_t enc_capa;
	uint16_t flags;
	uint8_t assoc_type;	// One of the association types above.
	uint8_t *wpa_ie;
	uint8_t *rsn_ie;
	uint8_t strength;	// 0 - 100% used to avoid sending signal strength events that aren't needed.
	char *cur_essid;
        double freq;
	uint8_t cur_bssid[6];
	struct found_ssids *ssid_cache;	// All SSIDs found on this interface.

	/** Keep track of the key length that is used in dynamic WEP.  (Basically,
     * we want to know the shortest unicast and shortest broadcast keys the
     * AP sent.)  This serves no functional purpose, but will allow us to warn
     * the user that some cards/drivers/APs are not happy using different length
     * WEP keys.
     **/
	uint8_t unicastKeyLen;

    /** \copydoc unicastKeyLen */
	uint8_t broadcastKeyLen;

	uint8_t pairwiseKeyType;
	uint8_t groupKeyType;

	struct found_ssids *temp_ssid;

  /** This contains the number of MIC failures the driver has reported.
   * Once it reaches 2, we should enable countermeasures.
   */
	uint8_t MICfailures;

	uint8_t replay_counter[8];

	uint8_t pmkids_supported;	///< The number of PMKIDs support in the association frames of this interface.  (Should be 0 if PMK caching isn't allowed.)
	pmksa_cache_element *pmksa_cache;
	uint8_t *pmkid_used;
#if defined(LINUX) || defined(__APPLE__)
	int okc;
    int ielen;
    uint8_t *pmkid_ptr;
    uint8_t pmksa_add_ioctl_supported;
#endif

} wireless_ctx;

/**
 * Different types of interfaces that we currently recognize.  Interface
 * numbers should be defined as follows :
 *
 * 0 - 802.3 Ethernet Interface
 * 1 - 802.11 Ethernet Interface (wireless)
 * 2-49 - Reserved
 * 50 - IPC Interface
 * 51-200 - Reserved
 * 201-255 - Vendor Specific
 **/
typedef enum {
	ETH_802_3_INT = 0,
	ETH_802_11_INT,
	IPC_INT = 50
} int_type;

/**
 * Values to be used with the flags field of the base context structure.
 *  Flags that are specific to wireless should be used in the wireless
 *  subcontext!
 **/
#define WAS_DOWN			BIT(0)
#define ALLMULTI			BIT(1)	 /**< Enable allmulti on this interface. */
#define TERM_ON_FAIL		BIT(2)	 /**< Terminate when we reach a failure. */
#define FORCED_CONN			BIT(3)	 /**< The connection has been set by an outside source.  (Probably the UI.) */
#define INT_GONE			BIT(4)	 /**< The interface has been removed from the machine already.  (So don't do any of the interface deinit stuff, just clear the context.) */
#define INT_IGNORE			BIT(5)	 /**< The interface is not currently being used, or managed. */
#define INT_REPROCESS		BIT(6)	 /**< We are reprocessing a frame on this interface, so skip ahead to the highest layer. */
#define DHCP_RELEASE_RENEW	BIT(7)	 /**< The next DHCP event should be a release/renew, and not just a renew. */

/**
 * Structure to store context information, mostly related to a specific
 * interface.
 **/
typedef struct context_data {
  /** The type of interface that this is.  (See definition above.)
   */
	int_type intType;

	uint8_t eapol_version;	// The last EAPoL version we got from the authenticator.

  /** The name of this interface.
   */
	char *intName;

  /** A description of the interface for situations where the intName above doesn't
   *  provide any useful information.  (I'm looking at you Windows! ;)
   */
	char *desc;

  /** This is a global tick, not a state machine tick!
   */
	uint8_t tick;

  /**
   * A pointer to some data that the OS specific frame handler will
   * use.  (Such as a socket.)
   **/
	void *sockData;

  /**
   *   Bitmap of true/false values. (For the interface.)
   **/
	FDEPTH flags;

  /** Source MAC address. (Local machine) */
	char source_mac[6];

  /** Destination MAC address. (Authenticator) */
	char dest_mac[6];

  /** Interface type information -- This is an opaque value whose **/
  /** meaning is defined by the value of 'intType' above. **/
	void *intTypeData;

  /** State machine info */
	struct dot1x_state *statemachine;

  /** EAP state machine */
	struct eap_sm_vars *eap_state;

  /** Timers for this interface. (Right now, this is only for wireless devices, */
  /**   but, it may be needed at a higher level, which is why it isn't defined  */
  /**   as part of the wireless context.                                        */
	struct timer_data *timers;

  /** Pointers to the connections and profiles in memory that this context is */
  /** using.                                                                  */
	char *conn_name;	///<  The connection name this context is using, so we can rebind correctly.
	config_connection *conn;
	config_profiles *prof;

	uint32_t auths;		///< The number of auths that have completed on this interface. Since we last cleared it.  (Used to determine if we need to renew a DHCP address.)

#ifdef HAVE_TNC
	libtnc_tncc_connection *tnc_data;	///< The TNC connection data.
#endif

	void *pwd_callback_data;	///< Data to be used in the password callback.  (Currently only used in EAP-GTC.)
	void (*pwd_callback) (void *);	///< The callback to be called to finish an authentication when it has been paused to ask for a password.
	void (*p2_pwd_callback) (void *, struct eap_sm_vars *, uint8_t **,
				 uint16_t *);

	uint8_t *sendframe, *recvframe;
	uint16_t send_size, recv_size;

#ifdef LINUX
	void *drv_handle;	/// XXX This needs to be moved, it doesn't belong here!
#endif

} context;

int context_init(context *, char *);
void context_destroy(context *);
void context_dump_flags(context *);
void context_rebind_all();
char config_build(context *, char *);
int context_config_set_globals(context *);
void context_init_ints_from_conf(context ** ctx);
int context_init_interface(context **, char *, char *, char *, FDEPTH);
context *context_allocate(context ** ctx);
int context_create_wireless_ctx(wireless_ctx **, uint8_t);
int context_destroy_wireless_ctx(wireless_ctx ** dest_wctx);
void context_disconnect(context * ctx);

#endif
