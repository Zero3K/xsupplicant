%{
/*******************************************************************
 * Grammar for configuration file
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * File: config_grammar.y
 *
 * Authors: bdpayne@cs.umd.edu, npetroni@cs.umd.edu, Chris.Hessing@utah.edu
 *
 * $Id: config_grammar.y,v 1.13 2006/10/05 22:23:49 chessing Exp $
 * $Date: 2006/10/05 22:23:49 $
 * $Log: config_grammar.y,v $
 * Revision 1.13  2006/10/05 22:23:49  chessing
 * Added new association option to the config file, and attempt to associate using methods other than open system.
 *
 * Revision 1.12  2006/06/01 22:49:49  galimorerpg
 * Converted all instances of u_char to uint8_t
 * Fixed a bad #include in the generic frame handler.
 *
 * Revision 1.11  2006/05/31 05:10:51  chessing
 * Beginnings of EAP-TTLS-EAP-MD5, and added internet draft for EAP-TTLS to doc/standards.
 *
 * Revision 1.10  2006/05/26 22:04:58  chessing
 * Fixed some memory access errors, and cleaned up some wext stuff that was causing issues with the madwifi driver in wext mode.
 *
 * Revision 1.9  2006/05/17 22:18:10  chessing
 * A couple of small changes to Xsupplicant, and some major changes to the GUI configuration/monitor tool.
 *
 * Revision 1.8  2006/05/13 05:56:44  chessing
 * Removed last pieces of code that relied on SIGALRM.  Active scan timeout is now configurable so that people that wish to hammer on their cards now have the option to do that. ;)
 *
 * Revision 1.7  2006/04/17 03:56:23  chessing
 * Added some support to enable/disable TNC support both via the configuration file, and via IPC.
 *
 * Revision 1.6  2006/03/08 00:16:04  chessing
 * Fixed EAP hints code to work correctly when the request ID packet is padded out with null bytes.  (Observed in Aruba APs.)  Some changes/fixes for the EAP-AKA module.
 *
 * Revision 1.5  2006/02/23 22:26:50  chessing
 * Fix for bug id #1415020.  'Building Xsupplicant 1.2.3 Fails on FC4'.
 *
 * Revision 1.4  2006/01/03 04:02:35  chessing
 * Added the ability to store the PEAP password in a hashed format.  (Basically, an MS-CHAPv1 hash.)  Also added an 'ntpwdhash' program to the tools directory that will convert a cleartext password in to a hash that can be copied to the configuration file.
 *
 * Revision 1.3  2005/11/10 04:56:54  chessing
 * Added patch from Ben Gardner to add support for setting a specific WEP key prior to attempting to associte.  (With a few slight modifications by me to make it fit in the current CVS code, and get it supported in config-parse.)  Added patch from Pekka Savola to fix some header ordering issues, and a potential buffer overflow.
 *
 * Revision 1.2  2005/10/26 18:56:12  chessing
 * Some build fixes and small updates.
 *
 * Revision 1.1  2005/10/17 00:15:55  chessing
 * Moved the config parsing routines out to a new library called libxsupconfig.a, so that it will be easier to create third-party tools that can easily parse a config.
 *
 * Revision 1.65  2005/10/14 02:26:17  shaftoe
 * - cleanup gcc 4 warnings
 * - (re)add support for a pid in the form of /var/run/xsupplicant.<iface>.pid
 *
 * -- Eric Evans <eevans@sym-link.com>
 *
 * Revision 1.64  2005/09/08 16:27:01  chessing
 * Some small updates to the new state machine code.  First attempt at an auto association mode.  (It mostly works. ;)
 *
 * Revision 1.63  2005/08/25 02:20:20  chessing
 * Some cleanup in xsup_debug.c, added the ability to wait for an interface to come up if it is down when Xsupplicant is started.  Roughed in the ability to choose between having Xsupplicant auto associate you, or allow you to set the ssid manually.  The stale key timer can now be set in the config file.  The association timeout can be set in the config file, and will also be used once the functionality is in place to attempt to guess the key settings needed for association, as well as the functionality to auto associate.
 *
 * Revision 1.62  2005/08/20 19:06:53  chessing
 * Patch from Carsten Grohmann to fix a few things in xsup_get_state.c.  Also added the ability to define an empty network clause, that will set the card in to encryption disabled mode.  From there, anything short of changing the SSID will be ignored by Xsupplicant.
 *
 * Revision 1.61  2005/08/18 03:19:04  chessing
 * Added the ability to define an SSID with static WEP keys.  When we switch to a network that has this type of configuration we will set the keys, and stop the various association timers.
 *
 * Revision 1.60  2005/08/12 03:34:06  chessing
 * Fix to the TLS implementation, should help avoid some of the weird 'block cipher pad' errors.  Also includes a partial implementation of the ability to use static WEP keys based on the SSID in use.
 *
 * Revision 1.59  2005/08/09 01:39:13  chessing
 * Cleaned out old commit notes from the released version.  Added a few small features including the ability to disable the friendly warnings that are spit out.  (Such as the warning that is displayed when keys aren't rotated after 10 minutes.)  We should also be able to start when the interface is down.  Last, but not least, we can handle empty network configs.  (This may be useful for situations where there isn't a good reason to have a default network defined.)
 *
 *******************************************************************/  
  
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
  
#include <profile.h>
#include "xsupconfig.h"
#include <xsup_err.h>
#include "xsup_debug.h"
#include "wpa.h"

#ifdef EAP_SIM_ENABLE
#include "winscard.h"
#endif

#ifdef USE_EFENCE
#include <efence.h>
#endif

#define CLEAN_EXIT cleanup_parse(); return XECONFIGPARSEFAIL

int yylex(void);  
int yyerror(char *err);

extern struct config_data *config_info;
extern int config_linenum;

extern int config_parse_debug;

struct config_data *tmp_config = NULL;

struct config_eap_tls *tmp_tls = NULL;
struct config_eap_md5 *tmp_md5 = NULL;
struct config_eap_ttls *tmp_ttls = NULL;
struct config_eap_leap *tmp_leap = NULL;
struct config_eap_mschapv2 *tmp_mschapv2 = NULL;
struct config_eap_peap *tmp_peap = NULL; 
struct config_eap_sim *tmp_sim = NULL;
struct config_eap_aka *tmp_aka = NULL;
struct config_wpa_psk *tmp_wpa_psk = NULL;
struct config_static_wep *tmp_static_wep = NULL;
struct config_static_wep *tmp_initial_wep = NULL;

struct config_pap *tmp_p2pap =NULL;
struct config_chap *tmp_p2chap = NULL;
struct config_mschap *tmp_p2mschap = NULL;
struct config_mschapv2 *tmp_p2mschapv2 = NULL;

struct config_network *tmp_network = NULL;



void set_current_tls() {
  if (tmp_tls == NULL) 
    initialize_config_eap_tls(&tmp_tls);
} 
void set_current_static_wep() {
  if (tmp_static_wep == NULL)
    initialize_config_static_wep(&tmp_static_wep);
}
void set_current_initial_wep() {
  if (tmp_initial_wep == NULL)
    initialize_config_static_wep(&tmp_initial_wep);
}
void set_current_md5() {
  if (tmp_md5 == NULL) 
    initialize_config_eap_md5(&tmp_md5);
} 
void set_current_ttls() {
  if (tmp_ttls == NULL) 
    initialize_config_eap_ttls(&tmp_ttls);
} 
void set_current_leap() {
  if (tmp_leap == NULL) 
    initialize_config_eap_leap(&tmp_leap);
} 
void set_current_mschapv2() {
  if (tmp_mschapv2 == NULL) 
    initialize_config_eap_mschapv2(&tmp_mschapv2);
} 
void set_current_peap() {
  if (tmp_peap == NULL) 
    initialize_config_eap_peap(&tmp_peap);
} 
void set_current_sim() {
  if (tmp_sim == NULL) 
    initialize_config_eap_sim(&tmp_sim);
} 

void set_current_aka() {
  if (tmp_aka == NULL)
    initialize_config_eap_aka(&tmp_aka);
}

void set_current_wpa_psk() {
  if (tmp_wpa_psk == NULL)
    initialize_config_wpa_psk(&tmp_wpa_psk);
}

void set_current_p2pap() {
  if (tmp_p2pap == NULL)
    initialize_config_pap(&tmp_p2pap);
}
void set_current_p2chap() {
  if (tmp_p2chap == NULL)
    initialize_config_chap(&tmp_p2chap);
}
void set_current_p2mschap() {
  if (tmp_p2mschap == NULL)
    initialize_config_mschap(&tmp_p2mschap);
}
void set_current_p2mschapv2() {
  if (tmp_p2mschapv2 == NULL)
    initialize_config_mschapv2(&tmp_p2mschapv2);
}

void set_current_config() {
  if (tmp_config == NULL) 
      initialize_config_data(&tmp_config);
} 

void set_current_globals() {
  set_current_config();
  if (!tmp_config->globals)
    initialize_config_globals(&(tmp_config->globals));
}   

void set_current_network() {
  if (tmp_network == NULL) 
    initialize_config_network(&tmp_network);
} 


void cleanup_parse()
{
  if (tmp_config)
    delete_config_data(&tmp_config);
  if (tmp_static_wep)
    delete_config_static_wep(&tmp_static_wep);
  if (tmp_initial_wep)
    delete_config_static_wep(&tmp_initial_wep);
  if (tmp_tls)
    delete_config_eap_tls(&tmp_tls);
  if (tmp_md5)
    delete_config_eap_md5(&tmp_md5);
  if (tmp_ttls)
    delete_config_eap_ttls(&tmp_ttls);
  if (tmp_leap)
    delete_config_eap_leap(&tmp_leap);
  if (tmp_mschapv2)
    delete_config_eap_mschapv2(&tmp_mschapv2);
  if (tmp_peap)
    delete_config_eap_peap(&tmp_peap);
  if (tmp_sim)
    delete_config_eap_sim(&tmp_sim);
  if (tmp_aka)
    delete_config_eap_aka(&tmp_aka);
  if (tmp_wpa_psk)
    delete_config_wpa_psk(&tmp_wpa_psk);
  if (tmp_p2pap)
    delete_config_pap(&tmp_p2pap);
  if (tmp_p2chap)
    delete_config_chap(&tmp_p2chap);
  if (tmp_p2mschap)
    delete_config_mschap(&tmp_p2mschap);
  if (tmp_p2mschapv2)
    delete_config_mschapv2(&tmp_p2mschapv2);
  if (tmp_network)
    delete_config_network(&tmp_network);
}



/* function to check if debug is on and if so print the message */
void parameter_debug(char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
#ifndef PARSE_DEBUG
  return;
#endif
  vprintf(fmt, ap);
  va_end(ap);
}

%}

%union {
        char    *str;
        int     num;
}


%token        TK_NETWORK_LIST
%token        TK_DEFAULT_NETNAME
%token<str>   TK_GENSTR
%token        TK_DEFAULT_INT
%token        TK_LOGFILE
%token        TK_LOG_FACILITY
%token        TK_AUTH_PERIOD
%token        TK_HELD_PERIOD
%token        TK_MAX_STARTS
%token        TK_STALE_KEY_TIMEOUT
%token        TK_ALLMULTI
%token        TK_IPC_GROUP
%token        TK_DESTINATION
%token        TK_BSSID
%token        TK_MULTICAST
%token        TK_SOURCE
%token        TK_AUTO
%token        TK_MANUAL
%token        TK_ASSOCIATION
%token        TK_ASSOC_TIMEOUT
%token        TK_ROAMING
%token        TK_FIRMWARE
%token        TK_XSUPPLICANT
%token        TK_PASSIVE_SCANNING
%token        TK_PASSIVE_TIMEOUT
%token        TK_SCAN_TIMEOUT
%token        TK_USE_EAP_HINTS
%token        TK_ALL
%token        TK_FRIENDLY_WARNINGS
%token        TK_TYPE
%token        TK_ALLOW_TYPES
%token        TK_FORCE_EAPOL_VER
%token        TK_WIRELESS
%token        TK_WIRED
%token        TK_CONTROL_WIRELESS
%token        TK_ASSOCIATION_TYPE
%token        TK_ASSOC_OPEN
%token        TK_ASSOC_SHARED
%token        TK_ASSOC_LEAP
%token        TK_WPA_GROUP_CRYPT
%token        TK_WPA_PAIRWISE_CRYPT
%token        TK_WEP40
%token        TK_TKIP
%token        TK_WRAP
%token        TK_CCMP
%token        TK_WEP104
%token        TK_ANY
%token        TK_PRIORITY
%token        TK_IDENTITY
%token<str>   TK_IDENTITY_VAL
%token        TK_DEST_MAC
%token<str>   TK_MACADDRESS
%token        TK_SSID
%token<str>   TK_SSID_VAL
%token        TK_USE_TNC
%token        TK_WPA_PSK
%token        TK_WPA_PSK_KEY
%token        TK_WPA_PSK_HEX_KEY
%token        TK_EAP_TLS
%token        TK_USER_CERT
%token        TK_USER_KEY
%token        TK_USER_KEY_PASS
%token        TK_SESSION_RESUME
%token        TK_CNCHECK
%token        TK_CNEXACT
%token        TK_ROOT_CERT
%token        TK_ROOT_DIR
%token        TK_CRL_DIR
%token        TK_CHUNK_SIZE
%token        TK_RANDOM_FILE
%token        TK_EAP_MD5
%token        TK_USERNAME
%token<str>   TK_USERNAME_VAL
%token        TK_PASSWORD
%token        TK_EAP_LEAP
%token        TK_EAP_TTLS
%token        TK_PHASE2_TYPE
%token        TK_PAP
%token        TK_CHAP
%token        TK_MSCHAP
%token        TK_MSCHAPV2
%token        TK_EAP_MSCHAPV2
%token        TK_MSCHAPV2_HASH_PWD
%token        TK_IAS_QUIRK
%token        TK_EAP_PEAP
%token        TK_PEAPV1_PROPER_KEYING
%token        TK_INNER_ID
%token        TK_EAP_SIM
%token        TK_EAP_AKA
%token        TK_AUTO_REALM
%token        TK_YES
%token        TK_NO
%token        TK_EAP_GTC
%token        TK_EAP_OTP

%token        TK_SMARTCARD
%token        TK_ENGINE_ID
%token        TK_OPENSC_SO_PATH
%token        TK_KEYID

%token        TK_STATIC_WEP
%token        TK_INITIAL_WEP
%token        TK_STATIC_KEY1
%token        TK_STATIC_KEY2
%token        TK_STATIC_KEY3
%token        TK_STATIC_KEY4
%token        TK_WEP_TX_KEY

%token<num>   TK_NUMBER
%token<str>   TK_UNQUOTED_STR
%token<str>   TK_PASS
%token<str>   TK_COMMAND
%token<str>   TK_QUOTED_STR


%%

configfile        : global_section network_section {
                     config_info = tmp_config;
                     tmp_config = NULL;
                  } 
                  | global_section { 
                      printf("Error: No networks defined.\n"); 
		      CLEAN_EXIT;
		    }
                  | network_section {
		      printf("Error: No globals defined.\n"); 
		      cleanup_parse();
		      return XECONFIGPARSEFAIL;
                    }
                  | error {
		    printf("General Parse error!\n");
 		      cleanup_parse();
		      return XECONFIGPARSEFAIL; }
                  ;

global_section    : global_section global_statement
                  | global_statement
                  ;

network_section   : network_section network_entry
                  | network_entry
                  ;

global_statement  : TK_NETWORK_LIST '=' TK_ALL {
                      set_current_globals();
                      parameter_debug("network_list: all\n");
		      // do nothing. leave null
                    } 
                  | TK_NETWORK_LIST '=' network_list {
		    // done below. nothing to do here
  		    }
                  | TK_DEFAULT_NETNAME '=' TK_UNQUOTED_STR {
 		     set_current_globals();
		     parameter_debug("Default network: \"%s\"\n", $3);
		     if (tmp_config->globals->default_net)
		       free($3);
		     else
		       tmp_config->globals->default_net = $3;
		  }
                  | TK_DEFAULT_NETNAME '=' TK_QUOTED_STR {
 		     set_current_globals();
		     parameter_debug("Default network: \"%s\"\n", $3);
		     if (tmp_config->globals->default_net)
		       free($3);
		     else
		       tmp_config->globals->default_net = $3;
		  }
                  | TK_FRIENDLY_WARNINGS '=' TK_YES {
		    set_current_globals();
		    parameter_debug("Friendly Warnings: YES\n");
		    UNSET_FLAG(tmp_config->globals->flags, 
			     CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS);
                    }
                  | TK_FRIENDLY_WARNINGS '=' TK_NO {
		    set_current_globals();
		    parameter_debug("Friendly Warnings: NO\n");
		    SET_FLAG(tmp_config->globals->flags,
			     CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS);
                    } 
                  | TK_FRIENDLY_WARNINGS '=' TK_UNQUOTED_STR {
		    set_current_globals();
		    printf("Invalid vale for \"friendly_warnings\" option! "
			   "defaulting to YES.\n");
		    parameter_debug("Friendly Warnings: Defaulting to YES"
				    " (Invalid value \"%s\")\n", $3);
                    UNSET_FLAG(tmp_config->globals->flags,
		             CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS);
                    }
                  | TK_ROAMING '=' TK_FIRMWARE {
                    set_current_globals();
                    parameter_debug("Firmware roaming.\n");
                    SET_FLAG(tmp_config->globals->flags, 
			     CONFIG_GLOBALS_FIRMWARE_ROAM);
                    }
                  | TK_ROAMING '=' TK_XSUPPLICANT {
                    set_current_globals();      
                    parameter_debug("Xsupplicant roaming.\n");
                    UNSET_FLAG(tmp_config->globals->flags, 
			       CONFIG_GLOBALS_FIRMWARE_ROAM);
                    }
                  | TK_ROAMING '=' TK_UNQUOTED_STR {
                    set_current_globals();
                    parameter_debug("Xsupplicant roaming.\n");
                    printf("Invalid setting for 'roaming' value.  "
                    	       "Defaulting to Xsupplicant based roaming.\n");
                    UNSET_FLAG(tmp_config->globals->flags, 
			       CONFIG_GLOBALS_FIRMWARE_ROAM);
                    }
                  | TK_PASSIVE_SCANNING '=' TK_YES {
                    set_current_globals();
                    parameter_debug("Passive Scanning : Yes\n");
                    SET_FLAG(tmp_config->globals->flags,
                             CONFIG_GLOBALS_PASSIVE_SCAN);
                    }
                  | TK_PASSIVE_SCANNING '=' TK_NO {
                    set_current_globals();
                    parameter_debug("Passive Scanning : No\n");
                    UNSET_FLAG(tmp_config->globals->flags,
	                       CONFIG_GLOBALS_PASSIVE_SCAN);
                    }
                  | TK_PASSIVE_SCANNING '=' TK_UNQUOTED_STR {
                    set_current_globals();
                    parameter_debug("Passive Scanning : Yes\n");
                    printf("Invalid setting for 'passive_scanning'."
	                         " Defaulting to yes.\n");
		    SET_FLAG(tmp_config->globals->flags,
			     CONFIG_GLOBALS_PASSIVE_SCAN);
                    }
                  | TK_USE_EAP_HINTS '=' TK_YES {
                    set_current_globals();
                    parameter_debug("Use EAP Hints : Yes\n");
                    UNSET_FLAG(tmp_config->globals->flags,
			       CONFIG_GLOBALS_NO_EAP_HINTS);
                    }
                  | TK_USE_EAP_HINTS '=' TK_NO {
                    set_current_globals();
                    parameter_debug("Use EAP Hints : No\n");
                    SET_FLAG(tmp_config->globals->flags,
			     CONFIG_GLOBALS_NO_EAP_HINTS);
                    }
                  | TK_USE_EAP_HINTS '=' TK_UNQUOTED_STR {
                    set_current_globals();
                    parameter_debug("Use EAP Hints : Yes\n");
                    printf("Invalid setting for 'use_eap_hints'."
	                         " Defaulting to yes.\n");
		    UNSET_FLAG(tmp_config->globals->flags,
			       CONFIG_GLOBALS_NO_EAP_HINTS);
                    }
                  | TK_PASSIVE_TIMEOUT '=' TK_NUMBER {
                    set_current_globals();
                    parameter_debug("Passive Scan Timer: %d\n", $3);
                    tmp_config->globals->passive_timeout = $3;
                    }
                  | TK_SCAN_TIMEOUT '=' TK_NUMBER {
		    set_current_globals();
		    parameter_debug("Scan timeout: %d\n", $3);
		    tmp_config->globals->active_timeout = $3;
		  }
                  | TK_LOGFILE '=' TK_UNQUOTED_STR {
		     set_current_globals();
		     parameter_debug("Logfile: \"%s\"\n", $3);
		     if (tmp_config->globals->logfile)
		       {
			 free($3);
			 tmp_config->globals->logfile = NULL;
		       }
		     else
		       tmp_config->globals->logfile = $3;
		    }
                  | TK_LOGFILE '=' TK_QUOTED_STR {
		    set_current_globals();
		    parameter_debug("Logfile: \"%s\"\n", $3);
		    if (tmp_config->globals->logfile)
		      {
			free($3);
			tmp_config->globals->logfile = NULL;
		      }
		    else
		      tmp_config->globals->logfile = $3;
		  }
                  | TK_DEFAULT_INT '=' TK_UNQUOTED_STR {
		    set_current_globals();
                    parameter_debug("Default Interface: \"%s\"\n", $3);
		    if (tmp_config->globals->default_int)
		      {
			free($3);
			tmp_config->globals->default_int = NULL;
		      }
		    else
		      tmp_config->globals->default_int = $3;
		    }
                  | TK_STALE_KEY_TIMEOUT '=' TK_NUMBER {
		    set_current_globals();
		    tmp_config->globals->stale_key_timeout = $3;
		    }
                  | TK_STALE_KEY_TIMEOUT '=' TK_UNQUOTED_STR {
		    set_current_globals();
		    printf("Invalid value for stale key "
				 "timer.  Leaving at the default of 10 minutes"
				 "!\n");
		    }
                  | TK_ASSOCIATION '=' TK_AUTO {
                    set_current_globals();
                    SET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_ASSOC_AUTO);
                  }
                  | TK_ASSOCIATION '=' TK_MANUAL {
                    set_current_globals();
                    UNSET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_ASSOC_AUTO);
                  }
                  | TK_ASSOCIATION '=' TK_UNQUOTED_STR {
                    set_current_globals();
                    printf("Invalid setting for 'association'! "
	                         "Leaving at default setting.\n");
                    UNSET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_ASSOC_AUTO);
                  }
                  | TK_ASSOC_TIMEOUT '=' TK_NUMBER {
                    set_current_globals();
                    tmp_config->globals->assoc_timeout = $3;
                  }
                  | TK_ASSOC_TIMEOUT '=' TK_UNQUOTED_STR {
                    set_current_globals();
                    printf("Invalid setting for association_timeout."
	                         " We will use the default setting.\n");
                  }
                  | TK_AUTH_PERIOD '=' TK_NUMBER {
		     set_current_globals();
		     if (!TEST_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_AUTH_PER)) {
		       SET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_AUTH_PER);
		       tmp_config->globals->auth_period = $3;
		     }
                    }
                  | TK_HELD_PERIOD '=' TK_NUMBER {
		     set_current_globals();
		     if (!TEST_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_HELD_PER)) {
		       SET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_HELD_PER);
		       tmp_config->globals->held_period = $3;
		     }
                    }
                  | TK_MAX_STARTS '=' TK_NUMBER {
		     set_current_globals();
		     if (!TEST_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_MAX_STARTS)) {
		       SET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_MAX_STARTS);
		       tmp_config->globals->max_starts = $3;
		     }
                    }
                  | TK_ALLMULTI '=' TK_YES {
		     set_current_globals();
		     SET_FLAG(tmp_config->globals->flags,
			      CONFIG_GLOBALS_ALLMULTI);
                    } 
                  | TK_ALLMULTI '=' TK_NO {
		     set_current_globals();
		     UNSET_FLAG(tmp_config->globals->flags,
				CONFIG_GLOBALS_ALLMULTI);
                    }
                  | TK_ALLMULTI '=' TK_UNQUOTED_STR {
                     printf("Unknown value for ALLMULTI = \"%s\"! Defaulting to YES! (Line : %d)\n", $3, config_linenum);
		     set_current_globals();
		     SET_FLAG(tmp_config->globals->flags,
			      CONFIG_GLOBALS_ALLMULTI);
                    }
                  | TK_IPC_GROUP '=' TK_UNQUOTED_STR {
		    set_current_globals();
		    if (!tmp_config->globals->ipc_group_name)
			  tmp_config->globals->ipc_group_name = $3;
			else
			  free($3);
                      }
                  | TK_DESTINATION '=' TK_AUTO {
		    set_current_globals();
		    tmp_config->globals->destination = DEST_AUTO;
                      }
                  | TK_DESTINATION '=' TK_BSSID {
		    set_current_globals();
		    tmp_config->globals->destination = DEST_BSSID;
                      }
                  | TK_DESTINATION '=' TK_MULTICAST {
		    set_current_globals();
		    tmp_config->globals->destination = DEST_MULTICAST;
                      }
                  | TK_DESTINATION '=' TK_SOURCE {
		    set_current_globals();
		    tmp_config->globals->destination = DEST_SOURCE;
                      }
                  | TK_DESTINATION '=' TK_UNQUOTED_STR {
		    printf("Invalid destination value = \"%s\"!  Defaulting to AUTO! (Line : %d)\n", $3, config_linenum);
                    set_current_globals();
                    tmp_config->globals->destination = DEST_AUTO;
                      }
                  | TK_LOG_FACILITY '=' TK_UNQUOTED_STR {
                    set_current_globals();
                    if (!tmp_config->globals->log_facility)
                          tmp_config->globals->log_facility = $3;
                    else
                      free($3);
                    }
                  ;

network_list      : network_list ',' TK_UNQUOTED_STR {
                       parameter_debug("network_list: \"%s\"\n", $3);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->allowed_nets,
							    $3))
			 free($3);
		       else 
			 config_string_list_add_string(&tmp_config->globals->allowed_nets,
						     $3);
                    }
                  | TK_UNQUOTED_STR { 
                       parameter_debug("network_list: \"%s\"\n", $1);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->allowed_nets,
							    $1))
			 free($1);
		       else 
			 config_string_list_add_string(&tmp_config->globals->allowed_nets,
						     $1);
                    }
		    | network_list ',' TK_QUOTED_STR {
                       parameter_debug("network_list: \"%s\"\n", $3);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->allowed_nets,
							    $3))
			 free($3);
		       else 
			 config_string_list_add_string(&tmp_config->globals->allowed_nets,
						     $3);
                    }
                  | TK_QUOTED_STR { 
                       parameter_debug("network_list: \"%s\"\n", $1);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->allowed_nets,
							    $1))
			 free($1);
		       else 
			 config_string_list_add_string(&tmp_config->globals->allowed_nets,
						     $1);
                    }
                  ;

network_entry     : TK_UNQUOTED_STR '{' network_statements '}' {
                      set_current_config();
		      tmp_network->name = $1;

		      // check if there is a networks field and that 
		      // the current tmp is not already listed
		      if ((!tmp_config->networks ||
			  !config_network_contains_net(tmp_config->networks,
						       tmp_network->name)) &&
			  config_allows_network(tmp_config, tmp_network->name))
		      {
			config_network_add_net(&(tmp_config->networks),
					       tmp_network);
		      }
		      // if we don't need it, delete it
		      else {
			delete_config_network(&tmp_network);
		      }
		      tmp_network = NULL;
                    }
                  | TK_NUMBER '{' network_statements '}' {
                      set_current_config();

		      tmp_network->name = (char *)malloc(100);
		      sprintf(tmp_network->name, "%d", $1);

		      // check if there is a networks field and that 
		      // the current tmp is not already listed
		      if ((!tmp_config->networks ||
			  !config_network_contains_net(tmp_config->networks,
						       tmp_network->name)) &&
			  config_allows_network(tmp_config, tmp_network->name))
		      {
			config_network_add_net(&(tmp_config->networks),
					       tmp_network);
		      }
		      // if we don't need it, delete it
		      else {
			delete_config_network(&tmp_network);
		      }
		      tmp_network = NULL;
                    }
                  | TK_QUOTED_STR '{' network_statements '}' {
		    set_current_config();
		    tmp_network->name = $1;

		      // check if there is a networks field and that 
		      // the current tmp is not already listed
		      if ((!tmp_config->networks ||
			  !config_network_contains_net(tmp_config->networks,
						       tmp_network->name)) &&
			  config_allows_network(tmp_config, tmp_network->name))
		      {
			config_network_add_net(&(tmp_config->networks),
					       tmp_network);
		      }
		      // if we don't need it, delete it
		      else {
			delete_config_network(&tmp_network);
		      }
		      tmp_network = NULL;
		    }
                  | TK_UNQUOTED_STR '{' '}' {
		    set_current_config();
		      set_current_network();

		      tmp_network->name = $1;
		      // check if there is a networks field and that 
		      // the current tmp is not already listed
		      if ((!tmp_config->networks ||
			  !config_network_contains_net(tmp_config->networks,
						       tmp_network->name)) &&
			  config_allows_network(tmp_config, tmp_network->name))
		      {
			config_network_add_net(&(tmp_config->networks),
					       tmp_network);
		      }
		      // if we don't need it, delete it
		      else {
			delete_config_network(&tmp_network);
		      }
		      tmp_network = NULL;
                    }
                  | TK_QUOTED_STR '{' '}' {
                      set_current_config();
		      set_current_network();

		      tmp_network->name = $1;
		      // check if there is a networks field and that 
		      // the current tmp is not already listed
		      if ((!tmp_config->networks ||
			  !config_network_contains_net(tmp_config->networks,
						       tmp_network->name)) &&
			  config_allows_network(tmp_config, tmp_network->name))
		      {
			config_network_add_net(&(tmp_config->networks),
					       tmp_network);
		      }
		      // if we don't need it, delete it
		      else {
			delete_config_network(&tmp_network);
		      }
		      tmp_network = NULL;
		    }
                  | TK_NUMBER '{' '}' {
                      set_current_config();
		      set_current_network();

		      tmp_network->name = (char *)malloc(100);
		      sprintf(tmp_network->name, "%d", $1);
		      // check if there is a networks field and that 
		      // the current tmp is not already listed
		      if ((!tmp_config->networks ||
			  !config_network_contains_net(tmp_config->networks,
						       tmp_network->name)) &&
			  config_allows_network(tmp_config, tmp_network->name))
		      {
			config_network_add_net(&(tmp_config->networks),
					       tmp_network);
		      }
		      // if we don't need it, delete it
		      else {
			delete_config_network(&tmp_network);
		      }
		      tmp_network = NULL;
		    }
                  ;

network_statements : network_statements network_parameter
                   | network_statements eap_type_statement
                   | network_parameter
                   | eap_type_statement
                   ;


network_parameter  : network_type_parameter
                   | network_priority
                   | network_use_tnc
                   | network_wpa_group_enc_type
                   | network_wpa_pairwise_enc_type
                   | network_force_eapol_ver
                   | network_identity_parameter
                   | network_dest_mac_parameter
                   | network_allow_parameter
                   | network_assoc_type
                   | network_control_wireless
                   ;

network_priority       : TK_PRIORITY '=' TK_NUMBER {
                           parameter_debug("Priority : %d\n", $3);
                           set_current_network();
                           tmp_network->priority = $3;
                         }
                       ;

network_type_parameter : TK_TYPE '=' TK_WIRELESS {
                           parameter_debug("Type: Wireless\n");
			   set_current_network();
			   if (tmp_network->type == UNSET)
			     tmp_network->type = WIRELESS;
                         }
                         | TK_TYPE '=' TK_WIRED {
                           parameter_debug("Type: Wired\n");
			   set_current_network();
			   if (tmp_network->type == UNSET)
			     tmp_network->type = WIRED;
                         }
                         | TK_TYPE '=' TK_UNQUOTED_STR {
			   set_current_network();
			   tmp_network->type = UNSET;
			   printf("Unknown interface type = \"%s\"!  Defaulting to UNSET! (Line : %d)\n", $3, config_linenum);
			 }
                       ;

network_wpa_group_enc_type  : TK_WPA_GROUP_CRYPT '=' TK_WEP40 {
                              parameter_debug("WPA Group Crypt : WEP40\n");
			      set_current_network();
			      tmp_network->wpa_group_crypt = CRYPT_WEP40;
			      }
                            | TK_WPA_GROUP_CRYPT '=' TK_TKIP {
			      parameter_debug("WPA Group Crypt : TKIP\n");
			      set_current_network();
			      tmp_network->wpa_group_crypt = CRYPT_TKIP;
			      }
                            | TK_WPA_GROUP_CRYPT '=' TK_WRAP {
			      parameter_debug("WPA Group Crypt : WRAP\n");
			      set_current_network();
			      tmp_network->wpa_group_crypt = CRYPT_WRAP;
			      }
                            | TK_WPA_GROUP_CRYPT '=' TK_CCMP {
			      parameter_debug("WPA Group Crypt : CCMP\n");
			      set_current_network();
			      tmp_network->wpa_group_crypt = CRYPT_CCMP;
			      }
                            | TK_WPA_GROUP_CRYPT '=' TK_WEP104 {
			      parameter_debug("WPA Group Crypt : WEP104\n");
			      set_current_network();
			      tmp_network->wpa_group_crypt = CRYPT_WEP104;
			      }
                            ; 

network_wpa_pairwise_enc_type  : TK_WPA_PAIRWISE_CRYPT '=' TK_WEP40 {
                                 parameter_debug("WPA Pairwise Crypt : WEP40\n");
				 set_current_network();
				 tmp_network->wpa_pairwise_crypt = CRYPT_WEP40;
                                 }
                               | TK_WPA_PAIRWISE_CRYPT '=' TK_TKIP {
				 parameter_debug("WPA Pairwise Crypt : TKIP\n");
				 set_current_network();
				 tmp_network->wpa_pairwise_crypt = CRYPT_TKIP;
			         }
                               | TK_WPA_PAIRWISE_CRYPT '=' TK_WRAP {
				 parameter_debug("WPA Pairwise Crypt : WRAP\n");
				 set_current_network();
				 tmp_network->wpa_pairwise_crypt = CRYPT_WRAP;
	      		         }
                               | TK_WPA_PAIRWISE_CRYPT '=' TK_CCMP {
				 parameter_debug("WPA Pairwise Crypt : CCMP\n");
				 set_current_network();
				 tmp_network->wpa_pairwise_crypt = CRYPT_CCMP;
			         }
                               | TK_WPA_PAIRWISE_CRYPT '=' TK_WEP104 {
				 parameter_debug("WPA Pairwise Crypt : WEP104\n");
				 set_current_network();
				 tmp_network->wpa_pairwise_crypt = CRYPT_WEP104;
			         }
                               ; 

network_force_eapol_ver  : TK_FORCE_EAPOL_VER '=' TK_NUMBER {
                           parameter_debug("Force EAPOL Version : %d\n", $3);
                           set_current_network();
                           tmp_network->force_eapol_ver = $3;
                         }
                       ;

network_assoc_type       : TK_ASSOCIATION_TYPE '=' TK_ASSOC_OPEN {
                           parameter_debug("Association Type : Open\n");
			   set_current_network();
			   tmp_network->assoc_type = ASSOC_OPEN;
                        }
                         | TK_ASSOCIATION_TYPE '=' TK_ASSOC_SHARED {
			   parameter_debug("Association Type : Shared\n");
			   set_current_network();
			   tmp_network->assoc_type = ASSOC_SHARED;
			 }
                        | TK_ASSOCIATION_TYPE '=' TK_ASSOC_LEAP {
			  parameter_debug("Association Type : LEAP\n");
			  set_current_network();
			  tmp_network->assoc_type = ASSOC_LEAP;
			}
                      ;

network_control_wireless : TK_CONTROL_WIRELESS '=' TK_YES {
                           parameter_debug("Control Wireless = YES\n");
			   set_current_network();
			   if (tmp_network->wireless_ctrl == CTL_UNSET)
			     tmp_network->wireless_ctrl = CTL_YES;
                         }
                         | TK_CONTROL_WIRELESS '=' TK_NO {
			   parameter_debug("Control Wireless = NO\n");
			   set_current_network();
			   if (tmp_network->wireless_ctrl == CTL_UNSET)
			     tmp_network->wireless_ctrl = CTL_NO;
			 }
                         | TK_CONTROL_WIRELESS '=' TK_UNQUOTED_STR {
			   set_current_network();
			   tmp_network->wireless_ctrl = CTL_UNSET;
			   printf("Unknown option for Control Wireless = \"%s\"!  Defaulting to UNSET! (Line : %d)\n", $3, config_linenum);
			 }
                       ;

network_identity_parameter : TK_IDENTITY '=' TK_IDENTITY_VAL {
                            parameter_debug("ID: \"%s\"\n", $3);
			    set_current_network();
			    if (!tmp_network->identity)
			      tmp_network->identity = $3;
			    else
			      free($3);
                          }
                          | TK_IDENTITY '=' TK_QUOTED_STR {
			    parameter_debug("ID: \"%s\"\n", $3);
			    set_current_network();
			    if (!tmp_network->identity)
			      tmp_network->identity = $3;
			    else
			      free($3);
			  }
                          | TK_IDENTITY '=' TK_UNQUOTED_STR {
			    parameter_debug("ID: \"%s\"\n", $3);
			    set_current_network();
			    if (!tmp_network->identity)
			      tmp_network->identity = $3;
			    else
			      free($3);
			  }
                        ;

network_use_tnc:        TK_USE_TNC '=' TK_YES {
                          parameter_debug("Use TNC : Yes");
                          set_current_network();
                          SET_FLAG(tmp_network->flags, CONFIG_NET_USE_TNC);
                        }
                        | TK_USE_TNC '=' TK_NO {
                          parameter_debug("Use TNC : No");
                          set_current_network();
                          UNSET_FLAG(tmp_network->flags, CONFIG_NET_USE_TNC);
                        }
                      ;

network_dest_mac_parameter: TK_DEST_MAC '=' TK_MACADDRESS {
                            parameter_debug("Dest Mac: %s\n", $3);
			    set_current_network();
			    if (TEST_FLAG(tmp_network->flags, CONFIG_NET_DEST_MAC)) {
			      free($3);
			    }
			    else {
			      int tmp_dst_mac[CONFIG_MAC_LEN];
			      int retval;
			      SET_FLAG(tmp_network->flags, CONFIG_NET_DEST_MAC);
			      retval = sscanf($3, "%2x:%2x:%2x:%2x:%2x:%2x", 
				     &tmp_dst_mac[0], 
				     &tmp_dst_mac[1], 
				     &tmp_dst_mac[2], 
				     &tmp_dst_mac[3], 
				     &tmp_dst_mac[4], 
				     &tmp_dst_mac[5]);
			      tmp_network->dest_mac[0] = tmp_dst_mac[0];
			      tmp_network->dest_mac[1] = tmp_dst_mac[1];
			      tmp_network->dest_mac[2] = tmp_dst_mac[2];
			      tmp_network->dest_mac[3] = tmp_dst_mac[3];
			      tmp_network->dest_mac[4] = tmp_dst_mac[4];
			      tmp_network->dest_mac[5] = tmp_dst_mac[5];
			    }
                         }
                       ;

network_allow_parameter: TK_ALLOW_TYPES '=' TK_ALL {
                           parameter_debug("Allow Types: ALL\n");
			   set_current_network();
			   SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_ALL);
                       }
                       | TK_ALLOW_TYPES '=' eap_type_list
                       ;

eap_type_statement  : eap_tls_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_TLS)) {
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_TLS,
					       tmp_tls);
		       }
		       else 
			 delete_config_eap_tls(&tmp_tls);
		       tmp_tls = NULL;
                      }
                    | eap_md5_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_MD5))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_MD5,
					       tmp_md5);
		       else 
			 delete_config_eap_md5(&tmp_md5);
		       tmp_md5 = NULL;
                      }
                    | eap_ttls_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_TTLS))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_TTLS,
					       tmp_ttls);
		       else 
			 delete_config_eap_ttls(&tmp_ttls);
		       tmp_ttls = NULL;
                      }
                    | static_wep_statement {
		      set_current_network();
		      if (!config_eap_method_contains_method(tmp_network->methods,
							     STATIC_WEP_METHOD))
			add_config_eap_method(&(tmp_network->methods),
					      STATIC_WEP_METHOD,
					      tmp_static_wep);
		      }
                    | initial_wep_statement {
		      set_current_network();
                      tmp_network->initial_wep = tmp_initial_wep;
		    }
                    | eap_leap_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_LEAP))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_LEAP,
					       tmp_leap);
		       else 
			 delete_config_eap_leap(&tmp_leap);
		       tmp_leap = NULL;
                      }
                    | eap_mschapv2_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_MSCHAPV2))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_MSCHAPV2,
					       tmp_mschapv2);
		       else 
			 delete_config_eap_mschapv2(&tmp_mschapv2);
		       tmp_mschapv2 = NULL;
                      }
                    | eap_peap_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_PEAP))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_PEAP,
					       tmp_peap);
		       else 
			 delete_config_eap_peap(&tmp_peap);
		       tmp_peap = NULL;
                      }
                    | eap_sim_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_SIM))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_SIM,
					       tmp_sim);
		       else 
			 delete_config_eap_sim(&tmp_sim);
		       tmp_sim = NULL;
                      }
                    | eap_aka_statement {
		      set_current_network();
		      if (!config_eap_method_contains_method(tmp_network->methods,
							     EAP_TYPE_AKA))
			add_config_eap_method(&(tmp_network->methods),
					      EAP_TYPE_AKA,
					      tmp_aka);
		      else
			delete_config_eap_aka(&tmp_aka);
		      tmp_aka = NULL;
                      }
                    | wpa_psk_statement {
		      set_current_network();
		      if (!config_eap_method_contains_method(tmp_network->methods,
							     WPA_PSK))
			add_config_eap_method(&(tmp_network->methods),
					      WPA_PSK,
					      tmp_wpa_psk);
		      else
			delete_config_wpa_psk(&tmp_wpa_psk);
		      tmp_wpa_psk = NULL;
                      }
                    ;

eap_type_list       : eap_type_list ',' eap_type 
                    | eap_type
                    ;

eap_type            : TK_EAP_TLS {
                        parameter_debug("Allow Type: TLS\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_TLS);
                      }
                    | TK_EAP_MD5 {
                        parameter_debug("Allow Type: MD5\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_MD5);
                      }
                    | TK_EAP_TTLS {
                        parameter_debug("Allow Type: TTLS\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_TTLS);
                      }
                    | TK_EAP_LEAP {
                        parameter_debug("Allow Type: LEAP\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_LEAP);
                      }
                    | TK_EAP_MSCHAPV2 {
                        parameter_debug("Allow Type: MSCHAPV2\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_MSCV2);
                      }
                    | TK_EAP_PEAP {
                        parameter_debug("Allow Type: PEAP\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_PEAP);
                      }
                    | TK_EAP_SIM {
                        parameter_debug("Allow Type: SIM\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_SIM);
                      }
                    | TK_EAP_AKA {
		        parameter_debug("Allow Type: AKA\n");
		        set_current_network();
		        SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_AKA);
		      }
                    | TK_EAP_GTC {
                        parameter_debug("Allow Type: GTC\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_GTC);
                      }
                    | TK_EAP_OTP {
                        parameter_debug("Allow Type: OTP\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_OTP);
                      }
                    ;

static_wep_statement: TK_STATIC_WEP '{' static_wep_params '}'
                    | TK_STATIC_WEP '{' '}' {
                        set_current_static_wep();  
                      }
                    ;

static_wep_params   : static_wep_params static_wep_param
                    | static_wep_param
                    ;

static_wep_param    : TK_STATIC_KEY1 '=' TK_QUOTED_STR {
                        set_current_static_wep();
                        parameter_debug("Static Key 1 : %s\n", $3);
			if (!tmp_static_wep->key[1])
			  tmp_static_wep->key[1] = (uint8_t *) $3;
                      }
                    | TK_STATIC_KEY2 '=' TK_QUOTED_STR {
		        set_current_static_wep();
		        parameter_debug("Static Key 2 : %s\n", $3);
		        if (!tmp_static_wep->key[2])
			  tmp_static_wep->key[2] = (uint8_t *) $3;
		    }
                    | TK_STATIC_KEY3 '=' TK_QUOTED_STR {
		        set_current_static_wep();
                        parameter_debug("Static Key 3 : %s\n", $3);
                        if (!tmp_static_wep->key[3])
                          tmp_static_wep->key[3] = (uint8_t *) $3;
                    }
                    | TK_STATIC_KEY4 '=' TK_QUOTED_STR {
		        set_current_static_wep();
                        parameter_debug("Static Key 4 : %s\n", $3);
                        if (!tmp_static_wep->key[4])
                          tmp_static_wep->key[4] = (uint8_t *) $3;
                    }
                    | TK_WEP_TX_KEY '=' TK_NUMBER {
                        set_current_static_wep();
                        parameter_debug("TX Key : %d\n", $3);
			if (($3>4) || ($3<1))
			  {
			    printf("Static WEP key index is out of range!  It must be a number in the range 1..4!  Defaulting to 1.\n");
			    tmp_static_wep->tx_key = 1;
			  } else {
			    tmp_static_wep->tx_key = $3;
			  }
                    } 
                    ;

initial_wep_statement: TK_INITIAL_WEP '{' initial_wep_params '}'
                    | TK_INITIAL_WEP '{' '}' {
                        set_current_initial_wep();
                      }
                    ;

initial_wep_params  : initial_wep_params initial_wep_param
                    | initial_wep_param
                    ;

initial_wep_param  : TK_STATIC_KEY1 '=' TK_QUOTED_STR {
                        set_current_initial_wep();
                        parameter_debug("Initial Key 1 : %s\n", $3);
			if (!tmp_initial_wep->key[1])
			  tmp_initial_wep->key[1] = (uint8_t *) $3;
                    }
                    | TK_STATIC_KEY2 '=' TK_QUOTED_STR {
		        set_current_initial_wep();
		        parameter_debug("Initial Key 2 : %s\n", $3);
		        if (!tmp_initial_wep->key[2])
			  tmp_initial_wep->key[2] = (uint8_t *) $3;
		    }
                    | TK_STATIC_KEY3 '=' TK_QUOTED_STR {
		        set_current_initial_wep();
                        parameter_debug("Initial Key 3 : %s\n", $3);
                        if (!tmp_initial_wep->key[3])
                          tmp_initial_wep->key[3] = (uint8_t *) $3;
                    }
                    | TK_STATIC_KEY4 '=' TK_QUOTED_STR {
		        set_current_initial_wep();
                        parameter_debug("Initial Key 4 : %s\n", $3);
                        if (!tmp_initial_wep->key[4])
                          tmp_initial_wep->key[4] = (uint8_t *) $3;
                    }
                    | TK_WEP_TX_KEY '=' TK_NUMBER {
                        set_current_initial_wep();
                        parameter_debug("Initial TX Key : %d\n", $3);
			if (($3>4) || ($3<1))
			  {
			    printf("Initial WEP key index is out of range!  It must be a number in the range 1..4!  Defaulting to 1.\n");
			    tmp_initial_wep->tx_key = 1;
			  } else {
			    tmp_initial_wep->tx_key = $3;
                     }
                    }
                    ;


eap_tls_statement   : TK_EAP_TLS '{' eap_tls_params '}'  
                    | TK_EAP_TLS '{' '}' {
                        set_current_tls(); /* define an empty tls struct*/
                      }
                    ;

eap_tls_params      : eap_tls_params eap_tls_param
                    | eap_tls_param
                    ;

smartcard_section   : TK_SMARTCARD '{' smartcard_params '}' {
		    	set_current_tls();
			parameter_debug("Using Engine: \"%s\"\n", 
						tmp_tls->sc.engine_id);
		      }
		    /* don't allow empty smartcard sections */
		    ;

smartcard_params    : smartcard_param smartcard_params
		    | smartcard_param
                    ;

smartcard_param     : TK_ENGINE_ID '=' TK_UNQUOTED_STR {
                        set_current_tls();
			tmp_tls->sc.engine_id = strdup($3);
		        parameter_debug("engine: \"%s\"\n", 
						tmp_tls->sc.engine_id);
		      }
                    | TK_OPENSC_SO_PATH '=' TK_UNQUOTED_STR {
                        set_current_tls();
			tmp_tls->sc.opensc_so_path = $3;
                        parameter_debug("opensc_so_path: \"%s\"\n", 
						tmp_tls->sc.opensc_so_path);
                      }
                    | TK_OPENSC_SO_PATH '=' TK_QUOTED_STR {
		        set_current_tls();
			tmp_tls->sc.opensc_so_path = $3;
			parameter_debug("opensc_so_path: \"%s\"\n",
					tmp_tls->sc.opensc_so_path);
		    }
		    | TK_KEYID '=' TK_UNQUOTED_STR {
                        set_current_tls();
			tmp_tls->sc.key_id = $3;
                        parameter_debug("cert_id: \"%s\"\n", 
						tmp_tls->sc.key_id);
                      }
                    | TK_KEYID '=' TK_NUMBER {
                        set_current_tls();
			tmp_tls->sc.key_id = (char *)malloc(5);
			sprintf(tmp_tls->sc.key_id, "%d", $3);
                        parameter_debug("cert_id: \"%s\"\n", 
						tmp_tls->sc.key_id);
                      }
                    ;

eap_tls_param       :  TK_USER_CERT '=' TK_UNQUOTED_STR {
                        parameter_debug("tls user cert: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_cert)
			  tmp_tls->user_cert = $3;
			else
			  free($3);
                      }
                    |  TK_USER_CERT '=' TK_QUOTED_STR {
  		        parameter_debug("tls user cert: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_cert)
			  tmp_tls->user_cert = $3;
			else
			  free($3);
		      }
                    |  TK_USER_KEY '=' TK_UNQUOTED_STR {
	 	        parameter_debug("tls user key: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_key)
			  tmp_tls->user_key = $3;
			else 
			  free($3);
        	      }
                    | TK_USER_KEY '=' TK_QUOTED_STR {
 		        parameter_debug("tls user key: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_key)
			  tmp_tls->user_key = $3;
			else
			  free($3);
		      }
                    |  TK_USER_KEY_PASS '=' TK_PASS {
	 	        parameter_debug("tls user pass: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_key_pass)
			  tmp_tls->user_key_pass = $3;
			else
			  free($3);
        	      }
                    | TK_USER_KEY_PASS '=' TK_QUOTED_STR {
		        parameter_debug("tls user pass: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_key_pass)
			  tmp_tls->user_key_pass = $3;
			else
			  free($3);
		      }
                    | TK_USER_KEY_PASS '=' TK_UNQUOTED_STR {
		        parameter_debug("tls user pass: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_key_pass)
			  tmp_tls->user_key_pass = $3;
			else
			  free($3);
		      }
                    |  TK_SESSION_RESUME '=' TK_YES {
		        parameter_debug("Session Resumption = YES\n");
		        set_current_tls();
		        if (tmp_tls->session_resume == RES_UNSET)
			  tmp_tls->session_resume = RES_YES;
		      }
                    | TK_SESSION_RESUME '=' TK_NO {
			parameter_debug("Session Resumption = NO\n");
			set_current_tls();
			if (tmp_tls->session_resume == RES_UNSET)
			  tmp_tls->session_resume = RES_NO;
		      }
                    | TK_SESSION_RESUME '=' TK_UNQUOTED_STR {
		      set_current_tls();
		      tmp_tls->session_resume = RES_NO;
		      printf("Invalid value for session resumption = \"%s\"!  Defaulting to NO! (Line : %d)\n", $3, config_linenum);
		    }
                    |  TK_ROOT_CERT  '=' TK_UNQUOTED_STR {
	 	        parameter_debug("tls root_cert: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->root_cert)
			  tmp_tls->root_cert = $3;
			else
			  free($3);
        	      }
                    |  TK_ROOT_CERT '=' TK_QUOTED_STR {
		        parameter_debug("tls root_cert: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->root_cert)
			  tmp_tls->root_cert = $3;
			else
			  free($3);
		      }
                    |  TK_ROOT_DIR  '=' TK_UNQUOTED_STR {
	 	        parameter_debug("tls root_dir: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->root_dir)
			  tmp_tls->root_dir = $3;
			else
			  free($3);
        	      }
                    |  TK_ROOT_DIR '=' TK_QUOTED_STR {
		        parameter_debug("tls root_dir: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->root_dir)
			  tmp_tls->root_dir = $3;
			else
			  free($3);
		      }
                    |  TK_CRL_DIR  '=' TK_UNQUOTED_STR {
	 	        parameter_debug("tls crl_dir: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->crl_dir)
			  tmp_tls->crl_dir = $3;
			else
			  free($3);
        	      }
                    | TK_CRL_DIR '=' TK_QUOTED_STR {
		        parameter_debug("tls crl_dir: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->crl_dir)
			  tmp_tls->crl_dir = $3;
			else
			  free($3);
		      }
                    |  TK_CHUNK_SIZE '=' TK_NUMBER {
 		        parameter_debug("tls chunk: %d\n", $3);
			set_current_tls();
			if (tmp_tls->chunk_size == 0)
			  tmp_tls->chunk_size = $3;
  		      }
                    |  TK_RANDOM_FILE '=' TK_UNQUOTED_STR {
	 	        parameter_debug("tls rand: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->random_file)
			  tmp_tls->random_file = $3;
			else 
			  free($3);
        	      }
                    |  TK_RANDOM_FILE '=' TK_QUOTED_STR {
		        parameter_debug("tls rand: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->random_file)
			  tmp_tls->random_file = $3;
			else
			  free($3);
		    }
		    |  smartcard_section
                    ;

eap_md5_statement   : TK_EAP_MD5 '{' eap_md5_params'}' 
                    | TK_EAP_MD5 '{' '}' {
                        set_current_md5(); /* define an empty md5 struct*/
                      }
                    ;

eap_md5_params     : eap_md5_params eap_md5_param
                   | eap_md5_param
                   ;

eap_md5_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("md5 username: \"%s\"\n", $3);
		       set_current_md5();
		       if (!tmp_md5->username)
			 tmp_md5->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
		       parameter_debug("md5 username: \"%s\"\n", $3);
		       set_current_md5();
		       if (!tmp_md5->username)
			 tmp_md5->username = $3;
		       else
			 free($3);
		     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
		       parameter_debug("md5 username: \"%s\"\n", $3);
		       set_current_md5();
		       if (!tmp_md5->username)
			 tmp_md5->username = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("md5 password: \"%s\"\n", $3);
		       set_current_md5();
		       if (!tmp_md5->password)
			 tmp_md5->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("md5 password: \"%s\"\n", $3);
		       set_current_md5();
		       if (!tmp_md5->password)
			 tmp_md5->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("md5 password: \"%s\"\n", $3);
		       set_current_md5();
		       if (!tmp_md5->password)
			 tmp_md5->password = $3;
		       else
			 free($3);
		     }
                   ;

eap_ttls_statement   : TK_EAP_TTLS '{' eap_ttls_params '}' 
                    | TK_EAP_TTLS '{' '}' {
                        set_current_ttls(); /* define an empty ttls struct*/
                      }
                    ;

eap_ttls_params      : eap_ttls_params eap_ttls_param
                    | eap_ttls_param
                    ;

eap_ttls_param       : TK_USER_CERT '=' TK_UNQUOTED_STR {
                        parameter_debug("ttls user cert: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_cert)
			  tmp_ttls->user_cert = $3;
			else
			  free($3);
                      }
                    |  TK_USER_CERT '=' TK_QUOTED_STR {
		        parameter_debug("ttls user cert: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_cert)
			  tmp_ttls->user_cert = $3;
			else
			  free($3);
		      }
                    |  TK_USER_KEY '=' TK_UNQUOTED_STR {
	 	        parameter_debug("ttls user key: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_key)
			  tmp_ttls->user_key = $3;
			else 
			  free($3);
        	      }
                    |  TK_USER_KEY '=' TK_QUOTED_STR {
	 	        parameter_debug("ttls user key: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_key)
			  tmp_ttls->user_key = $3;
			else 
			  free($3);
        	      }
                    |  TK_USER_KEY_PASS '=' TK_PASS {
	 	        parameter_debug("ttls user pass: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_key_pass)
			  tmp_ttls->user_key_pass = $3;
			else
			  free($3);
        	      }
                    | TK_USER_KEY_PASS '=' TK_UNQUOTED_STR {
	 	        parameter_debug("ttls user pass: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_key_pass)
			  tmp_ttls->user_key_pass = $3;
			else
			  free($3);
        	      }
                    | TK_USER_KEY_PASS '=' TK_QUOTED_STR {
	 	        parameter_debug("ttls user pass: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_key_pass)
			  tmp_ttls->user_key_pass = $3;
			else
			  free($3);
        	      }
                    | TK_ROOT_CERT  '=' TK_UNQUOTED_STR {
	 	        parameter_debug("ttls root_cert: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->root_cert)
			  tmp_ttls->root_cert = $3;
			else
			  free($3);
        	      }
                    |  TK_ROOT_CERT '=' TK_QUOTED_STR {
	 	        parameter_debug("ttls root_cert: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->root_cert)
			  tmp_ttls->root_cert = $3;
			else
			  free($3);
        	      }
                    |  TK_ROOT_DIR '=' TK_UNQUOTED_STR {
	 	        parameter_debug("ttls root_dir: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->root_dir)
			  tmp_ttls->root_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_ROOT_DIR '=' TK_QUOTED_STR {
	 	        parameter_debug("ttls root_dir: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->root_dir)
			  tmp_ttls->root_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_CRL_DIR '=' TK_UNQUOTED_STR {
	 	        parameter_debug("ttls crl_dir: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->crl_dir)
			  tmp_ttls->crl_dir = $3;
			else 
			  free($3);
        	      }
                    | TK_CRL_DIR '=' TK_QUOTED_STR {
	 	        parameter_debug("ttls crl_dir: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->crl_dir)
			  tmp_ttls->crl_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_CHUNK_SIZE '=' TK_NUMBER {
 		        parameter_debug("ttls chunk: %d\n", $3);
			set_current_ttls();
			if (tmp_ttls->chunk_size == 0)
			  tmp_ttls->chunk_size = $3;
  		      }
                    |  TK_RANDOM_FILE '=' TK_UNQUOTED_STR {
	 	        parameter_debug("ttls rand: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->random_file)
			  tmp_ttls->random_file = $3;
			else 
			  free($3);
        	      }
                    |  TK_RANDOM_FILE '=' TK_QUOTED_STR {
	 	        parameter_debug("ttls rand: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->random_file)
			  tmp_ttls->random_file = $3;
			else 
			  free($3);
        	      }
                    |  TK_SESSION_RESUME '=' TK_YES {
		        parameter_debug("Session Resumption = YES\n");
		        set_current_ttls();
		        if (tmp_ttls->session_resume == RES_UNSET)
			  tmp_ttls->session_resume = RES_YES;
		      }
                    | TK_SESSION_RESUME '=' TK_NO {
			parameter_debug("Session Resumption = NO\n");
			set_current_ttls();
			if (tmp_ttls->session_resume == RES_UNSET)
			  tmp_ttls->session_resume = RES_NO;
		      }
                    | TK_SESSION_RESUME '=' TK_UNQUOTED_STR {
		      set_current_ttls();
		      tmp_ttls->session_resume = RES_NO;
		      printf("Invalid value for session resume = \"%s\"!  Defaulting to NO!  (Line : %d)\n", $3, config_linenum);
		    }
                    |  TK_CNCHECK '=' TK_UNQUOTED_STR {
		        parameter_debug("ttls CN check : \"%s\"\n", $3);
                        set_current_ttls();
                        if (!tmp_ttls->cncheck)
                          tmp_ttls->cncheck = $3;
                        else
                          free($3);
		      }
                    | TK_CNEXACT '=' TK_YES {
  		        parameter_debug("match CN exactly : \"yes\"\n");
		        set_current_ttls();
		        tmp_ttls->cnexact = 1;
		    }
                    | TK_CNEXACT '=' TK_NO {
  		        parameter_debug("match CN exactly : \"no\"\n");
		        set_current_ttls();
		        tmp_ttls->cnexact = 0;
		    }
                    |  TK_PHASE2_TYPE '=' TK_PAP {
	 	        parameter_debug("ttls phase2_type 'pap'\n");
			if (tmp_ttls && 
			    tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
			  cleanup_parse();
			  return XECONFIGPARSEFAIL;  
			}
			set_current_ttls();
			tmp_ttls->phase2_type = TTLS_PHASE2_PAP;
        	      }
                    |  TK_PHASE2_TYPE '=' TK_CHAP {
	 	        parameter_debug("ttls phase2_type 'chap'\n");
			if (tmp_ttls && 
			    tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
			  cleanup_parse();
			  return XECONFIGPARSEFAIL;  
			}
			set_current_ttls();
			tmp_ttls->phase2_type = TTLS_PHASE2_CHAP;
        	      }
                    |  TK_PHASE2_TYPE '=' TK_MSCHAP {
	 	        parameter_debug("ttls phase2_type 'mschap'\n");
			if (tmp_ttls && 
			    tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
			  cleanup_parse();
			  return XECONFIGPARSEFAIL;  
			}
			set_current_ttls();
			tmp_ttls->phase2_type = TTLS_PHASE2_MSCHAP;
        	      }
                    |  TK_PHASE2_TYPE '=' TK_MSCHAPV2 {
	 	        parameter_debug("ttls phase2_type 'mschapv2'\n");
			if (tmp_ttls && 
			    tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
			  cleanup_parse();
			  return XECONFIGPARSEFAIL;  
			}
			set_current_ttls();
			tmp_ttls->phase2_type = TTLS_PHASE2_MSCHAPV2;
        	      }
                    |  TK_PHASE2_TYPE '=' TK_EAP_MD5 {
                        parameter_debug("ttls phase2_type 'eap_md5'\n");
                        if (tmp_ttls &&
                            tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
                          cleanup_parse();
                          return XECONFIGPARSEFAIL;
                        }
                        set_current_ttls();
                        tmp_ttls->phase2_type = TTLS_PHASE2_EAP_MD5;
                     }
                    | eap_ttls_phase2_statement
                    ;

eap_ttls_phase2_statement  : phase2_pap_statement
                           | phase2_chap_statement
                           | phase2_mschap_statement
                           | phase2_mschapv2_statement
                           | eap_ttls_phase2_eap_statement
                           ;

phase2_pap_statement   : TK_PAP '{' phase2_pap_params'}' {
                       set_current_ttls(); 
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
							       TTLS_PHASE2_PAP))
			 add_config_ttls_phase2(&(tmp_ttls->phase2), 
						TTLS_PHASE2_PAP,
						tmp_p2pap);
		       else
			 delete_config_pap(&tmp_p2pap);
		       tmp_p2pap = NULL;
                      }
                    ;

phase2_pap_params     : phase2_pap_params phase2_pap_param
                   | phase2_pap_param
                   ;

phase2_pap_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("pap username: \"%s\"\n", $3);
		       set_current_p2pap();
		       if (!tmp_p2pap->username)
			 tmp_p2pap->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
                       parameter_debug("pap username: \"%s\"\n", $3);
		       set_current_p2pap();
		       if (!tmp_p2pap->username)
			 tmp_p2pap->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
                       parameter_debug("pap username: \"%s\"\n", $3);
		       set_current_p2pap();
		       if (!tmp_p2pap->username)
			 tmp_p2pap->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("pap password: \"%s\"\n", $3);
		       set_current_p2pap();
		       if (!tmp_p2pap->password)
			 tmp_p2pap->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("pap password: \"%s\"\n", $3);
		       set_current_p2pap();
		       if (!tmp_p2pap->password)
			 tmp_p2pap->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("pap password: \"%s\"\n", $3);
		       set_current_p2pap();
		       if (!tmp_p2pap->password)
			 tmp_p2pap->password = $3;
		       else
			 free($3);
		     }
                   ;

phase2_chap_statement   : TK_CHAP '{' phase2_chap_params'}' {
                       set_current_ttls(); 
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
							       TTLS_PHASE2_CHAP))
			 add_config_ttls_phase2(&(tmp_ttls->phase2), 
						TTLS_PHASE2_CHAP,
						tmp_p2chap);
		       else
			 delete_config_chap(&tmp_p2chap);
		       tmp_p2chap = NULL;
                      }
                    ;

phase2_chap_params     : phase2_chap_params phase2_chap_param
                   | phase2_chap_param
                   ;

phase2_chap_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("chap username: \"%s\"\n", $3);
		       set_current_p2chap();
		       if (!tmp_p2chap->username)
			 tmp_p2chap->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
                       parameter_debug("chap username: \"%s\"\n", $3);
		       set_current_p2chap();
		       if (!tmp_p2chap->username)
			 tmp_p2chap->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
                       parameter_debug("chap username: \"%s\"\n", $3);
		       set_current_p2chap();
		       if (!tmp_p2chap->username)
			 tmp_p2chap->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("chap password: \"%s\"\n", $3);
		       set_current_p2chap();
		       if (!tmp_p2chap->password)
			 tmp_p2chap->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("chap password: \"%s\"\n", $3);
		       set_current_p2chap();
		       if (!tmp_p2chap->password)
			 tmp_p2chap->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("chap password: \"%s\"\n", $3);
		       set_current_p2chap();
		       if (!tmp_p2chap->password)
			 tmp_p2chap->password = $3;
		       else
			 free($3);
		     }
                   ;

phase2_mschap_statement   : TK_MSCHAP '{' phase2_mschap_params'}' {
                       set_current_ttls(); 
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
							       TTLS_PHASE2_MSCHAP))
			 add_config_ttls_phase2(&(tmp_ttls->phase2), 
						TTLS_PHASE2_MSCHAP,
						tmp_p2mschap);
		       else
			 delete_config_mschap(&tmp_p2mschap);
		       tmp_p2mschap = NULL;
                      }
                    ;

phase2_mschap_params     : phase2_mschap_params phase2_mschap_param
                   | phase2_mschap_param
                   ;

phase2_mschap_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("mschap username: \"%s\"\n", $3);
		       set_current_p2mschap();
		       if (!tmp_p2mschap->username)
			 tmp_p2mschap->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
                       parameter_debug("mschap username: \"%s\"\n", $3);
		       set_current_p2mschap();
		       if (!tmp_p2mschap->username)
			 tmp_p2mschap->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
                       parameter_debug("mschap username: \"%s\"\n", $3);
		       set_current_p2mschap();
		       if (!tmp_p2mschap->username)
			 tmp_p2mschap->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("mschap password: \"%s\"\n", $3);
		       set_current_p2mschap();
		       if (!tmp_p2mschap->password)
			 tmp_p2mschap->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("mschap password: \"%s\"\n", $3);
		       set_current_p2mschap();
		       if (!tmp_p2mschap->password)
			 tmp_p2mschap->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("mschap password: \"%s\"\n", $3);
		       set_current_p2mschap();
		       if (!tmp_p2mschap->password)
			 tmp_p2mschap->password = $3;
		       else
			 free($3);
		     }
                   ;


phase2_mschapv2_statement   : TK_MSCHAPV2 '{' phase2_mschapv2_params'}' {
                       set_current_ttls(); 
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
							       TTLS_PHASE2_MSCHAPV2))
			 add_config_ttls_phase2(&(tmp_ttls->phase2), 
						TTLS_PHASE2_MSCHAPV2,
						tmp_p2mschapv2);
		       else
			 delete_config_mschapv2(&tmp_p2mschapv2);
		       tmp_p2mschapv2 = NULL;
                      }
                    ;

phase2_mschapv2_params     : phase2_mschapv2_params phase2_mschapv2_param
                   | phase2_mschapv2_param
                   ;

phase2_mschapv2_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("mschapv2 username: \"%s\"\n", $3);
		       set_current_p2mschapv2();
		       if (!tmp_p2mschapv2->username)
			 tmp_p2mschapv2->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
                       parameter_debug("mschapv2 username: \"%s\"\n", $3);
		       set_current_p2mschapv2();
		       if (!tmp_p2mschapv2->username)
			 tmp_p2mschapv2->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
                       parameter_debug("mschapv2 username: \"%s\"\n", $3);
		       set_current_p2mschapv2();
		       if (!tmp_p2mschapv2->username)
			 tmp_p2mschapv2->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("mschapv2 password: \"%s\"\n", $3);
		       set_current_p2mschapv2();
		       if (!tmp_p2mschapv2->password)
			 tmp_p2mschapv2->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("mschapv2 password: \"%s\"\n", $3);
		       set_current_p2mschapv2();
		       if (!tmp_p2mschapv2->password)
			 tmp_p2mschapv2->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("mschapv2 password: \"%s\"\n", $3);
		       set_current_p2mschapv2();
		       if (!tmp_p2mschapv2->password)
			 tmp_p2mschapv2->password = $3;
		       else
			 free($3);
		     }
                   ;

eap_ttls_phase2_eap_statement : eap_md5_statement {
		       set_current_ttls();
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
                                                                 TTLS_PHASE2_EAP_MD5))
		         add_config_ttls_phase2(&(tmp_ttls->phase2),
			  	  	        TTLS_PHASE2_EAP_MD5,
					        tmp_md5);
		       else
		         delete_config_eap_md5(&tmp_md5);
		       tmp_p2mschapv2 = NULL;
                     }
                   ;

eap_leap_statement   : TK_EAP_LEAP '{' eap_leap_params'}' 
                    | TK_EAP_LEAP '{' '}' {
                        set_current_leap(); /* define an empty leap struct*/
                      }
                    ;

eap_leap_params     : eap_leap_params eap_leap_param
                   | eap_leap_param
                   ;

eap_leap_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("leap username: \"%s\"\n", $3);
		       set_current_leap();
		       if (!tmp_leap->username)
			 tmp_leap->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
                       parameter_debug("leap username: \"%s\"\n", $3);
		       set_current_leap();
		       if (!tmp_leap->username)
			 tmp_leap->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
                       parameter_debug("leap username: \"%s\"\n", $3);
		       set_current_leap();
		       if (!tmp_leap->username)
			 tmp_leap->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("leap password: \"%s\"\n", $3);
		       set_current_leap();
		       if (!tmp_leap->password)
			 tmp_leap->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("leap password: \"%s\"\n", $3);
		       set_current_leap();
		       if (!tmp_leap->password)
			 tmp_leap->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("leap password: \"%s\"\n", $3);
		       set_current_leap();
		       if (!tmp_leap->password)
			 tmp_leap->password = $3;
		       else
			 free($3);
		     }
                   ;

eap_mschapv2_statement   : TK_EAP_MSCHAPV2 '{' eap_mschapv2_params'}'
                    | TK_EAP_MSCHAPV2 '{' '}' {
                        set_current_mschapv2(); /* define an empty mschapv2 struct*/
                      }
                         ;

eap_mschapv2_params     : eap_mschapv2_params eap_mschapv2_param
                   | eap_mschapv2_param
                   ;

eap_mschapv2_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("mschapv2 username: \"%s\"\n", $3);
		       set_current_mschapv2();
		       if (!tmp_mschapv2->username)
			 tmp_mschapv2->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
                       parameter_debug("mschapv2 username: \"%s\"\n", $3);
		       set_current_mschapv2();
		       if (!tmp_mschapv2->username)
			 tmp_mschapv2->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
		       parameter_debug("mschapv2 username: \"%s\"\n", $3);
		       set_current_mschapv2();
		       if (!tmp_mschapv2->username)
			 tmp_mschapv2->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("mschapv2 password: \"%s\"\n", $3);
		       set_current_mschapv2();
		       if (!tmp_mschapv2->password)
			 tmp_mschapv2->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("mschapv2 password: \"%s\"\n", $3);
		       set_current_mschapv2();
		       if (!tmp_mschapv2->password)
			 tmp_mschapv2->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("mschapv2 password: \"%s\"\n", $3);
		       set_current_mschapv2();
		       if (!tmp_mschapv2->password)
			 tmp_mschapv2->password = $3;
		       else
			 free($3);
		     }
                   | TK_MSCHAPV2_HASH_PWD '=' TK_UNQUOTED_STR {
                       parameter_debug("mschapv2 NT password hash: \"%s\"\n", $3);
                       set_current_mschapv2();
                       if (!tmp_mschapv2->nthash)
                         tmp_mschapv2->nthash = $3;
                       else
                         free($3);
                     }
                   ;

eap_peap_statement   : TK_EAP_PEAP '{' eap_peap_params '}'
                    | TK_EAP_PEAP '{' '}' {
                        set_current_peap(); /* define an empty peap struct*/
                      }
                    ;

eap_peap_params      : eap_peap_params eap_peap_param
                    | eap_peap_param
                    ;

eap_peap_param       : TK_IDENTITY '=' TK_IDENTITY_VAL {
                            parameter_debug("ID: \"%s\"\n", $3);
			    set_current_peap();
			    if (!tmp_peap->identity)
			      tmp_peap->identity = $3;
			    else
			      free($3);
                          }
                    | TK_IDENTITY '=' TK_UNQUOTED_STR {
                            parameter_debug("ID: \"%s\"\n", $3);
			    set_current_peap();
			    if (!tmp_peap->identity)
			      tmp_peap->identity = $3;
			    else
			      free($3);
                          }
                    | TK_IDENTITY '=' TK_QUOTED_STR {
                            parameter_debug("ID: \"%s\"\n", $3);
			    set_current_peap();
			    if (!tmp_peap->identity)
			      tmp_peap->identity = $3;
			    else
			      free($3);
                          }
                    |   TK_USER_CERT '=' TK_UNQUOTED_STR {
                        parameter_debug("peap user cert: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_cert)
			  tmp_peap->user_cert = $3;
			else
			  free($3);
                      }
                    | TK_USER_CERT '=' TK_QUOTED_STR {
                        parameter_debug("peap user cert: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_cert)
			  tmp_peap->user_cert = $3;
			else
			  free($3);
                      }
                    |  TK_USER_KEY '=' TK_UNQUOTED_STR {
	 	        parameter_debug("peap user key: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_key)
			  tmp_peap->user_key = $3;
			else 
			  free($3);
        	      }
                    | TK_USER_KEY '=' TK_QUOTED_STR {
	 	        parameter_debug("peap user key: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_key)
			  tmp_peap->user_key = $3;
			else 
			  free($3);
        	      }
                    |  TK_USER_KEY_PASS '=' TK_PASS {
	 	        parameter_debug("peap user pass: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_key_pass)
			  tmp_peap->user_key_pass = $3;
			else
			  free($3);
        	      }
                    | TK_USER_KEY_PASS '=' TK_UNQUOTED_STR {
	 	        parameter_debug("peap user pass: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_key_pass)
			  tmp_peap->user_key_pass = $3;
			else
			  free($3);
        	      }
                    | TK_USER_KEY_PASS '=' TK_QUOTED_STR {
	 	        parameter_debug("peap user pass: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_key_pass)
			  tmp_peap->user_key_pass = $3;
			else
			  free($3);
        	      }
                    |TK_ROOT_CERT  '=' TK_UNQUOTED_STR {
	 	        parameter_debug("peap root_cert: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->root_cert)
			  tmp_peap->root_cert = $3;
			else
			  free($3);
        	      }
                    | TK_ROOT_CERT '=' TK_QUOTED_STR {
	 	        parameter_debug("peap root_cert: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->root_cert)
			  tmp_peap->root_cert = $3;
			else
			  free($3);
        	      }
                    |  TK_ROOT_DIR '=' TK_UNQUOTED_STR {
	 	        parameter_debug("peap root_dir: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->root_dir)
			  tmp_peap->root_dir = $3;
			else 
			  free($3);
        	      }
                    | TK_ROOT_DIR '=' TK_QUOTED_STR {
	 	        parameter_debug("peap root_dir: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->root_dir)
			  tmp_peap->root_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_CRL_DIR '=' TK_UNQUOTED_STR {
	 	        parameter_debug("peap crl_dir: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->crl_dir)
			  tmp_peap->crl_dir = $3;
			else 
			  free($3);
        	      }
                    | TK_CRL_DIR '=' TK_QUOTED_STR {
	 	        parameter_debug("peap crl_dir: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->crl_dir)
			  tmp_peap->crl_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_SESSION_RESUME '=' TK_YES {
		        parameter_debug("Session Resumption = YES\n");
		        set_current_peap();
		        if (tmp_peap->session_resume == RES_UNSET)
			  tmp_peap->session_resume = RES_YES;
		      }
                    | TK_SESSION_RESUME '=' TK_NO {
			parameter_debug("Session Resumption = NO\n");
			set_current_peap();
			if (tmp_peap->session_resume == RES_UNSET)
			  tmp_peap->session_resume = RES_NO;
		      }
                    | TK_SESSION_RESUME '=' TK_UNQUOTED_STR {
		      set_current_peap();
		      tmp_peap->session_resume = RES_NO;
		      printf("Invalid setting for PEAP session resumption = \"%s\"!  Defaulting to NO! (Line : %d)\n", $3, config_linenum);
		    }
                    | TK_PEAPV1_PROPER_KEYING '=' TK_YES {
		      parameter_debug("Proper PEAPv1 Keying = YES\n");
		      set_current_peap();
		      if (tmp_peap->proper_peapv1 == 0)
			tmp_peap->proper_peapv1 = 1;
		    }
                    | TK_PEAPV1_PROPER_KEYING '=' TK_NO {
		      parameter_debug("Proper PEAPv1 Keying = NO\n");
		      set_current_peap();
		      if (tmp_peap->proper_peapv1 == 1)
			tmp_peap->proper_peapv1 = 0;
		    }
                    | TK_PEAPV1_PROPER_KEYING '=' TK_UNQUOTED_STR {
		      parameter_debug("Unknown 'Proper PEAPv1 Keying' setting!\n");
		      printf("Unknown value for 'proper_peap_v1_keying'!\n");
		    }
                    | TK_INNER_ID '=' TK_UNQUOTED_STR {
                      parameter_debug("inner id : %s\n", $3);
                      set_current_peap();
                      if (!tmp_peap->identity)
			tmp_peap->identity = $3;
                    }
                    | TK_INNER_ID '=' TK_QUOTED_STR {
		      parameter_debug("inner id : %s\n", $3);
		      set_current_peap();
		      if (!tmp_peap->identity)
			tmp_peap->identity = $3;
		    }
                    |  TK_CHUNK_SIZE '=' TK_NUMBER {
 		        parameter_debug("peap chunk: %d\n", $3);
			set_current_peap();
			if (tmp_peap->chunk_size == 0)
			  tmp_peap->chunk_size = $3;
  		      }
                    |  TK_CNCHECK '=' TK_UNQUOTED_STR {
		        parameter_debug("peap CN check : \"%s\"\n", $3);
                        set_current_peap();
                        if (!tmp_peap->cncheck)
                          tmp_peap->cncheck = $3;
                        else
                          free($3);
		      }
                    | TK_CNEXACT '=' TK_YES {
  		        parameter_debug("match CN exactly : \"yes\"\n");
		        set_current_peap();
		        tmp_peap->cnexact = 1;
		    }
                    | TK_CNEXACT '=' TK_NO {
  		        parameter_debug("match CN exactly : \"no\"\n");
		        set_current_peap();
		        tmp_peap->cnexact = 0;
       		    }
                    |  TK_RANDOM_FILE '=' TK_UNQUOTED_STR {
	 	        parameter_debug("peap rand: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->random_file)
			  tmp_peap->random_file = $3;
			else 
			  free($3);
        	      }
                   | TK_RANDOM_FILE '=' TK_QUOTED_STR {
	 	        parameter_debug("peap rand: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->random_file)
			  tmp_peap->random_file = $3;
			else 
			  free($3);
        	      }
                   | TK_IAS_QUIRK '=' TK_YES {
		       parameter_debug("peap ias quirk: YES\n");
		       set_current_peap();
		       tmp_peap->ias_quirk=1;
		     }
                   | TK_IAS_QUIRK '=' TK_NO {
		       parameter_debug("peap ias quirk: NO\n");
		       set_current_peap();
		       tmp_peap->ias_quirk=0;
		     }
                   | TK_IAS_QUIRK '=' TK_UNQUOTED_STR {
		       parameter_debug("peap ias quirk: %s\n", $3);
		       parameter_debug("Defaulting to NO!\n");
		       set_current_peap();
		       tmp_peap->ias_quirk=0;
		     }
                    | eap_peap_allow_parameter {}
                    | eap_peap_phase2_statement {}
                    ;

eap_peap_allow_parameter: TK_ALLOW_TYPES '=' TK_ALL {
                           parameter_debug("PEAP Allow Types: ALL\n");
			   set_current_peap();
			   SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_ALL);
                       }
                       | TK_ALLOW_TYPES '=' eap_peap_phase2_type_list
                       ;

eap_peap_phase2_type_list  : eap_peap_phase2_type_list ',' eap_peap_phase2_type 
                           | eap_peap_phase2_type
                           ;

eap_peap_phase2_type  : TK_EAP_MSCHAPV2 {
                          parameter_debug("PEAP Allow Type: MSCHAPV2\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_MSCV2);
                        }
                      | TK_EAP_MD5 {
                          parameter_debug("PEAP Allow Type: MD5\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_MD5);
                        }
                      | TK_EAP_SIM {
                          parameter_debug("PEAP Allow Type: SIM\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_SIM);
                        }
                      | TK_EAP_OTP {
                          parameter_debug("PEAP Allow Type: OTP\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_OTP);
                        }
                      | TK_EAP_GTC {
                          parameter_debug("PEAP Allow Type: GTC\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_GTC);
                        }
                       ;


eap_peap_phase2_statement : eap_mschapv2_statement {
                             set_current_peap(); 
	   	             if (!config_eap_method_contains_method(tmp_peap->phase2,
								    EAP_TYPE_MSCHAPV2))
			       {
			       add_config_eap_method(&(tmp_peap->phase2),
						     EAP_TYPE_MSCHAPV2,
						     tmp_mschapv2);

			       // If we don't have an identity, then copy this
			       // one.
			       if (!tmp_peap->identity)
				 {
				   tmp_peap->identity = strdup(tmp_mschapv2->username);
				 }
			       }
			     else
			       delete_config_eap_mschapv2(&tmp_mschapv2);
			     tmp_mschapv2 = NULL;
                            }
                          | eap_md5_statement {
                             set_current_peap(); 
	   	             if (!config_eap_method_contains_method(tmp_peap->phase2,
								    EAP_TYPE_MD5))
			       {
			       add_config_eap_method(&(tmp_peap->phase2),
						     EAP_TYPE_MD5,
						     tmp_md5);

			       // If we don't have an identity, then copy this
			       // one.
			       if (!tmp_peap->identity)
				 {
				   tmp_peap->identity = strdup(tmp_md5->username);
				 }
			       }
			     else
			       delete_config_eap_md5(&tmp_md5);
			     tmp_md5 = NULL;
                            }
                          | eap_sim_statement {
                             set_current_peap(); 
	   	             if (!config_eap_method_contains_method(tmp_peap->phase2,
								    EAP_TYPE_SIM))
			       {
			       add_config_eap_method(&(tmp_peap->phase2),
						     EAP_TYPE_SIM,
						     tmp_sim);
			       
			       // If we don't have an identity, then copy this
			       // one.
			       if (!tmp_peap->identity)
				 {
				   tmp_peap->identity = strdup(tmp_sim->username);
				 }
			       }
			     else
			       delete_config_eap_sim(&tmp_sim);
			     tmp_sim = NULL;
                            }
                          ;

eap_sim_statement   : TK_EAP_SIM '{' eap_sim_params'}' 
                    | TK_EAP_SIM '{' '}' {
                        set_current_sim(); /* define an empty sim struct*/
                      }
                    ;

eap_sim_params     : eap_sim_params eap_sim_param
                   | eap_sim_param
                   ;

eap_sim_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("sim username: \"%s\"\n", $3);
		       set_current_sim();
		       if (!tmp_sim->username)
			 tmp_sim->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
                       parameter_debug("sim username: \"%s\"\n", $3);
		       set_current_sim();
		       if (!tmp_sim->username)
			 tmp_sim->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
                       parameter_debug("sim username: \"%s\"\n", $3);
		       set_current_sim();
		       if (!tmp_sim->username)
			 tmp_sim->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("sim password: \"%s\"\n", $3);
		       set_current_sim();
		       if (!tmp_sim->password)
			 tmp_sim->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("sim password: \"%s\"\n", $3);
		       set_current_sim();
		       if (!tmp_sim->password)
			 tmp_sim->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("sim password: \"%s\"\n", $3);
		       set_current_sim();
		       if (!tmp_sim->password)
			 tmp_sim->password = $3;
		       else
			 free($3);
		     }
                   | TK_AUTO_REALM '=' TK_YES {
  		       parameter_debug("sim auto_realm: \"yes\"\n");
		       set_current_sim();
		       tmp_sim->auto_realm = 1;
		   }
                   | TK_AUTO_REALM '=' TK_NO {
  		       parameter_debug("sim auto_realm: \"no\"\n");
		       set_current_sim();
		       tmp_sim->auto_realm = 0;
		   }
                   | TK_AUTO_REALM '=' TK_UNQUOTED_STR {
		       parameter_debug("sim auto_realm: \"%s\"\n", $3);
		       parameter_debug("Defaulting to NO!\n");
		       set_current_sim();
		       tmp_sim->auto_realm = 0;
		   }
                   ;
eap_aka_statement   : TK_EAP_AKA '{' eap_aka_params'}' 
                    | TK_EAP_AKA '{' '}' {
                        set_current_aka(); /* define an empty aka struct*/
                      }
                    ;

eap_aka_params     : eap_aka_params eap_aka_param
                   | eap_aka_param
                   ;

eap_aka_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("aka username: \"%s\"\n", $3);
		       set_current_aka();
		       if (!tmp_aka->username)
			 tmp_aka->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_UNQUOTED_STR {
                       parameter_debug("aka username: \"%s\"\n", $3);
		       set_current_aka();
		       if (!tmp_aka->username)
			 tmp_aka->username = $3;
		       else
			 free($3);
                     }
                   | TK_USERNAME '=' TK_QUOTED_STR {
                       parameter_debug("aka username: \"%s\"\n", $3);
		       set_current_aka();
		       if (!tmp_aka->username)
			 tmp_aka->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("aka password: \"%s\"\n", $3);
		       set_current_aka();
		       if (!tmp_aka->password)
			 tmp_aka->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_UNQUOTED_STR {
		       parameter_debug("aka password: \"%s\"\n", $3);
		       set_current_aka();
		       if (!tmp_aka->password)
			 tmp_aka->password = $3;
		       else
			 free($3);
		     }
                   | TK_PASSWORD '=' TK_QUOTED_STR {
		       parameter_debug("aka password: \"%s\"\n", $3);
		       set_current_aka();
		       if (!tmp_aka->password)
			 tmp_aka->password = $3;
		       else
			 free($3);
		     }
                   | TK_AUTO_REALM '=' TK_YES {
  		       parameter_debug("aka auto_realm: \"yes\"\n");
		       set_current_aka();
		       tmp_aka->auto_realm = 1;
		   }
                   | TK_AUTO_REALM '=' TK_NO {
  		       parameter_debug("aka auto_realm: \"no\"\n");
		       set_current_aka();
		       tmp_aka->auto_realm = 0;
		   }
                   | TK_AUTO_REALM '=' TK_UNQUOTED_STR {
		       parameter_debug("aka auto_realm: \"%s\"\n", $3);
		       set_current_aka();
		       tmp_aka->auto_realm = 0;
		   }
                   ;
wpa_psk_statement   : TK_WPA_PSK '{' wpa_psk_params'}'
                   | TK_WPA_PSK '{' '}' {
                       set_current_wpa_psk(); /* define an empty wpa psk struct*/
                   }
                   ;

wpa_psk_params     : wpa_psk_params wpa_psk_param
                   | wpa_psk_param
                   ;

wpa_psk_param      : TK_WPA_PSK_KEY '=' TK_UNQUOTED_STR {
                       parameter_debug("ascii key : \"%s\"\n", $3);
                       set_current_wpa_psk();
		       if (!tmp_wpa_psk->key)
			 tmp_wpa_psk->key = $3;
		       else
			 free($3);
                   }
                   | TK_WPA_PSK_KEY '=' TK_QUOTED_STR {
                       parameter_debug("ascii key : \"%s\"\n", $3);
                       set_current_wpa_psk();
		       if (!tmp_wpa_psk->key)
			 tmp_wpa_psk->key = $3;
		       else
			 free($3);
                   }
                   | TK_WPA_PSK_HEX_KEY '=' TK_UNQUOTED_STR {
                       parameter_debug("hex key : \"%s\"\n", $3);
                       set_current_wpa_psk();
                       if (!tmp_wpa_psk->hex_key)
                         tmp_wpa_psk->hex_key = $3;
                       else
                         free($3);
                   }
                   ;
%%
