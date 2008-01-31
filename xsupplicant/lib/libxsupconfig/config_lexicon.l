%{
/*******************************************************************
 * Tokens for configuration file
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * File: config_lexicon.l
 *
 * Authors: bdpayne@cs.umd.edu, npetroni@cs.umd.edu, Chris.Hessing@utah.edu
 *
 * $Id: config_lexicon.l,v 1.13 2006/10/05 22:23:49 chessing Exp $
 * $Date: 2006/10/05 22:23:49 $
 * $Log: config_lexicon.l,v $
 * Revision 1.13  2006/10/05 22:23:49  chessing
 * Added new association option to the config file, and attempt to associate using methods other than open system.
 *
 * Revision 1.12  2006/06/13 18:02:56  chessing
 * Fixed a problem that would result in a segfault if a HUP was received.  Created stub functions for implementation of EAP-TNC to support Trusted Network Connect.
 *
 * Revision 1.11  2006/06/05 19:56:42  chessing
 * Fixed a 16k memory leak in the config parse code.  Cleaned up some of the TLS code.
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
 * Revision 1.41  2005/09/08 16:27:01  chessing
 * Some small updates to the new state machine code.  First attempt at an auto association mode.  (It mostly works. ;)
 *
 * Revision 1.40  2005/08/25 02:20:20  chessing
 * Some cleanup in xsup_debug.c, added the ability to wait for an interface to come up if it is down when Xsupplicant is started.  Roughed in the ability to choose between having Xsupplicant auto associate you, or allow you to set the ssid manually.  The stale key timer can now be set in the config file.  The association timeout can be set in the config file, and will also be used once the functionality is in place to attempt to guess the key settings needed for association, as well as the functionality to auto associate.
 *
 * Revision 1.39  2005/08/18 03:19:04  chessing
 * Added the ability to define an SSID with static WEP keys.  When we switch to a network that has this type of configuration we will set the keys, and stop the various association timers.
 *
 * Revision 1.38  2005/08/12 03:34:06  chessing
 * Fix to the TLS implementation, should help avoid some of the weird 'block cipher pad' errors.  Also includes a partial implementation of the ability to use static WEP keys based on the SSID in use.
 *
 * Revision 1.37  2005/08/09 01:39:13  chessing
 * Cleaned out old commit notes from the released version.  Added a few small features including the ability to disable the friendly warnings that are spit out.  (Such as the warning that is displayed when keys aren't rotated after 10 minutes.)  We should also be able to start when the interface is down.  Last, but not least, we can handle empty network configs.  (This may be useful for situations where there isn't a good reason to have a default network defined.)
 *
 *******************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_grammar.h"
#include "xsupconfig.h"
#include "xsup_debug.h"
#include "xsup_err.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

int config_linenum = 1;
char linebuf[500];
int tokenpos = 0;
extern struct config_data config_info;
%}

HEXDIGIT    [0-9a-fA-F]

%%

\n.*                { strcpy(linebuf, yytext+1);  /* save the next line */
                      config_linenum++;
                      yyless(1);     /* return all but the \n to the queue. */
		      tokenpos = 0;
		    }  

"network_list"      {tokenpos+=yyleng; return TK_NETWORK_LIST; }
"default_netname"   {tokenpos+=yyleng; return TK_DEFAULT_NETNAME; }
"all"               {tokenpos+=yyleng; return TK_ALL; }
"friendly_warnings" {tokenpos+=yyleng; return TK_FRIENDLY_WARNINGS; }
"default_interface" {tokenpos+=yyleng; return TK_DEFAULT_INT; }
"logfile"           {tokenpos+=yyleng; return TK_LOGFILE; }
"log_facility"      {tokenpos+=yyleng; return TK_LOG_FACILITY; }
"ipc_group"         {tokenpos+=yyleng; return TK_IPC_GROUP; }
"destination"       {tokenpos+=yyleng; return TK_DESTINATION; }
"bssid"             {tokenpos+=yyleng; return TK_BSSID; }
"BSSID"             {tokenpos+=yyleng; return TK_BSSID; }
"multicast"         {tokenpos+=yyleng; return TK_MULTICAST; }
"source"            {tokenpos+=yyleng; return TK_SOURCE; }
"auth_period"       {tokenpos+=yyleng; return TK_AUTH_PERIOD; }
"held_period"       {tokenpos+=yyleng; return TK_HELD_PERIOD; }
"stale_key_timeout" {tokenpos+=yyleng; return TK_STALE_KEY_TIMEOUT; }
"max_starts"        {tokenpos+=yyleng; return TK_MAX_STARTS; }
"allmulti"          {tokenpos+=yyleng; return TK_ALLMULTI; }
"auto"              {tokenpos+=yyleng; return TK_AUTO; }
"manual"            {tokenpos+=yyleng; return TK_MANUAL; }
"association"       {tokenpos+=yyleng; return TK_ASSOCIATION; }
"association_timeout" {tokenpos+=yyleng; return TK_ASSOC_TIMEOUT; }
"roaming"           {tokenpos+=yyleng; return TK_ROAMING; }
"firmware"          {tokenpos+=yyleng; return TK_FIRMWARE; }
"xsupplicant"       {tokenpos+=yyleng; return TK_XSUPPLICANT; }
"passive_scanning"  {tokenpos+=yyleng; return TK_PASSIVE_SCANNING; }
"passive_timer"     {tokenpos+=yyleng; return TK_PASSIVE_TIMEOUT; }
"scan_timeout"      {tokenpos+=yyleng; return TK_SCAN_TIMEOUT; }
"use_eap_hints"     {tokenpos+=yyleng; return TK_USE_EAP_HINTS; }

"type"              {tokenpos+=yyleng; return TK_TYPE; }
"allow_types"       {tokenpos+=yyleng; return TK_ALLOW_TYPES; }
"force_eapol_ver"   {tokenpos+=yyleng; return TK_FORCE_EAPOL_VER; }
"wireless"          {tokenpos+=yyleng; return TK_WIRELESS; }
"wired"             {tokenpos+=yyleng; return TK_WIRED; }
"identity"          {tokenpos+=yyleng; return TK_IDENTITY; }
"use_tnc"           {tokenpos+=yyleng; return TK_USE_TNC; }
"dest_mac"          {tokenpos+=yyleng; return TK_DEST_MAC; }
"wireless_control"  {tokenpos+=yyleng; return TK_CONTROL_WIRELESS; }
"association_type"  {tokenpos+=yyleng; return TK_ASSOCIATION_TYPE; }
"open"              {tokenpos+=yyleng; return TK_ASSOC_OPEN; }
"shared"            {tokenpos+=yyleng; return TK_ASSOC_SHARED; }
"leap"              {tokenpos+=yyleng; return TK_ASSOC_LEAP; }
"wpa_group_cipher"   {tokenpos+=yyleng; return TK_WPA_GROUP_CRYPT; }
"wpa_pairwise_cipher" {tokenpos+=yyleng; return TK_WPA_PAIRWISE_CRYPT; }
"wep40"             {tokenpos+=yyleng; return TK_WEP40; }
"WEP40"             {tokenpos+=yyleng; return TK_WEP40; }
"tkip"              {tokenpos+=yyleng; return TK_TKIP; }
"TKIP"              {tokenpos+=yyleng; return TK_TKIP; }
"wrap"              {tokenpos+=yyleng; return TK_WRAP; }
"WRAP"              {tokenpos+=yyleng; return TK_WRAP; }
"ccmp"              {tokenpos+=yyleng; return TK_CCMP; }
"CCMP"              {tokenpos+=yyleng; return TK_CCMP; }
"wep104"            {tokenpos+=yyleng; return TK_WEP104; }
"WEP104"            {tokenpos+=yyleng; return TK_WEP104; }
"wep128"            {tokenpos+=yyleng; return TK_WEP104; }
"WEP128"            {tokenpos+=yyleng; return TK_WEP104; }
"any"               {tokenpos+=yyleng; return TK_ANY; }

"priority"          {tokenpos+=yyleng; return TK_PRIORITY; }

"wpa_psk"           {tokenpos+=yyleng; return TK_WPA_PSK; }
"wpa-psk"           {tokenpos+=yyleng; return TK_WPA_PSK; }
"key"               {tokenpos+=yyleng; return TK_WPA_PSK_KEY; }
"hex-key"           {tokenpos+=yyleng; return TK_WPA_PSK_HEX_KEY; }

"eap_tls"           {tokenpos+=yyleng; return TK_EAP_TLS; }
"eap-tls"           {tokenpos+=yyleng; return TK_EAP_TLS; }
"user_cert"          {tokenpos+=yyleng; return TK_USER_CERT; }
"user_key"           {tokenpos+=yyleng; return TK_USER_KEY; }
"user_key_pass"      {tokenpos+=yyleng; return TK_USER_KEY_PASS; }
"root_cert"          {tokenpos+=yyleng; return TK_ROOT_CERT; }
"root_dir"          {tokenpos+=yyleng; return TK_ROOT_DIR; }
"crl_dir"          {tokenpos+=yyleng; return TK_CRL_DIR; }
"session_resume"   {tokenpos+=yyleng; return TK_SESSION_RESUME; }
"chunk_size"    {tokenpos+=yyleng; return TK_CHUNK_SIZE; }
"random_file"   {tokenpos+=yyleng; return TK_RANDOM_FILE; }
"cncheck"       {tokenpos+=yyleng; return TK_CNCHECK; }
"cnexact"       {tokenpos+=yyleng; return TK_CNEXACT; }

"smartcard"	 {tokenpos+=yyleng; return TK_SMARTCARD; }
"engine_id"      {tokenpos+=yyleng; return TK_ENGINE_ID; }
"opensc_so_path" {tokenpos+=yyleng; return TK_OPENSC_SO_PATH; }
"key_id"	 {tokenpos+=yyleng; return TK_KEYID; }

"eap_md5"           {tokenpos+=yyleng; return TK_EAP_MD5; }
"eap-md5"           {tokenpos+=yyleng; return TK_EAP_MD5; }
"username"          {tokenpos+=yyleng; return TK_USERNAME; }
"password"          {tokenpos+=yyleng; return TK_PASSWORD; }

"eap-ttls"          {tokenpos+=yyleng; return TK_EAP_TTLS; }
"eap_ttls"          {tokenpos+=yyleng; return TK_EAP_TTLS; }
"phase2_type"       {tokenpos+=yyleng; return TK_PHASE2_TYPE; }
"pap"               {tokenpos+=yyleng; return TK_PAP;  }
"chap"              {tokenpos+=yyleng; return TK_CHAP;  }
"mschap"            {tokenpos+=yyleng; return TK_MSCHAP;  }
"mschapv2"          {tokenpos+=yyleng; return TK_MSCHAPV2;  }

"eap-leap"          {tokenpos+=yyleng; return TK_EAP_LEAP; }
"eap_leap"          {tokenpos+=yyleng; return TK_EAP_LEAP; }

"eap-mschapv2"      {tokenpos+=yyleng; return TK_EAP_MSCHAPV2; }
"eap_mschapv2"      {tokenpos+=yyleng; return TK_EAP_MSCHAPV2; }
"ntpwdhash"         {tokenpos+=yyleng; return TK_MSCHAPV2_HASH_PWD; }
"ias_quirk"         {tokenpos+=yyleng; return TK_IAS_QUIRK; }
"ias-quirk"         {tokenpos+=yyleng; return TK_IAS_QUIRK; }

"eap-peap"          {tokenpos+=yyleng; return TK_EAP_PEAP; }
"eap_peap"          {tokenpos+=yyleng; return TK_EAP_PEAP; }
"proper_peap_v1_keying" {tokenpos+=yyleng; return TK_PEAPV1_PROPER_KEYING; }
"inner_id"          {tokenpos+=yyleng; return TK_INNER_ID; }

"eap-sim"           {tokenpos+=yyleng; return TK_EAP_SIM; }
"eap_sim"           {tokenpos+=yyleng; return TK_EAP_SIM; }
"auto_realm"        {tokenpos+=yyleng; return TK_AUTO_REALM; }
"yes"               {tokenpos+=yyleng; return TK_YES; }
"no"                {tokenpos+=yyleng; return TK_NO; }

"eap-aka"           {tokenpos+=yyleng; return TK_EAP_AKA; }
"eap_aka"           {tokenpos+=yyleng; return TK_EAP_AKA; }

"eap-gtc"           {tokenpos+=yyleng; return TK_EAP_GTC; }
"eap_gtc"           {tokenpos+=yyleng; return TK_EAP_GTC; }

"eap-otp"           {tokenpos+=yyleng; return TK_EAP_OTP; }
"eap_otp"           {tokenpos+=yyleng; return TK_EAP_OTP; }

"static_wep"        {tokenpos+=yyleng; return TK_STATIC_WEP; }
"static-wep"        {tokenpos+=yyleng; return TK_STATIC_WEP; }
"initial_wep"       {tokenpos+=yyleng; return TK_INITIAL_WEP; }
"initial-wep"       {tokenpos+=yyleng; return TK_INITIAL_WEP; }
"key1"              {tokenpos+=yyleng; return TK_STATIC_KEY1; }
"key2"              {tokenpos+=yyleng; return TK_STATIC_KEY2; }
"key3"              {tokenpos+=yyleng; return TK_STATIC_KEY3; }
"key4"              {tokenpos+=yyleng; return TK_STATIC_KEY4; }
"tx_key"            {tokenpos+=yyleng; return TK_WEP_TX_KEY; }


<INITIAL>"="    {tokenpos+=yyleng; return yytext[0];     }
"{"             {tokenpos+=yyleng; return yytext[0];     }
"}"             {tokenpos+=yyleng; return yytext[0];     }
","             {tokenpos+=yyleng; return yytext[0];     }

[0123456789]+   {
                    tokenpos+=yyleng;
                    yylval.num = atoi(yytext);
                    return TK_NUMBER;
                }

{HEXDIGIT}{2}":"{HEXDIGIT}{2}":"{HEXDIGIT}{2}":"{HEXDIGIT}{2}":"{HEXDIGIT}{2}":"{HEXDIGIT}{2} {
                     tokenpos+=yyleng;
                     yylval.str = strdup(yytext);
                     return TK_MACADDRESS;
                   }

[[:alnum:]/_\-\\\.@]+ {
                     tokenpos+=yyleng;
                     yylval.str = strdup(yytext);
                     return TK_UNQUOTED_STR;
                   }

"#".*          /* skip comments */  

<INITIAL>[ \t]+          /* de nada  */

\"[^"\n]*["\n]            { int len = strlen(yytext)-2;      
                            tokenpos+=yyleng;
			    yylval.str = 
			      (char *)malloc(sizeof(char) * (len+1));
			    strncpy(yylval.str, yytext+1, len);
			    yylval.str[len] = '\0';
			    return TK_QUOTED_STR; }

%%

void yycleanup(void)
{
        yy_delete_buffer( YY_CURRENT_BUFFER );
}

int
yywrap(void)
{
	return 1;
}

int
yyerror(char *e)
{
        printf("Error in configuration, at line %d:\n%s:\n\n%s\n",
	       config_linenum, e, linebuf);
	printf("%*s\n", 1+tokenpos, "^");

	return XECONFIGPARSEFAIL;
}
