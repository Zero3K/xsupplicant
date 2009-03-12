/**
 * Mac OS X wireless card interface implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_macosx_wireless.c
 *
 * \author chris@open1x.org
 *
 * $Id: cardif_macosx_wireless.c,v 1.1 2008/01/30 20:46:41 galimorerpg Exp $
 * $Date: 2008/01/30 20:46:41 $
 **/

#ifdef DARWIN_WIRELESS

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "xsupconfig_structs.h"
#include "xsup_common.h"
#include "darwinwireless.h"
#include "xsupconfig.h"
#include "context.h"
#include "eap_sm.h"
#include "config_ssid.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "wireless_sm.h"
#include "cardif/cardif.h"
#include "cardif_macosx.h"
#include "cardif_macosx_wireless.h"
#include "wpa.h"

/********************************************************************
 *
 * Display error messages that are returned from libdarwinwireless.
 *
 ********************************************************************/
void cardif_macosx_wireless_process_error(int errmsg)
{
	switch (errmsg) {
	case DNO_ERROR:
		debug_printf(DEBUG_NORMAL, "There was no error!\n");
		break;

	case DGENERAL_ERROR:
		debug_printf(DEBUG_NORMAL, "There was a general error!\n");
		break;

	case DINVALID_OPAQUE_DATA:
		debug_printf(DEBUG_NORMAL,
			     "Invalid opaque data passed in to call!\n");
		break;

	case DNO_WIRELESS:
		debug_printf(DEBUG_NORMAL, "This interface is not wireless!\n");
		break;

	case DWIRELESS_INIT_FAILED:
		debug_printf(DEBUG_NORMAL,
			     "Failed to init wireless interface.\n");
		break;

	case DBAD_WEP_KEY_LEN:
		debug_printf(DEBUG_NORMAL,
			     "The length of the WEP key passed is invalid! "
			     "Key lengths must be 5, or 13 bytes.\n");
		break;

	case DBAD_KEY_IDX:
		debug_printf(DEBUG_NORMAL,
			     "The key index pass is not between 1 and 4!\n");
		break;

	case DKEY_SET_ERROR:
		debug_printf(DEBUG_NORMAL, "General error setting key.\n");
		break;

	case DNO_SSID_DATA:
		debug_printf(DEBUG_NORMAL, "No SSID data was returned.\n");
		break;

	case DMALLOC_ERROR:
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory!\n");
		break;

	case DASSOCIATION_FAILURE:
		debug_printf(DEBUG_NORMAL, "Failed to associate to network.\n");
		break;

	case DDISASSOCIATION_FAILURE:
		debug_printf(DEBUG_NORMAL,
			     "Failed to disassociate from the network.\n");
		break;

	case DSCAN_FAILURE:
		debug_printf(DEBUG_NORMAL, "Failed to generate scan data.\n");
		break;

	default:
		debug_printf(DEBUG_NORMAL, "Unknown error!\n");
		break;
	}
}

/********************************************************************
 *
 *  Clear out the allocated memory for a single instance of scan
 *  results.
 *
 ********************************************************************/
void cardif_macosx_wireless_free_single_scan(struct darwin_scan_results *cur)
{
	if (!xsup_assert((cur != NULL), "cur != NULL", FALSE))
		return;

	FREE(cur->ssid);
	FREE(cur->unicastciphers);
	FREE(cur->authmodes);
}

/********************************************************************
 *
 *  Send the keydata to the Airport API.
 *
 ********************************************************************/
int cardif_macosx_wireless_set_key_material(context * ctx)
{
	struct darwin_sock_data *sockData;
	int res = 0;

	debug_printf(DEBUG_INT, "Applying keying material.\n");

	sockData = (struct darwin_sock_data *)ctx->sockData;

	debug_printf(DEBUG_NORMAL, "Key data : ");
	if (ctx->eap_state->eapKeyData == NULL)
		debug_printf_nl(DEBUG_NORMAL, "NONE!\n");
	else
		debug_hex_printf(DEBUG_NORMAL, ctx->eap_state->eapKeyData, 64);

	res = darwin_set_keying_material(sockData->wireless_blob,
					 ctx->eap_state->eapKeyData);
	if (res != 0) {
		debug_printf(DEBUG_NORMAL, "Failed to set key material!\n");
		cardif_macosx_wireless_process_error(res);
	}

	return res;
}

/********************************************************************
 *
 *  Call to issue a scan request.  (For OS X, it also gets scan results.)
 *  Since the libdarwinwireless doesn't have the option of doing a 
 *  passive scan, the passive option is irrelevant.
 *
 ********************************************************************/
int cardif_macosx_wireless_scan(context * ctx, char passive)
{
	struct darwin_sock_data *sockData = NULL;
	struct darwin_scan_results *results = NULL;
	struct darwin_scan_results *cur = NULL;
	struct darwin_scan_results *next = NULL;
	struct config_network *net = NULL;
	int res;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (passive == TRUE)
		return XECANTPASSIVE;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	while (results == NULL) {
		res = darwin_do_scan(sockData->wireless_blob, &results);

		if (results == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "No scan results were returned.  Will "
				     "try again.\n");
			sleep(1);
		}
	}

	// Iterate through the results, cleaning up memory behind us.
	cur = results;

	while (cur != NULL) {
		next = cur->next;

		config_ssid_add_ssid_name(ctx->intTypeData, cur->ssid);

		if (cur->iswpa != 0) {
			// The Mac doesn't care if this is a WPA1, or WPA2 IE.  So, just set the flags that say we
			// are using some form of WPA, so that we will attempt to associate with WPA.
			config_ssid_update_abilities(ctx->intTypeData, WPA_IE);
		}

		cardif_macosx_wireless_free_single_scan(cur);

		FREE(cur);

		cur = next;
	}

	// Then, scan for any hidden SSIDs that we have configured.
#warning FIX!
	/*
	   info = config_get_config_info();
	   net = info->networks;
	 */
	net = NULL;

	while (net != NULL) {
		//      if (net->hidden == TRUE)
		{
			//      debug_printf(DEBUG_NORMAL, "Looking for hidden network %s!\n", net->name);
			// Scan for the hidden network.
			//      res = darwin_find_hidden(sockData->wireless_blob, net->name, &results);

			// Add it to the list of known networks.
			if (results != NULL) {
				// Iterate through the results, cleaning up memory behind us.
				cur = results;

				while (cur != NULL) {
					next = cur->next;

					config_ssid_add_ssid_name(ctx->
								  intTypeData,
								  cur->ssid);

					if (cur->iswpa != 0) {
						config_ssid_update_abilities
						    (ctx->intTypeData, WPA_IE);
					}

					cardif_macosx_wireless_free_single_scan
					    (cur);

					FREE(cur);

					cur = next;
				}
			}
		}
		//      net = net->next;
	}

	return 0;
}

/********************************************************************
 *
 *  Issue a disassociate request. 
 *
 ********************************************************************/
int cardif_macosx_wireless_disassociate(context * ctx, int reason)
{
	struct darwin_sock_data *sockData;
	int res = 0;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	res = darwin_disassociate(sockData->wireless_blob);
	if (res != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error disassociating from this SSID!\n");
		cardif_macosx_wireless_process_error(res);
	}

	return res;
}

/********************************************************************
 *
 *  Read the SSID from the wireless driver.
 *
 ********************************************************************/
int cardif_macosx_wireless_get_ssid(context * ctx, char *ssidname)
{
	char *ssid;
	struct darwin_sock_data *sockData;
	int res;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	if (sockData == NULL)
		return -1;

	res = darwin_get_ssid(sockData->wireless_blob, &ssid);
	if (res != 0) {
		cardif_macosx_wireless_process_error(res);
		return res;
	}

	strcpy(ssidname, ssid);
	FREE(ssid);

	return 0;
}

/********************************************************************
 *
 *  Send a WEP key to the driver.
 *
 ********************************************************************/
int cardif_macosx_wireless_set_WEP_key(context * ctx, uint8_t * key,
				       int keylen, int index)
{
	struct darwin_sock_data *sockData;
	uint8_t i = 0;
	int result;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	if (sockData == NULL)
		return -1;

	if ((index & 0x80) == 0x80)
		i = 1;

	result =
	    darwin_set_wep_key(sockData->wireless_blob, (char *)key, keylen, i,
			       (index & 0x7f));

	if (result != 0) {
		debug_printf(DEBUG_NORMAL, "Error setting key for index %d.\n",
			     (index & 0x7f));
		cardif_macosx_wireless_process_error(result);
	}

	return result;
}

/*********************************************************************
 *
 *  Do a WEP association.
 *
 *********************************************************************/
int cardif_macosx_wireless_wep_associate(context * ctx, int zeros)
{
	struct darwin_sock_data *sockData;
	wireless_ctx *wctx = NULL;
	int res = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (!xsup_assert
	    ((ctx->intTypeData != NULL), "ctx->intTypeData != NULL", FALSE))
		return -1;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	if (sockData == NULL)
		return -1;

	// The MAC associates fast, so we start by assuming we are associated right
	// after the call to associate.  We will sort out if we really associated
	// when we go through the manual event loop.
	wctx = (wireless_ctx *) ctx->intTypeData;
	SET_FLAG(wctx->flags, WIRELESS_SM_ASSOCIATED);

	res =
	    darwin_wep_associate(sockData->wireless_blob, wctx->cur_essid,
				 FALSE);

	if (res != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Failed to associate to WEP enabled network!\n");
		cardif_macosx_wireless_process_error(res);
	}

	return res;
}

/*****************************************************************
 *
 *  Return the BSSID of a wireless interface.
 *
 *****************************************************************/
int cardif_macosx_wireless_get_bssid(context * ctx, char *bssid)
{
	char *temp;
	struct darwin_sock_data *sockData;
	int res = 0;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	if (sockData == NULL)
		return -1;

	res = darwin_get_bssid(sockData->wireless_blob, &temp);
	if (res != 0) {
		debug_printf(DEBUG_NORMAL, "Error getting BSSID.\n");
		cardif_macosx_wireless_process_error(res);
		return res;
	}

	memcpy(bssid, temp, 6);
	FREE(temp);

	return 0;
}

/*****************************************************************
 *
 *  Establish a WPA/WPA2 association.
 *
 *****************************************************************/
void cardif_macosx_wireless_associate(context * ctx)
{
	struct darwin_sock_data *sockData;
	wireless_ctx *wctx = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return;

	if (!xsup_assert((ctx->intTypeData != NULL), "ctx->intTypeData != NULL",
			 FALSE))
		return;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	if (sockData == NULL)
		return;

	wctx = (wireless_ctx *) ctx->intTypeData;

	if (darwin_associate(sockData->wireless_blob, wctx->cur_essid, FALSE)) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't associate to WPA/WPA2 enabled SSID "
			     "'%s'!\n", wctx->cur_essid);
	}
}

/*******************************************************************
 *
 *  Delete a key.
 *
 *******************************************************************/
int cardif_macosx_wireless_delete_key(context * ctx, int key_idx, int set_tx)
{
	struct darwin_sock_data *sockData;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	if (sockData == NULL)
		return -1;

	if (darwin_clear_key(sockData->wireless_blob, key_idx) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error clearing key with index of %d!\n", key_idx);
		return -1;
	}

	return 0;
}

/**
 * \brief Get the signal strength percentage for the interface pointed to by
 *        'ctx'.
 * 
 * @param[in] ctx   The context for the interface we want to get the signal
 *                  strength for.
 *
 * \retval >=0   The signal strength (as a percentage)
 * \retval <0   An error occurred.
 **/
int cardif_macosx_wireless_get_signal_percent(context * ctx)
{
#warning FINISH!
	return -1;
}

struct cardif_funcs cardif_macosx_wireless_driver = {
	.scan = cardif_macosx_wireless_scan,
	.disassociate = cardif_macosx_wireless_disassociate,
	.set_wep_key = cardif_macosx_wireless_set_WEP_key,
	.set_tkip_key = NULL,
	.set_ccmp_key = NULL,
	.delete_key = cardif_macosx_wireless_delete_key,
	.associate = cardif_macosx_wireless_associate,
	.get_ssid = cardif_macosx_wireless_get_ssid,
	.get_bssid = cardif_macosx_wireless_get_bssid,
	.wpa_state = NULL,
	.wpa = NULL,
	.wep_associate = cardif_macosx_wireless_wep_associate,
	.countermeasures = NULL,
	.drop_unencrypted = NULL,
	.get_wpa_ie = NULL,
	.get_wpa2_ie = NULL,
	.enc_disable = NULL,
	.enc_capabilities = NULL,
	.setbssid = NULL,
	.set_operstate = NULL,
	.set_linkmode = NULL,
	.get_signal_percent = cardif_macosx_wireless_get_signal_percent,
};

#endif				// DARWIN_WIRELESS
