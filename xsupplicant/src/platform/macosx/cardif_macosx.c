/**
 * Mac OS X card interface implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_macosx.c
 *
 * \author Chris.Hessing@utah.edu with some code from the BSD implementation
 *    that was done by Fednando Schapachnik <fernando@mecon.gov.ar> and
 *    Ivan Voras <ivoras@fer.hr>.
 *
 * $Id: cardif_macosx.c,v 1.1 2008/01/30 20:46:41 galimorerpg Exp $
 * $Date: 2008/01/30 20:46:41 $
 *
 **/

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <net/if_media.h>
#include <net/ethernet.h>
#include <net/ndrv.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "config_ssid.h"
#include "platform/cardif.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "snmp.h"
#include "statemachine.h"
#include "wireless_sm.h"
#include "xsup_common.h"
#include "event_core.h"
#include "eapol.h"
#include "interfaces.h"

#ifdef DARWIN_WIRELESS
#include "darwinwireless.h"
#endif

#include "platform/macosx/cardif_macosx.h"
#include "platform/macosx/cardif_macosx_wireless.h"
#include "platform/macosx/ndrv_socket.h"
#include "timer.h"

#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL 0x888e
#endif

/***********************************************
 * Get the MAC address of an interface
 ***********************************************/
static int _getmac(char *dest, char *ifname)
{

	struct ifaddrs *ifap;

	debug_printf(DEBUG_INT, "Looking for MAC address for %s!\n", ifname);

	if (getifaddrs(&ifap) == 0) {
		struct ifaddrs *p;
		for (p = ifap; p; p = p->ifa_next) {
			if (p->ifa_addr->sa_family == AF_LINK
			    && strcmp(p->ifa_name, ifname) == 0) {
				struct sockaddr_dl *sdp =
				    (struct sockaddr_dl *)p->ifa_addr;
				memcpy(dest, sdp->sdl_data + sdp->sdl_nlen, 6);
				//                printf("I think I saw a MAC address: %s: %x:%x:%x:%x:%x:%x\n", p->ifa_name, dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]);
				freeifaddrs(ifap);
				return TRUE;
			}
		}
		freeifaddrs(ifap);
	}

	return FALSE;
}

static int _getiff(char *ifname, int *flags)
{
	struct ifaddrs *ifa_master, *ifa;

	getifaddrs(&ifa_master);

	for (ifa = ifa_master; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_LINK
		    && strcmp(ifa->ifa_name, ifname) == 0)
			break;
	}

	if (ifa == NULL)
		return FALSE;

	*flags = ifa->ifa_flags;

	freeifaddrs(ifa_master);

	return TRUE;
}

// Define this, so the compiler doesn't complain.
extern unsigned int if_nametoindex(const char *);

// This contains a pointer to the functions needed for wireless.  
struct cardif_funcs *wireless;

/***********************************************
 *
 * Determine if we are currently associated. 
 *
 ***********************************************/
int cardif_check_associated(context * intdata)
{
	debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
	return -1;
}

/***********************************************
 *
 * Set up the wireless cardif_funcs structure to the driver that the user
 * has requested.
 *
 ***********************************************/
void cardif_set_driver(char driver)
{
#ifndef DARWIN_WIRELESS
	switch (driver) {
	case DRIVER_NONE:
		wireless = NULL;
		break;

	default:
		debug_printf(DEBUG_NORMAL, "Unknown driver id of %d!\n",
			     driver);
		break;
	}
#else
	wireless = &cardif_macosx_wireless_driver;
#endif
}

/***********************************************
 *
 * Do whatever is needed to get the interface in to a state that we can send
 * and recieve frames on the network.  Any information that we need to later
 * use should be stored in the context structure.
 *
 ***********************************************/
int cardif_init(context * ctx, char driver)
{
	struct darwin_sock_data *sockData;
	struct config_globals *globals;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	globals = config_get_globals();

	if (globals == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No valid configuration globals available!\n");
		return XEGENERROR;
	}

	ctx->sockData = (void *)malloc(sizeof(struct darwin_sock_data));
	if (ctx->sockData == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for socket "
			     "data in %s()!\n", __FUNCTION__);
		return XEMALLOC;
	}

	memset(ctx->sockData, 0x00, sizeof(struct darwin_sock_data));

	sockData = (struct darwin_sock_data *)ctx->sockData;

	// Set up wireless card drivers.
	cardif_set_driver(driver);

	// Set up wireless data.
#ifdef DARWIN_WIRELESS
	if (cardif_int_is_wireless(ctx) == TRUE) {
		debug_printf(DEBUG_INT, "Interface is wireless.\n");
		ctx->intType = ETH_802_11_INT;

		if (context_create_wireless_ctx
		    ((wireless_ctx **) & ctx->intTypeData, 0) != XENONE) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't create wireless context for "
				     "interface!\n");
			return -1;
		}

		darwin_init_wireless(&sockData->wireless_blob);
	}

	cardif_disassociate(ctx, 0);
#endif

	debug_printf(DEBUG_INT,
		     "Initializing frame socket for interface %s..\n",
		     ctx->intName);

	// Find out what the interface index is.
	//  ctx->intIndex = if_nametoindex(ctx->intName);
	//  debug_printf(DEBUG_INT, "Index : %d\n", ctx->intIndex);

	// Get our MAC address.  (Needed for sending frames out correctly.)
	if (!_getmac(ctx->source_mac, ctx->intName)) {
		debug_printf(DEBUG_INT, "Cannot get MAC address\n");
		return XENOSOCK;
	}
	// Establish a socket handle.
	sockData->sockInt = ndrv_socket(ctx->intName);
	if (sockData->sockInt < 0) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't initialize socket for interface %s!\n",
			     ctx->intName);
		debug_printf(DEBUG_NORMAL,
			     "\n\nIt is likely that the native Mac OS X "
			     "supplicant is already running.  If it is, then "
			     "Xsupplicant won't be able to start.  You should kill all "
			     "instances of 'eapolclient' and try again.\n");
		return XENOSOCK;
	}

	if (ndrv_socket_bind
	    (sockData->sockInt, EAPOL_802_1_X_FAMILY, ETH_P_EAPOL) < 0) {
		debug_printf(DEBUG_NORMAL, "Couldn't bind to ndrv socket!\n");
		return XENOSOCK;
	}

	ctx->sendframe = malloc(FRAMESIZE);
	if (ctx->sendframe == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store frames to "
			     "be sent!\n");
		return XEMALLOC;
	}

	memset(ctx->sendframe, 0x00, FRAMESIZE);
	ctx->send_size = 0;

	event_core_register(cardif_get_socket(ctx), ctx, eapol_withframe,
			    LOW_PRIORITY, "frame handler");

	return XENONE;
}

/**************************************************************
 *
 * Tell the wireless card to start scanning for wireless networks.
 *
 **************************************************************/
int cardif_do_wireless_scan(context * thisint, char passive)
{
	if (wireless == NULL)
		return -1;

	if (wireless->scan == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->scan(thisint, passive);
}

/**************************************************************
 *
 * Send a disassociate message.
 *
 **************************************************************/
int cardif_disassociate(context * thisint, int reason_code)
{
	if (wireless == NULL) {
		debug_printf(DEBUG_NORMAL, "No wireless handler found!\n");
		return -1;
	}

	if (wireless->disassociate == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->disassociate(thisint, reason_code);
}

/******************************************
 *
 * Return the socket number for functions that need it.
 *
 ******************************************/
int cardif_get_socket(context * ctx)
{
	struct darwin_sock_data *sockData;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (!xsup_assert
	    ((ctx->sockData != NULL), "ctx->sockData != NULL", FALSE))
		return -1;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	return sockData->sockInt;
}

/******************************************
 *
 * Clean up anything that was created during the initialization and operation
 * of the interface.  This will be called before the program terminates.
 *
 ******************************************/
int cardif_deinit(context * thisint)
{
	debug_printf(DEBUG_INT | DEBUG_DEINIT, "Cleaning up interface %s...\n",
		     thisint->intName);
	struct darwin_sock_data *sockData;
	sockData = (struct darwin_sock_data *)thisint->sockData;

#ifdef DARWIN_WIRELESS
	darwin_deinit_wireless(sockData->wireless_blob);
#endif

	/*
	   // Check if we want ALLMULTI mode, and enable it.
	   if (TEST_FLAG(thisint->flags, ALLMULTI))
	   {
	   // Tell the ifreq struct which interface we want to use.
	   Strncpy((char *)&ifr.ifr_name, thisint->intName, sizeof(ifr.ifr_name));

	   if (ioctl(sockData->sockInt, SIOCGIFFLAGS, &ifr) < 0)
	   {
	   debug_printf(DEBUG_NORMAL, "Couldn't get interface flags!\n");
	   } else {
	   // Check if allmulti was disabled when we started.  If it was,
	   // then disable it again, so everything is good.
	   if (!(thisint->flags & ALLMULTI))
	   {
	   debug_printf(DEBUG_INT, "Turning off ALLMULTI mode!\n");

	   ifr.ifr_flags &= ~IFF_ALLMULTI;
	   if (ioctl(sockData->sockInt, SIOCSIFFLAGS, &ifr) < 0)
	   {
	   debug_printf(DEBUG_NORMAL, "Couldn't set ALLMULTI mode on this interface!  We will continue anyway!\n");
	   }
	   }
	   }
	   }
	 */

	close(sockData->sockInt);

	FREE(thisint->sockData);

	return XENONE;
}

/******************************************
 *
 * Set a WEP key.  Also, based on the index, we may change the transmit
 * key.
 *
 ******************************************/
int cardif_set_wep_key(context * thisint, uint8_t * key, int keylen, int index)
{
	if (wireless == NULL)
		return -1;

	if (wireless->set_wep_key == NULL) {
		debug_printf(DEBUG_INT, "set_wep_key not implemented.\n");
		return -1;
	}

	return wireless->set_wep_key(thisint, key, keylen, index);
}

/**********************************************************
 *
 * Set a TKIP key. 
 *
 **********************************************************/
int cardif_set_tkip_key(context * thisint, char *addr,
			int keyidx, int settx, char *key, int keylen)
{
	if (wireless == NULL)
		return -1;

	if (wireless->set_tkip_key == NULL) {
		debug_printf(DEBUG_INT, "set_tkip_key not implemented.\n");
		return -1;
	}

	return wireless->set_tkip_key(thisint, (uint8_t *) addr, keyidx, settx,
				      key, keylen);
}

/**********************************************************
 *
 * Set a CCMP (AES) key
 *
 **********************************************************/
int cardif_set_ccmp_key(context * thisint, char *addr, int keyidx,
			int settx, char *key, int keylen)
{
	if (wireless == NULL)
		return -1;

	if (wireless->set_ccmp_key == NULL) {
		debug_printf(DEBUG_INT, "set_ccmp_key not implemented.\n");
		return -1;
	}

	return wireless->set_ccmp_key(thisint, (uint8_t *) addr, keyidx, settx,
				      key, keylen);
}

/**********************************************************
 *
 * Delete a key
 *
 **********************************************************/
int cardif_delete_key(context * intdata, int key_idx, int set_tx)
{
	if (wireless == NULL)
		return -1;

	if (wireless->delete_key == NULL) {
		debug_printf(DEBUG_INT, "delete_key not implemented.\n");
		return -1;
	}

	return wireless->delete_key(intdata, key_idx, set_tx);
}

/******************************************
 *
 * If our association timer expires, we need to attempt to associate again.
 *
 ******************************************/
void cardif_association_timeout_expired(context * intdata)
{
	// And try to associate again.
	cardif_associate(intdata);
}

/******************************************
 *
 * Do whatever we need to do in order to associate based on the flags in
 * the ssids_list struct.
 *
 ******************************************/
void cardif_associate(context * intdata)
{
	if (intdata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid interface struct passed to %s!\n",
			     __FUNCTION__);
		return;
	}

	if (wireless == NULL)
		return;

	if (wireless->associate == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return;
	}

	wireless->associate(intdata);
}

/******************************************
 *
 * Ask the wireless card for the ESSID that we are currently connected to.  If
 * this is not a wireless card, or the information is not available, we should
 * return an error.
 *
 * @param[in] ssidsize   The size of the ssid_name buffer.
 ******************************************/
int cardif_GetSSID(context * thisint, char *ssid_name, unsigned int ssidsize)
{
	if (wireless == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No valid call to get SSID for this driver!" "\n");
		return -1;
	}

	if ((thisint == NULL) || (ssid_name == NULL)) {
		debug_printf(DEBUG_INT, "NULL value passed to %s!\n",
			     __FUNCTION__);
		return -1;
	}

	if (wireless->get_ssid == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->get_ssid(thisint, ssid_name, ssidsize);
}

/******************************************
 *
 * Get the Broadcast SSID (MAC address) of the Access Point we are connected 
 * to.  If this is not a wireless card, or the information is not available,
 * we should return an error.
 *
 ******************************************/
int cardif_GetBSSID(context * thisint, char *bssid_dest)
{
	if (wireless == NULL)
		return -1;

	if (thisint == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid interface data structure passed to %s!\n",
			     __FUNCTION__);
		return -1;
	}

	if (bssid_dest == NULL) {
		debug_printf(DEBUG_NORMAL, "Invalid bssid_dest in %s!\n",
			     __FUNCTION__);
		return -1;
	}

	if (wireless->get_bssid == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->get_bssid(thisint, bssid_dest);
}

/******************************************
 *
 * Set the flag in the state machine that indicates if this interface is up
 * or down.  If there isn't an interface, we should return an error.
 *
 ******************************************/
int cardif_get_if_state(context * thisint)
{
	int flags;

	if (!_getiff(thisint->intName, &flags))
		return XENONE;

	return (flags & IFF_UP) != 0;
}

/**
 * \brief Get the link state of an interface.
 *
 * @param[in] ctx   The context for the interface that we want to determine the link
 *                  state of an interface for.
 *
 * \retval XEMALLOC on memory allocation error
 * \retval TRUE if link is up
 * \retval FALSE if link is down
 **/
int cardif_get_link_state(context * ctx)
{
	//int retVal = 0;
	int result = 0;		//, *state = NULL;
	struct darwin_sock_data *sockData = NULL;

	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return XEMALLOC;

	if (TEST_FLAG(ctx->flags, INT_GONE))
		return FALSE;	// The interface isn't there, so it can't be up. ;)

	sockData = ctx->sockData;

	if (!xsup_assert((sockData != NULL), "sockData != NULL", FALSE))
		return XEMALLOC;

#warning This is a stub.  Need to implement.

	if (result == 0) {
		return TRUE;
	}

	return FALSE;
}

/******************************************
 *
 * Send a frame out of the network card interface.  If there isn't an 
 * interface, we should return an error.  We should return a different error
 * if we have a problem sending the frame.
 *
 ******************************************/
int cardif_sendframe(context * ctx)
{
	char nomac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	int retval;
	struct darwin_sock_data *sockData;
	struct sockaddr_ndrv ndrv;
	uint16_t pad;

	if (ctx == NULL)
		return XEMALLOC;

	sockData = (struct darwin_sock_data *)ctx->sockData;

	if (ctx->send_size == 0)
		return XENONE;

	if (ctx->conn == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No connection information to use during "
			     "authentication!\n");
		return XENONE;
	}
	// The frame we are handed in shouldn't have a src/dest, so put it in.
	memcpy(&ctx->sendframe[0], &ctx->dest_mac[0], 6);
	memcpy(&ctx->sendframe[6], &ctx->source_mac[0], 6);

	if (memcmp(nomac, (char *)&ctx->conn->dest_mac[0], 6) != 0) {
		debug_printf(DEBUG_INT,
			     "Static MAC address defined!  Using it!\n");
		memcpy(&ctx->sendframe[0], &ctx->conn->dest_mac[0], 6);
	}
	// Make sure the frame is large enough.
	if ((ctx->intType != ETH_802_11_INT) && (ctx->send_size < 64)) {
		pad = 64 - ctx->send_size;
		debug_printf(DEBUG_INT,
			     "Padding frame to 64 bytes by adding %d byte"
			     "(s).\n", pad);
		memset(&ctx->sendframe[ctx->send_size + 1], 0x00, pad);
		ctx->send_size += pad;
	}

	debug_printf(DEBUG_INT, "Frame to be sent (%d) : \n", ctx->send_size);
	debug_hex_dump(DEBUG_INT, ctx->sendframe, ctx->send_size);

	memset(&ndrv, 0x00, sizeof(ndrv));
	ndrv.snd_len = sizeof(ndrv);
	ndrv.snd_family = AF_NDRV;

	snmp_dot1xSuppEapolFramesTx();
	retval = sendto(sockData->sockInt, ctx->sendframe, ctx->send_size,
			0, (struct sockaddr *)&ndrv, sizeof(ndrv));

	if (retval != ctx->send_size)
		debug_printf(DEBUG_NORMAL, "Couldn't send frame! %d: %s\n",
			     errno, strerror(errno));

	memset(ctx->sendframe, 0x00, FRAMESIZE);
	ctx->send_size = 0;

	if (ctx->recvframe != NULL) {
		memset(ctx->recvframe, 0x00, FRAMESIZE);
		ctx->recv_size = 0;
	}

	return retval;
}

/******************************************
 * 
 * Get a frame from the network.  Make sure to check the frame, to determine 
 * if it is something we care about, and act accordingly.
 *
 ******************************************/
int cardif_getframe(context * thisint)
{
	int newsize = 0;
	char dot1x_default_dest[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
	struct darwin_sock_data *sockData;
	uint8_t *resultframe;
	int resultsize;
	struct config_globals *globals;

	if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
		return XEMALLOC;

	globals = config_get_globals();

	if (!xsup_assert((globals != NULL), "globals != NULL", FALSE))
		return XEMALLOC;

	sockData = (struct darwin_sock_data *)thisint->sockData;

	errno = 0;
	resultsize = FRAMESIZE;

	FREE(thisint->recvframe);

	resultframe = malloc(FRAMESIZE);
	if (resultframe == NULL) {
		debug_printf(DEBUG_INT,
			     "Couldn't allocate memory for incoming frame!\n");
		return -1;
	}

	memset(resultframe, 0x00, FRAMESIZE);

	newsize = recv(sockData->sockInt, resultframe, resultsize, 0);
	if (newsize <= 0) {
		if (errno != EAGAIN) {
			debug_printf(DEBUG_NORMAL, "Error (%d) : %s  (%s:%d)\n",
				     errno, strerror(errno), __FUNCTION__,
				     __LINE__);
		}
		return XENOFRAMES;
	} else {
		debug_printf(DEBUG_INT, "Got Frame : \n");
		debug_hex_dump(DEBUG_INT, resultframe, newsize);
	}

	snmp_dot1xSuppEapolFramesRx();

	// Make sure that the frame we got is for us..
	if ((memcmp(&thisint->source_mac[0], &resultframe[0], 6) == 0) ||
	    ((memcmp(&resultframe[0], &dot1x_default_dest[0], 6) == 0) &&
	     (memcmp(&resultframe[6], &thisint->source_mac[0], 6) != 0))) {
		// Since we now know this frame is for us, record the address it
		// came from.
		snmp_dot1xSuppLastEapolFrameSource((uint8_t *) &
						   resultframe[6]);

		resultsize = newsize;

		switch (globals->destination) {
		case DEST_AUTO:
		case DEST_SOURCE:
			if (memcmp(thisint->dest_mac, &resultframe[6], 6) != 0) {
				debug_printf(DEBUG_INT,
					     "Changing destination mac to source.\n");
			}
			memcpy(thisint->dest_mac, &resultframe[6], 6);
			break;

		case DEST_MULTICAST:
			memcpy(thisint->dest_mac, dot1x_default_dest, 6);
			break;

		case DEST_BSSID:
			cardif_GetBSSID(thisint, thisint->dest_mac);
			break;

		default:
			debug_printf(DEBUG_NORMAL,
				     "Unknown destination mode!\n");
			break;
		}

		thisint->recv_size = newsize;

		//      memcpy(thisint->recvframe, resultframe, newsize);
		thisint->recvframe = resultframe;
		return newsize;
	}
	// Otherwise it isn't for us. 
	debug_printf(DEBUG_INT, "Got a frame, not for us.\n");
	return XENOFRAMES;
}

/**************************************************************
 *
 * Set the state needed to associate to a WPA enabled AP, and actually
 * do a WPA authentication.
 *
 **************************************************************/
int cardif_enable_wpa_state(context * thisint)
{
	if (wireless == NULL)
		return -1;

	if (wireless->wpa_state == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->wpa_state(thisint, 1);
}

/**************************************************************
 *
 * Clear the state needed to associate to a WPA enabled AP, and actually
 * do a WPA authentication.
 *
 **************************************************************/
int cardif_disable_wpa_state(context * thisint)
{
	if (wireless == NULL)
		return -1;

	if (wireless->wpa_state == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->wpa_state(thisint, 0);
}

/**************************************************************
 *
 * Enable WPA (if it is supported.)
 *
 **************************************************************/
int cardif_enable_wpa(context * thisint)
{
	if (wireless == NULL)
		return -1;

	if (wireless->wpa == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->wpa(thisint, TRUE);
}

/**************************************************************
 *
 * Call this when we roam to a different AP, or disassociate from an AP.
 *
 **************************************************************/
int cardif_roam(context * thisint)
{
	if (wireless == NULL)
		return -1;

	debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
	return -1;
}

/******************************************
 *
 * Validate an interface, based on if it has a MAC address.
 *
 ******************************************/
int cardif_validate(char *interface)
{
	char mac[6];
	if (_getmac(mac, interface) == XENONE)
		return TRUE;
	else
		return FALSE;
}

/******************************************
 *
 * (en)/(dis)able countermeasures on this interface.
 *
 ******************************************/
int cardif_countermeasures(context * intdata, char endis)
{
	if (wireless == NULL)
		return -1;

	debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
	return -1;
}

/******************************************
 *
 * (en)/(dis)able receiving of unencrypted frames on this interface.
 *
 ******************************************/
int cardif_drop_unencrypted(context * intdata, char endis)
{
	if (wireless == NULL)
		return -1;

	debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
	return -1;
}

/*******************************************************
 *
 * Check to see if an interface is wireless.  On freebsd, we look in
 * /proc/net/wireless to see if the interface is registered with the
 * wireless extensions.
 *
 *******************************************************/
int cardif_int_is_wireless(context * ctx)
{
	// XXX Fix this to be a real check.  Probably need to walk the ioreg, and 
	// compare the MAC address in the Airport section to the MAC address of
	// the interface itself.
	if (strcmp(ctx->intName, "en1") == 0)
		return TRUE;

	debug_printf(DEBUG_INT, "Interface is wired.\n");
	return FALSE;
}

int cardif_get_wpa_ie(context * intdata, char *iedata, int *ielen)
{
	if (intdata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Error!  Invalid interface data structure! "
			     "(%s:%d)\n", __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	if (iedata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid bucket for IE data! (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	if (wireless->get_wpa_ie == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->get_wpa_ie(intdata, iedata, ielen);
}

int cardif_get_wpa2_ie(context * intdata, char *iedata, int *ielen)
{
	if (intdata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Error!  Invalid interface data structure! "
			     "(%s:%d)\n", __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	if (iedata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid bucket for IE data! (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return XEMALLOC;
	}

	if (wireless->get_wpa2_ie == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return -1;
	}

	return wireless->get_wpa2_ie(intdata, iedata, ielen);
}

/**************************************************************
 *
 * This function should clear out all keys that have been applied to the card.
 * It should be independant of the type (WEP/TKIP/CCMP) of key that was
 * applied.
 *
 **************************************************************/
int cardif_clear_keys(context * intdata)
{
	if (wireless == NULL)
		return -1;

	if (wireless->delete_key == NULL) {
		debug_printf(DEBUG_NORMAL, "%s not implemented!\n",
			     __FUNCTION__);
		return -1;
	}

	wireless->delete_key(intdata, 1, 0);
	wireless->delete_key(intdata, 2, 0);
	return 0;
}

/***********************************************************************
 *
 *  The Darwin wireless extensions don't seem to have an event generation
 *  function.  So, we need to manually trap, and process events such as
 *  SSID and BSSID changes, association state changes, etc.
 *
 ***********************************************************************/
int cardif_macosx_manual_events(context * ctx)
{
#ifdef DARWIN_WIRELESS
	char bssid[6];
	char ssid[99];
	uint8_t na[6] = { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 };
	wireless_ctx *wctx;

	debug_printf(DEBUG_INT, "[OS X Wireless] %s\n", __FUNCTION__);

	if (ctx->intType == ETH_802_11_INT) {
		wctx = (wireless_ctx *) ctx->intTypeData;

		if (cardif_GetBSSID(ctx, (char *)&bssid) == XENONE) {
			// Check and see if the BSSID changed.
			if (memcmp(ctx->dest_mac, bssid, 6) != 0) {
				debug_printf(DEBUG_INT,
					     "[OS X Wireless] BSSID change!\n");
				debug_printf(DEBUG_INT,
					     "[OS X Wireless] Clearing keys.\n");
				cardif_clear_keys(ctx);
				debug_printf(DEBUG_INT,
					     "[OS X Wireless] New BSSID : ");
				debug_hex_printf(DEBUG_INT, bssid, 6);
				memcpy(ctx->dest_mac, bssid, 6);

				if (memcmp(na, ctx->dest_mac, 6) == 0) {
					// We aren't associated.
					UNSET_FLAG(wctx->flags,
						   WIRELESS_SM_ASSOCIATED);
					UNSET_FLAG(wctx->flags,
						   WIRELESS_SM_STALE_ASSOCIATION);
				} else {
					if (!TEST_FLAG
					    (wctx->flags,
					     WIRELESS_SM_STALE_ASSOCIATION))
						SET_FLAG(wctx->flags,
							 WIRELESS_SM_ASSOCIATED);
				}
			}
		}

		if (cardif_GetSSID(ctx, (char *)&ssid, 99) == XENONE) {
			if (strcmp(wctx->cur_essid, ssid) != 0) {
				debug_printf(DEBUG_INT,
					     "[OS X Wireless] SSID change!\n");
				debug_printf(DEBUG_INT,
					     "[OS X Wireless] New SSID : %s\n",
					     ssid);
				debug_printf(DEBUG_INT,
					     "[OS X Wireless] Old SSID : %s\n",
					     wctx->cur_essid);

				FREE(wctx->cur_essid);

				wctx->cur_essid = strdup(ssid);

				if (config_build(ctx, wctx->cur_essid) == FALSE) {
					debug_printf(DEBUG_NORMAL,
						     "Couldn't build a valid "
						     "configuration for ESSID '%s'!\n",
						     ssid);
				}
			}
		}
	}
#endif

	return 0;
}

void cardif_reassociate(context * intdata, uint8_t reason)
{
	if (intdata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid interface struct passed to %s!\n",
			     __FUNCTION__);
		return;
	}

	if (wireless == NULL)
		return;

	if (wireless->associate == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return;
	}

	wireless->associate(intdata);
}

void cardif_try_associate(context * intdata)
{
	if (intdata == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid interface struct passed to %s!\n",
			     __FUNCTION__);
		return;
	}

	if (wireless == NULL)
		return;

	if (wireless->associate == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented.\n", __FUNCTION__);
		return;
	}

	wireless->associate(intdata);
}

void cardif_get_abilities(context * intdata)
{
	if (wireless == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented!\n", __FUNCTION__);
		return;
	}

	if (wireless->enc_capabilities == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented!\n", __FUNCTION__);
		return;
	}

	wireless->enc_capabilities(intdata);
}

void cardif_wait_for_int(char *intname)
{
	// XXX Do we need to write something here?  In most cases, people won't add
	// additional interfaces to their machines.  They just use what it comes with.
}

void cardif_passive_scan_timeout(context * ctx)
{
	// Nothing to do here, since we don't support passive scanning on the Mac!
}

int cardif_enc_disable(context * ctx)
{
	// The Airport API doesn't have an option to disable encryption.
	return XENONE;
}

int cardif_wep_associate(context * ctx, int zeros)
{
	if (wireless == NULL)
		return -1;

	if (wireless->wep_associate == NULL) {
		debug_printf(DEBUG_INT, "%s not implemented!\n", __FUNCTION__);
		return -1;
	}

	return wireless->wep_associate(ctx, zeros);
}

void cardif_operstate(context * ctx, uint8_t newstate)
{
	// No operstate stuff for OS X.
}

/**
 * \brief Determine if an interface is wireless based on it's name.
 *
 * @param[in] intname   The interface name to check on.
 *
 * \retval TRUE if the interface is wireless
 * \retval FALSE if the interface isn't wireless
 *
 * \todo Actually figure out if the interface is wireless or not, instead of
 *       just assuming it is interface en1!
 **/
int is_wireless(char *intname)
{
#ifdef DARWIN_WIRELESS
	//  This is a hack for now..  Find something better!
	if (strcmp(intname, "en1") == 0)
		return TRUE;

	return FALSE;
#else
	// If we aren't built with wireless, don't bother checking.
	return FALSE;
#endif
}

/**
 * \brief Enumerate all of the interfaces that are on the machine, and put
 *        them in the interface cache.
 **/
void cardif_enum_ints()
{
	struct if_nameindex *ifnames;
	int i = 0;
	char mac[6];

	ifnames = if_nameindex();
	if (ifnames == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Got an error with if_nameindex() call!\n");
		debug_printf(DEBUG_NORMAL,
			     "Are there no interfaces on this machine?\n");
		return;
	}

	while ((ifnames[i].if_index != 0) && (ifnames[i].if_name != NULL)) {
		debug_printf(DEBUG_INT, "Interface %d named %s.\n",
			     ifnames[i].if_index, ifnames[i].if_name);

		// Make sure we aren't looking at any loopback interfaces.
		if (strcasestr(ifnames[i].if_name, "lo") == NULL) {
			if (_getmac((char *)&mac, ifnames[i].if_name) == TRUE) {
				// Add it to our interface cache!
				interfaces_add(ifnames[i].if_name,
					       ifnames[i].if_name, mac,
					       is_wireless(ifnames[i].if_name));
			}
		}

		i++;
	}

	if_freenameindex(ifnames);
}

/**
 * \brief Determine the signal strength (as a percentage) of the wireless 
 *        connection.
 *
 * @param[in] ctx   The context for the interface we want to get the signal
 *                  strength for.
 *
 * \retval >=0   The signal strength for the context.
 * \retval <0   An error.
 **/
int cardif_get_signal_strength_percent(context * ctx)
{
	if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
		return -1;

	if (wireless == NULL)
		return -1;

	if (!wireless->get_signal_percent) {
		debug_printf(DEBUG_INT,
			     "No function defined to get the signal strength!\n");
		return -1;
	}

	return wireless->get_signal_percent(ctx);
}

struct ifaddrs *find_ip_int(context * ctx, struct ifaddrs *root)
{
	struct ifaddrs *cur = NULL;

	if (root == NULL)
		return NULL;
	if (ctx == NULL)
		return NULL;

	cur = root;

	while (cur) {
		if ((strcmp(ctx->intName, cur->ifa_name) == 0) &&
		    (cur->ifa_addr->sa_family == AF_INET))
			return cur;

		cur = cur->ifa_next;
	}

	return NULL;		// Not found!
}

/**
 * \brief Return the IP address of the interface pointed to by ctx.
 *
 * @param[in] ctx   The context for the interface we want to get information
 *                  about.
 *
 * \retval NULL on error.
 * \retval ptr to an IP address on success
 **/
char *cardif_get_ip(context * ctx)
{
	struct ifaddrs *ifs = NULL, *cur = NULL;
	char *ipaddr = NULL;

	if (ctx == NULL) {
		debug_printf(DEBUG_NORMAL, "Context is invalid!\n");
		return NULL;
	}

	if (getifaddrs(&ifs) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't get interface information!\n");
		return NULL;
	}

	cur = find_ip_int(ctx, ifs);
	if (cur == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't locate IPv4 information for interface"
			     " %s!\n", ctx->intName);
		freeifaddrs(ifs);
		return NULL;
	}
	// The value returned by inet_ntoa() resides in a static buffer.  So we need
	// to make a copy of it.
	ipaddr =
	    strdup(inet_ntoa
		   (((struct sockaddr_in *)(cur->ifa_addr))->sin_addr));
	if (ipaddr == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't convert IP address to a string!\n");
		freeifaddrs(ifs);
		return NULL;
	}

	debug_printf(DEBUG_INT, "Found IP address %s for interface %s.\n",
		     ipaddr, ctx->intName);

	freeifaddrs(ifs);

	return ipaddr;
}

char *cardif_get_netmask(context * ctx)
{
	struct ifaddrs *ifs = NULL, *cur = NULL;
	char *netmask = NULL;

	if (ctx == NULL) {
		debug_printf(DEBUG_NORMAL, "Context is invalid!\n");
		return NULL;
	}

	if (getifaddrs(&ifs) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't get interface information!\n");
		return NULL;
	}

	cur = find_ip_int(ctx, ifs);
	if (cur == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't locate IPv4 information for interface"
			     " %s!\n", ctx->intName);
		freeifaddrs(ifs);
		return NULL;
	}
	// The return value of inet_ntoa is a static buffer, so we need to make a 
	// copy of the resulting string.
	netmask =
	    strdup(inet_ntoa
		   (((struct sockaddr_in *)(cur->ifa_netmask))->sin_addr));
	if (netmask == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't convert netmask to a string!\n");
		freeifaddrs(ifs);
		return NULL;
	}

	debug_printf(DEBUG_INT, "Found netmask  %s for interface %s.\n",
		     netmask, ctx->intName);

	freeifaddrs(ifs);

	return netmask;
}

/**
 * \brief Round up an integer to a multiple of 4.
 *
 * @param[in] a   The integer value to round up.
 *
 * \retval int   The multiple of 4.
 **/
int div4(int a)
{
	int t;

	t = (a % 4);
	if (t > 0) {
		t = a + (4 - t);
	} else {
		t = a;
	}

	return t;
}

/**
 * \brief Determine the default gateway that is in use for this host.
 *
 * @param[in] ctx   The context for the interface that we want to determine
 *                  the default gateway for.
 *
 * \retval NULL on error
 * \retval ptr to IP address of the default gateway on success.
 **/
char *cardif_get_gw(context * ctx)
{
	struct sockaddr *sockdata = NULL;
	struct sockaddr_in *sin = NULL;
	struct rt_msghdr *rtm = NULL;
	char buf[512];
	int seq = 0, s = 0, l = 0;
	char *retval = NULL;

	memset(&buf, 0x00, 512);

	rtm = (struct rt_msghdr *)&buf[0];

	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = RTF_UP | RTF_GATEWAY;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_seq = ++seq;
	rtm->rtm_addrs = RTA_DST | RTA_NETMASK;

	sockdata = (struct sockaddr *)&buf[div4(sizeof(struct rt_msghdr))];
	sockdata->sa_family = AF_INET;
	sockdata->sa_len = sizeof(struct sockaddr_in);

	sockdata =
	    (struct sockaddr *)&buf[div4(sizeof(struct rt_msghdr)) +
				    div4(sizeof(struct sockaddr_in))];
	sockdata->sa_family = AF_INET;
	sockdata->sa_len = sizeof(struct sockaddr_in);

	rtm->rtm_msglen =
	    (div4(sizeof(struct sockaddr_in)) * 2) +
	    div4(sizeof(struct rt_msghdr));;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		debug_printf(DEBUG_NORMAL, "Error getting RTNetlink socket!\n");
		return NULL;
	}

	if (write(s, &buf, rtm->rtm_msglen) < 0) {
		debug_printf(DEBUG_NORMAL, "Error writing routing socket!\n");
		debug_printf(DEBUG_NORMAL, "Error %d : %s\n", errno,
			     strerror(errno));
		return NULL;
	}

	do {
		// Look for the proper sequence number for the response.
		l = read(s, (char *)&buf, sizeof(buf));
	} while ((l > 0) && (rtm->rtm_seq != seq));

	close(s);

	sin = (struct sockaddr_in *)&buf[div4(sizeof(struct rt_msghdr))];

	sin =
	    (struct sockaddr_in *)&buf[div4(sizeof(struct rt_msghdr)) +
				       div4(sizeof(struct sockaddr_in))];

	retval = strdup(inet_ntoa(sin->sin_addr));
	debug_printf(DEBUG_INT, "Default Route : %s\n", retval);

	return retval;
}

/**
 * \brief Get the first DNS in our list.
 *
 * @param[in] ctx   Get the DNS for the context listed.
 *
 * \retval NULL on error
 * \retval ptr the first DNS
 **/
char *cardif_get_dns1(context * ctx)
{
	struct __res_state res;
	int numservs = 0;
	union res_sockaddr_union u[MAXNS];
	char *retval = NULL;

	if (res_ninit(&res) != 0) {
		debug_printf(DEBUG_NORMAL, "Couldn't init resolver library!\n");
		return NULL;
	}

	numservs = res_getservers(&res, (union res_sockaddr_union *)&u, MAXNS);

	if (numservs < 1)
		return NULL;

	retval = strdup(inet_ntoa(u[0].sin.sin_addr));
	res_nclose(&res);

	return retval;
}

/**
 * \brief Get the first DNS in our list.
 *
 * @param[in] ctx   Get the DNS for the context listed.
 *
 * \retval NULL on error
 * \retval ptr the first DNS
 **/
char *cardif_get_dns2(context * ctx)
{
	struct __res_state res;
	int numservs = 0;
	union res_sockaddr_union u[MAXNS];
	char *retval = NULL;

	if (res_ninit(&res) != 0) {
		debug_printf(DEBUG_NORMAL, "Couldn't init resolver library!\n");
		return NULL;
	}

	numservs = res_getservers(&res, (union res_sockaddr_union *)&u, MAXNS);

	if (numservs < 2)
		return NULL;

	retval = strdup(inet_ntoa(u[1].sin.sin_addr));
	res_nclose(&res);

	return retval;
}

/**
 * \brief Get the first DNS in our list.
 *
 * @param[in] ctx   Get the DNS for the context listed.
 *
 * \retval NULL on error
 * \retval ptr the first DNS
 **/
char *cardif_get_dns3(context * ctx)
{
	struct __res_state res;
	int numservs = 0;
	union res_sockaddr_union u[MAXNS];
	char *retval = NULL;

	if (res_ninit(&res) != 0) {
		debug_printf(DEBUG_NORMAL, "Couldn't init resolver library!\n");
		return NULL;
	}

	numservs = res_getservers(&res, (union res_sockaddr_union *)&u, MAXNS);

	if (numservs < 3)
		return NULL;

	retval = strdup(inet_ntoa(u[2].sin.sin_addr));
	res_nclose(&res);

	return retval;
}

/**
 * \brief Determine in an interface is wireless based on it's OS specific
 *        interface name.
 *
 * @param[in] intname   The OS specific interface name that we want to check
 *                      to see if it is wireless.
 *
 * \retval TRUE if the interface is wireless
 * \retval FALSE if the interface is *NOT* wireless
 **/
int cardif_is_wireless_by_name(char *intname)
{
	return is_wireless(intname);
}

/**
 * \brief Determine the device description based on the OS specific interface
 *        name.  For Darwin, the OS specific interface name, and the
 *        device description will be the same.
 *
 * @param[in] intname   The OS specific interface name to search for.
 *
 * \retval NULL on error, or interface not found.
 * \retval ptr to the interface description
 **/
char *cardif_find_description(char *intname)
{
	return strdup(intname);
}

/**
 * \brief Get a string representation of an interface's MAC address based on the
 *        OS specific interface name.
 *
 * @param[in] intname   The OS specific interface name for the interface we want \
to
*                      get information on.
*
* \retval NULL on error
* \retval ptr to MAC address string on success
**/
char *cardif_get_mac_str(char *intname)
{
	uint8_t mac[6];
	char *resmac = NULL;

	if (_getmac((char *)&mac, intname) != TRUE)
		return NULL;

	resmac = Malloc(25);
	if (resmac == NULL)
		return NULL;

	sprintf(resmac, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2]
		, mac[3], mac[4], mac[5]);

	return resmac;
}
