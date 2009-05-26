/*******************************************************************
 * FreeBSD card interface implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_freebsd.c
 *
 * \author Fernando Schapachnik <fernando@mecon.gov.ar>, based
 * on the work of Ivan Voras <ivoras@fer.hr> and the Linux version by
 * chris@open1x.org.
 *
 *******************************************************************/

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
#include <net/bpf.h>

#include "config.h"
#include "context.h"
#include "config_ssid.h"
#include "xsup_common.h"
#include "cardif/cardif.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "snmp.h"
#include "statemachine.h"
#include "cardif_freebsd.h"
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

/* open a bpf device; return fd handle */
static int _bpf_setup(struct interface_data *idata)
{
	char basedev[] = "/dev/bpf";
	char devname[15];
	int ndev = 0, fd;
	struct ifreq ifr;
	int one = 1, zero = 0;
	struct fbsd_sock_data *sockData;

	struct bpf_insn progcodes[] = {
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),	// inspect ethernet_frame_type
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_EAPOL, 0, 1),	// if EAPOL frame, continue with next instruction, else jump
		BPF_STMT(BPF_RET + BPF_K, (u_int) - 1),
		BPF_STMT(BPF_RET + BPF_K, 0)
	};

	struct bpf_program prog = {
		4,
		(struct bpf_insn *)&progcodes
	};

	struct timeval tv;

	do {			// try and open a bpf device
		sprintf(devname, "%s%d", basedev, ndev);
		fd = open(devname, O_RDWR);
		ndev++;
	} while (fd < 0 && ndev < 15);

	if (fd < 0) {
		debug_printf(DEBUG_INT, "Cannot open a bpf device\n");
		return FALSE;
	};

	idata->sockData = Malloc(sizeof(struct fbsd_sock_data));
	if (idata->sockData == NULL) {
		debug_printf(DEBUG_INT, "malloc(%d) of sockData failed\n",
			     sizeof(struct fbsd_sock_data));
		return FALSE;
	}
	sockData = (struct fbsd_sock_data *)idata->sockData;
	sockData->bpf = fd;

	if (ioctl(fd, BIOCGBLEN, &sockData->buf_size) < 0) {
		debug_printf(DEBUG_INT, "BIOCGBLEN failed\n");
		return FALSE;
	}

	Strncpy(ifr.ifr_name, idata->intName, IFNAMSIZ);
	if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
		debug_printf(DEBUG_INT, "BIOCSETIF failed on %s\n",
			     ifr.ifr_name);
		return FALSE;
	}

	sockData->buf = Malloc(sockData->buf_size);
	if (sockData->buf == NULL) {
		debug_printf(DEBUG_INT, "malloc(%d) of buf failed\n",
			     sockData->buf_size);
		return FALSE;
	}

	if (ioctl(fd, BIOCIMMEDIATE, &one) < 0) {
		debug_printf(DEBUG_INT, "BIOCIMMEDIATE failed\n");
		return FALSE;
	}

	tv.tv_sec = 0;
	tv.tv_usec = 500000;
	if (ioctl(fd, BIOCSRTIMEOUT, &tv) < 0) {
		debug_printf(DEBUG_INT, "BIOCSRTIMEOUT failed\n");
		return FALSE;
	}

	if (ioctl(fd, BIOCSSEESENT, &zero) < 0) {
		debug_printf(DEBUG_INT, "BIOCSSEESENT failes\n");
		return FALSE;
	}

	if (ioctl(fd, BIOCSETF, &prog) < 0) {
		debug_printf(DEBUG_INT, "BIOCSETF failed\n");
		return FALSE;
	}

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
int cardif_check_associated(struct interface_data *intdata)
{
	debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n", __FUNCTION__);
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
	switch (driver) {
	case DRIVER_NONE:
		wireless = NULL;
		break;

		/* No wireless drivers supported by now. */
	}
}

/***********************************************
 *
 * Do whatever is needed to get the interface in to a state that we can send
 * and recieve frames on the network.  Any information that we need to later
 * use should be stored in the interface_data structure.
 *
 ***********************************************/
int cardif_init(struct interface_data *thisint, char driver)
{
	struct ifreq ifr;
	struct fbsd_sock_data *sockData;
	struct config_globals *globals;

	if (thisint == NULL) {
		debug_printf(DEBUG_NORMAL, "Invalid interface data in %s!\n",
			     __FUNCTION__);
		return XEGENERROR;
	}

	globals = config_get_globals();

	if (globals == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No valid configuration globals available!\n");
		return XEGENERROR;
	}

	debug_printf(DEBUG_INT, "Initializing bpf for interface %s..\n",
		     thisint->intName);

	// Keep track of which driver we were assigned.
	thisint->driver_in_use = driver;

	// Find out what the interface index is.
	thisint->intIndex = if_nametoindex(thisint->intName);
	debug_printf(DEBUG_INT, "Index : %d\n", thisint->intIndex);

	if (!_bpf_setup(thisint)) {
		debug_printf(DEBUG_INT,
			     "--> Cannot setup bpf! This is fatal!\n");
		return XENOSOCK;
	}
	// Get our MAC address.  (Needed for sending frames out correctly.)
	if (!_getmac(thisint->source_mac, thisint->intName)) {
		debug_printf(DEBUG_INT, "Cannot get MAC address\n");
		return XENOSOCK;
	}
	// Establish a socket handle.
	sockData = (struct fbsd_sock_data *)thisint->sockData;
	sockData->sockInt = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockData->sockInt < 0) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't initialize socket for interface %s!\n",
			     thisint->intName);
		return XENOSOCK;
	}
	// Check if we want ALLMULTI mode, and enable it.
	if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_ALLMULTI) {
	    // Tell the ifreq struct which interface we want to use.
	    Strncpy((char *)&ifr.ifr_name, thisint->intName,
		    sizeof(ifr.ifr_name));
	    if (ioctl(sockData->sockInt, SIOCGIFFLAGS, &ifr) < 0) {
	    debug_printf(DEBUG_NORMAL,
			 "Couldn't determine if ALLMULTI is enabled!\n");}
	    else {
	    if (ifr.ifr_flags & IFF_ALLMULTI) {
	    debug_printf(DEBUG_INT,
			 "Allmulti mode is already enabled on this device!\n");
	    thisint->flags |= ALLMULTI;}
	    else {
	    debug_printf(DEBUG_INT,
			 "Allmulti is currently disabled on this device!\n");
	    thisint->flags &= ~ALLMULTI;}
	    }

	    ifr.ifr_flags |= IFF_ALLMULTI;
	    if (ioctl(sockData->sockInt, SIOCSIFFLAGS, &ifr) < 0) {
	    debug_printf(DEBUG_NORMAL,
			 "Couldn't set ALLMULTI mode on this interface!  We will continue anyway!\n");}
	    }

	    // Set up wireless card drivers.
	    cardif_set_driver(driver); if (!block_wpa) {
	    debug_printf(DEBUG_NORMAL, "WPA support not available!\n");}
	    else {
	    debug_printf(DEBUG_NORMAL, "Not turning on WPA support!\n");}

	    return XENONE;}

/**************************************************************
 *
 * Tell the wireless card to start scanning for wireless networks.
 *
 **************************************************************/
	    int cardif_do_wireless_scan(struct interface_data *thisint) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/**************************************************************
 *
 * Send a disassociate message.
 *
 **************************************************************/
	    int cardif_disassociate(struct interface_data *thisint,
				    int reason_code) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/******************************************
 *
 * Return the socket number for functions that need it.
 *
 ******************************************/
	    int cardif_get_socket(struct interface_data *thisint) {
	    debug_printf(DEBUG_EXCESSIVE, "%s not needed in BSD.\n",
			 __FUNCTION__); return 0;}

/******************************************
 *
 * Clean up anything that was created during the initialization and operation
 * of the interface.  This will be called before the program terminates.
 *
 ******************************************/
	    int cardif_deinit(struct interface_data *thisint) {
	    struct ifreq ifr;
	    debug_printf(DEBUG_EVERYTHING, "Cleaning up interface %s...\n",
			 thisint->intName); struct fbsd_sock_data * sockData;
	    sockData = (struct fbsd_sock_data *)thisint->sockData;
	    // Check if we want ALLMULTI mode, and enable it.
	    if (TEST_FLAG(thisint->flags, ALLMULTI)) {
	    // Tell the ifreq struct which interface we want to use.
	    Strncpy((char *)&ifr.ifr_name, thisint->intName,
		    sizeof(ifr.ifr_name));
	    if (ioctl(sockData->sockInt, SIOCGIFFLAGS, &ifr) < 0) {
	    debug_printf(DEBUG_NORMAL, "Couldn't get interface flags!\n");}
	    else {
	    // Check if allmulti was disabled when we started.  If it was,
	    // then disable it again, so everything is good.
	    if (!(thisint->flags & ALLMULTI)) {
	    debug_printf(DEBUG_INT, "Turning off ALLMULTI mode!\n");
	    ifr.ifr_flags &= ~IFF_ALLMULTI;
	    if (ioctl(sockData->sockInt, SIOCSIFFLAGS, &ifr) < 0) {
	    debug_printf(DEBUG_NORMAL,
			 "Couldn't set ALLMULTI mode on this interface!  We will continue anyway!\n");}
	    }
	    }
	    }

	    close(sockData->sockInt);
	    close(sockData->bpf);
	    FREE(sockData->buf); FREE(thisint->sockData); return XENONE;}

/******************************************
 *
 * Set a WEP key.  Also, based on the index, we may change the transmit
 * key.
 *
 ******************************************/
	    int cardif_set_wep_key(struct interface_data *thisint,
				   uint8_t * key, int keylen, int index) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "set_wep_key not implemented.\n");
	    return -1;}

/**********************************************************
 *
 * Set a TKIP key. 
 *
 **********************************************************/
	    int cardif_set_tkip_key(struct interface_data *thisint, char *addr,
				    int keyidx, int settx, char *seq,
				    int seqlen, char *key, int keylen) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "set_tkip_key not implemented.\n");
	    return -1;}

/**********************************************************
 *
 * Set a CCMP (AES) key
 *
 **********************************************************/
	    int cardif_set_ccmp_key(struct interface_data *thisint, char *addr,
				    int keyidx, int settx, char *seq,
				    int seqlen, char *key, int keylen) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "set_ccmp_key not implemented.\n");
	    return -1;}

/**********************************************************
 *
 * Delete a key
 *
 **********************************************************/
	    int cardif_delete_key(struct interface_data *intdata, int key_idx,
				  int set_tx) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "delete_key not implemented.\n");
	    return -1;}

/******************************************
 *
 * If our association timer expires, we need to attempt to associate again.
 *
 ******************************************/
	    void cardif_association_timeout_expired(struct interface_data
						    *intdata) {
	    // And try to associate again.
	    cardif_associate(intdata, intdata->cur_essid);}

/******************************************
 *
 * Do whatever we need to do in order to associate based on the flags in
 * the ssids_list struct.
 *
 ******************************************/
	    void cardif_associate(struct interface_data *intdata, char *newssid) {
	    if (intdata == NULL) {
	    debug_printf(DEBUG_NORMAL,
			 "Invalid interface struct passed to %s!\n",
			 __FUNCTION__); return;}

	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return;}

/******************************************
 *
 * Ask the wireless card for the ESSID that we are currently connected to.  If
 * this is not a wireless card, or the information is not available, we should
 * return an error.
 *
 ******************************************/
	    int cardif_GetSSID(struct interface_data *thisint, char *ssid_name) {
	    if (wireless == NULL) {
	    debug_printf(DEBUG_NORMAL,
			 "No valid call to get SSID for this driver!" "\n");
	    return -1;}

	    if ((thisint == NULL) || (ssid_name == NULL)) {
	    debug_printf(DEBUG_INT, "NULL value passed to %s!\n", __FUNCTION__);
	    return -1;}
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/******************************************
 *
 * Get the Broadcast SSID (MAC address) of the Access Point we are connected 
 * to.  If this is not a wireless card, or the information is not available,
 * we should return an error.
 *
 ******************************************/
	    int cardif_GetBSSID(struct interface_data *thisint,
				char *bssid_dest) {
	    if (wireless == NULL) return -1; if (thisint == NULL) {
	    debug_printf(DEBUG_NORMAL,
			 "Invalid interface data structure passed to %s!\n",
			 __FUNCTION__); return -1;}

	    if (bssid_dest == NULL) {
	    debug_printf(DEBUG_NORMAL, "Invalid bssid_dest in %s!\n",
			 __FUNCTION__); return -1;}

	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/******************************************
 *
 * Set the flag in the state machine that indicates if this interface is up
 * or down.  If there isn't an interface, we should return an error.
 *
 ******************************************/
	    int cardif_get_if_state(struct interface_data *thisint) {
	    int flags; if (!_getiff(thisint->intName, &flags))
	    return XENONE; return (flags & IFF_UP) != 0;}

/******************************************
 *
 * Send a frame out of the network card interface.  If there isn't an 
 * interface, we should return an error.  We should return a different error
 * if we have a problem sending the frame.
 *
 ******************************************/
	    int cardif_sendframe(struct interface_data *thisint) {
	    char nomac[] = {
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	    int retval;
	    struct fbsd_sock_data * sockData;
	    struct config_network * network_data;
	    sockData = (struct fbsd_sock_data *)thisint->sockData;
	    if (thisint == NULL) return XEMALLOC;
	    if (thisint->send_size == 0) return XENONE;
	    network_data = config_get_network_config();
	    if (network_data == NULL) {
	    debug_printf(DEBUG_NORMAL,
			 "Invalid network configuration structure! "
			 "(%s:%d)\n", __FUNCTION__, __LINE__);
	    return XEBADCONFIG;}

	    // The frame we are handed in shouldn't have a src/dest, so put it in.
	    memcpy(&thisint->sendframe[0], &thisint->dest_mac[0], 6);
	    memcpy(&thisint->sendframe[6], &thisint->source_mac[0], 6);
	    if (memcmp(nomac, (char *)&network_data->dest_mac[0], 6) != 0) {
	    debug_printf(DEBUG_INT, "Static MAC address defined!  Using it!\n");
	    memcpy(&thisint->sendframe[0], &network_data->dest_mac[0], 6);}

	    debug_printf(DEBUG_EVERYTHING, "Frame to be sent : \n");
	    debug_hex_dump(DEBUG_EVERYTHING, thisint->sendframe,
			   thisint->send_size); snmp_dot1xSuppEapolFramesTx();
	    retval =
	    write(sockData->bpf, thisint->sendframe, thisint->send_size);
	    if (retval != thisint->send_size)
	    debug_printf(DEBUG_NORMAL, "Couldn't send frame! %d: %s\n", errno,
			 strerror(errno)); thisint->send_size = 0;
	    return retval;}

/******************************************
 * 
 * Get a frame from the network.  Make sure to check the frame, to determine 
 * if it is something we care about, and act accordingly.
 *
 ******************************************/
	    int cardif_getframe(struct interface_data *thisint) {
	    int newsize = 0; char dot1x_default_dest[6] = {
	    0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
	    struct fbsd_sock_data * sockData;
	    uint8_t resultframe[1520];
	    int resultsize; if (!cardif_frameavail(thisint))
	    return XENOFRAMES;
	    sockData = (struct fbsd_sock_data *)thisint->sockData;
	    struct bpf_hdr * bh = (struct bpf_hdr *)sockData->buf;
	    errno = 0;
	    resultsize = 1550;
	    newsize = read(sockData->bpf, sockData->buf, sockData->buf_size);
	    if (newsize > 0) {
	    debug_printf(DEBUG_EVERYTHING,
			 "recvframe; %d (need to strip bpf header)\n", newsize);
	    if (bh->bh_datalen > resultsize) {
	    debug_printf(DEBUG_NORMAL, "Got a too big frame: %d?!\n",
			 bh->bh_datalen); return XENOFRAMES;}
	    memcpy(resultframe, sockData->buf + bh->bh_hdrlen, bh->bh_datalen);
	    newsize = bh->bh_datalen;}

	    if (newsize <= 0) {
	    if (errno != EAGAIN) {
	    debug_printf(DEBUG_NORMAL, "Error (%d) : %s  (%s:%d)\n", errno,
			 strerror(errno), __FUNCTION__, __LINE__);}
	    return XENOFRAMES;}
	    else {
	    debug_printf(DEBUG_EVERYTHING, "Got Frame : \n");
	    debug_hex_dump(DEBUG_EVERYTHING, resultframe, newsize);}

	    snmp_dot1xSuppEapolFramesRx();
	    // Make sure that the frame we got is for us..
	    if ((memcmp(&thisint->source_mac[0], &resultframe[0], 6) == 0) ||
		((memcmp(&resultframe[0], &dot1x_default_dest[0], 6) == 0) &&
		 (memcmp(&resultframe[6], &thisint->source_mac[0], 6) != 0))) {
	    // Since we now know this frame is for us, record the address it
	    // came from.
	    snmp_dot1xSuppLastEapolFrameSource((char *)&resultframe[6]);
	    resultsize = newsize; switch (config_get_destination()) {
case DEST_AUTO:
case DEST_SOURCE:
	    if (memcmp(thisint->dest_mac, &resultframe[6], 6) != 0) {
	    debug_printf(DEBUG_INT, "Changing destination mac to source.\n");}
memcpy(thisint->dest_mac, &resultframe[6], 6); break; case DEST_MULTICAST:
memcpy(thisint->dest_mac, dot1x_default_dest, 6); break; case DEST_BSSID:
cardif_GetBSSID(thisint, thisint->dest_mac); break; default:
	    debug_printf(DEBUG_NORMAL, "Unknown destination mode!\n"); break;}

	    thisint->recv_size = newsize;
	    memcpy(thisint->recvframe, resultframe, newsize); return newsize;}

	    // Otherwise it isn't for us. 
	    debug_printf(DEBUG_INT, "Got a frame, not for us.\n");
	    return XENOFRAMES;}

/**************************************************************
 *
 * Set the state needed to associate to a WPA enabled AP, and actually
 * do a WPA authentication.
 *
 **************************************************************/
	    int cardif_enable_wpa_state(struct interface_data *thisint) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/**************************************************************
 *
 * Clear the state needed to associate to a WPA enabled AP, and actually
 * do a WPA authentication.
 *
 **************************************************************/
	    int cardif_disable_wpa_state(struct interface_data *thisint) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/**************************************************************
 *
 * Enable WPA (if it is supported.)
 *
 **************************************************************/
	    int cardif_enable_wpa(struct interface_data *thisint) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/**************************************************************
 *
 * Call this when we roam to a different AP, or disassociate from an AP.
 *
 **************************************************************/
	    int cardif_roam(struct interface_data *thisint) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/******************************************
 * 
 * Return true if there is a frame in the queue to be processed.
 *
 ******************************************/
	    int cardif_frameavail(struct interface_data *thisint) {
	    fd_set readfds; struct timeval timeout; struct fbsd_sock_data * sockData; int nfds, ready_sockets, result; sockData = (struct fbsd_sock_data *)thisint->sockData; FD_ZERO(&readfds); FD_SET(sockData->bpf, &readfds); timeout.tv_sec = timeout.tv_usec = 0;	/* Non blocking. */
	    nfds = sockData->bpf + 1;
	    do {
	    ready_sockets = select(nfds, &readfds, (fd_set *) NULL,
				   (fd_set *) NULL,
				   &timeout);} while (ready_sockets < 0
						      && errno == EINTR);
	    if (ready_sockets < 0 && errno != EINTR) {
	    debug_printf(DEBUG_NORMAL, "Error reading sockets: %s\n",
			 strerror(errno)); return FALSE;}

	    result =
	    ((ready_sockets > 0
	      && FD_ISSET(sockData->bpf, &readfds)) ? TRUE : FALSE);
	    return result;}

/******************************************
 *
 * Validate an interface, based on if it has a MAC address.
 *
 ******************************************/
	    int cardif_validate(char *interface) {
	    char mac[6]; if (_getmac(mac, interface) == XENONE)
	    return TRUE;
	    else
	    return FALSE;}

/******************************************
 *
 * (en)/(dis)able countermeasures on this interface.
 *
 ******************************************/
	    int cardif_countermeasures(struct interface_data *intdata,
				       char endis) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/******************************************
 *
 * (en)/(dis)able receiving of unencrypted frames on this interface.
 *
 ******************************************/
	    int cardif_drop_unencrypted(struct interface_data *intdata,
					char endis) {
	    if (wireless == NULL) return -1;
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/*******************************************************
 *
 * Check to see if an interface is wireless.  On freebsd, we look in
 * /proc/net/wireless to see if the interface is registered with the
 * wireless extensions.
 *
 *******************************************************/
	    int cardif_int_is_wireless(char *interface) {
	    debug_printf(DEBUG_INT, "cardif_int_is_wireless not implemented, "
			 "assuming %s is NOT wireless\n", interface);
	    return FALSE;}

	    int cardif_get_wpa_ie(struct interface_data *intdata, char *iedata,
				  int *ielen) {
	    if (intdata == NULL) {
	    debug_printf(DEBUG_NORMAL,
			 "Error!  Invalid interface data structure! "
			 "(%s:%d)\n", __FUNCTION__, __LINE__); return XEMALLOC;}

	    if (iedata == NULL) {
	    debug_printf(DEBUG_NORMAL, "Invalid bucket for IE data! (%s:%d)\n",
			 __FUNCTION__, __LINE__); return XEMALLOC;}

	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

	    int cardif_get_wpa2_ie(struct interface_data *intdata, char *iedata,
				   int *ielen) {
	    if (intdata == NULL) {
	    debug_printf(DEBUG_NORMAL,
			 "Error!  Invalid interface data structure! "
			 "(%s:%d)\n", __FUNCTION__, __LINE__); return XEMALLOC;}

	    if (iedata == NULL) {
	    debug_printf(DEBUG_NORMAL, "Invalid bucket for IE data! (%s:%d)\n",
			 __FUNCTION__, __LINE__); return XEMALLOC;}

	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

/**************************************************************
 *
 * This function should clear out all keys that have been applied to the card.
 * It should be indepentant of the type (WEP/TKIP/CCMP) of key that was
 * applied.
 *
 **************************************************************/
	    int cardif_clear_keys(struct interface_data *intdata) {
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__); return -1;}

	    void cardif_reassociate(struct interface_data *intiface,
				    uint8_t reason) {
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented.\n",
			 __FUNCTION__);}

	    void cardif_try_associate(struct interface_data *intiface) {
	    debug_printf(DEBUG_EXCESSIVE, "%s not implemented!\n",
			 __FUNCTION__);}

	    void cardif_get_abilitites(struct interface_data *intdata) {
	    intdata->enc_capa = 0;}
