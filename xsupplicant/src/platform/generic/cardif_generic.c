/*******************************************************************
 * A generic PCAP handler for support of various OSes.  (Doesn't
 * provide any kind of wireless support!!!!!!)
 *
 * File: cardif_generic.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#ifndef WINDOWS
#include <unistd.h>
#else
#include <packet32.h>
#include <Ntddndis.h>
#endif

#include "../cardif.h"
#include "libxsupconfig/xsupconfig.h"
#include "src/xsup_common.h"
#include "src/context.h"
#include "src/xsup_debug.h"
#include "src/xsup_err.h"
#include "cardif_generic.h"

#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL 0x888e
#endif

#ifdef WINDOWS
char *getmac(char *devname)
{
  PPACKET_OID_DATA    pOidData;
  CHAR *pStr = NULL;
  LPADAPTER adapt = NULL;
  char *mac = NULL;

  // Create an adapter object.
  adapt = PacketOpenAdapter(devname);	
  if (adapt == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't create the adapter object needed to query the MAC address!\n");
	  return NULL;
  }

  pStr = malloc(sizeof(PACKET_OID_DATA)+128);
  ZeroMemory(pStr, sizeof(PACKET_OID_DATA)+128);
  pOidData = (PPACKET_OID_DATA) pStr;
  pOidData->Oid = OID_802_3_CURRENT_ADDRESS;
  pOidData->Length = 6;
  
  if (PacketRequest(adapt, FALSE, pOidData) != TRUE)
  {
	  debug_printf(DEBUG_NORMAL, "Unable to request the MAC address for this interface!\n");
	  PacketCloseAdapter(adapt);
	  return NULL;
  }

  mac = Malloc(6);
  if (mac == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store interface MAC address!\n");
	  PacketCloseAdapter(adapt);
	  return NULL;
  }

  memcpy(mac, pOidData->Data, 6);
  
  debug_printf(DEBUG_INT, "MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", pOidData->Data[0], pOidData->Data[1], pOidData->Data[2],
				pOidData->Data[3], pOidData->Data[4], pOidData->Data[5]);

  PacketCloseAdapter(adapt);

  return mac;
}
#else
#error You need to implement a MAC address discovery function for operation on this OS!
#endif

/***********************************************
 *
 * Return a handle to a pcap descriptor.  If NULL is returned,
 * we have an error.
 *
 ***********************************************/
pcap_t *setup_pcap(char *dev_to_use, char *src_mac, int buf_size, int timeout, 
		   char pcapErr[PCAP_ERRBUF_SIZE])
{
  char pcap_err[PCAP_ERRBUF_SIZE];   // pcap error buffer.
  pcap_t *pcap_descr = NULL;
  bpf_u_int32 pcap_maskp;
  bpf_u_int32 pcap_netp;
  char pcap_filter[100];
  struct bpf_program pcap_fp;
  char *errbuf=NULL;

  pcap_lookupnet(dev_to_use, &pcap_netp, &pcap_maskp, pcap_err);

  pcap_descr = pcap_open_live(dev_to_use, buf_size, 1, timeout, pcap_err);
  if (pcap_descr == NULL)
    {
      debug_printf(DEBUG_NORMAL, "pcap_open_live(): %s\n", pcap_err);
      return NULL;
    }

  sprintf(pcap_filter, "ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether dst 01:80:c2:00:00:03 and ether proto 0x888e", (uint8_t)src_mac[0], (uint8_t)src_mac[1], (uint8_t)src_mac[2],
	  (uint8_t)src_mac[3], (uint8_t)src_mac[4], (uint8_t)src_mac[5]);

  debug_printf(DEBUG_INT, "PCAP Filter : %s\n", pcap_filter);
  
  if (pcap_compile(pcap_descr, &pcap_fp, pcap_filter, 0, pcap_netp) == -1)
    {
      debug_printf(DEBUG_NORMAL, "Error running pcap compile!\n");
      return NULL;
    }

  if (pcap_setfilter(pcap_descr, &pcap_fp) == -1)
    {
      debug_printf(DEBUG_NORMAL, "Error setting filter!\n");
      return NULL;
    }

  return pcap_descr;
}

/***********************************************
 *
 * Do whatever is needed to get the interface in to a state that we can send
 * and recieve frames on the network.  Any information that we need to later
 * use should be stored in the context structure.
 *
 ***********************************************/
int cardif_init(context *thisint, char driver)
{
  char pcap_err[PCAP_ERRBUF_SIZE];
  uint8_t *source_mac = NULL;
  struct gen_sock_data *sockData;

  debug_printf(DEBUG_INT, "Initializing interface %s..\n", thisint->intName);

  if (thisint->intName == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface!\n");
      return -1;
    }

  // For this code, we only handle 1 interface, so the index doesn't matter.
  thisint->intIndex = 0;

  // Allocate memory for the things we need.
  thisint->sockData = (void *)Malloc(sizeof(struct gen_sock_data));
  if (thisint->sockData == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error allocating memory!\n");
      return XEMALLOC;
    }

  sockData = thisint->sockData;

  source_mac = getmac(thisint->intName);

  if (source_mac == NULL) return XEMALLOC;

  if ((sockData->pcap_descr = setup_pcap(thisint->intName, 
					 (char *)source_mac, 
					 1700, 1000, 
					 pcap_err)) == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't open interface %s at line %d in cardif_generic.c!\n",
		   thisint->intName, __LINE__);
      return -1;
    }



  // Store a copy of our source MAC for later use.
  memcpy((char *)&thisint->source_mac[0], (char *)&source_mac[0], 6);

  FREE(source_mac);

  // Allocate a send buffer.
  thisint->sendframe = Malloc(1524);
  if (thisint->sendframe == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for send frame buffer!\n");
	  return -1;
  }

  return XENONE;
}

/**************************************************************
 *
 * We don't know how to handle keys, so don't do anything.
 *
 **************************************************************/
void cardif_reset_keys(context *thisint)
{
  return;
}

/**************************************************************
 *
 * If we determine that this interface is a wireless interface, then
 * we should call this, to have the destination address changed to the
 * AP that we are talking to.  Otherwise, we will always send frames to
 * the multicast address, instead of the AP.  (And, most APs won't answer
 * to the multicast address.)
 *
 **************************************************************/
int cardif_check_dest(context *thisint)
{
  // We probably don't need this either.
  return XENOWIRELESS;
}

/******************************************
 *
 * Return the socket number for functions that need it.
 *
 ******************************************/
int cardif_get_socket(context *thisint)
{
  // This has no meaning in the context of this driver!

  // Update this to use the "get selectable socket" pieces in current libpcap versions.
  return -1;
}

/******************************************
 *
 * Clean up anything that was created during the initialization and operation
 * of the interface.  This will be called before the program terminates.
 *
 ******************************************/
int cardif_deinit(context *thisint)
{
  struct gen_sock_data *sockData;

  sockData = thisint->sockData;

  debug_printf(DEBUG_EVERYTHING, "Cleaning up interface %s...\n",thisint->intName);

  if (sockData->pcap_descr != NULL)
    {
      pcap_close(sockData->pcap_descr);
    }

  // Now clean up the memory.
  FREE(thisint->sockData);

  return XENONE;
}

/******************************************
 *
 * Set a wireless key.  Also, based on the index, we may change the transmit
 * key.
 *
 ******************************************/
int cardif_set_wireless_key(context *thisint, uint8_t *key, 
			    int keylen, int index)
{
  // We won't ever set a key, so return an error.
  return XENOWIRELESS;
}

/******************************************
 *
 * Ask the wireless card for the ESSID that we are currently connected to.  If
 * this is not a wireless card, or the information is not available, we should
 * return an error.
 *
 ******************************************/
int cardif_GetSSID(context *thisint, char *ssid_name)
{
  // We don't have any wireless interfaces.
  return XENOWIRELESS;
}

/******************************************
 *
 * Normally set the SSID on the card.  But, cardif_generic doesn't understand
 * keying, so return XENOWIRELESS.
 *
 ******************************************/
int cardif_SetSSID(context *thisint, char *ssid_name)
{
  return XENOWIRELESS;
}

/******************************************
 *
 * Check the SSID against what we currently have, and determine if we need
 * to reset our configuration.
 *
 ******************************************/
int cardif_check_ssid(context *thisint)
{
  // We aren't wireless!
  return XENOWIRELESS;
}

/******************************************
 *
 * Get the Broadcast SSID (MAC address) of the Access Point we are connected 
 * to.  If this is not a wireless card, or the information is not available,
 * we should return an error.
 *
 ******************************************/
int cardif_GetBSSID(context *thisint, char *bssid_dest)
{
  // Not wireless
  return XENOWIRELESS;
}

/******************************************
 *
 * Set the flag in the state machine that indicates if this interface is up
 * or down.  If there isn't an interface, we should return an error.
 *
 ******************************************/
int cardif_get_if_state(context *thisint)
{
  // Not sure if there is a good way to do this.
  return TRUE;
}

/******************************************
 *
 * Send a frame out of the network card interface.  If there isn't an 
 * interface, we should return an error.  We should return a different error
 * if we have a problem sending the frame.
 *
 ******************************************/
int cardif_sendframe(context *thisint)
{
  char nomac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  struct gen_sock_data *sockData;
  struct config_network *network_data;
  int pad;

  sockData = thisint->sockData;

  if (thisint == NULL) return XEMALLOC;

  if (thisint->sendframe == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Cannot send NULL frame!\n");
      return XENOFRAMES;
    }

  if (thisint->send_size == 0) return XENONE;

  network_data = config_get_network_config();

  if (network_data == NULL) 
  {
	  debug_printf(DEBUG_NORMAL, "No valid network data available!  Discarding packet!\n");
	  return XEGENERROR;
  }

  // The frame we are handed in shouldn't have a src/dest, so put it in.
  memcpy(&thisint->sendframe[0], &thisint->dest_mac[0], 6);
  memcpy(&thisint->sendframe[6], &thisint->source_mac[0], 6);

  if (memcmp(nomac, (char *)&network_data->dest_mac[0], 6) != 0)
    {
      debug_printf(DEBUG_INT, "Static MAC address defined!  Using it!\n");
      memcpy(&thisint->sendframe[0], &network_data->dest_mac[0], 6);
    }

  if (thisint->send_size < 64)
  {
      pad = 64 - thisint->send_size;
      debug_printf(DEBUG_INT, "Padding frame to 64 bytes by adding %d byte"
                   "(s).\n", pad);
      memset(&thisint->sendframe[thisint->send_size+1], 0x00, pad);
      thisint->send_size += pad;
  }

  debug_printf(DEBUG_EVERYTHING, "Frame to be sent (%d) : \n", thisint->send_size);
  debug_hex_dump(DEBUG_EVERYTHING, thisint->sendframe, thisint->send_size);

  if (pcap_sendpacket(sockData->pcap_descr, thisint->sendframe, thisint->send_size) < 0)
  {
	  debug_printf(DEBUG_NORMAL, "Error sending frame!\n");
	  pcap_perror(sockData->pcap_descr, NULL);
	  return -1;
  }

  return XENONE;  // We didn't get an error.
}

/******************************************
 * 
 * Get a frame from the network.  Since we are in promisc. mode, we will get
 * frames that aren't intended for us.  So, check the frame, determine if it
 * is something we care about, and act accordingly.
 *
 ******************************************/
int cardif_getframe(context *thisint)
{
  int pcap_ret_val = 0;
  char dot1x_default_dest[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
  struct gen_sock_data *sockData;
  uint8_t *resultframe = NULL;
  struct pcap_pkthdr *pkt_header = NULL;
  u_char *pkt_data = NULL;

  sockData = thisint->sockData;

  FREE(thisint->recvframe);
  thisint->recv_size = 0;

  resultframe = Malloc(1524);
  if (resultframe == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store resulting frame!\n");
	  return XESOCKOP;
  }

  switch (pcap_next_ex(sockData->pcap_descr, &pkt_header, &pkt_data))
  {
  case 1:
	  // Everything went fine, move on.
	  break;

  case 0:
	  return XEWINTIMEREXPIRED;
	  break;

  case -1:
	  return XESOCKOP;
	  break;

  case -2:
	  debug_printf(DEBUG_NORMAL, "Hit an EOF reading a pcap file!?  This shouldn't happen!\n");
	  return XEGENERROR;

  default:
	  debug_printf(DEBUG_NORMAL, "Unknown result came from pcap!\n");
	  return XEGENERROR;
  }

  // We have more frames available.
  memcpy(resultframe, pkt_data, pkt_header->len);

  debug_printf(DEBUG_EVERYTHING, "Got Frame : \n");
  debug_hex_dump(DEBUG_EVERYTHING, resultframe, pkt_header->len);

//#warning FIX!
  //  snmp_dot1xSuppEapolFramesRx();

  // Make sure that the frame we got is for us..
  if ((memcmp(&thisint->source_mac[0], &resultframe[0], 6) == 0) ||
      ((memcmp(&resultframe[0], &dot1x_default_dest[0], 6) == 0) &&
       (memcmp(&resultframe[6], &thisint->source_mac[0], 6) != 0)))
    {
      thisint->recv_size = pkt_header->len;
	  thisint->recvframe = resultframe;
      return pkt_header->len;
    }

  // Otherwise it isn't for us. 
  debug_printf(DEBUG_INT, "Got a frame, not for us.\n");

  FREE(resultframe);

  return XENOFRAMES;
}

/******************************************
 *
 * Validate an interface, based on if it has a MAC address.
 *
 ******************************************/
int cardif_validate(char *interf)
{
  // Assume that the interface is valid, or the user wouldn't have
  // told us to use it. ;)
  return TRUE;
}

/*******************************************************
 *
 * Check to see if an interface is wireless.  On linux, we look in
 * /proc/net/wireless to see if the interface is registered with the
 * wireless extensions.
 *
 *******************************************************/
int cardif_int_is_wireless(char *interf)
{
  // Not ever going to be wireless!
  return FALSE;
}

/******************************************************
 *
 * Stub for wireless scan.
 *
 *****************************************************/
int cardif_start_wireless_scan(context *thisint)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for encryption capabilities.
 *
 *****************************************************/
void cardif_get_abilities(context *thisint)
{
  thisint->enc_capa = 0;
}

/*****************************************************
 *
 * Stub for interface attachment
 *
 *****************************************************/
void cardif_wait_for_int(char *intname)
{
}

/*****************************************************
 *
 * Stub for clearing encryption keys
 *
 *****************************************************/
int cardif_clear_keys(context *intdata)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for wireless disassociation
 *
 *****************************************************/
int cardif_disassociate(context *thisint, int reason_code)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for passive scan timer callback
 *
 *****************************************************/
void cardif_passive_scan_timeout(context *ctx)
{
}

/*****************************************************
 *
 * Stub for deleting an encryption key
 *
 *****************************************************/
int cardif_delete_key(context *intdata, int key_idx, int set_tx)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for disabling WPA association state
 *
 *****************************************************/
int cardif_disable_wpa_state(context *thisint)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for wireless scanning
 *
 *****************************************************/
int cardif_do_wireless_scan(context *thisint, char passive)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for disabling encryption
 *
 *****************************************************/
int cardif_enc_disable(context *intdata)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for reassociating to a wireless network
 *
 *****************************************************/
void cardif_reassociate(context *intiface, uint8_t reason)
{
}

/*****************************************************
 *
 * Stub for setting WEP keys
 *
 *****************************************************/
int cardif_set_wep_key(context *thisint, uint8_t *key,
                       int keylen, int index)
{
}

/*****************************************************
 *
 * Stub for disassociate/roam
 *
 *****************************************************/
int cardif_wep_associate(context *thisint, int zeros)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for setting CCMP keys
 *
 *****************************************************/
int cardif_set_ccmp_key(context *thisint, char *addr, int keyidx,
                        int settx, char *key, int keylen)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for setting TKIP keys
 *
 *****************************************************/
int cardif_set_tkip_key(context *thisint, char *addr,
			int keyidx, int settx, char *key, int keylen)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for enabling/disabling rx of unencrypted frames on an interface
 *
 *****************************************************/
int cardif_drop_unencrypted(context *intdata, char endis)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for getting the WPA-IE
 *
 *****************************************************/
int cardif_get_wpa_ie(context *intdata, char *iedata, int *ielen)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for getting the RSN-IE
 *
 *****************************************************/
int cardif_get_wpa2_ie(context *intdata, char *iedata, int *ielen)
{
  return XENONE;
}

/*****************************************************
 *
 * Stub for enabling/disabling countermeasures on an interface
 *
 *****************************************************/
int cardif_countermeasures(context *intdata, char endis)
{
  return XENONE;
}

void cardif_operstate(context *ctx, uint8_t newstate)
{
}

