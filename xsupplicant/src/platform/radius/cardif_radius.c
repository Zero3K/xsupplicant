/*******************************************************************
 * A simple NAS implementation to allow direct authentication against a
 * RADIUS server for testing purposes!
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_radius.c
 *
 * \author chris@open1x.org
 *
 *******************************************************************/

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/hmac.h>

#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_common.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "eap_sm.h"
#include "eapol.h"
#include "frame_structs.h"
#include "eap_types/eap_type_common.h"
#include "cardif_radius.h"

#warning Change the RAD_* values below to point to your RADIUS server.
#define RAD_SERVER "10.0.4.101"
#define RAD_PORT 1812
#define RAD_SECRET "secret"

#define TO_SEND_IDS  1

static struct sockaddr_in dest;

static uint8_t send_eap_id = 0;
static uint8_t packetid = 1;

int cardif_init(context * ctx, char driver)
{
	int *sock;

	ctx->sockData = Malloc(sizeof(int));
	if (ctx->sockData == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store socket "
			     "id!\n");
		return XEMALLOC;
	}

	sock = (int *)ctx->sockData;

	(*sock) = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	printf("Got socket %d\n", (*sock));
	if ((*sock) == -1) {
		debug_printf(DEBUG_NORMAL, "Couldn't get socket!\n");
		return XENOSOCK;
	}

	dest.sin_family = AF_INET;
	dest.sin_port = htons(RAD_PORT);
	if (inet_aton(RAD_SERVER, &dest.sin_addr) == 0) {
		debug_printf(DEBUG_NORMAL, "inet_aton() failed!\n");
		return XENOSOCK;
	}

	return XENONE;
}

int cardif_deinit(context * ctx)
{
	int *sock;

	sock = (int *)ctx->sockData;

	close((*sock));

	return XENONE;
}

int cardif_get_socket(context * ctx)
{
	int *sock;

	sock = (int *)ctx->sockData;

	return (*sock);
}

void build_rad_avp(uint8_t * packet, uint16_t * offset, uint8_t type,
		   uint8_t len, uint8_t * data)
{
	struct radius_avp *radavp;

	radavp = (struct radius_avp *)&packet[(*offset)];

	radavp->attribute = type;
	radavp->length = len + sizeof(struct radius_avp);

	memcpy(&packet[(*offset) + sizeof(struct radius_avp)], data, len);
	(*offset) += len + sizeof(struct radius_avp);
}

void build_rad_header(uint8_t * packet, uint16_t size)
{
	struct radius_pkt *pkt;
	int i;

	pkt = (struct radius_pkt *)packet;

	pkt->code = RADIUS_ACCESS_REQUEST;
	pkt->id = packetid;
	pkt->length = htons(size);

	for (i = 0; i < 16; i++) {
		pkt->authenticator[i] = random();
	}
#warning Figure out the authenticator piece.
}

int cardif_sendframe(context * ctx)
{
	uint8_t *packet, blksiz;
	uint16_t offset = 0, eaplen, i, o;
	struct config_network *netdata;
	uint16_t blocks;
	int *sock;
	char authhmac[16];
	char *temp;

	debug_printf(DEBUG_NORMAL, "Preparing to send to RADIUS server.\n");

	if (ctx->send_size == 0) {
		debug_printf(DEBUG_NORMAL, "Nothing to send!\n");
		return -1;
	}

	packet = Malloc(1500);
	if (packet == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory for packet!\n");
		return XEMALLOC;
	}

	netdata = config_get_network_config();

	offset = sizeof(struct radius_pkt);

	build_rad_avp(packet, &offset, RADIUS_AVP_USERNAME,
		      strlen(netdata->identity), netdata->identity);

	eaplen = eap_type_common_get_eap_length(&ctx->sendframe[OFFSET_TO_EAP]);

	debug_printf(DEBUG_NORMAL, "EAP packet is %d byte(s) long.\n", eaplen);

	// Now, add the EAP data in chunks.
	blocks = eaplen / (0xff - 2);

	if ((blocks * (0xff - 2)) != eaplen)
		blocks++;

	debug_printf(DEBUG_NORMAL, "There are %d blocks to send.\n", blocks);

	for (i = 0; i < blocks; i++) {
		if (((i + 1) * (0xff - 2)) > eaplen) {
			blksiz = eaplen - (i * (0xff - 2));
		} else {
			blksiz = (0xff - 2);
		}

		debug_printf(DEBUG_NORMAL, "This block is %d byte(s) long.\n",
			     blksiz);

		build_rad_avp(packet, &offset, RADIUS_AVP_EAPMSG, blksiz,
			      &ctx->sendframe[OFFSET_TO_EAP +
					      (i * (0xff - 2))]);
	}

	memset(&authhmac, 0x00, 16);

	build_rad_avp(packet, &offset, 80, 16, &authhmac);

	build_rad_header(packet, offset);

	printf("offset = %d\n", offset);
	temp = strdup(RAD_SECRET);
	o = offset;
	HMAC(EVP_md5(), temp, strlen(temp), packet, offset, authhmac, &i);

#warning Fix this correctly!
	offset = o;
	printf("offset = %d  i = %d\n", offset, i);

	memcpy(&packet[offset - 16], &authhmac, 16);
	FREE(temp);

	debug_printf(DEBUG_NORMAL, "Sending (%d) : \n", offset);
	debug_hex_dump(DEBUG_NORMAL, packet, offset);

	sock = (int *)ctx->sockData;

	if (sendto((*sock), packet, offset, 0, &dest, sizeof(dest)) != offset) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't send all of our packet?!\n");
	}

	FREE(packet);

	ctx->send_size = 0;

	return XENONE;
}

uint16_t verify_rad_hdr(uint8_t * packet, uint16_t size)
{
	struct radius_pkt *pkt;

	if (size < sizeof(struct radius_pkt)) {
		debug_printf(DEBUG_NORMAL,
			     "Packet too small to be a valid RADIUS packet!\n");
		return 0;
	}

	pkt = (struct radius_pkt *)packet;

	if ((pkt->code != RADIUS_ACCESS_CHALLENGE) &&
	    (pkt->code != RADIUS_ACCESS_REJECT) &&
	    (pkt->code != RADIUS_ACCESS_ACCEPT)) {
		debug_printf(DEBUG_NORMAL, "Unknown RADIUS code! (%d)\n",
			     pkt->code);
		return 0;
	}

	if (pkt->id != packetid) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid RADIUS packet id!  (Got %d should "
			     "be %d!)\n", pkt->id, packetid);
		return 0;
	}

	if (pkt->code == RADIUS_ACCESS_REJECT) {
		return 0xffff;
	}

	packetid++;

	return ntohs(pkt->length);
}

int cardif_getframe(context * ctx)
{
	uint8_t *packet;
	int size;
	int *sock;
	uint16_t radsiz, offset, eapptr;
	struct radius_avp *radavp;
	struct eapol_header *eapolhdr;

	packet = Malloc(1500);
	if (packet == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store RADIUS "
			     "packet!\n");
		return XEMALLOC;
	}

	sock = (int *)ctx->sockData;

#ifndef __CYGWIN__
	size = recvfrom((*sock), packet, 1500, MSG_DONTWAIT, NULL, 0);
#else
	size = recvfrom((*sock), packet, 1500, 0, NULL, 0);
#endif

	debug_printf(DEBUG_NORMAL, "Got a RADIUS packet of %d byte(s)\n", size);

	if (send_eap_id < (TO_SEND_IDS + 1))
		return OFFSET_TO_DATA;

	if (size < 0)
		return XENOFRAMES;

	debug_printf(DEBUG_NORMAL, "Got :\n");
	debug_hex_dump(DEBUG_NORMAL, packet, size);

	radsiz = verify_rad_hdr(packet, size);

	if (radsiz == 0xffff) {
		debug_printf(DEBUG_NORMAL, "Got an Access-Reject\n");
		ctx->eap_state->rxFailure = TRUE;
		return 0;
	}

	debug_printf(DEBUG_NORMAL, "Packet size is %d!\n", radsiz);

	// Process AVPs.
	offset = sizeof(struct radius_pkt);
	eapptr = OFFSET_TO_EAP;

	while (offset < radsiz) {
		radavp = (struct radius_avp *)&packet[offset];

		switch (radavp->attribute) {
		case RADIUS_AVP_EAPMSG:
			memcpy(&ctx->recvframe[eapptr], &packet[offset + 2],
			       radavp->length - 2);
			offset += radavp->length;
			eapptr += radavp->length - 2;
			break;

		default:
			debug_printf(DEBUG_NORMAL, "Skipping AVP %02X\n",
				     radavp->attribute);
			offset += radavp->length;
			break;
		}
	}

	eapolhdr = (struct eapol_header *)&ctx->recvframe[OFFSET_PAST_MAC];

	eapolhdr->frame_type = htons(EAPOL_FRAME);
	eapolhdr->eapol_version = 1;
	eapolhdr->eapol_type = EAP_PACKET;
	eapolhdr->eapol_length =
	    htons(sizeof(struct eapol_header) + sizeof(struct eap_header));

	debug_printf(DEBUG_INT, "EAP Packet Dump : \n");
	debug_hex_dump(DEBUG_INT, ctx->recvframe, eapptr);

	return eapptr;
}

uint8_t cardif_radius_eap_sm(context * ctx)
{
	struct eap_header *eaphdr;
	struct eapol_header *eapolhdr;

	if (send_eap_id < TO_SEND_IDS) {
		// We need to fake an EAP request ID.
		debug_printf(DEBUG_NORMAL, "Building fake EAP request ID.\n");

		if (config_build("radius") != TRUE) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't build config for network "
				     "\"radius\"!\n");
			return FALSE;
		}

		eaphdr = Malloc(sizeof(struct eap_header));
		if (eaphdr == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate memory for faked "
				     "EAP request ID!\n");
			debug_printf(DEBUG_NORMAL, "Nothing to do!\n");
			send_eap_id++;	// To avoid looping and filling the screen.
			return FALSE;
		}

		eaphdr->eap_code = EAP_REQUEST_PKT;
		eaphdr->eap_identifier = send_eap_id + 1;
		eaphdr->eap_length = htons(sizeof(struct eap_header));
		eaphdr->eap_type = EAP_REQUEST_ID;

		memcpy(&ctx->recvframe[OFFSET_TO_EAP], (uint8_t *) eaphdr,
		       sizeof(struct eap_header));

		FREE(eaphdr);

		eapolhdr = Malloc(sizeof(struct eapol_header));
		if (eapolhdr == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate memory to fake EAPoL "
				     "header!\n");
			return FALSE;
		}

		eapolhdr->frame_type = htons(EAPOL_FRAME);
		eapolhdr->eapol_version = 1;
		eapolhdr->eapol_type = EAP_PACKET;
		eapolhdr->eapol_length =
		    htons(sizeof(struct eapol_header) +
			  sizeof(struct eap_header));
		memcpy(&ctx->recvframe[OFFSET_PAST_MAC], eapolhdr,
		       sizeof(struct eapol_header));

		debug_printf(DEBUG_NORMAL, "EAPoL Header : \n");
		debug_hex_dump(DEBUG_NORMAL, (uint8_t *) eapolhdr,
			       sizeof(struct eapol_header));

		debug_printf(DEBUG_NORMAL, "Frame dump : \n");
		debug_hex_dump(DEBUG_NORMAL, (uint8_t *) & ctx->recvframe,
			       ctx->recv_size);

		FREE(eapolhdr);

		ctx->recv_size = OFFSET_TO_DATA;
		ctx->eap_state->eapReq = TRUE;

		ctx->statemachine->eapolEap = TRUE;
		ctx->statemachine->suppStart = TRUE;

		send_eap_id++;
		return TRUE;
	}
	// Otherwise, do nothing.
	send_eap_id = 0xff;
	return FALSE;
}

void cardif_clock_tick(context * ctx)
{
}

int cardif_get_if_state(context * ctx)
{
	// Assume that this "interface" is always up.
	return TRUE;
}

int cardif_int_is_valid(char *intname)
{
	if (strcmp(intname, "radius") == 0) {
		return TRUE;
	}

	return FALSE;
}

int cardif_check_dest(context * ctx)
{
	return TRUE;
}

int cardif_validate(char *intname)
{
	if (strcmp(intname, "radius") == 0) {
		return TRUE;
	}

	return FALSE;
}

char *cardif_get_search_ssid()
{
	return NULL;
}

void cardif_set_search_ssid(char *newssid)
{

}

int cardif_enable_wpa(context * ctx)
{
	return XENOWIRELESS;
}

int cardif_do_wireless_scan(context * ctx, char *c)
{
	return XENOWIRELESS;
}

int cardif_set_wep_key(context * ctx, uint8_t * key, int size1, int size2)
{
	return XENOWIRELESS;
}

int cardif_set_tkip_key(context * ctx, char *c, int i1, int i2, char *c2,
			int i3)
{
	return XENOWIRELESS;
}

int cardif_set_ccmp_key(context * ctx, char *c, int i1, int i2, char *c2,
			int i3)
{
	return XENOWIRELESS;
}

int cardif_delete_key(context * ctx, int i1, int i2)
{
	return XENOWIRELESS;
}

void cardif_associate(context * ctx)
{
	debug_printf(DEBUG_NORMAL,
		     "Got an association call for the RADIUS driver." "\n");
}

int cardif_disassociate(context * ctx, int i1)
{
	debug_printf(DEBUG_NORMAL, "Got a disassociation call for the RADIUS "
		     "driver\n");
	return XENOWIRELESS;
}

int cardif_GetSSID(context * ctx, char *ssid)
{
	return XENOWIRELESS;
}

int cardif_check_ssid(context * ctx)
{
	return XENOWIRELESS;
}

int cardif_GetBSSID(context * ctx, char *ssid)
{
	return XENOWIRELESS;
}

int cardif_setBSSID(context * ctx, uint8_t * newssid)
{
	return XENOWIRELESS;
}

int cardif_int_is_wireless(char *intname)
{
	return FALSE;
}

int cardif_wep_associate(context * ctx, int zs)
{
	return XENOWIRELESS;
}

int cardif_disable_wpa_state(context * ctx)
{
	return XENOWIRELESS;
}

int cardif_enable_wpa_state(context * ctx)
{
	return XENOWIRELESS;
}

int cardif_drop_unencrypted(context * ctx, char c)
{
	return XENOWIRELESS;
}

int cardif_countermeasures(context * ctx, char c)
{
	return XENOWIRELESS;
}

int cardif_get_wpa_ie(context * ctx, char *c, int *i)
{
	return XENOWIRELESS;
}

int cardif_get_wpa2_ie(context * ctx, char *c, int *i)
{
	return XENOWIRELESS;
}

int cardif_clear_keys(context * ctx)
{
	return XENOWIRELESS;
}

int cardif_check_associated(context * ctx)
{
	return XENOWIRELESS;
}

void cardif_reassociate(context * ctx, uint8_t i)
{
	// Do nothing
}

void cardif_association_timeout_expired(context * ctx)
{
	// Do nothing
}

int cardif_enc_disable(context * ctx)
{
	return XENOWIRELESS;
}

void cardif_get_abilities(context * ctx)
{
	// Do nothing.
}

void cardif_wait_for_int(char *intname)
{
	// Do nothing.
}

void cardif_passive_scan_timeout(context * ctx)
{
	// Do nothing.
}

void cardif_operstate(context * ctx, uint8_t state)
{
	// Do nothing.
}

void cardif_linkmode(context * ctx, uint8_t state)
{
	// Do nothing.
}
