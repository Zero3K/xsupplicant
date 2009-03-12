/**
 * EAP-AKA utility functions
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 * 
 * \file aka.h
 *
 * \author chris@open1x.org
 *
 **/

/**
 *
 * The development of the EAP/AKA support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 **/

#ifdef EAP_SIM_ENABLE
#ifndef _AKA_H_
#define _AKA_H_

int aka_do_at_identity(struct aka_eaptypedata *, uint8_t *, uint16_t *);
int aka_do_at_rand(struct aka_eaptypedata *, uint8_t *, uint16_t *);
int aka_do_at_autn(struct aka_eaptypedata *, uint8_t *, uint16_t *);
int aka_do_at_mac(eap_type_data *, struct aka_eaptypedata *,
		  uint8_t *, int, uint16_t *, char *);
uint8_t *aka_do_sync_fail(struct aka_eaptypedata *, uint8_t);
uint8_t *aka_resp_identity(struct aka_eaptypedata *, uint8_t, char *);
int aka_skip_not_implemented(uint8_t *, uint16_t *);

#endif
#endif
