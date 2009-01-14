/**
 * Functions that are useful in more than one EAP method.
 *
 * \file eap_type_common.c
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 **/

#ifndef WINDOWS
#include <stdint.h>
#else
#include <winsock2.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "libxsupconfig/xsupconfig_structs.h"
#include "../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../context.h"
#include "../eap_sm.h"
#include "../frame_structs.h"
#include "../xsup_debug.h"
#include "../ipc_events.h"
#include "../ipc_events_index.h"
#include "eap_type_common.h"

/***************************************************************
 *
 *  Return an ACK message.
 *
 ***************************************************************/
uint8_t *eap_type_common_buildAck(eap_type_data *eapdata, uint8_t eap_method)
{
  struct eap_header *eaphdr;
  uint8_t reqId;
  uint8_t *ackres;
  uint16_t total_size;

  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return NULL;

  if (!xsup_assert((eapdata->eapReqData != NULL),
                   "eapdata->eapReqData != NULL", FALSE))
    return NULL;

  eaphdr = (struct eap_header *)eapdata->eapReqData;
  reqId = eaphdr->eap_identifier;

  ackres = Malloc(1 + sizeof(struct eap_header));
  if (ackres == NULL) return NULL;

  eaphdr = (struct eap_header *)ackres;

  eaphdr->eap_code = EAP_RESPONSE_PKT;
  eaphdr->eap_identifier = reqId;
  total_size = 1 + sizeof(struct eap_header);
  eaphdr->eap_length = htons(total_size);
  eaphdr->eap_type = eap_method;

  ackres[sizeof(struct eap_header)] = 0x00;

  return ackres;
}

/************************************************************************
 *
 * Set values that we need to set when we have a failure.
 *
 ************************************************************************/
void eap_type_common_fail(eap_type_data *eapdata)
{
  if (!xsup_assert((eapdata != NULL), "eapdata != NULL", FALSE))
    return;

  eapdata->decision = EAP_FAIL;
  eapdata->ignore = TRUE;
}

/************************************************************************
 *
 * Get the request ID from an EAP packet.
 *
 ************************************************************************/
uint8_t eap_type_common_get_eap_reqid(uint8_t *packet)
{
  struct eap_header *eaphdr;

  if (!xsup_assert((packet != NULL), "packet != NULL", FALSE))
    return 0;

  eaphdr = (struct eap_header *)packet;

  return eaphdr->eap_identifier;
}

/*************************************************************************
 *
 * Return the EAP length from a given packet.
 *
 *************************************************************************/
uint16_t eap_type_common_get_eap_length(uint8_t *packet)
{
  struct eap_header *eaphdr;

  if (!xsup_assert((packet != NULL), "packet != NULL", FALSE))
    return 0;

  eaphdr = (struct eap_header *)packet;

  return ntohs(eaphdr->eap_length);
}

/**************************************************************************
 *
 * Return the common length for EAP key data.  (This is what will be used
 * by most EAP methods.  The exceptions would be methods that return no
 * keying material, and LEAP.)
 *
 **************************************************************************/
uint8_t eap_type_common_get_common_key_len(eap_type_data *eapdata)
{
  return COMMON_KEY_LEN;
}

/**************************************************************************
 *
 * Return a key length of 0 for EAP methods that don't provide keying 
 * material.
 *
 **************************************************************************/
uint8_t eap_type_common_get_zero_len(eap_type_data *eapdata)
{
  return 0;
}

/**************************************************************************
 *
 * Convert an array of uint8_t to a string.
 *
 **************************************************************************/
char *eap_type_common_convert_hex(uint8_t *inhex, uint16_t insize)
{
  uint16_t strsize = 0, i;
  char *retstr = NULL;
  char bytes[3];

  if (!xsup_assert((inhex != NULL), "inhex != NULL", FALSE))
    return NULL;

  strsize = (insize * 2)+1;

  retstr = (char *)Malloc(strsize);
  if (retstr == NULL) return NULL;

  memset(&bytes, 0x00, 3);

  for (i=0;i<insize;i++)
    {
      sprintf(bytes, "%02X", inhex[i]);
      if (Strcat(retstr, strsize, bytes) != 0)
	{
	  fprintf(stderr, "Refusing to overflow string!\n");
	  ipc_events_error(NULL, IPC_EVENT_ERROR_OVERFLOW_ATTEMPTED, (char *)__FUNCTION__);
	  return NULL;
	}
    }

  return retstr;
}

/**************************************************************************
 *
 *  Reset the eap_type_data variables to what they should be when an
 *  EAP type reaches INIT state.
 *
 **************************************************************************/
void eap_type_common_init_eap_data(eap_type_data *eapdata)
{
  eapdata->ignore = FALSE;
  eapdata->eapKeyAvailable = FALSE;
  eapdata->altAccept = FALSE;
  eapdata->altReject = FALSE;
}

/**
 * \brief Many different EAP methods just need a username/password.  So this common function just returns that
 *			so that the same thing doesn't need to be implemented over and over in each EAP method.
 *
 * \retval EAP_REQUIRES_USERNAME|EAP_REQUIRES_PASSWORD
 **/
int eap_type_common_upw_required(void *config)
{
	return (EAP_REQUIRES_USERNAME | EAP_REQUIRES_PASSWORD);
}

/**
 * \brief Return a username if we need to override it for some reason (such as a
 *			desire to use logon credentials.
 *
 * \note Any non-NULL value returned here will override any configuration file setting
 *			or user provided entry (if any).  This call should be USED WITH CARE!
 *
 * \retval NULL if no username is to be returned, ptr to the new username otherwise.
 **/
char *eap_type_common_get_username(void *config)
{
	struct config_pwd_only *pwd = NULL;

	if (config == NULL) return NULL;

	pwd = (struct config_pwd_only *)config;

	if (TEST_FLAG(pwd->flags, CONFIG_PWD_ONLY_USE_LOGON_CREDS))
	{
		if (logon_creds_username_available() == TRUE) return logon_creds_get_username();
	}

	return NULL;
}

