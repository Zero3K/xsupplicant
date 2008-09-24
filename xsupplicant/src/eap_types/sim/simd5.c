/**
 * EAP-SIM (draft 5 specific) function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 * 
 * \file simd5.c
 *
 * \author chris@open1x.org
 *
 * \todo Add IPC error events
 *
 **/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/


#ifdef EAP_SIM_ENABLE

#ifndef WINDOWS
#include <inttypes.h>
#include <netinet/in.h>
#endif

#include <string.h>
#include <openssl/hmac.h>

#include "winscard.h"
#include "xsupconfig.h"
#include "../../context.h"
#include "../../eap_sm.h"
#include "eapsim.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

// Draft 5 (version 0) specific calls.

int do_v0_at_mac(eap_type_data *thisint, char *K_int, char *indata, 
		 int in_size, int inoffset, char *resultmac)
{
  char *framecpy, *mac_calc;
  int saved_offset, i;
  uint16_t value16;

  if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((K_int != NULL), "K_int != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((resultmac != NULL), "resultmac != NULL", FALSE))
    return XEMALLOC;

  if (indata[inoffset] != AT_MAC)
    {
      printf("Error!  The offset passed in is not of type AT_MAC!\n");
      return -1;
    }
  
  inoffset++;
	      
  if (indata[inoffset] != 5) printf("AT_MAC length isn't 5!\n");
  inoffset+=2;  // Skip the reserved bytes.

  saved_offset = inoffset;

  framecpy = (char *)Malloc(in_size+50);  // We need extra to
	                                  // reconstruct the eap 
	                                  // piece.
  if (framecpy == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for framecpy!\n");
      return XEMALLOC;
    }

  // Now, reconstruct the header for the EAP piece, so we can
  // calculate the MAC across all of it.
  framecpy[0] = 1;  // It was a request.
  framecpy[1] = eap_type_common_get_eap_reqid(thisint->eapReqData);
  value16 = in_size + 5;
  value16 = htons(value16);

  memcpy((char *)&framecpy[2], &value16, 2);
  framecpy[4] = EAP_TYPE_SIM;  
  
  memcpy((char *)&framecpy[5], (char *)&indata[0], in_size);

  // Now, zero out the MAC value.
  for (i=(saved_offset+5);i<=(in_size+5);i++)
    {
      framecpy[i] = 0x00;
    }

  debug_printf(DEBUG_AUTHTYPES, "Calculating MAC on : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, framecpy, (in_size+5));
  
  // We should now be ready to calculate the AT_MAC for 
  // ourselves.
  mac_calc = (char *)Malloc(100);
  if (mac_calc == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for mac_calc! "
		   "(%s:%d)\n", __FUNCTION__, __LINE__);
      return XEMALLOC;
    }

  HMAC(EVP_sha1(), &K_int[0], 16, framecpy, (in_size+5), mac_calc, &i);

  memcpy(resultmac, mac_calc, 16);  // We get 20 back, but we only want 16.

  FREE(framecpy);
  FREE(mac_calc);

  return 0;
}

#endif
