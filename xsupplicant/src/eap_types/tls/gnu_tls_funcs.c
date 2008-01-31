/**
 * TLS implementation using GNUTLS.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file gnu_tls_funcs.c
 *
 * \author chris@open1x.org
 *
 * $Id: gnu_tls_funcs.c,v 1.3 2008/01/26 01:20:00 chessing Exp $
 * $Date: 2008/01/26 01:20:00 $
 * $Log: gnu_tls_funcs.c,v $
 * Revision 1.3  2008/01/26 01:20:00  chessing
 * Finished syncing the commits between 1_3_START_BRANCH and HEAD.
 *
 * Revision 1.1.2.23  2007/04/20 18:35:54  chessing
 * Work on the debug/trace output.  Added a WHOLE BUNCH of new debug levels.  Fixed a couple of small bugs, and cleaned out some cruft.
 *
 * Revision 1.1.2.22  2007/02/07 07:17:40  chessing
 * Updated my e-mail address in all source files.  Replaced strcpy() with a safer version.  Updated Strncpy() to be a little safer.
 *
 **/
#ifdef USE_GNUTLS

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef WINDOWS
#include <winsock2.h>
#endif

#include "../../profile.h"
#include "../../eap_sm.h"
#include "eaptls.h"
#include "tls_funcs.h"
#include "../../xsup_common.h"
#include "../../xsup_err.h"
#include "../../xsup_debug.h"
#include "../../frame_structs.h"

static uint8_t inited = 0;

//#warning Add gnutls_alert code.

/**********************************************************************
 *
 *  This callback function is used by GNU-TLS to put data in our buffer
 *  that we will need to send out.  Other functions are responsible for
 *  actually sending the data.  This function just queues it.
 *
 **********************************************************************/
ssize_t tls_funcs_push(gnutls_transport_ptr_t ptr,
		       const void *buf, size_t bufsiz)
{
  struct tls_vars *mytls_vars;

  mytls_vars = (struct tls_vars *)ptr;

  mytls_vars->tlsoutdata = realloc(mytls_vars->tlsoutdata, 
				   mytls_vars->tlsoutsize + bufsiz);

  memcpy((uint8_t *)&mytls_vars->tlsoutdata[mytls_vars->tlsoutsize],
	 buf, bufsiz);

  mytls_vars->tlsoutsize += bufsiz;

  debug_printf(DEBUG_TLS_CORE, "There are now %d byte(s) in the waiting "
	       "buffer.\n", mytls_vars->tlsoutsize);

  debug_printf(DEBUG_TLS_CORE, "Buffer dump (%d) : \n", 
	       mytls_vars->tlsoutsize);
  debug_hex_dump(DEBUG_TLS_CORE, mytls_vars->tlsoutdata,
		 mytls_vars->tlsoutsize);

  return bufsiz;
}

/***********************************************************************
 *
 *  This callback function is used by GNU-TLS to take data from our buffer
 *  and process it.  Other functions are responsible for filling the buffer.
 *  This function just sends it to GNU-TLS. 
 *
 ***********************************************************************/
ssize_t tls_funcs_pull(gnutls_transport_ptr_t ptr,
		       void *buf, size_t bufsiz)
{
  struct tls_vars *mytls_vars = NULL;
  ssize_t retsize = 0;

  mytls_vars = (struct tls_vars *)ptr;

  debug_printf(DEBUG_TLS_CORE, "Total data in memory : %d byte(s)\n",
               mytls_vars->tlsinsize);


  // If we don't have anything to send, ask GNU-TLS to wait.
  if (mytls_vars->tlsindata == NULL)
    {
      errno = EWOULDBLOCK;
      return -1;
    }

  // Otherwise, return "bufsiz" (or less) worth of data.  
  if (mytls_vars->tlsinsize <= bufsiz)
    {
      // We can send everything we have.
      memcpy((uint8_t *)buf, mytls_vars->tlsindata, mytls_vars->tlsinsize);
      mytls_vars->tlsinptr = mytls_vars->tlsinsize;
      retsize = mytls_vars->tlsinsize;
      debug_printf(DEBUG_TLS_CORE, "Returned complete packet of %d byte(s) to"
		   " GNU-TLS.\n", retsize);
    }
  else
    {
      // Send a chunk.
      retsize = (mytls_vars->tlsinsize - mytls_vars->tlsinptr);
      if (retsize > bufsiz) retsize = bufsiz;

      memcpy((uint8_t *)buf, 
	     (uint8_t *)&mytls_vars->tlsindata[mytls_vars->tlsinptr],
	     retsize);

      mytls_vars->tlsinptr += retsize;

      debug_printf(DEBUG_TLS_CORE, "Returned a fragment of %d byte(s) to "
		   "GNU-TLS.\n", retsize);
    }

  if (mytls_vars->tlsinptr >= mytls_vars->tlsinsize)
    {
      debug_printf(DEBUG_TLS_CORE, "Finished with this data chunk. "
		   "Freeing.\n");
      FREE(mytls_vars->tlsindata);
      mytls_vars->tlsinptr = 0;
      mytls_vars->tlsinsize = 0;
    }

  return retsize;
}

/***********************************************************************
 *
 *  This callback function is used by GNU-TLS to allow us to do something
 *  with it's log data.  The verbosity of the log data is configured in
 *  tls_funcs_init().
 *
 ***********************************************************************/
void tls_log(int level, const char *logline)
{
  debug_printf(DEBUG_NORMAL, "GNUTLS Log : %s\n", logline);
}

/***********************************************************************
 *
 *  Do whatever we need to do in order to set up GNU-TLS and get it to the
 *  point that we can use it to authenticate.
 *
 ***********************************************************************/
int tls_funcs_init(struct tls_vars *mytls_vars)
{
  int err = 0;
  int allowed_protos[3] = { GNUTLS_TLS1_0, GNUTLS_TLS1_1, 0};
  int allowed_certs[2] = { GNUTLS_CRT_X509, 0 };

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEGENERROR;

  debug_printf(DEBUG_TLS_CORE, "(TLS Engine : GNU) Initing\n");

//#warning Find a better way to handle this!
  if (inited == 0)
    {
      debug_printf(DEBUG_TLS_CORE, "(TLS Engine) Doing global init!\n");
      if (gnutls_global_init() != 0)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't initialize GNU-TLS global state!\n");
	  return XEGENERROR;
	}

      gnutls_global_set_log_function(tls_log);
      if (debug_getlevel() == DEBUG_TLS_CORE)
	{
	  gnutls_global_set_log_level(10);               // Maximum logging.
	} 
    }

//#warning Session resume here!

  if (mytls_vars->session != NULL)
    {
      // Clear any active sessions so we can start again.
      debug_printf(DEBUG_TLS_CORE, "(TLS Engine) Cleaning up old session "
		   "data.\n");
      gnutls_deinit(mytls_vars->session);
      mytls_vars->handshake_done = FALSE;
    }

  if (gnutls_init(&mytls_vars->session, GNUTLS_CLIENT) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize the GNU-TLS library!\n");
      return XEGENERROR;
    }

  err = gnutls_set_default_priority(mytls_vars->session);

  if (err != 0)
    {
      debug_printf(DEBUG_NORMAL, "Using default priorities. : %s\n", 
		   gnutls_strerror(err));
      return XEGENERROR;
    }

  err = gnutls_certificate_type_set_priority(mytls_vars->session, 
					     allowed_certs);

  if (err != 0)
    {
      debug_printf(DEBUG_NORMAL, "Setting certificate type priorities : %s\n",
		   gnutls_strerror(err));
      return XEGENERROR;
    }

  err = gnutls_protocol_set_priority(mytls_vars->session, allowed_protos);

  if (err != 0)
    {
      debug_printf(DEBUG_NORMAL, "Setting allowed protocols : %s\n",
		   gnutls_strerror(err));
      return XEGENERROR;
    }

  gnutls_transport_set_push_function(mytls_vars->session, tls_funcs_push);
  gnutls_transport_set_pull_function(mytls_vars->session, tls_funcs_pull);
  gnutls_transport_set_ptr(mytls_vars->session,
                           (gnutls_transport_ptr) mytls_vars);


  err = gnutls_certificate_allocate_credentials(&mytls_vars->creds);

  if (err != 0)
    {
      debug_printf(DEBUG_NORMAL, "Allocating credentials : %s\n",
		   gnutls_strerror(err));
      return XEGENERROR;
    }

  return XENONE;
}


/*************************************************************************
 *
 *  Load any root certificates that the user would want to use.  Note :
 *  This functions differently than the older OpenSSL method.
 *
 *************************************************************************/
int tls_funcs_load_root_certs(struct tls_vars *mytls_vars, 
			      char *root_cert, char *root_dir, 
			      char *crl_dir)
{
  int err = 0;

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEGENERROR;

//#warning Fix these!
  if (root_dir != NULL)
    {
      debug_printf(DEBUG_NORMAL, "Certificate directories aren't supported "
		   "yet!\n");
      // Continue in case a root_cert is also set.
    }

  if (crl_dir != NULL)
    {
      debug_printf(DEBUG_NORMAL, "CRL directories aren't supported yet!\n");
      // Use gnutls_certificate_set_x509_crl_file()
      // Continue, because this is non-fatal.
    }

  if (root_cert == NULL)
    {
      debug_printf(DEBUG_NORMAL, "You *MUST* specify a root CA "
		   "certificate!\n");
      return XEGENERROR;
    }

  if (mytls_vars->creds == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate credentials.\n");
      return XEGENERROR;
    }

  err = gnutls_certificate_set_x509_trust_file(mytls_vars->creds, root_cert,
					       GNUTLS_X509_FMT_PEM);
  if (err < 1)
    {
      debug_printf(DEBUG_TLS_CORE, "Non-fatal error loading certificate (%d) "
		   ": %s -- Trying to load as DER.\n", err, 
		   gnutls_strerror(err));

      // It may be a DER certificate.  So try that instead.
      err = gnutls_certificate_set_x509_trust_file(mytls_vars->creds, 
						   root_cert, 
						   GNUTLS_X509_FMT_DER);

      if (err < 1)
	{
	  debug_printf(DEBUG_NORMAL, "Error loading root CA certificate!\n");
	  return XEGENERROR;
	}
    }

  return XENONE;
}

//#warning Need to add loading of random data functions.

/************************************************************************
 *
 *  Load a user certificate in to GNU-TLS so that it can be used for
 *  authentication.
 *
 ************************************************************************/
int tls_funcs_load_user_cert(struct tls_vars *mytls_vars, char *user_cert,
			     char *user_key, char *userpass)
{
  gnutls_x509_privkey key;
  uint8_t *certbuf;
  FILE *fp;
  size_t size;
  gnutls_datum cert;

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEGENERROR;

  if (user_cert == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No user certificate to load!\n");
      return XEGENERROR;
    }

  if (user_key == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No user key file to load!\n");
      return XEGENERROR;
    }

  if (userpass == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No password provided!\n");
      return XEGENERROR;
    }

//#warning Need to import the user certificate.

  gnutls_x509_privkey_init(&key);

  certbuf = Malloc(64 * 1024);
  if (certbuf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store "
		   "user certificate.\n");
      return XEMALLOC;
    }

  // Open the certificate key file.
  fp = fopen(user_key, "r");
  if (fp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't open file '%s'.\n");
      return XEGENERROR;
    }

  size = fread(certbuf, 1, (64 * 1024)-1, fp);

  if (ferror(fp) != 0)
    {
      debug_printf(DEBUG_NORMAL, "File read error at %s:%d!\n", __FUNCTION__,
		   __LINE__);
      return XEGENERROR;
    }

  fclose(fp);

  cert.data = certbuf;
  cert.size = size;

  if (gnutls_x509_privkey_import(key, &cert, GNUTLS_X509_FMT_PEM) != 0)
    {
      debug_printf(DEBUG_TLS_CORE, "Couldn't load certificate as PEM! (With"
		   " no password.)  Trying DER.\n");
      
      if (gnutls_x509_privkey_import(key, &cert, GNUTLS_X509_FMT_DER) != 0)
	{
	  debug_printf(DEBUG_TLS_CORE, "Couldn't load certificate as DER! "
		       "(With no password.)  Trying PEM with password.\n");

	  if (gnutls_x509_privkey_import_pkcs8(key, &cert, 
					       GNUTLS_X509_FMT_PEM, userpass,
					       0) != 0)
	    {
	      debug_printf(DEBUG_TLS_CORE, "Couldn't load certificate as PEM"
			   " with password!  Trying DER with password!\n");

	      if (gnutls_x509_privkey_import_pkcs8(key, &cert,
						   GNUTLS_X509_FMT_DER,
						   userpass, 0) != 0)
		{
		  debug_printf(DEBUG_TLS_CORE, "Couldn't load certificate as "
			       "encrypted DER with password!  Trying as "
			       "unencrypted DER with password!\n");

		  if (gnutls_x509_privkey_import_pkcs8(key, &cert,
						       GNUTLS_X509_FMT_DER,
						       userpass,
						       GNUTLS_PKCS_PLAIN) != 0)
		    {
		      debug_printf(DEBUG_TLS_CORE, "Couldn't load certficate"
				   " in any way we know of!  Your certificate"
				   " is either incorrect, or has issues.\n");
		      return XEGENERROR;
		    }
		}
	    }
	}
    }
//#warning Need to set a flag so that we can clean up the privkey import when we shut down.


  return XENONE;
}

/**********************************************************************
 *
 *  This function is called when we recieve a start request (0x20) from 
 *  the server.  It should finalize credentials, and begin the handshake.
 *
 **********************************************************************/
int gnutls_funcs_do_start(struct tls_vars *mytls_vars)
{
  int err = 0;

  err = gnutls_credentials_set(mytls_vars->session, GNUTLS_CRD_CERTIFICATE,
                               mytls_vars->creds);
  if (err != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't enable credentials.  Error was : "
		   "%s\n", gnutls_strerror(err));
      return XEGENERROR;
    }

  err = gnutls_handshake(mytls_vars->session);

  if ((err != 0) && (err != GNUTLS_E_AGAIN))
    {
      debug_printf(DEBUG_NORMAL, "Couldn't start handshake!  Error was (%d): "
		   "%s\n", err, gnutls_strerror(err));
      return XEGENERROR;
    }

  return XENONE;
}

/*************************************************************************
 *
 *  Verify that the common name field of a certificate matches a user defined
 *  value.  If exact == TRUE, then it must match exactly.  Otherwise, it
 *  must only contain the substring specified by the user.
 *
 *************************************************************************/
uint8_t tls_funcs_check_cn(char *cn, char *tomatch, uint8_t exact)
{
  if (exact == TRUE)
    {
      // Check for an exact match.
      if (strcmp(cn, tomatch) == 0) return TRUE;
    }
  else
    {
//#warning  We should do some additional checks to be sure the substring is at the tail end of the string.  Otherwise a search for "monkey.com" would also match "monkey.com.com" or similar.
      // Check for a substring match.
      if (strstr(cn, tomatch) != NULL) return TRUE;
    }

  return FALSE;
}

/*************************************************************************
 *
 *  Do a bunch of different checks against the certificate chain that we
 *  have.
 *
 *************************************************************************/
int verify_certificate(gnutls_session_t session, char *common_name, 
		       uint8_t exact_match)
{
  unsigned int status;
  const gnutls_datum_t *cert_list;
  int cert_list_size, ret, retval = XENONE;
  gnutls_x509_crt_t cert;
  char dnsname[256];
  size_t dnsnamesize;

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  ret = gnutls_certificate_verify_peers2 (session, &status);

  if (ret < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error checking certificate!\n");
      debug_printf(DEBUG_NORMAL, "Error was (%d) : %s\n", ret, 
		   gnutls_strerror(ret));
      return XEGENERROR;
    }

  if (status & GNUTLS_CERT_INVALID)
    debug_printf(DEBUG_NORMAL, "The certificate is not trusted.\n");

  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    debug_printf(DEBUG_NORMAL, "The certificate hasn't got a known issuer.\n");

  if (status & GNUTLS_CERT_REVOKED)
    debug_printf(DEBUG_NORMAL, "The certificate has been revoked.\n");

  if (status != 0)
    {
      debug_printf(DEBUG_NORMAL, "Certificate checks failed!\n");
      return XEGENERROR;
    }

  /* Up to here the process is the same for X.509 certificates and
   * OpenPGP keys. From now on X.509 certificates are assumed. This can
   * be easily extended to work with openpgp keys as well.
   */
  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
    {
      debug_printf(DEBUG_NORMAL, "Certificate is not a valid x.509 "
		   "certificate!\n");
      return XEGENERROR;
    }

  if (gnutls_x509_crt_init (&cert) < 0)
    {
      debug_printf (DEBUG_NORMAL, "Error initializing certificate "
		    "structures.\n");
      retval = XEGENERROR;
      goto deinit;
    }

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
  if (cert_list == NULL)
    {
      debug_printf (DEBUG_NORMAL, "The server didn't send us any "
		    "certificates.\n");
      retval = XEGENERROR;
      goto deinit;
    }

  /* This is not a real world example, since we only check the first 
   * certificate in the given chain.
   */
  if (gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0)
    {
      debug_printf (DEBUG_NORMAL, "Error parsing certificate.\n");
      retval = XEGENERROR;
      goto deinit;
    }

  /* Beware here we do not check for errors.
   */
  if (gnutls_x509_crt_get_expiration_time (cert) < time (0))
    {
      debug_printf (DEBUG_NORMAL, "The certificate has expired!\n");
      retval = XEGENERROR;
      goto deinit;
    }

  if (gnutls_x509_crt_get_activation_time (cert) > time (0))
    {
      debug_printf (DEBUG_NORMAL, "The certificate is not yet activated!\n");
      retval = XEGENERROR;
      goto deinit;
    }

  dnsnamesize = sizeof(dnsname);

  if (gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0,
				    0, dnsname, &dnsnamesize) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't find a common name field in the "
		   "certificate!\n");
      retval = XEGENERROR;
      goto deinit;
    }

  debug_printf(DEBUG_TLS_CORE, "CN = %s\n", dnsname);
  if (common_name != NULL)
    {
      // We need to do a match.
      if (tls_funcs_check_cn(dnsname, common_name, exact_match) != TRUE)
	{
	  if (exact_match == TRUE)
	    {
	      debug_printf(DEBUG_NORMAL, "The certificate's common name did "
			   "not match!  You asked that the certificate's CN "
			   "match '%s' exactly.  But, the certificate's CN "
			   "was '%s'.\n", common_name, dnsname);
	    }
	  else
	    {
	      debug_printf(DEBUG_NORMAL, "The certificate's common name did "
			   "not match!  You asked that the certificate's CN "
			   "contain '%s'.  But, the certificate's CN was "
			   "'%s'.\n", common_name, dnsname);
	    }
	  retval = XEGENERROR;
	  goto deinit;
	}
    }

 deinit:
  gnutls_x509_crt_deinit (cert);

  return retval;
}

/************************************************************************
 *
 *  This function is called to process packets that aren't start packets.
 *
 ************************************************************************/
uint8_t gnutls_funcs_process_other(struct tls_vars *mytls_vars,
				   uint8_t *eappacket)
{
  uint8_t *cur = NULL;
  uint32_t resp_size, packet_size;
  struct eap_header *eaphdr;
  int err = 0;
  uint8_t temp;

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return EAP_FAIL;

  if (!xsup_assert((eappacket != NULL), "eappacket != NULL", FALSE))
    return EAP_FAIL;

  // Assume we aren't going to send an ACK, until we actually decide we are.
  mytls_vars->send_ack = FALSE;

  eaphdr = (struct eap_header *)eappacket;
  packet_size = ntohs(eaphdr->eap_length);

  // First, process the byte that follows the EAP header.
  cur = (uint8_t *)&eappacket[sizeof(struct eap_header)];
  packet_size -= sizeof(struct eap_header);

  temp = cur[0];

  if ((temp == EAPTLS_ACK) && (packet_size <= (sizeof(struct eap_header)+1)))
    {
      debug_printf(DEBUG_TLS_CORE, "Got an ACK. (Packet size = %d)\n",
                   packet_size);
      return CONT;
    }

  cur++;
  packet_size--;

  if (temp & EAPTLS_LENGTH_INCL)
    {
      // Grab out the total size of the response.
      memcpy(&resp_size, cur, sizeof(uint32_t));
      resp_size = ntohl(resp_size);
      debug_printf(DEBUG_TLS_CORE, "Expecting %d byte(s) worth of response."
		   "\n", resp_size);
      mytls_vars->tlsinsize = resp_size;
      packet_size -= 4;
      cur += 4;
    }

  debug_printf(DEBUG_TLS_CORE, "Copying (%d) : \n", packet_size);
  debug_hex_dump(DEBUG_TLS_CORE, cur, packet_size);

  // If there are more fragments coming, our response should be an ACK.
  if (temp & EAPTLS_MORE_FRAGS) mytls_vars->send_ack = TRUE;

  mytls_vars->tlsindata = realloc(mytls_vars->tlsindata, 
				  (mytls_vars->tlsinptr + packet_size));

  if (mytls_vars->tlsindata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "There was an error getting enough memory "
		   "to hold the packet fragment.\n");
      return EAP_FAIL;
    }

  memcpy((uint8_t *)&mytls_vars->tlsindata[mytls_vars->tlsinptr],
	 cur, packet_size);

  debug_printf(DEBUG_TLS_CORE, "Copied %d byte(s) to our buffer.\n",
	       packet_size);

  mytls_vars->tlsinptr += packet_size;

  if (mytls_vars->send_ack == FALSE)
    {
      if (mytls_vars->tlsinptr != mytls_vars->tlsinsize)
	{
	  debug_printf(DEBUG_NORMAL, "The data we got was not the same size "
		       "as the data we were expecting! (Current offset %d, "
		       "expected offset %d.)\n", mytls_vars->tlsinptr,
		       mytls_vars->tlsinsize);

	  // We should have already freed our buffer before now, so just
	  // clear these values.
	  mytls_vars->tlsinptr = 0;
	  mytls_vars->tlsinsize = 0;
	  return XEGENERROR;
	}

      mytls_vars->tlsinptr = 0;

      err = gnutls_handshake(mytls_vars->session);
      
      if ((err != 0) && (err != GNUTLS_E_AGAIN))
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't continue handshake!  Error was "
		       "(%d): %s\n", err, gnutls_strerror(err));
	  return XEGENERROR;
	}

      if (err == 0)
	{
	  // The handshake is complete.
	  mytls_vars->handshake_done = TRUE;

	  if (mytls_vars->verify_cert == TRUE)
	    {
	      if (verify_certificate(mytls_vars->session, mytls_vars->cncheck, 
				     mytls_vars->cnexact) != XENONE)
		{
		  return XEGENERROR;
		}
	    }
	}
    }

  return XENONE;
}

/**************************************************************************
*
* This function processes the packets, and decides if it is a start, or
* another type of packet.  It then calls the appropriate handler function.
*
***************************************************************************/
uint8_t tls_funcs_process(struct tls_vars *mytls_vars, uint8_t *eappacket)
{
  if (eappacket[sizeof(struct eap_header)] == EAPTLS_START)
    {
      gnutls_funcs_do_start(mytls_vars);
      return CONT;
    }
  else
    {
      return gnutls_funcs_process_other(mytls_vars, eappacket);
    }
}

/**************************************************************************
*
*  This function pulls data out of the queue that needs to be sent to the
*  authentication server.
*
***************************************************************************/
int tls_funcs_get_packet(struct tls_vars *mytls_vars, int maxsize,
			     uint8_t **result, uint16_t *res_size)
{
  uint8_t *retdata;
  uint32_t retlen;

  if ((mytls_vars->tlsoutdata == NULL) && (mytls_vars->send_ack == TRUE))
    {
      retdata = Malloc(1);
      if (retdata == NULL) 
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for return "
		       "buffer!\n");
	  return XEMALLOC;
	}

      debug_printf(DEBUG_TLS_CORE, "Sending ACK!\n");
      retdata[0] = EAPTLS_ACK;
      *res_size = 1;
      (*result) = retdata;

      return XENONE;
    }

  if (mytls_vars->tlsoutsize == 0)
    {
      debug_printf(DEBUG_TLS_CORE, "No data left to send.\n");
      (*result) = NULL;
      *res_size = 0;
      return XENONE;
    }

  if (mytls_vars->tlsoutsize < maxsize) 
    {
      // Send everything.
      (*res_size) = mytls_vars->tlsoutsize + 5;
      retdata = Malloc((*res_size));
      if (retdata == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for return "
		       "buffer!\n");
	  return XEMALLOC;
	}

      retdata[0] = EAPTLS_LENGTH_INCL;  // No additional fragments.
      retlen = htonl(mytls_vars->tlsoutsize);
      memcpy(&retdata[1], &retlen, sizeof(uint32_t));
      memcpy(&retdata[5], mytls_vars->tlsoutdata, mytls_vars->tlsoutsize);
      (*result) = retdata;

      // There is nothing left, so free the memory we used.
      FREE(mytls_vars->tlsoutdata);
      mytls_vars->tlsoutsize = 0;

      return XENONE;
    }

  if (mytls_vars->tlsoutptr < mytls_vars->tlsoutsize)
    {
      maxsize -= 5;
      if ((mytls_vars->tlsoutsize - mytls_vars->tlsoutptr) > maxsize)
        {
          (*res_size) = maxsize;
        }
      else
        {
          (*res_size) = (mytls_vars->tlsoutsize - mytls_vars->tlsoutptr);
        }

      retdata = Malloc((*res_size) + 5);
      if (retdata == NULL)
        {
          debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for return "
                       "fragment!\n");
          return XEMALLOC;
        }

      // Need to send a fragment.
      if (mytls_vars->tlsoutptr == 0)
        {
          debug_printf(DEBUG_TLS_CORE, "Sending response with length & frags."
                       "\n");
          // This is the first packet, so send a length value with it.
          retdata[0] = EAPTLS_LENGTH_INCL + EAPTLS_MORE_FRAGS;
          retlen = htonl(mytls_vars->tlsoutsize);
          memcpy(&retdata[1], &retlen, sizeof(uint32_t));
          memcpy(&retdata[5], &mytls_vars->tlsoutdata[mytls_vars->tlsoutptr],
                 (*res_size));
          (*result) = retdata;
          mytls_vars->tlsoutptr += (*res_size);
          (*res_size) += 5;
        }
      else
        {
          if ((mytls_vars->tlsoutsize - mytls_vars->tlsoutptr) > maxsize)
            {
              debug_printf(DEBUG_TLS_CORE, "More frags comming.\n");
              retdata[0] = EAPTLS_MORE_FRAGS;
            }
          else
            {
              debug_printf(DEBUG_TLS_CORE, "Fragment done.\n");
              retdata[0] = EAPTLS_FINAL;
            }

          memcpy(&retdata[1], &mytls_vars->tlsoutdata[mytls_vars->tlsoutptr],
                 (*res_size));
          (*result) = retdata;
          (*res_size) += 1;
        }

      if (mytls_vars->tlsoutptr >= mytls_vars->tlsoutsize)
        {
          // We are done.
          FREE(mytls_vars->tlsoutdata);
          mytls_vars->tlsoutptr = 0;
          mytls_vars->tlsoutsize = 0;
        }

      return XENONE;
    }

  debug_printf(DEBUG_NORMAL, "No data to send?!\n");
  return XEGENERROR;
}

/************************************************************************
 *
 * Request that GNU-TLS encrypt some amount of data.  This call will result
 * in a call to the push callback function which should queue the encrypted
 * data, and return it on the next request.
 *
 ************************************************************************/
int tls_funcs_encrypt(struct tls_vars *mytls_vars, uint8_t *tosend,
		      uint16_t tosend_size)
{
  debug_printf(DEBUG_TLS_CORE, "Encrypting :\n");
  debug_hex_dump(DEBUG_TLS_CORE, tosend, tosend_size);

  if (gnutls_record_send(mytls_vars->session, tosend, tosend_size) != tosend_size)
    {
      debug_printf(DEBUG_NORMAL, "More to send? \n");
      return XEGENERROR;
    }

  return XENONE;
}

/************************************************************************
 *
 * Decrypt data that we got from the authentication server.  This should
 * result in a call to the push callback function, which should queue the
 * encrypted data, and return it on the next request.
 *
 ************************************************************************/
int tls_funcs_decrypt(struct tls_vars *mytls_vars, uint8_t *tosend,
		      uint16_t *tosend_size)
{
  int retsiz;

  if (mytls_vars->tlsindata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "The decrypt buffer is currently empty. "
		   "Please put something in it using the tls_funcs_buffer"
		   "() call, and try again.\n");
      return XEGENERROR;
    }

  retsiz = gnutls_record_recv(mytls_vars->session, tosend, 
			      (size_t)tosend_size);

  *tosend_size = retsiz;

  if (retsiz < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error writing data.\n");
      return XEGENERROR;
    }

  debug_printf(DEBUG_TLS_CORE, "Decrypted dump (%d) :\n", retsiz);
  debug_hex_dump(DEBUG_TLS_CORE, tosend, retsiz);
  return XENONE;
}

/************************************************************************
 *
 *  Determine if our decrypt buffer is full.  If it is, then return the 
 *  amount of data that is currently stored in our buffer,
 *  if not, return 0.  If the buffer appears to be over-full, then
 *  display a warning, and continue anyway.
 *
 ************************************************************************/
int tls_funcs_decrypt_ready(struct tls_vars *mytls_vars)
{
  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return -1;

  // The buffer is full.
  if (mytls_vars->tlsinsize == mytls_vars->tlsinptr) 
    {
      mytls_vars->tlsinptr = 0;
      return mytls_vars->tlsinsize;
    }

  // The buffer is over full.
  if (mytls_vars->tlsinptr > mytls_vars->tlsinsize)
    {
      if (config_get_friendly_warnings() == TRUE)
	{
	  debug_printf(DEBUG_NORMAL, "Your decryption buffer has overflowed. "
		       "It is likely that decryption will fail, however we "
		       "will attempt to proceed anyway.\n");
	}
      mytls_vars->tlsinsize = mytls_vars->tlsinptr;
      mytls_vars->tlsinptr = 0;
      return mytls_vars->tlsinsize;
    }

  // Otherwise, we aren't ready yet.
  return 0;
}

/************************************************************************
 *
 * Buffer input data until it is ready to be decrypted.  If the variable
 * totalsize is 0, then we will not update the tlsinsize value.  (This is
 * useful for adding fragments that don't contain a length field.)
 *
 ************************************************************************/
int tls_funcs_buffer(struct tls_vars *mytls_vars, uint8_t *newfrag,
		     uint16_t fragsize)
{
  uint32_t value32;
  uint8_t *p;

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEGENERROR;

  if (!xsup_assert((newfrag != NULL), "newfrag != NULL", FALSE))
    return XEGENERROR;

  p = newfrag;
  if ((newfrag[0] & EAPTLS_LENGTH_INCL) == EAPTLS_LENGTH_INCL)
    {
      // We have length data, which means this should be the first piece 
      // of a fragment.  So, verify that there isn't anything already
      // buffered.
      if (mytls_vars->tlsindata != NULL)
	{
	  if (config_get_friendly_warnings() == TRUE)
	    {
	      debug_printf(DEBUG_NORMAL, "This appears to be the first piece "
			   "of a data fragment.  However, there is already "
			   "data in the fragment buffer.  It "
			   "is likely that your authentication will fail!\n");
	    }
	}

      p++;    // Skip to the bytes that contain the value.

      memcpy(&value32, p, 4);
      value32 = ntohl(value32);
      p+=3;

      mytls_vars->tlsinsize = value32;
      fragsize -= 4;                  // Skip the length value.
    }

  p++;  // Skip the ID bytes.
  fragsize--;

  debug_printf(DEBUG_TLS_CORE, "Total data size should be %d.  We currently"
	       " have %d byte(s) of data, and will be adding %d more.\n",
	       mytls_vars->tlsinsize, mytls_vars->tlsinptr, fragsize);

  mytls_vars->tlsindata = realloc(mytls_vars->tlsindata,
				  mytls_vars->tlsinptr + fragsize);
  if (mytls_vars->tlsindata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to buffer data.\n");
      return XEMALLOC;
    }

  memcpy(&mytls_vars->tlsindata[mytls_vars->tlsinptr], p, fragsize);
  mytls_vars->tlsinptr += fragsize;

  if (((newfrag[0] & EAPTLS_MORE_FRAGS) != EAPTLS_MORE_FRAGS) &&
      (mytls_vars->tlsinptr < mytls_vars->tlsinsize))
    {
      if (config_get_friendly_warnings() == TRUE)
	{
	  debug_printf(DEBUG_NORMAL, "The server indicated that there are no "
		       "fragments remaining.  However, we only have %d of %d "
		       "byte(s).  It is likely your authentication will fail."
		       "\n", mytls_vars->tlsinptr, mytls_vars->tlsinsize);
	}
    }
  
  if (((newfrag[0] & EAPTLS_MORE_FRAGS) != EAPTLS_MORE_FRAGS) &&
       (mytls_vars->tlsinptr > mytls_vars->tlsinsize))
    {
      mytls_vars->tlsinsize += mytls_vars->tlsinptr;
    }

  return XENONE;
}

/************************************************************************
 *
 *  Generate our TLS keyblock to use as keying material, or an implicit
 *  challenge for TTLS.
 *
 ************************************************************************/
uint8_t *tls_funcs_gen_keyblock(struct tls_vars *mytls_vars, 
				uint8_t *sesskey, uint16_t sesskeylen)
{
  uint8_t *retblock = NULL;
  int err;

  debug_printf(DEBUG_TLS_CORE, "Generating key block!\n");

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return NULL;

  if (sesskey == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No keying material is available!  It is "
                   "unlikely that your session will work properly.\n");
      return NULL;
    }

  debug_printf(DEBUG_TLS_CORE, "Using session key constant of : %s\n",
	       sesskey);

  retblock = Malloc(TLS_SESSION_KEY_SIZE);
  if (!retblock)
    {
      return NULL;
    }

  err = gnutls_prf(mytls_vars->session, sesskeylen, sesskey, FALSE, 0, NULL,
		   TLS_SESSION_KEY_SIZE, retblock);

  if (err != 0)
    {
      debug_printf(DEBUG_NORMAL, "Error generating key block.  Error was (%d)"
		   " : %s\n", err, gnutls_strerror(err));
      return NULL;
    }

  return retblock;
}

/************************************************************************
 *
 *  Clean up after ourselves.
 *
 ************************************************************************/
void tls_funcs_deinit(struct tls_vars *mytls_vars)
{
  gnutls_certificate_free_credentials(mytls_vars->creds);

  if (mytls_vars->session != NULL)
    gnutls_deinit(mytls_vars->session);

  gnutls_global_deinit();

  debug_printf(DEBUG_TLS_CORE, "(TLS Engine : GNU) TLS Deinit complete.\n");
}


#endif
