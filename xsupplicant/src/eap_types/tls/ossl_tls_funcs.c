/**
 * EAPTLS (RFC 2716) Function implementations
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file ossl_tls_funcs.c
 *
 * \author chris@open1x.org
 *
 * $Id: ossl_tls_funcs.c,v 1.8 2008/01/26 03:19:42 chessing Exp $
 * $Date: 2008/01/26 03:19:42 $
 */

#ifndef USE_GNUTLS

#ifdef WINDOWS
#define OPENSSL_NO_ENGINE

#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>

#ifndef WINDOWS
/* For some reason, including this file on windows right now will cause the compiler to fail.
	Since it generally isn't used, we will disable it on Windows for now. */
#include <openssl/engine.h>
#endif

#include <openssl/ui.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/bio.h>

#ifndef WINDOWS
#include <netinet/in.h>
#include <inttypes.h>
#include <unistd.h>
#endif

#include <string.h>
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "../../context.h"
#include "../../eap_sm.h"
#include "../../eap_types/tls/eaptls.h"
#include "tls_funcs.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "../../frame_structs.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

// In OpenSSL 0.9.8 we need to explicitly include the SHA header.
#ifndef SHA_DIGEST_LENGTH
#include <openssl/sha.h>
#endif

// If it *STILL* isn't around, then just define it.
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

int engine_load_dynamic_opensc(struct smartcard *sc);
void set_smartcard_pin(char *pin);
UI_METHOD *UI_noninteractive(void);

/************************************************************************
 *
 * Get the common name field from a certificate for later processing.
 *
 ************************************************************************/
char *get_cert_common_name(SSL *ssl_ctx)
{
  char *commonName = NULL;
  X509 *server_cert;

  TRACE

  if (!xsup_assert((ssl_ctx != NULL), "ssl_ctx != NULL", FALSE))
    return NULL;

  // Get our certificate.
  server_cert = SSL_get_peer_certificate(ssl_ctx);

  if (!server_cert) return NULL;

  commonName = (char *)Malloc(512);
  if (commonName == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to hold the common name!\n");
	  ipc_events_malloc_failed(NULL);
      return NULL;
    }

  if (X509_NAME_get_text_by_NID(X509_get_subject_name(server_cert),
				NID_commonName, commonName, 512) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't extract common name from server certificate!\n");
      return NULL;
    }

  debug_printf(DEBUG_TLS_CORE, "Extracted common name of %s\n",commonName);
  return commonName;
}

/************************************************************************
 *
 *  Process an error condition and display some information about it.
 *
 ************************************************************************/
void tls_funcs_process_error()
{
  unsigned long err;

  TRACE

  err = ERR_get_error();
  if (err != 0)
    {
      debug_printf(DEBUG_NORMAL, "OpenSSL Error -- %s\n", 
		   ERR_error_string(err, NULL));
      debug_printf(DEBUG_NORMAL, "Library  : %s\n", ERR_lib_error_string(err));
      debug_printf(DEBUG_NORMAL, "Function : %s\n", ERR_func_error_string(err));
      debug_printf(DEBUG_NORMAL, "Reason   : %s\n", ERR_reason_error_string(err));
    }
}

/************************************************************************
 *
 *  Determine if we have any data pending.  If we do, return the number of
 *  bytes that are pending.
 *
 ************************************************************************/
uint32_t tls_funcs_data_pending(struct tls_vars *mytls_vars)
{
	uint32_t retsize;

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return 0;

  if (queue_get_size(&mytls_vars->tlsoutqueue, &retsize) < 0)
	  return 0;                // Something was wrong, so we can't have anything more to send.

  return retsize;
}

/************************************************************************
 *
 *  Do some standard checks to be sure our certificate is valid.
 *
 ************************************************************************/
static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  char buf[256];
  X509 *err_cert;
  int err, depth;

  TRACE

  if (!xsup_assert((ctx != NULL), "ctx != NULL", FALSE))
    return XEMALLOC;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);
  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

  debug_printf(DEBUG_TLS_CORE, "     --- SSL_verify : depth %d\n", depth);

  if (!preverify_ok)
    {
      debug_printf(DEBUG_TLS_CORE, "     --- SSL_verify error : num=%d:%s:depth=%d:%s\n",
		   err, X509_verify_cert_error_string(err), depth, buf);

      // Ignore the self signed certificate error, from OpenSSL.
      if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) preverify_ok = 1;
    }

  debug_printf(DEBUG_TLS_CORE, "preverify_ok = %d\n", preverify_ok);

  return preverify_ok;
}

/***********************************************************************
 *
 *  Initialize the Open SC smart card handler.
 *
 ***********************************************************************/
#ifndef WINDOWS
int tls_funcs_load_engine(struct tls_vars *mytls_vars, struct smartcard *sc)
{
  if(!engine_load_dynamic_opensc(sc))
    {
      debug_printf(DEBUG_NORMAL, "OpenSC Engine will be unavailable!\n");
      return XEGENERROR;
    }

  debug_printf(DEBUG_NORMAL, "Using Engine with ID \"%s\"\n", 
	       sc->engine_id);

  mytls_vars->engine = ENGINE_by_id(sc->engine_id);
  if (!mytls_vars->engine)
    {
      debug_printf(DEBUG_NORMAL, "Engine not available!\n");
      return XETLSINIT;
    }
								       
  /* Now everything that can be done without having a smartcard plugged in
   * is done. The next step is initializing the Engine.
   * This step should probably be done in some place where it can be
   * retried if it fails.
   */

  if (!ENGINE_init(mytls_vars->engine))
    {
      debug_printf(DEBUG_NORMAL, "Can't initialize OpenSC Engine! "
		   "Is the smartcard plugged in?\n");
      /* If we get this error there's probably no smartcard connected -
       * we should be able to retry the call to ENGINE_init() */
      return XETLSINIT;
    }
  return XENONE;
}
#endif  // WINDOWS


/***********************************************************************
 *
 *  Configure the cipher suites to only do TLS_DH_anon_WITH_AES_128_CBC_SHA
 *  this is use with EAP-FAST to provide unauthenticated provisioning.
 *
 ***********************************************************************/
int tls_funcs_set_anon_dh_aes(struct tls_vars *mytls_vars)
{
  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return -1;

  if (!xsup_assert((mytls_vars->ssl != NULL), "mytls_vars->ssl != NULL",
		   FALSE))
    return -1;

  if (SSL_set_cipher_list(mytls_vars->ssl, "ADH-AES128-SHA") != 1)
    {
      // The cipher type wasn't allowed. (Probably not compiled in.)
      debug_printf(DEBUG_NORMAL, "Anonymous cipher ADH-AES128-SHA was not "
		   "available!  It is possible that your OpenSSL was not "
		   "compiled with support for it!\n");
      return -1;
    }

  return 0;
}

/***********************************************************************
 *
 *  Allocate memory, and set up structures needed to complete a TLS
 *  based authentication.
 *
 ***********************************************************************/
int tls_funcs_init(struct tls_vars *mytls_vars, uint8_t eaptype)
{
  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XETLSINIT;

  // XXX Need to move the global init pieces here. (OpenSSL init stuff.) Once we
  // finish making the changes to allow GNU-TLS as an option.

  if (mytls_vars->ssl)
    {
      SSL_shutdown(mytls_vars->ssl);
      SSL_free(mytls_vars->ssl);
      mytls_vars->ssl = NULL;
    }

  if (mytls_vars->ctx != NULL)
    {
      SSL_CTX_free(mytls_vars->ctx);
      mytls_vars->ctx = NULL;
    }

  mytls_vars->ctx = SSL_CTX_new(TLSv1_method());
  if (mytls_vars->ctx == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize OpenSSL TLS library!\n");
      tls_funcs_process_error();
	  ipc_events_malloc_failed(NULL);
      return XETLSINIT;
    }

  mytls_vars->method_in_use = eaptype;

  return XENONE;
}

/*************************************************************************
*
* Allocate a new context for OpenSSL.
*
**************************************************************************/
int tls_funcs_build_new_session(struct tls_vars *mytls_vars)
{
  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEMALLOC;

  if (mytls_vars->ssl)
    {
      SSL_shutdown(mytls_vars->ssl);
  }

  if (mytls_vars->ssl)
  {
      SSL_free(mytls_vars->ssl);
      mytls_vars->ssl = NULL;
    }

  if (mytls_vars->ctx == NULL)
  {
	  debug_printf(DEBUG_NORMAL, "The SSL context is NULL.  (This shouldn't happen.)  Working around it.\n");
	  if (tls_funcs_init(mytls_vars, mytls_vars->method_in_use) != XENONE) return XETLSSTARTFAIL;
  }

  mytls_vars->ssl = SSL_new(mytls_vars->ctx);
  if (!mytls_vars->ssl)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't create SSL object!\n");
      tls_funcs_process_error();
      
      return XETLSSTARTFAIL;
    }

  return XENONE;
}
  
/*************************************************************************
*
*  Handle processing of a start packet.
*
**************************************************************************/
int ossl_funcs_do_start(struct tls_vars *mytls_vars)
{
  SSL_SESSION *sess = NULL;
  unsigned long err;
  int counter, resval = XENONE;
  int mode = 0, ressize = 0;
  uint8_t *tempdata = NULL;

  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEMALLOC;

  debug_printf(DEBUG_TLS_CORE, "Got TLS Start!\n");

  mytls_vars->resuming = 0;

  if ((mytls_vars->ssl == NULL) || (mytls_vars->resume != RES_YES))
    {
      resval = tls_funcs_build_new_session(mytls_vars);
      if (resval != XENONE) 
		{
			debug_printf(DEBUG_NORMAL, "Error building a new session!\n");
			return resval;
		}
    } else {
      // We already established a connection, so we probably we need to
      // resume the session.
      if (mytls_vars->resume == RES_YES)
		{
			sess = SSL_get_session(mytls_vars->ssl);
			if (!sess)
				{
					debug_printf(DEBUG_TLS_CORE, "Couldn't get session information!"
						" We won't try to resume this session!\n");
					mytls_vars->resuming = 0;

			      // Clear the old session data.
				    SSL_free(mytls_vars->ssl);

			      // Set up a new session.	
			      resval = tls_funcs_build_new_session(mytls_vars);
			      if (resval != XENONE) return resval;
			    } else {
			      debug_printf(DEBUG_TLS_CORE, "Got session information, trying "
					   "to resume session!\n");
			      mytls_vars->resuming = 1;

	      // We don't want to send an alert to the other end..  So do a 
	      // quiet shutdown.  This violates the TLS standard, but it is 
	      // needed to avoid confusing the other end of the connection 
	      // when we want to do a reconnect!
	      SSL_set_quiet_shutdown(mytls_vars->ssl, 1);
	      
	      // Now, close off our old session.
	      err = 0;
	      counter = 0;

	      SSL_shutdown(mytls_vars->ssl);

	      while ((err == 0) && (counter < 60))
		{
		  err = SSL_shutdown(mytls_vars->ssl);
		  if (err == 0)
		    {
#ifndef WINDOWS
		      sleep(1);
#else
			  Sleep(1000);
#endif
		      counter++;
		    }
		}

	      if (err < 0)
		{
		  debug_printf(DEBUG_NORMAL, "Error trying to shut down SSL "
			       "context data.\n");
		  tls_funcs_process_error();
		}
	    }
	}
    }

  mytls_vars->ssl_in = BIO_new(BIO_s_mem());
  if (!mytls_vars->ssl_in)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't create ssl_in!\n");
      tls_funcs_process_error();
	  ipc_events_malloc_failed(NULL);
      return XETLSSTARTFAIL;
    }

  if (BIO_reset(mytls_vars->ssl_in) < 1)
    {
      debug_printf(DEBUG_NORMAL, "Error : %s:%d\n", __FUNCTION__, __LINE__);
      tls_funcs_process_error();
    }

  mytls_vars->ssl_out = BIO_new(BIO_s_mem());
  if (!mytls_vars->ssl_out)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't create ssl_out!\n");
      tls_funcs_process_error();
	  ipc_events_malloc_failed(NULL);
      return XETLSSTARTFAIL;
    }

  if (BIO_reset(mytls_vars->ssl_out) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error : %s:%d\n", __FUNCTION__, __LINE__);
      tls_funcs_process_error();
    }

  if (sess != NULL)
    {
      // If we have session information, we need to use it to resume the 
      // session.
      debug_printf(DEBUG_TLS_CORE, "Attempting to resume session...\n");
      if (SSL_set_session(mytls_vars->ssl, sess) <= 0)
	{
	  debug_printf(DEBUG_NORMAL, "There was an error attempting to resume "
		       "the session!\n");
	  tls_funcs_process_error();
	}
    }

  SSL_set_bio(mytls_vars->ssl, mytls_vars->ssl_in, mytls_vars->ssl_out);

  // Set this to SSL_VERIFY_NONE if we don't want to do anything with a failed
  // verification.

  if (mytls_vars->verify_cert == TRUE)
    {
      mode = SSL_VERIFY_PEER;
    }
  else
    {
      mode = SSL_VERIFY_NONE;
    }

  SSL_set_verify(mytls_vars->ssl, mode, ssl_verify_callback);

  err = SSL_connect(mytls_vars->ssl);

  if (err < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't start handshake!  Error was %d.\n",
		   err);
      err = SSL_get_error(mytls_vars->ssl, err);
      debug_printf(DEBUG_NORMAL, "Error : %d\n", err);

      if (err != 0)
	{
	  debug_printf(DEBUG_NORMAL, "OpenSSL Error -- %s\n",
		       ERR_error_string(err, NULL));
	  debug_printf(DEBUG_NORMAL, "Library  : %s\n", ERR_lib_error_string(err));
	  debug_printf(DEBUG_NORMAL, "Function : %s\n", ERR_func_error_string(err));
	  debug_printf(DEBUG_NORMAL, "Reason   : %s\n", ERR_reason_error_string(err));
	}

      tls_funcs_process_error();
      return XEGENERROR;
    }

  tempdata = Malloc(1500);
  if (tempdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store return "
		   "TLS data!\n");
	  ipc_events_malloc_failed(NULL);
      return XEMALLOC;
    }

  ressize = BIO_read(mytls_vars->ssl_out, 
				     tempdata, 1500);
  if (ressize <= 0)
  {
#if 0
	  if (BIO_should_retry(mytls_vars->ssl_out) == TRUE)
	  {
		  printf("Should retry.\n");
	  }
	  else
	  {
		  printf("********************************************************Failure! (%d)\n", ressize);
	  }
#endif
    FREE(tempdata);
	return XEGENERROR;
  }

  // If a queue already exists, destroy it.
  if (NULL != mytls_vars->tlsoutqueue) queue_destroy(&mytls_vars->tlsoutqueue);
  if (NULL != mytls_vars->tlsinqueue) queue_destroy(&mytls_vars->tlsinqueue);

  // Make sure our queue is ready to accept the data.
  if (NULL == mytls_vars->tlsoutqueue)
  {
	  debug_printf(DEBUG_TLS_CORE, "Creating a new queue!\n");
	  if (queue_create(&mytls_vars->tlsoutqueue) < 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't create data queue for response data!\n");
		  FREE(tempdata);
		  return XEGENERROR;
	  }
  }

  if (queue_enqueue(&mytls_vars->tlsoutqueue, tempdata, ressize) < 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't enqueue response data!  Destroying queue.\n");
	  if (queue_destroy(&mytls_vars->tlsoutqueue) < 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't destroy queue!  This is *REALLY* bad!\n");
		  FREE(tempdata);
		  return XEGENERROR;
	  }
  }

  FREE(tempdata);

  BIO_reset(mytls_vars->ssl_out);
  BIO_reset(mytls_vars->ssl_in);

  return XENONE;
}

/**************************************************************************
 *
 * Process packets that aren't start packets.
 *
 **************************************************************************/
uint8_t ossl_funcs_process_other(struct tls_vars *mytls_vars,
				 uint8_t *eappacket)
{
  uint8_t *cur = NULL;
  uint8_t *tempdata = NULL;
  uint32_t resp_size = 0, packet_size = 0;
  struct eap_header *eaphdr = NULL;
  int err = 0;
  uint8_t temp = 0;
  uint16_t size = 0;
  char *error_str = NULL;

  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return DONE;

  if (!xsup_assert((eappacket != NULL), "eappacket != NULL", FALSE))
    return DONE;

  if (mytls_vars->ssl == NULL) 
  {
	  debug_printf(DEBUG_NORMAL, "The server sent a mid-conversation message when we expected a start.  If this is a wireless connection, it is likely that the wireless card hopped to a new AP in the middle of a conversation.\n");
	  return DONE;
  }

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
	  mytls_vars->expected_in = resp_size;
      packet_size -= 4;
      cur += 4;
    }

  if (temp == 0x00)
  {
	  // We got a TLS message that doesn't contain a length value.  So, it is probably
	  // all inclusive.
	  if (mytls_vars->expected_in == 0)
	  {
		  // Yup.  It is.
		  mytls_vars->expected_in = packet_size;
		  debug_printf(DEBUG_TLS_CORE, "Expecting a total of %d byte(s). (Single packet message)\n", mytls_vars->expected_in);
	  }
  }

  debug_printf(DEBUG_TLS_CORE, "Copying (%d) : \n", packet_size);
  debug_hex_dump(DEBUG_TLS_CORE, cur, packet_size);

  // If there are more fragments coming, our response should be an ACK.
  if (temp & EAPTLS_MORE_FRAGS) mytls_vars->send_ack = TRUE;

  mytls_vars->in_so_far += packet_size;
  
  if (BIO_write(mytls_vars->ssl_in, cur, packet_size) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't BIO_write!\n");
      return DONE;
    }

  if (mytls_vars->send_ack == FALSE)
    {
      if (mytls_vars->in_so_far != mytls_vars->expected_in)
        {
          debug_printf(DEBUG_NORMAL, "The data we got was not the same size "
                       "as the data we were expecting! (Current offset %d, "
                       "expected offset %d.)\n", mytls_vars->in_so_far,
                       mytls_vars->expected_in);

          // We should have already freed our buffer before now, so just
          // clear these values.
          mytls_vars->in_so_far = 0;
          mytls_vars->expected_in = 0;
          return DONE;
        }

      debug_printf(DEBUG_TLS_CORE, "Writing %d byte(s) of data to OpenSSL:\n",
		   mytls_vars->expected_in);

	  mytls_vars->in_so_far = 0;
	  mytls_vars->expected_in =0;

      err = SSL_connect(mytls_vars->ssl);

      if (err != 1) 
        {
			err = ERR_get_error();
			if (err != 0)
			{
				sprintf(error_str, "Authentication handshake failed.  Reason : %s", ERR_reason_error_string(err));
				debug_printf(DEBUG_NORMAL, "%s\n", error_str);
				ipc_events_error(NULL, IPC_EVENT_ERROR_TEXT, error_str);

				tls_funcs_deinit(mytls_vars);

				return DONE;
			}
        }

      size = BIO_ctrl_pending(mytls_vars->ssl_out);

	  if (size > 0)
	  {
		tempdata = Malloc(size);
		if (tempdata == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store OpenSSL's response data!\n");
		  return DONE;
		}

		err = BIO_read(mytls_vars->ssl_out, 
			 tempdata, size);
		if (err > 0)
			{
				if (mytls_vars->tlsoutqueue == NULL)
				{
					if (queue_create(&mytls_vars->tlsoutqueue) < 0)
					{
						debug_printf(DEBUG_NORMAL, "Couldn't create queue data for OpenSSL's TLS response data!\n");
						FREE(tempdata);
						return DONE;
					}
				}

				if (queue_enqueue(&mytls_vars->tlsoutqueue, tempdata, size) < 0)
				{
					debug_printf(DEBUG_NORMAL, "Couldn't enqueue OpenSSL's TLS response data!\n");
					FREE(tempdata);
					return DONE;
				}
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "The BIO claimed there was data "
					"available, but it got an error returning it to "
					"us!\n");
			}
		FREE(tempdata);
	  }
	}
#if 0
      else
	{
	  if (size == 0)
	    {

	      debug_printf(DEBUG_TLS_CORE, "Nothing to return, ACKing!\n");
		}
    }
#endif

  if (SSL_get_state(mytls_vars->ssl) == 0x0003)
    {
	  if (tls_funcs_cn_check(mytls_vars) != XENONE)
	    {
	      debug_printf(DEBUG_NORMAL, "Failed certificate common name "
			   "check!\n");
		  queue_destroy(&mytls_vars->tlsinqueue);
		  queue_destroy(&mytls_vars->tlsoutqueue);
	      return DONE;
	    }
	  else
	  {
        mytls_vars->handshake_done = TRUE;
	  }
    }

  return MAY_CONT;
}

/**************************************************************************
 *
 * This function processes the packets, and decides if it is a start, or
 * another type of packet.  It then calls the appropriate handler function.
 *
 ***************************************************************************/
uint8_t tls_funcs_process(struct tls_vars *mytls_vars, uint8_t *eappacket)
{
  TRACE

  if (eappacket[sizeof(struct eap_header)] == EAPTLS_START)
    {
      if (ossl_funcs_do_start(mytls_vars) == 0)
	  {
		return CONT;
	  }
	  else
	  {
		  return EAP_FAIL;
	  }
    }
  else
    {
      return ossl_funcs_process_other(mytls_vars, eappacket);
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
  uint8_t *retdata = NULL;
  uint8_t *dequeue_data = NULL;
  uint8_t *dataptr = NULL;
  uint32_t retlen = 0;
  uint32_t cpysize = 0;
  uint32_t queuesize = 0;
  int more = 0;
  int athead = 0;

  TRACE

  if ((mytls_vars->tlsoutqueue == NULL) && (mytls_vars->send_ack == TRUE))
    {
      retdata = Malloc(1);
      if (retdata == NULL)
        {
          debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for return "
                       "buffer!\n");
		  ipc_events_malloc_failed(NULL);
          return XEMALLOC;
        }

      debug_printf(DEBUG_TLS_CORE, "Sending ACK!\n");
      retdata[0] = EAPTLS_ACK;
      *res_size = 1;
      (*result) = retdata;

      return XENONE;
    }

	  if (queue_get_size(&mytls_vars->tlsoutqueue, &queuesize) < 0)
	  {
		  if (mytls_vars->tlsoutqueue != NULL) debug_printf(DEBUG_NORMAL, "Error getting queue depth!\n");
		  return XEGENERROR;
	  }

	  athead = queue_at_head(&mytls_vars->tlsoutqueue);

  if (queuesize == 0)
    {
      debug_printf(DEBUG_TLS_CORE, "No data left to send.\n");
      (*result) = NULL;
      *res_size = 0;
      return XENONE;
    }

	  (*res_size) = maxsize - 6;  // Leave room in case we need to slap a length header on.

	  more = queue_dequeue(&mytls_vars->tlsoutqueue, &dequeue_data, (uint32_t *)res_size);

  	  if (more < 0) 
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't get more fragments to send to authenticator.\n");
		  return XEGENERROR;  
	  }

	  // If we are at the head of the list, we need to send a length.
	  if ((athead == TRUE) && (more == TRUE))
	  {
		retdata = Malloc((*res_size) + 5);
		if (retdata == NULL) return XEMALLOC;

		dataptr = (uint8_t *)&retdata[5];
		retdata[0] = EAPTLS_LENGTH_INCL;  // Length is included in this message.
		cpysize = (*res_size);
		retlen = htonl(queuesize);
		memcpy(&retdata[1], &retlen, sizeof(uint32_t));
		(*res_size)+=5;
	  }
	  else
	  {
		  retdata = Malloc((*res_size)+1);
		  if (retdata == NULL) return XEMALLOC;

		  cpysize = (*res_size);
		  dataptr = (uint8_t *)&retdata[1];
		  (*res_size)++;
	  }

	  // If more == TRUE then we have more fragments, and need to include that indication
	  if (more == TRUE) 
	  {
		  retdata[0] |= EAPTLS_MORE_FRAGS;
	  }
	  else
	  {
		  retdata[0] |= EAPTLS_FINAL;
	  }

	  memcpy(dataptr, dequeue_data, cpysize);

	  FREE(dequeue_data);

	  if (queue_queue_done(&mytls_vars->tlsoutqueue) != 0)
	  {
		  debug_printf(DEBUG_TLS_CORE, "Finished with queue... Freeing.\n");
		  if (queue_destroy(&mytls_vars->tlsoutqueue) != 0)
		  {
			  debug_printf(DEBUG_NORMAL, "Couldn't destroy queue data!  (We will probably leak memory.)\n");
		  }
	  }

	  debug_printf(DEBUG_TLS_CORE, "TLS Returns (%d bytes) :\n", (*res_size));
	  debug_hex_dump(DEBUG_TLS_CORE, retdata, (*res_size));

	  (*result) = retdata;

	  return XENONE;
}

/***********************************************************************
 *
 *  Check the CN field of a certificate against what the user has requested
 *  that we test with.
 *
 ***********************************************************************/
int tls_funcs_cn_check(struct tls_vars *mytls_vars)
{
  char *cnname = NULL;
  char *temp = NULL;

  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEMALLOC;

  if (mytls_vars->cncheck != NULL)
    {
      cnname = get_cert_common_name(mytls_vars->ssl);

      debug_printf(DEBUG_TLS_CORE, "Certificate CN : %s\n",cnname);

      // mytls_vars->cncheck == NULL, do nothing.
      debug_printf(DEBUG_TLS_CORE, "Doing a CN Check!\n");

      if (mytls_vars->cnexact == 1)
	{
	  debug_printf(DEBUG_TLS_CORE, "Looking for an exact match!\n");

	  if (cnname != NULL)
	    {
	      if (strcmp(mytls_vars->cncheck, cnname) != 0)
		{
		  debug_printf(DEBUG_NORMAL, "Certificate CN didn't "
			  "match!  (Server : %s    Us : %s)\n", cnname, mytls_vars->cncheck);
		  FREE(cnname);
		  return XEBADCN;
		} else {
		  debug_printf(DEBUG_TLS_CORE, "Certificate CN matched!\n");
		}
	    }
	} else {
	  debug_printf(DEBUG_TLS_CORE, "Looking for a relative match!\n");

	  temp = mytls_vars->cncheck;
	  if (cnname != NULL)
	    {
	      if (strstr(cnname, temp) == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Certificate CN didn't "
			  "match!   (Server : %s    Us : %s)\n", cnname, temp);
		  FREE(cnname);
		  return XEBADCN;
		} else {
		  debug_printf(DEBUG_TLS_CORE, "Certificate CN matched!\n");
		}
	    }
	}
    }

  FREE(cnname);

  return XENONE;
}

/**********************************************************************
 *
 *  Provide some form of error messages from OpenSSL back to the user.
 *
 **********************************************************************/
static void ssl_info_callback(SSL *ssl, int w, int r)
{
  TRACE

  if (!xsup_assert((ssl != NULL), "ssl != NULL", FALSE))
    return;

  debug_printf(DEBUG_TLS_CORE, "     --- SSL : %s\n", SSL_state_string_long(ssl));
  if (w & SSL_CB_ALERT)
    debug_printf(DEBUG_TLS_CORE, "     --- ALERT : %s\n", SSL_alert_desc_string_long(r));
}

/***********************************************************************
 *
 *  Return the password for our user certificate.
 *
 ***********************************************************************/
static int return_password(char *buf, int size, int rwflag, void *userdata)
{
  TRACE

  if (!xsup_assert((buf != NULL), "buf != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((userdata != NULL), "userdata != NULL", FALSE))
    return XEMALLOC;

  if (Strncpy(buf, size, (char *)(userdata), size) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Attempt to overflow a buffer in %s() at %d!\n",
		  __FUNCTION__, __LINE__);
	  return -1;
  }

  buf[size-1] = '\0';
  return(strlen(buf));
}

/**************************************************************************
 *
 * Load any root certificates that the user would want to use.
 *
 **************************************************************************/
int tls_funcs_load_root_certs(struct tls_vars *mytls_vars, char *root_cert, 
			      char *root_dir, char *crl_dir)
{
  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((mytls_vars->ctx != NULL), "mytls_vars->ctx != NULL", 
		   FALSE))
    return XEMALLOC;

  if ((!root_cert) && (!root_dir))
    {
      debug_printf(DEBUG_NORMAL, "Error loading cert!  Path to cert is NULL!\n");
      return XETLSCERTLOAD;
    } 

  if (mytls_vars->ctx == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid context in tls_funcs_load_root_certs()!\n");
      return XEMALLOC;
    }

  debug_printf(DEBUG_TLS_CORE, "Trying to load root certificate %s or "
	       "certificate directory %s\n", root_cert, root_dir);

  SSL_CTX_set_info_callback(mytls_vars->ctx, (void (*) (const SSL *, int, int)) ssl_info_callback);
  
  if (SSL_CTX_load_verify_locations(mytls_vars->ctx, root_cert, root_dir) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Failed to initialize path to root certificate!\n");
      tls_funcs_process_error();

      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
      return XETLSCERTLOAD;
    }

  debug_printf(DEBUG_TLS_CORE, "Loaded root certificate %s and directory %s\n",
		root_cert, root_dir);

  if (crl_dir) {
    if (SSL_CTX_load_verify_locations(mytls_vars->ctx, NULL, crl_dir) == 0)
      {
	debug_printf(DEBUG_NORMAL, "Failed to initalize path to CRLs!\n");
	tls_funcs_process_error();
	//debug_printf(DEBUG_NORMAL, "Error : %s\n", ERR_error_string(ERR_get_error(), NULL));
	if(mytls_vars->ctx)
	  {
	    SSL_CTX_free(mytls_vars->ctx);
	    mytls_vars->ctx = NULL;
	  }
	return XETLSCERTLOAD;
      }
  }
  

  /* Do we really want to pick up the default paths? */
  if (SSL_CTX_set_default_verify_paths(mytls_vars->ctx) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Failed to initalize default paths for root certificates!\n");
      tls_funcs_process_error();

      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
      return XETLSCERTLOAD;
    }

  return XENONE;
}

/*************************************************************************
 *
 *  Use a file to load some random data.
 *
 *************************************************************************/
int tls_funcs_load_random(struct tls_vars *mytls_vars, char *random_file)
{
  char *default_random = "/dev/urandom", *file;

  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEMALLOC;

  file = random_file == NULL ? default_random : random_file;

  if (RAND_load_file(file, 1024) < 0)
    {
      tls_funcs_process_error();
      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
	  
      debug_printf(DEBUG_NORMAL, "Couldn't load random data from %s\n", file);

      return -1;
    } 

  return XENONE;
}


/***************************************************************************
 *
 * Load a user certificate in to OpenSSL so that it can be used for
 * authentication.
 *
 ***************************************************************************/
int tls_funcs_load_user_cert(struct tls_vars *mytls_vars, 
			     char *client_cert, char *key_file, char *password)
{
  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((client_cert != NULL), "client_cert != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((key_file != NULL), "key_file != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((password != NULL), "password != NULL", FALSE))
    return XEMALLOC;

  SSL_CTX_set_default_passwd_cb_userdata(mytls_vars->ctx, password);
  SSL_CTX_set_default_passwd_cb(mytls_vars->ctx, return_password);

  if (SSL_CTX_use_certificate_file(mytls_vars->ctx, client_cert, 
				   SSL_FILETYPE_ASN1) != 1 &&
      SSL_CTX_use_certificate_file(mytls_vars->ctx, client_cert, 
				   SSL_FILETYPE_PEM) != 1 )
    {
      debug_printf(DEBUG_NORMAL, "Couldn't load client certificate data!\n");
      tls_funcs_process_error();
      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
      return XETLSCERTLOAD;
    }

  debug_printf(DEBUG_TLS_CORE, "Loading user Private Key from %s...\n", key_file);
  
  // XXX Add back support for smart card based TLS.
  /*
  if (userdata->sc.engine_id)
    {
      EVP_PKEY *pkey;
      debug_printf(DEBUG_CONFIG, "Loading user Private Key with id %s from %s...\n", userdata->sc.key_id, userdata->sc.engine_id);
      set_smartcard_pin(password);
      pkey = ENGINE_load_private_key(mytls_vars->engine, userdata->sc.key_id,
		      UI_noninteractive(), NULL);
      SSL_CTX_use_PrivateKey(mytls_vars->ctx, pkey);
      //EVP_PKEY_free(pkey);
    }
    else  */
  if (SSL_CTX_use_PrivateKey_file(mytls_vars->ctx, key_file, 
				  SSL_FILETYPE_PEM) != 1 &&
      SSL_CTX_use_PrivateKey_file(mytls_vars->ctx, key_file, 
				  SSL_FILETYPE_ASN1) != 1) 
    {
      tls_funcs_process_error();
      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
      debug_printf(DEBUG_NORMAL, "Couldn't load client private key!\n");
      return XETLSCERTLOAD;
    }

  if (!SSL_CTX_check_private_key(mytls_vars->ctx))
    {
      debug_printf(DEBUG_NORMAL, "Private key isn't valid!\n");
      tls_funcs_process_error();
      return XETLSCERTLOAD;
    }

  SSL_CTX_set_options(mytls_vars->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		      SSL_OP_SINGLE_DH_USE);

  if (mytls_vars->verify_cert == TRUE)
    {
      SSL_CTX_set_verify(mytls_vars->ctx, SSL_VERIFY_PEER | 
			 SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
  else
    {
      SSL_CTX_set_verify(mytls_vars->ctx, SSL_VERIFY_NONE |
			 SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }

  return XENONE;
}

/* TLS PRF from rfc2246 pages 11-12 */
int
ossl_tls_funcs_PRF(uint8_t *secret, int secret_len, uint8_t *label, 
		   int label_len, uint8_t *seed, int seed_len, uint8_t *output,
		   int outlen)
{
  int retVal = 0;
  int L_S1, L_S2;
  uint8_t *S1, *S2;
  uint8_t *P_MD5_buf, *P_SHA1_buf;
  uint8_t *P_seed;
  int P_seed_len;
  uint8_t A_MD5[MD5_DIGEST_LENGTH];
  uint8_t A_SHA1[SHA_DIGEST_LENGTH];
  int MD5_iterations, SHA1_iterations;
  int i, hashed_len;
  const EVP_MD *hash;
  HMAC_CTX ctx;

  TRACE

  if (!xsup_assert((secret != NULL), "secret != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((label != NULL), "label != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((seed != NULL), "seed != NULL", FALSE))
    return XEMALLOC;

  if (!xsup_assert((output != NULL), "output != NULL", FALSE))
    return XEMALLOC;

  /* determine the length of "half" the secret */
  if (secret_len % 2 == 0) {
    L_S1 = secret_len / 2;
  }
  else {
    L_S1 = secret_len / 2 + 1;
  }
  L_S2 = L_S1;
  S1 = secret; /* first L_S1 bytes of secret */
  S2 = secret + secret_len - L_S2;  /* last L_S2 bytes of secret */
  MD5_iterations = outlen / MD5_DIGEST_LENGTH;
  /* if there is anything left over, iterate 1 more time */
  MD5_iterations = outlen % MD5_DIGEST_LENGTH == 0 ? 
    MD5_iterations : MD5_iterations + 1;
  SHA1_iterations = outlen / SHA_DIGEST_LENGTH;
  SHA1_iterations = outlen % SHA_DIGEST_LENGTH == 0 ?
    SHA1_iterations : SHA1_iterations + 1;
  P_seed_len = label_len + seed_len;
  P_seed = (uint8_t *)Malloc(sizeof(uint8_t) * P_seed_len);
  if (P_seed == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of P_seed in tls_funcs_PRF().\n");
	  ipc_events_malloc_failed(NULL);
      return XEMALLOC;
    }

  memcpy(P_seed, label, label_len);
  memcpy(P_seed+label_len, seed, seed_len);
  P_MD5_buf = (uint8_t *)Malloc(sizeof(uint8_t) * 
			       MD5_iterations  * MD5_DIGEST_LENGTH);
  if (P_MD5_buf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of P_MD5_buf in tls_funcs_PRF().\n");
	  ipc_events_malloc_failed(NULL);
      FREE(P_seed);
      return XEMALLOC;
    }

  P_SHA1_buf = (uint8_t *)Malloc(sizeof(uint8_t) *
				SHA1_iterations * SHA_DIGEST_LENGTH);
  if (P_SHA1_buf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of P_SHA1_buf in tls_funcs_PRF().\n");
	  ipc_events_malloc_failed(NULL);
      FREE(P_seed);
      FREE(P_MD5_buf);
      return XEMALLOC;
    }

  /* P_MD5 */
  hash = EVP_md5();
  /* Initialize A_MD5 */
  HMAC(hash, S1, L_S1, P_seed, P_seed_len, A_MD5, (u_int *) &hashed_len);

  for (i = 0; i < MD5_iterations; i++) {
    HMAC_Init(&ctx, S1, L_S1, hash);
    HMAC_Update(&ctx, A_MD5, MD5_DIGEST_LENGTH);
    HMAC_Update(&ctx, P_seed, P_seed_len);
    HMAC_Final(&ctx, P_MD5_buf + i*(MD5_DIGEST_LENGTH), (u_int *) &hashed_len);
    HMAC_cleanup(&ctx);
    HMAC(hash, S1, L_S1, A_MD5, MD5_DIGEST_LENGTH,
	 A_MD5, (u_int *) &hashed_len);
  }
    

  /* do P_SHA1 */
  hash = EVP_sha1();
  /* Initialize A_SHA1 */
  HMAC(hash, S2, L_S2, P_seed, P_seed_len, A_SHA1, (u_int *) &hashed_len);

  for (i = 0; i < SHA1_iterations; i++) {
    HMAC_Init(&ctx, S2, L_S2, hash);
    HMAC_Update(&ctx, A_SHA1, SHA_DIGEST_LENGTH);
    HMAC_Update(&ctx, P_seed, P_seed_len);
    HMAC_Final(&ctx, P_SHA1_buf + i*(SHA_DIGEST_LENGTH), (u_int *) &hashed_len);
    HMAC_cleanup(&ctx);
    HMAC(hash, S2, L_S2, A_SHA1, SHA_DIGEST_LENGTH,
	 A_SHA1, (u_int *) &hashed_len);
  }
  /* XOR Them for the answer */
  for (i = 0; i < outlen; i++) {
    *(output + i) = P_MD5_buf[i] ^ P_SHA1_buf[i];
  }

  FREE(P_seed);
  FREE(P_MD5_buf);
  FREE(P_SHA1_buf);

  return retVal;
}

/* smartcard support */

#define OPENSC_ENGINE_SO_PATH "/usr/lib/opensc/engine_opensc.so"
#define OPENSC_ENGINE_ID      "opensc"

/* This function 
 * - loads OpenSSL's "dynamic" engine
 * - executes all the commands given in the pre array of strings
 *   These commands will usually load the shared object, do some 
 *   initialization and add the engine to OpenSSL's internal list of 
 *   Engines
 */
#ifndef WINDOWS
int engine_load_dynamic(char *pre[])
{
  char *engine_id = "dynamic";
  int rc;
  ENGINE *e;
  ENGINE_load_dynamic();
  e = ENGINE_by_id(engine_id);
  if(!e)
    {
      printf("can't find engine %s\n", engine_id);
      goto err;
    }
  while(pre && pre[0])
    {
      /*printf("\"%s\" \"%s\"\n", pre[0], pre[1]);*/
      rc = ENGINE_ctrl_cmd_string(e, pre[0], pre[1], 0);
      if(rc == 0)
        {
          printf("ctrl cmd_string failed: %s %s\n", 
					pre[0], pre[1]);
  	  goto err_pre;
        }
      pre += 2;
    }
  /* Free the reference to the "dynamic" engine
   * The OpenSC engine can still be looked up using 
   * ENGINE_by_id() */

  ENGINE_free(e);
  return 1;
err_pre:
  ENGINE_free(e);
err:
  ENGINE_cleanup();
  return 0;
}
#endif  // WINDOWS

/* This function
 *  - makes the opensc engine available to OpenSSL
 */
#ifndef WINDOWS
int engine_load_dynamic_opensc(struct smartcard *sc)
{
  char *pre_cmd[] = 
    {
      "SO_PATH", sc->opensc_so_path,
      "ID", OPENSC_ENGINE_ID,
      "LIST_ADD", "1",
      "LOAD", NULL,
      NULL, NULL
    };

  if (xsup_assert((sc != NULL), "sc != NULL", FALSE))
    return XEMALLOC;

  debug_printf(DEBUG_NORMAL, "Loading opensc engine.\n");
  if(!sc->opensc_so_path)
    {
      /* use the default value */
      sc->opensc_so_path = OPENSC_ENGINE_SO_PATH;
    }

  return engine_load_dynamic(pre_cmd);
}
#endif  // WINDOWS

/* provide a UI_METHOD that makes it possible to use a string as the
 * smartcard PIN */
char *smartcard_pin = NULL;

void set_smartcard_pin(char *pin)
{
  smartcard_pin = pin;
}

void unset_smartcard_pin()
{
  set_smartcard_pin(NULL);
}

int read_string(UI *ui, UI_STRING *uis)
{
  if(smartcard_pin)
    {
      UI_set_result(ui, uis, smartcard_pin);
      return 1;
    }
  return 0;
}

UI_METHOD *UI_noninteractive(void)
{
  UI_METHOD *ui_method;
  ui_method = UI_create_method("ui_noninteractive");
  UI_method_set_reader(ui_method, read_string);
  return ui_method;
}

/**********************************************************************
 *
 *  Generate a key block to be used to derive keys.
 *
 **********************************************************************/
uint8_t *tls_funcs_gen_keyblock(struct tls_vars *mytls_vars, uint8_t first,
				uint8_t *sesskey, uint16_t sesskeylen)
{
  uint8_t seed[SSL3_RANDOM_SIZE*2];
  uint8_t *p = seed;
  uint8_t *retblock;

  TRACE

  debug_printf(DEBUG_TLS_CORE, "Generating key block!\n");

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return NULL;

  if (sesskey == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No keying material is available!  It is "
                   "unlikely that your session will work properly.\n");
      return NULL;
    }

  if (!mytls_vars->ssl)
    {
      debug_printf(DEBUG_NORMAL, "No valid SSL context found!\n");
      return NULL;
    }

  debug_printf(DEBUG_TLS_CORE, "Using session key const of : %s\n",
               sesskey);

  retblock = (uint8_t *)Malloc(TLS_SESSION_KEY_SIZE);
  if (!retblock)
  {
	  ipc_events_malloc_failed(NULL);
    return NULL;
  }

  if (first == TLS_FUNCS_CLIENT_FIRST)
    {
      memcpy(p, mytls_vars->ssl->s3->client_random, SSL3_RANDOM_SIZE);
      p+= SSL3_RANDOM_SIZE;
      memcpy(p, mytls_vars->ssl->s3->server_random, SSL3_RANDOM_SIZE);
    }
  else
    {
      memcpy(p, mytls_vars->ssl->s3->server_random, SSL3_RANDOM_SIZE);
      p+= SSL3_RANDOM_SIZE;
      memcpy(p, mytls_vars->ssl->s3->client_random, SSL3_RANDOM_SIZE);
    }

  ossl_tls_funcs_PRF(SSL_get_session(mytls_vars->ssl)->master_key,
		     SSL_get_session(mytls_vars->ssl)->master_key_length,
		     (uint8_t *) sesskey, sesskeylen, seed,
		     SSL3_RANDOM_SIZE * 2, retblock,
		     TLS_SESSION_KEY_SIZE);

  debug_printf(DEBUG_TLS_CORE, "Keyblock (%d) :\n ", TLS_SESSION_KEY_SIZE);
  debug_hex_dump(DEBUG_TLS_CORE, retblock, TLS_SESSION_KEY_SIZE);
  return retblock;
}


/************************************************************************
 *
 *  Buffer any data that will eventually need to be sent to OpenSSL.
 *
 ************************************************************************/
int tls_funcs_buffer(struct tls_vars *mytls_vars, uint8_t *newfrag,
		     uint16_t fragsize)
{
  uint32_t value32 = 0;
  uint8_t *p = NULL;

  TRACE

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
      if (mytls_vars->tlsinqueue != NULL)
        {
		if (config_get_friendly_warnings() == TRUE)
		    {
		      debug_printf(DEBUG_NORMAL, "This appears to be the first piece "
				   "of a data fragment.  However, there is already "
				   "data in the fragment buffer.  It "
				   "is likely that your authentication will fail!\n");
		    }
        }
	  else
  	    {
		  // This is the first packet, possibly in a sequence.  So create our queue.
		  if (queue_create(&mytls_vars->tlsinqueue) != 0)
		  {
			  debug_printf(DEBUG_NORMAL, "Couldn't create queue to store incoming fragments!\n");
			  return XEGENERROR;
		  }
	   }

      p++;    // Skip to the bytes that contain the value.

      memcpy(&value32, p, 4);
      value32 = ntohl(value32);
      p+=3;

      mytls_vars->expected_in = value32;
      fragsize -= 4;                  // Skip the length value.
    }
    else
	  {
		  if (queue_create(&mytls_vars->tlsinqueue) != 0)
		 {
			  debug_printf(DEBUG_NORMAL, "Couldn't create queue to store incoming message.\n");
			  return XEGENERROR;
		}
	}


  p++;  // Skip the ID byte.
  fragsize--;

  if (queue_get_size(&mytls_vars->tlsinqueue, &value32) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't determine the queue size!  We won't be able to "
		  "continue!\n");
	  return XEGENERROR;
  }

  debug_printf(DEBUG_TLS_CORE, "Total expected data size should be %d.  (0 means we don't know what to expect!) We currently"
               " have %d byte(s) of data, and will be adding %d more.\n",
               mytls_vars->expected_in, value32, fragsize);

  if (queue_enqueue(&mytls_vars->tlsinqueue, p, fragsize) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't enqueue the data fragment!\n");
	  return XEGENERROR;
  }

  if (queue_get_size(&mytls_vars->tlsinqueue, &value32) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't determine new queue size!\n");
  }
  else
  {
	if (((newfrag[0] & EAPTLS_MORE_FRAGS) != EAPTLS_MORE_FRAGS) &&
		(value32 < mytls_vars->expected_in))
    {
		debug_printf(DEBUG_NORMAL, "The server indicated that there are no "
			  "fragments remaining.  However, we only have %d of %d "
 			  "byte(s).  It is likely your authentication will fail."
			  "\n", value32, mytls_vars->expected_in);
	}
  }

  return XENONE;
}

/************************************************************************
 *
 *  Do we have something that is ready to be decrypted?
 *
 ************************************************************************/
int tls_funcs_decrypt_ready(struct tls_vars *mytls_vars)
{
	uint32_t value32 = 0;

  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return -1;

  // The buffer is full.
  if (queue_get_size(&mytls_vars->tlsinqueue, &value32) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't determine the queue depth!\n");
	  return -1;
  }

  debug_printf(DEBUG_TLS_CORE, "Expected size : %d  Current size : %d\n",
	  mytls_vars->expected_in, value32);

  if (mytls_vars->expected_in == value32)
      return value32;

  if (value32 > mytls_vars->expected_in)
	  return value32;

  // Otherwise, we aren't ready yet.
  return 0;
}

/************************************************************************
 *
 *  Decrypt data in our buffer.
 *
 * This function derived from the original Xsupplicant code written by 
 * Danielle Brevi.
 *
 ************************************************************************/
int tls_funcs_decrypt(struct tls_vars *mytls_vars, uint8_t *indata,
		      uint16_t *insize)
{
  int rc = 0;
  uint8_t *toencrypt = NULL;
  uint32_t value32 = 0;
  uint32_t expected = 0;

  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return -1;

  if (!xsup_assert((indata != NULL), "indata != NULL", FALSE))
    return -1;

  if (!xsup_assert((insize != NULL), "insize != NULL", FALSE))
    return -1;

  // Determine how much data we have to push in.
  if (queue_get_size(&mytls_vars->tlsinqueue, &value32) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't determine queue depth!\n");
	  return -1;
  }

  // Remember how much data we expect to get back.
  expected = value32;

  // Then, dequeue it all.
  if (queue_dequeue(&mytls_vars->tlsinqueue, &toencrypt, &value32) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't dequeue data!\n");
	  return -1;
  }

  // We are done with this queue.  Destroy it.
  if (queue_destroy(&mytls_vars->tlsinqueue) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Couldn't destroy queue!  We will leak memory!\n");
	  FREE(toencrypt);
	  return -1;
  }

  if (expected != value32)  // ACK!  What happened!? -- This is probably a show-stopper.
  {
	  debug_printf(DEBUG_NORMAL, "We didn't dequeue the amount of data we were expecting.  Something "
			"is *SERIOUSLY* wrong!\n");
	  FREE(toencrypt);
	  return -1;
  }

  rc = BIO_write(mytls_vars->ssl_in, toencrypt, value32);
  if (rc < 0)
    {
      debug_printf(DEBUG_NORMAL, "Failed to send data to OpenSSL for "
		   "decryption.\n");
	  FREE(toencrypt);
      return -1;
    }

  FREE(toencrypt);

  memset(indata, 0x00, (*insize));

  rc = SSL_read(mytls_vars->ssl, indata, (*insize));
  if (rc < 0)
    {
      debug_printf(DEBUG_NORMAL, "Failed to get decyrpted data from OpenSSL."
		   "\n");
      tls_funcs_process_error();
      return XEMALLOC;
    }

  (*insize) = rc;

  return XENONE;
}

/************************************************************************
 *
 *  Encrypt data in our buffer.
 *
 ************************************************************************/
int tls_funcs_encrypt(struct tls_vars *mytls_vars, uint8_t *inbuf,
		      uint16_t insize)
{
  uint8_t *encrdata = NULL;
  int rc = 0;

  TRACE

  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return -1;

  if (!xsup_assert((inbuf != NULL), "inbuf != NULL", FALSE))
    return -1;

  encrdata = Malloc(1500);
  if (encrdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store encrypted"
		   " data!\n");
	  ipc_events_malloc_failed(NULL);
      return XEMALLOC;
    }

  BIO_reset(mytls_vars->ssl_in);
  BIO_reset(mytls_vars->ssl_out);

  debug_printf(DEBUG_TLS_CORE, "inbuf (%d) :\n", insize);
  debug_hex_dump(DEBUG_TLS_CORE, inbuf, insize);

  rc = SSL_write(mytls_vars->ssl, inbuf, insize);
  if (rc <= 0)
    {
      debug_printf(DEBUG_NORMAL, "Error sending data to OpenSSL to be "
		   "encrypted.\n");
      rc = SSL_get_error(mytls_vars->ssl, rc);
      debug_printf(DEBUG_NORMAL, "Error was : ");
      switch (rc)
	{
	case SSL_ERROR_ZERO_RETURN:
	  debug_printf_nl(DEBUG_NORMAL, "zero return\n");
	  break;

	case SSL_ERROR_WANT_READ:
	  debug_printf_nl(DEBUG_NORMAL, "want read\n");
	  break;

	case SSL_ERROR_WANT_WRITE:
	  debug_printf_nl(DEBUG_NORMAL, "want write\n");
	  break;

	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	  debug_printf_nl(DEBUG_NORMAL, "want connect/accept.\n");
	  break;

	case SSL_ERROR_WANT_X509_LOOKUP:
	  debug_printf_nl(DEBUG_NORMAL, "want x509 lookup.\n");
	  break;

	case SSL_ERROR_SYSCALL:
	  debug_printf_nl(DEBUG_NORMAL, "error syscall.\n");
	  break;
	}

      tls_funcs_process_error();
      FREE(encrdata);
      return -1;
    }

  if (mytls_vars->tlsoutqueue == NULL)
  {
	  // Need to build a queue.
	  debug_printf(DEBUG_TLS_CORE, "First packet in a possible chain.  Building queue.\n");
	  if (queue_create(&mytls_vars->tlsoutqueue) != 0)
	  {
		  debug_printf(DEBUG_NORMAL, "Couldn't create queue for outgoing data!!\n");
		  return -1;
	  }
  }

  rc = BIO_read(mytls_vars->ssl_out, encrdata, 1500);
  if (rc <= 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't read encrypted data from OpenSSL!"
		   "\n");
      tls_funcs_process_error();
      FREE(encrdata);
      return -1;
    }

  if (queue_enqueue(&mytls_vars->tlsoutqueue, encrdata, rc) != 0)
  {
	  debug_printf(DEBUG_NORMAL, "Failed to enqueue %d byte(s)!\n", rc);
	  FREE(encrdata);
	  return -1;
  }

  FREE(encrdata);

  return XENONE;
}

/************************************************************************
 *
 *  Clean up any memory that we used during our TLS session.
 *
 ************************************************************************/
void tls_funcs_deinit(struct tls_vars *mytls_vars)
{
  if (!xsup_assert((mytls_vars != NULL), "mytls_vars != NULL", FALSE))
    return;

  queue_destroy(&mytls_vars->tlsinqueue);
  queue_destroy(&mytls_vars->tlsoutqueue);

  //  BIOs are freed by the SSL_free call below.  Do not try to free them any other
  //  way, or you will segfault!
  if (mytls_vars->ssl != NULL)
    {
      SSL_free(mytls_vars->ssl);
      mytls_vars->ssl = NULL;
    }

  if (mytls_vars->ctx != NULL)
    {
      SSL_CTX_free(mytls_vars->ctx);
      mytls_vars->ctx = NULL;
    }
}

int tls_funcs_get_keyblock_len(struct tls_vars *mytls_vars)
{
  EVP_CIPHER *key_material;
  EVP_MD *hash;
  int len;

  key_material = (EVP_CIPHER *)mytls_vars->ssl->enc_read_ctx->cipher;
  hash = (EVP_MD *)mytls_vars->ssl->read_hash;

  len = 0;

  len = (EVP_CIPHER_key_length(key_material) * 2);
  len += (EVP_MD_size(hash) * 2);
  len += (EVP_CIPHER_iv_length(key_material) * 2);

  debug_printf(DEBUG_TLS_CORE, "Key block length used is %d byte(s).\n",
	       len);

  return len;
}

int tls_funcs_set_hello_extension(struct tls_vars *myvars, int type,
				  void *data, int len)
{
#ifdef EAP_FAST
  return SSL_set_hello_extension(myvars->ssl, type, data, len);
#else
  return -1;
#endif
}

uint8_t *tls_funcs_get_client_random(struct tls_vars *myvars)
{
  uint8_t *temp;

  temp = Malloc(SSL3_RANDOM_SIZE);
  if (temp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store a "
		   "temporary copy of the TLS client random!\n");
	  ipc_events_malloc_failed(NULL);
      return NULL;
    }

  memcpy(temp, myvars->ssl->s3->client_random, SSL3_RANDOM_SIZE);

  return temp;
}

#ifdef EAP_FAST
static int tls_funcs_set_secret_cb(SSL *s, void *secret, int *secret_len,
				   STACK_OF(SSL_CIPHER) *peer_ciphers, 
				   SSL_CIPHER **cipher, void *arg)
{
  struct tls_vars *mytls_vars;

  mytls_vars = (struct tls_vars *)arg;

  debug_printf(DEBUG_NORMAL, "Secret CB called!\n");
  memcpy(secret, mytls_vars->derived_shared_secret, 
	 mytls_vars->derived_shared_secret_len);

  (*secret_len) = mytls_vars->derived_shared_secret_len;

  debug_printf(DEBUG_TLS_CORE, "Shared secret : \n");
  debug_hex_dump(DEBUG_TLS_CORE, secret, (*secret_len));

  return 1;
}

int tls_funcs_set_master_secret(struct tls_vars *myvars, uint8_t *new_secret,
				uint16_t length)
{
  if (!xsup_assert((myvars != NULL), "myvars != NULL", FALSE))
    return -1;

  if (!xsup_assert((new_secret != NULL), "new_secret != NULL", FALSE))
    return -1;

  myvars->derived_shared_secret = Malloc(length);
  if (myvars->derived_shared_secret == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store derived "
		   "shared secret!\n");
	  ipc_events_malloc_failed(NULL);
      return -1;
    }

  debug_printf(DEBUG_TLS_CORE, "Shared secret : \n");
  debug_hex_dump(DEBUG_TLS_CORE, new_secret, length);

  memcpy(myvars->derived_shared_secret, new_secret, length);
  myvars->derived_shared_secret_len = length;

  if (SSL_set_session_secret_cb(myvars->ssl, tls_funcs_set_secret_cb, myvars) != 1)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't set the derived secret callback "
		   "function!\n");
      return -1;
    }

  return 0;
}
#endif // EAP_FAST

#endif
