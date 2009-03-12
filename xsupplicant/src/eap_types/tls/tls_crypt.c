/**
 * TLS En/Decrypt Function implementations
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file tls_crypt.c
 *
 * \Author Chris.Hessing@utah.edu
 *
 * $Id: tls_crypt.c,v 1.24 2006/12/26 18:38:55 chessing Exp $
 * $Date: 2006/12/26 18:38:55 $
 * $Log: tls_crypt.c,v $
 * Revision 1.24  2006/12/26 18:38:55  chessing
 * Fixed assertion from bug id 1601394 to display an error message instead.  Need to figure out the rest.
 *
 * Revision 1.23  2006/10/28 02:20:50  chessing
 * Patches from Carsten Grohmann to fix some memory leaks, catch some pointers that may potentially be NULL and handle them correctly.
 *
 * Revision 1.22  2006/08/25 23:37:18  chessing
 * Numerous patches that have come in over the last month or two.
 *
 * Revision 1.21  2006/06/05 01:40:41  chessing
 * Various small cleanups.
 *
 * Revision 1.20  2006/06/01 22:49:50  galimorerpg
 * Converted all instances of u_char to uint8_t
 * Fixed a bad #include in the generic frame handler.
 *
 * Revision 1.19  2006/06/01 20:46:25  chessing
 * More patches from Carsten Grohmann.
 *
 * Revision 1.18  2006/05/29 04:17:58  chessing
 * Fixes for some memory leaks.
 *
 * Revision 1.17  2006/04/25 01:17:44  chessing
 * LOTS of code cleanups, new error checking/debugging code added, and other misc. fixes/changes.
 *
 * Revision 1.16  2005/10/17 03:56:54  chessing
 * Updates to the libxsupconfig library.  It no longer relies on other source from the main tree, so it can be used safely in other code with problems.
 *
 * Revision 1.15  2005/10/14 02:26:18  shaftoe
 * - cleanup gcc 4 warnings
 * - (re)add support for a pid in the form of /var/run/xsupplicant.<iface>.pid
 *
 * -- Eric Evans <eevans@sym-link.com>
 *
 * Revision 1.14  2005/08/09 01:39:18  chessing
 * Cleaned out old commit notes from the released version.  Added a few small features including the ability to disable the friendly warnings that are spit out.  (Such as the warning that is displayed when keys aren't rotated after 10 minutes.)  We should also be able to start when the interface is down.  Last, but not least, we can handle empty network configs.  (This may be useful for situations where there isn't a good reason to have a default network defined.)
 *
 */

#include <string.h>
#include <strings.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <netinet/in.h>

#include "xsupconfig.h"
#include "profile.h"
#include "eap.h"
#include "eaptls.h"
#include "tls_funcs.h"
#include "../../xsup_common.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

uint8_t *tls_crypt_gen_keyblock(struct generic_eap_data * thisint,
				char *sesskey, int sesskeylen)
{
	uint8_t seed[SSL3_RANDOM_SIZE * 2];
	uint8_t *p = seed;
	struct tls_vars *mytls_vars;
	uint8_t *retblock;

	debug_printf(DEBUG_EVERYTHING, "Generating key block!\n");

	if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
		return NULL;

	if (sesskey == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "No keying material is available!  It is "
			     "unlikely that your session will work properly.\n");
		return NULL;
	}

	mytls_vars = (struct tls_vars *)thisint->eap_data;

	if (!mytls_vars->ssl) {
		debug_printf(DEBUG_NORMAL, "No valid SSL context found!\n");
		return NULL;
	}

	debug_printf(DEBUG_EVERYTHING, "Using session key const of : %s\n",
		     sesskey);

	retblock = (uint8_t *) malloc(TLS_SESSION_KEY_SIZE);
	if (!retblock)
		return NULL;

	memcpy(p, mytls_vars->ssl->s3->client_random, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;
	memcpy(p, mytls_vars->ssl->s3->server_random, SSL3_RANDOM_SIZE);
	tls_funcs_PRF(SSL_get_session(mytls_vars->ssl)->master_key,
		      SSL_get_session(mytls_vars->ssl)->master_key_length,
		      (uint8_t *) sesskey, sesskeylen, seed,
		      SSL3_RANDOM_SIZE * 2, retblock, TLS_SESSION_KEY_SIZE);

	return retblock;
}

/* This function written by Danielle Brevi  */
int tls_crypt_decrypt(struct generic_eap_data *thisint, uint8_t * in_data,
		      int in_size, uint8_t * out_data, int *out_size)
{
	struct tls_vars *mytls_vars;
	int rc = 0;

	if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((in_data != NULL), "in_data != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out_data != NULL), "out_data != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out_size != NULL), "out_size != NULL", FALSE))
		return XEMALLOC;

	mytls_vars = (struct tls_vars *)thisint->eap_data;

	if (BIO_reset(mytls_vars->ssl_in) <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt.c, BIO_reset(mytls_vars->ssl_in) failed.\n");
		tls_funcs_process_error();

		return XETLSCRYPTFAIL;
	}

	rc = BIO_write(mytls_vars->ssl_in, in_data, in_size);

	if (BIO_reset(mytls_vars->ssl_out) <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt.c, BIO_reset(mytls_vars->ssl_out) failed.\n");
		tls_funcs_process_error();

		return XETLSCRYPTFAIL;
	}

	rc = SSL_read(mytls_vars->ssl, out_data, 1000);
	if (rc <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt.c, SSL_read(mytls_vars->ssl, out_data, 1000) failed.\n");
		tls_funcs_process_error();

		return XETLSCRYPTFAIL;
	}

	*out_size = rc;

	return XENONE;
}

int tls_crypt_encrypt(struct generic_eap_data *thisint, uint8_t * in_data,
		      int in_size, uint8_t * out_data, int *out_size)
{
	struct tls_vars *mytls_vars;
	int rc = 0;
	uint8_t *p = NULL;
	int to_send_size = 0;
	uint64_t length;

	if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((in_data != NULL), "in_data != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out_data != NULL), "out_data != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((thisint->eap_data != NULL), "thisint->eap_data != NULL", FALSE))
		return XEMALLOC;

	mytls_vars = (struct tls_vars *)thisint->eap_data;

	/* XXX We need to modify this, to read more when there is more to be returned. */
	p = (uint8_t *) Malloc(1000);
	if (p == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Error with malloc of \"p\" in tls_crypt_encrypt().\n");
		return XEMALLOC;
	}

	if (BIO_reset(mytls_vars->ssl_in) <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt.c, BIO_reset(mytls_vars->ssl_in) failed.\n");
		tls_funcs_process_error();
		FREE(p);
		return -1;
	}

	if (BIO_reset(mytls_vars->ssl_out) <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt.c, BIO_reset(mytls_vars->ssl_out) failed.\n");
		tls_funcs_process_error();
		FREE(p);
		return -1;
	}

	rc = SSL_write(mytls_vars->ssl, in_data, in_size);
	if (rc <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt.c, SSL_write in encrypt failed!\n");
		tls_funcs_process_error();
		FREE(p);
		return -1;
	}

	rc = BIO_read(mytls_vars->ssl_out, p, 1000);	/* Allow largest possible read. */
	if (rc <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt.c, BIO_read in encrypt failed!\n");
		tls_funcs_process_error();
		FREE(p)
		    return -1;
	}

	to_send_size = rc;

	out_data[0] = EAPTLS_LENGTH_INCL;	// No more to send.
	length = ntohl(to_send_size + 5);
	memcpy(&out_data[1], &length, 4);
	memcpy(&out_data[5], p, to_send_size);

	*out_size = to_send_size + 5;

	FREE(p);
	return XENONE;
}

int tls_crypt_encrypt_nolen(struct generic_eap_data *thisint, uint8_t * in_data,
			    int in_size, uint8_t * out_data, int *out_size)
{
	struct tls_vars *mytls_vars;
	int rc = 0;
	uint8_t *p = NULL;
	int to_send_size = 0;

	if (!xsup_assert((thisint != NULL), "thisint != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert
	    ((thisint->eap_data != NULL), "thisint->eap_data != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((in_data != NULL), "in_data != NULL", FALSE))
		return XEMALLOC;

	if (!xsup_assert((out_data != NULL), "out_data != NULL", FALSE))
		return XEMALLOC;

	mytls_vars = (struct tls_vars *)thisint->eap_data;

	/* We need to modify this, to read more when there is more to be returned. */
	p = (uint8_t *) Malloc(1000);
	if (p == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Error with malloc of \"p\" in tls_crypt_encrypt().\n");
		return XEMALLOC;
	}

	if (BIO_reset(mytls_vars->ssl_in) <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt (nolen), BIO_reset failed in encrypt!\n");
		tls_funcs_process_error();
		FREE(p);
		return -1;
	}

	if (BIO_reset(mytls_vars->ssl_out) <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt (nolen), BIO_reset (2) failed in encrypt!\n");
		tls_funcs_process_error();
		FREE(p);
		return -1;
	}

	rc = SSL_write(mytls_vars->ssl, in_data, in_size);
	if (rc <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt (nolen), SSL_write failed in encrypt!\n");
		tls_funcs_process_error();
	}

	rc = BIO_read(mytls_vars->ssl_out, p, 1000);	// Allow largest possible read.
	if (rc <= 0) {
		debug_printf(DEBUG_NORMAL,
			     "In tls_crypt (nolen), BIO_read failed in encrypt!\n");
		tls_funcs_process_error();
		FREE(p);
		return -1;
	}

	to_send_size = rc;

	out_data[0] = 0x00;	// No more to send.
	memcpy(&out_data[1], p, to_send_size);

	*out_size = to_send_size + 1;
	FREE(p);
	return XENONE;
}
