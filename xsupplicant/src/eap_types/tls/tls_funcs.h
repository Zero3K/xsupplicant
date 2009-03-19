/**
 * TLS En/Decrypt Function header
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file tls_funcs.h
 * \Author chris@open1x.org
 **/

#ifndef _TLS_FUNCS_
#define _TLS_FUNCS_

#define TLS_FUNCS_CLIENT_FIRST   1
#define TLS_FUNCS_SERVER_FIRST   2

// EAP-FAST Session Ticket TLS Extension
#define FAST_SESSION_TICKET          35

#ifdef WINDOWS
#define EWOULDBLOCK 0xff
#endif

#include "liblist/queue.h"

struct tls_vars {
#ifndef USE_GNUTLS
	SSL_CTX *ctx;		// Our OpenSSL context.
	SSL *ssl;
	ENGINE *engine;
	BIO *ssl_in, *ssl_out;
#else
	gnutls_session_t session;	// TLS session data.
	gnutls_certificate_credentials_t creds;
#endif

#ifdef WINDOWS
	unsigned long hcProv;
	uint32_t pdwKeyspec;
	uint32_t pfCallerFreeProv;
#endif				// WINDOWS

	int resume;		// Should we attempt to resume this connection?
	int resumable;		// Is this session in a resumable state?

	uint8_t cnexact;	// Should be the same as the cnexact value for
	// TTLS or PEAP, depending on which one we are
	// using.

	char *cncheck;
	queue_data *tlsinqueue;
	uint16_t expected_in;	// The number of bytes that we expect to have in our "in" queue when we are done.
	uint16_t in_so_far;	// The number of bytes we have taken in so far.
	queue_data *tlsoutqueue;
	uint8_t *sessionkeyconst;
	uint32_t sessionkeylen;
	void *phase2data;
	uint8_t send_ack;
	uint8_t handshake_done;
	uint8_t verify_cert;
	uint8_t certs_loaded;
	uint8_t *keyblock;
	uint8_t last_eap_type;
	uint8_t *derived_shared_secret;
	uint16_t derived_shared_secret_len;
	uint8_t method_in_use;
	char *cipher_list;
	uint8_t *pac;		// Used in EAP-FAST  (Reference pointer.  DO NOT FREE!)
	uint16_t pac_length;	// Used in EAP-FAST
};

int tls_funcs_init(struct tls_vars *, uint8_t);
int tls_funcs_load_root_certs(struct tls_vars *, char *, char *, char *);
int tls_funcs_load_user_cert(struct tls_vars *, char *, char *, char *);
uint8_t tls_funcs_process(struct tls_vars *, uint8_t *);
int tls_funcs_get_packet(struct tls_vars *, int, uint8_t **, uint16_t *);
int tls_funcs_encrypt(struct tls_vars *, uint8_t *, uint16_t);
uint8_t *tls_funcs_gen_keyblock(struct tls_vars *, uint8_t, uint8_t *,
				uint16_t);
int tls_funcs_buffer(struct tls_vars *, uint8_t *, uint16_t);
int tls_funcs_decrypt_ready(struct tls_vars *);
int tls_funcs_decrypt(struct tls_vars *, uint8_t **, uint16_t *);
int tls_funcs_load_random(struct tls_vars *, char *);
void tls_funcs_deinit(struct tls_vars *);
int tls_funcs_get_keyblock_len(struct tls_vars *);
int tls_funcs_set_hello_extension(struct tls_vars *, int, void *, int);
uint8_t *tls_funcs_get_client_random(struct tls_vars *);
int tls_funcs_set_master_secret(struct tls_vars *, uint8_t *, uint16_t);
int tls_funcs_build_new_session(struct tls_vars *);
uint32_t tls_funcs_data_pending(struct tls_vars *);
void tls_funcs_set_cipher_list(struct tls_vars *, char *cipherlist);

int tls_funcs_load_engine(struct tls_vars *, struct smartcard *);

#endif
