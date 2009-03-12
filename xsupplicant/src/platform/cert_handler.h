/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cert_handler.h
 *
 * \author chris@open1x.org
 **/
#ifndef _CERT_HANDLER_H_
#define _CERT_HANDLER_H_

typedef struct _cert_enum {
	char *storetype;
	char *certname;
	char *friendlyname;
	char *issuer;
	char *commonname;
	char *location;
	uint16_t month;
	uint16_t day;
	uint16_t year;
} cert_enum;

typedef struct _cert_info {
	char *C;		///< The Country Field in the Certificate
	char *S;		///< The State Field in the Certificate
	char *L;		///< The Location Field in the Certificate
	char *O;		///< The Organization Field in the Certificate
	char *OU;		///< The Organizational Unit Field in the Certificate
	char *CN;		///< The Common Name Field in the Certificate
} cert_info;

int cert_handler_init();	///< Do whatever is needed to set up the certificate store(s).
void cert_handler_deinit();	///< Do whatever is needed to clean up the certificate store(s).
int cert_handler_num_root_ca_certs();	///< Determine the number of root CA certs we are interested in.
int cert_handler_enum_root_ca_certs(int *, cert_enum **);	///< Enumerate the certificates, and return them in cert_enum.
int cert_handler_get_info_from_store(char *, char *, cert_info *);	///< Search for a certificate in a store, and return it's attribute(s).
void cert_handler_free_cert_info(cert_info *);	///< Free the memory used by the members of the cert_info struct.
void cert_handler_free_cert_enum(int numcas, cert_enum ** cas);
int cert_handler_num_user_certs();
int cert_handler_enum_user_certs(int *numcer, cert_enum ** cer);
int cert_handler_add_cert_to_store(char *path_to_cert);

#endif				// _CERT_HANDLER_H_
