/**
 * Linux certificate handler
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file lin_cert_handler.c
 *
 * \author chris@open1x.org
 *
 * $Id: lin_cert_handler.c,v 1.1 2008/01/30 20:46:41 galimorerpg Exp $
 * $Date: 2008/01/30 20:46:41 $
 **/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "src/xsup_common.h"
#include "src/xsup_err.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/context.h"
#include "src/xsup_debug.h"
#include "../cert_handler.h"

/**
 * \brief Initialize the Linux certificate store.
 *
 * \retval XENONE on success
 * \retval XEGENERROR on failure
 **/
int cert_handler_init()
{
  // Nothing to do here.
	return XENONE;
}

/**
 * \brief Close the certificate store handle.
 **/
void cert_handler_deinit()
{
}

/**
 * \brief Parse the ASN.1 Encoded Subject information, and pull out things like the CN, 
 *        OU, O, etc.
 *
 * @param[in] pCertContext   A pointer to the certificate context for the certificate we want
 *                           to gather the data for.
 * @param[in,out] certinfo   A pointer to the structure that we will populate with the 
 *                           certificate information.
 *
 * \note Not all of the values listed in the structure will be present in all of the 
 *       certificates that we are looking at.   The caller should be prepared to deal
 *       with some (or perhaps all) of the fields being NULL.
 *
 * \retval 0 on success
 * \retval -1 on failure
 **/
#if 0
int cert_handler_get_info(PCCERT_CONTEXT  pCertContext, cert_info *certinfo)
{
  return -1;
}
#endif

/**
 * \brief Given the certificate name, get the information about it.
 *
 * @param[in] certname   The certificate's "friendly" name that we want to use.
 * @param[in,out] certinfo   A pointer to the structure that will contain all
 *                           of the certificate information requested.
 *
 * \retval 0 on success
 * \retval -1 on error
 **/
int cert_handler_get_info_from_name(char *certname, cert_info *certinfo)
{
  return -1;
}

/**
 * \brief Free all of the fields that are included in a cert_info structure.
 *
 * @param[in] cinfo   A pointer to the structure that we want to free the members of.
 **/
void cert_handler_free_cert_info(cert_info *cinfo)
{
	FREE(cinfo->C);
	FREE(cinfo->CN);
	FREE(cinfo->O);
	FREE(cinfo->L);
	FREE(cinfo->OU);
	FREE(cinfo->S);
}

/**
 * \brief Determine the number of root CA certificates are in the store that
 *        can be used for server authentication.
 *
 * \retval -1 on error
 * \retval >=0 is the number of certificates that will be in the list.
 **/
int cert_handler_num_root_ca_certs()
{
  return -1;
}

/**
 * \brief Free the memory that was allocated to store the certificate enumeration.
 *
 * @param[in] numcas   The number of CAs that are represented in the enumeration.
 * @param[in] cas   The array of CA names.
 **/
void cert_handler_free_cert_enum(int numcas, cert_enum **cas)
{
	cert_enum *casa = NULL;
	int i = 0;

	casa = (*cas);

	for (i = 0; i < numcas; i++)
	{
		if (casa[i].certname != NULL) free(casa[i].certname);
                if (casa[i].friendlyname != NULL) free(casa[i].friendlyname);
                if (casa[i].issuer != NULL) free(casa[i].issuer);
	}

	free((*cas));
	(*cas) = NULL;
}

/**
 * \brief Enumerate root CA certificates that are in the store that
 *        can be used for server authentication.
 *
 * @param[in] numcas   An integer the specifies the number of CA certificates we are expected to
 *                     return.  This value should come from the cert_handler_num_root_ca_certs().
 *                     On return, this will contain the number of certificates that are actually in
 *                     the array.
 *
 * @param[in,out] cas   An array of certificates that contains the number of certificates defined
 *                      by numcas.
 *
 * \retval -1 on error
 * \retval 0 on success
 **/
int cert_handler_enum_root_ca_certs(int *numcas, cert_enum **cas)
{
  return -1;
}

int cert_handler_get_info_from_store(char *storetype, char *location, cert_info *certinfo) 
{
  return 0;
}

int cert_handler_add_cert_to_store(char *path_to_cert)
{
  return 0;
}
