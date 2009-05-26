/**
 * Darwin certificate handler
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file darwin_cert_handler.c
 *
 * \author chris@open1x.org
 *
 * $Id: darwin_cert_handler.c,v 1.1 2008/01/30 20:46:41 galimorerpg Exp $
 * $Date: 2008/01/30 20:46:41 $
 **/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "xsup_common.h"
#include "src/xsup_err.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "src/context.h"
#include "src/xsup_debug.h"
#include "../cert_handler.h"

/**
 * \brief Initialize the Darwin certificate store.
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
 * \brief Look for a container value (such as "OU=") and return the value that it is
 *        set to.
 *
 * @param[in] pszSubjectString   The string that we want to search for the data.
 * @param[in] container   The container value that we are looking for. (Such as "OU=")
 *
 * \retval NULL on error
 * \retval ptr to a string that contains the value.
 **/
static char *cert_handler_get_container_value(char *pszSubjectString,
					      char *container)
{
	char *temp = NULL;
	char *end = NULL;
	char *result = NULL;

	temp = Malloc(strlen(pszSubjectString) + 1);
	if (temp == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store temporary work buffer!\n");
		return NULL;
	}

	end = strstr(pszSubjectString, container);
	if (end == NULL)
		return NULL;	// Couldn't find what we were looking for.

	strcpy(temp, end);
//      temp += strlen(container);  // Skip the container value

	if (temp[strlen(container)] == '"') {
		// It is a quoted value.
		end = strstr(&temp[strlen(container)], "\"");
		end[0] = 0x00;	// Set it to a NULL.
	} else {
		end = strstr(&temp[strlen(container)], ",");
		if (end != NULL)	// If we are already at the end, we will return NULL. So ignore it.
			end[0] = 0x00;	// Set it to a NULL.
	}

	result = Malloc(strlen(temp));
	if (result == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't allocate memory to store final result!  (in %s())\n",
			     __FUNCTION__);
		return NULL;
	}

	strcpy(result, &temp[strlen(container)]);
	FREE(temp);

	return result;
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
int cert_handler_get_info(PCCERT_CONTEXT pCertContext, cert_info * certinfo)
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
int cert_handler_get_info_from_name(char *certname, cert_info * certinfo)
{
	return -1;
}

/**
 * \brief Free all of the fields that are included in a cert_info structure.
 *
 * @param[in] cinfo   A pointer to the structure that we want to free the members of.
 **/
void cert_handler_free_cert_info(cert_info * cinfo)
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
void cert_handler_free_cert_enum(int numcas, cert_enum ** cas)
{
	cert_enum *casa = NULL;
	int i = 0;

	casa = (*cas);

	for (i = 0; i < numcas; i++) {
		if (casa[i].certname != NULL)
			free(casa[i].certname);
		if (casa[i].friendlyname != NULL)
			free(casa[i].friendlyname);
		if (casa[i].issuer != NULL)
			free(casa[i].issuer);
	}

	FREE((*cas));
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
int cert_handler_enum_root_ca_certs(int *numcas, cert_enum ** cas)
{
	return -1;
}

int cert_handler_get_info_from_store(char *storetype, char *location,
				     cert_info * certinfo)
{
	return 0;
}

int cert_handler_add_cert_to_store(char *path_to_cert)
{
	return 0;
}

/**
 * \brief Return the number of user certificates in our store.
 *
 * \retval -1 on error
 * \retval >=0 is the number of certificates that will be in the list.
 **/
int cert_handler_num_user_certs()
{
#warning Implement!
	return 0;
}

int cert_handler_enum_user_certs(int *numcer, cert_enum ** cer)
{
#warning Implement!
	return -1;
}
