/**
 * Windows certificate handler
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file win_cert_handler.c
 *
 * \author chris@open1x.org
 **/

#include <windows.h>
#include <wincrypt.h>

#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef WINDOWS
#include "../../stdintwin.h"
#endif

#include "../../xsup_err.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "../../xsup_debug.h"
#include "../cert_handler.h"
#include "../../ipc_events_index.h"
#include "../../eap_types/tls/tls_funcs.h"
#include "cardif_windows.h"

//  #define CHECK_EKU   1      // Only show root certs with the server EKUs.  (Same as Windows XP defaults.)

HCERTSTORE hCertStore = NULL;
HCERTSTORE hCertUserStore = NULL;

/**
 * \brief Initialize the Windows certificate store.
 *
 * \retval XENONE on success
 * \retval XEGENERROR on failure
 **/
int cert_handler_init()
{
	debug_printf(DEBUG_CERTS, "Starting Certificate Services...\n");
	hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
								(HCRYPTPROV_LEGACY)NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
	if (hCertStore == NULL)
	{
		return XEGENERROR;
	}

	return XENONE;
}

/**
 * \brief Initialize the Windows user certificate store.  (If impersonation is required it should be done
 *			before this call!)
 *
 * \retval XENONE on success
 * \retval XEGENERROR on failure
 **/
int cert_handler_user_init()
{
	debug_printf(DEBUG_CERTS, "Starting User Certificate Services...\n");
	hCertUserStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
								(HCRYPTPROV_LEGACY)NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
	if (hCertUserStore == NULL)
	{
		return XEGENERROR;
	}

	return XENONE;
}

/**
 * \brief Close the certificate store handle.
 **/
void cert_handler_user_deinit()
{
	debug_printf(DEBUG_CERTS, "Killing user certificate services...\n");
	if (hCertUserStore != NULL) CertCloseStore(hCertUserStore, 0);
	hCertUserStore = NULL;
}

/**
 * \brief Close the certificate store handle.
 **/
void cert_handler_deinit()
{
	debug_printf(DEBUG_CERTS, "Killing certificate services...\n");
	if (hCertStore != NULL) CertCloseStore(hCertStore, 0);
	hCertStore = NULL;
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
static char *cert_handler_get_container_value(char *pszSubjectString, char *container)
{
	char *temp = NULL;
	char *end = NULL;
	char *result = NULL;

	temp = Malloc(strlen(pszSubjectString)+1);
	if (temp == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store temporary work buffer!\n");
		return NULL;
	}

	end = strstr(pszSubjectString, container);
	if (end == NULL) return NULL;                   // Couldn't find what we were looking for.

	strcpy(temp, end);

	if (temp[strlen(container)] == '"')
	{
		// It is a quoted value.
		end = strstr(&temp[strlen(container)], "\"");
		end[0] = 0x00;   // Set it to a NULL.
	}
	else
	{
		end = strstr(&temp[strlen(container)], ",");
		if (end != NULL)         // If we are already at the end, we will return NULL. So ignore it.
			end[0] = 0x00;   // Set it to a NULL.
	}

	result = Malloc(strlen(temp));
	if (result == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store final result!  (in %s())\n",
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
int cert_handler_get_info(PCCERT_CONTEXT  pCertContext, cert_info *certinfo)
{
	char pszSubjectString[1024];
	char *temp;

	if (CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_X500_NAME_STR, pszSubjectString, 1024) > 0)
	{
		certinfo->C = cert_handler_get_container_value(pszSubjectString, "C=");

		certinfo->S = cert_handler_get_container_value(pszSubjectString, "S=");

		certinfo->L = cert_handler_get_container_value(pszSubjectString, "L=");

		certinfo->O = cert_handler_get_container_value(pszSubjectString, "O=");

		certinfo->OU = cert_handler_get_container_value(pszSubjectString, "OU=");

		certinfo->CN = cert_handler_get_container_value(pszSubjectString, "CN=");

		return 0;
	}

	return -1;
}

PCCERT_CONTEXT win_cert_handler_get_from_win_store(char *storetype, char *location)
{
	PCCERT_CONTEXT  pCertContext = NULL;
	CRYPT_HASH_BLOB toFindData;
	uint8_t *hashData = NULL;

	if (storetype == NULL) return NULL;
	if (location == NULL) return NULL;

	str2hex(location, &hashData, &toFindData.cbData);
	toFindData.pbData = hashData;

	pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &toFindData, NULL);
	FREE(hashData);  // Clean up the memory no matter what.
	
	if (pCertContext == NULL)
	{ 
		debug_printf(DEBUG_NORMAL, "Couldn't locate the certificate!\n");
		return NULL;
	}

	return pCertContext;
}

PCCERT_CONTEXT win_cert_handler_get_from_user_store(char *storetype, char *location)
{
	PCCERT_CONTEXT  pCertContext = NULL;
	CRYPT_HASH_BLOB toFindData;
	uint8_t *hashData = NULL;

	if (storetype == NULL) return NULL;
	if (location == NULL) return NULL;

	str2hex(location, &hashData, &toFindData.cbData);
	toFindData.pbData = hashData;

	cert_handler_user_init();

	pCertContext = CertFindCertificateInStore(hCertUserStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &toFindData, NULL);
	FREE(hashData);  // Clean up the memory no matter what.
	
	if (pCertContext == NULL)
	{ 
		debug_printf(DEBUG_NORMAL, "Couldn't locate the certificate!\n");
		cert_handler_user_deinit();
		return NULL;
	}

	cert_handler_user_deinit();
	return pCertContext;
}

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
int cert_handler_get_info_from_store(char *storetype, char *location, cert_info *certinfo)
{
	PCCERT_CONTEXT  pCertContext = NULL;

	pCertContext = win_cert_handler_get_from_win_store(storetype, location);
	if (pCertContext == NULL)
	{ 
		debug_printf(DEBUG_NORMAL, "Couldn't locate the certificate!\n");
		return -1;
	}


	return cert_handler_get_info(pCertContext, certinfo);
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
	PCCERT_CONTEXT  pCertContext = NULL;
	int numcerts = 0;
	int i = 0;
	char pszNameString[256];
	DWORD size = 0;
	CERT_ENHKEY_USAGE *enhkey = NULL;

	if (hCertStore != NULL)
	{
		cert_handler_deinit();
		cert_handler_init();
	}

	// Enumerate all of the certificates, and count only the ones that have the
	// server authentication EKU set.
	while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)))
	{
		// We only check this certificate if we can get it's name.  If not, it is ignored.
		if (!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128))
		{
			debug_printf(DEBUG_NORMAL, "Unable to determine certificate name.\n");
		}
		else
		{
#ifdef CHECK_EKU
			if (CertGetEnhancedKeyUsage(pCertContext, 0, NULL, &size))
			{
				enhkey = malloc(size);
				if (enhkey == NULL)
				{
					debug_printf(DEBUG_NORMAL, "Unable to allocate memory to get EKU data!\n");
					return -1;
				}

				if (CertGetEnhancedKeyUsage(pCertContext, 0, enhkey, &size))
				{
					for (i = 0; i < enhkey->cUsageIdentifier; i++)
					{
						if (strcmp(enhkey->rgpszUsageIdentifier[i], szOID_PKIX_KP_SERVER_AUTH) == 0)
#endif
							numcerts++;
#ifdef CHECK_EKU
					}
				}

				FREE(enhkey);
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Unable to determine EKU data size!\n");
				return -1;
			}
#endif
		}
	}

	debug_printf(DEBUG_CERTS, "There were %d cert(s) that can be used for server authentication.\n", numcerts);
	return numcerts;
}

/**
 * \brief Determine the number of user certificates are in the store that
 *        can be used for authentication.
 *
 * \retval -1 on error
 * \retval >=0 is the number of certificates that will be in the list.
 **/
int cert_handler_num_user_certs()
{
	PCCERT_CONTEXT  pCertContext = NULL;
	int numcerts = 0;
	int i = 0;
	char pszNameString[256];
	DWORD size = 0;
	CERT_ENHKEY_USAGE *enhkey = NULL;

	if (hCertUserStore != NULL)
	{
		cert_handler_user_deinit();
		cert_handler_user_init();
	}
	else
	{
		cert_handler_user_init();
	}

	// Enumerate all of the certificates, and count only the ones that have the
	// server authentication EKU set.
	while ((pCertContext = CertEnumCertificatesInStore(hCertUserStore, pCertContext)))
	{
		// We only check this certificate if we can get it's name.  If not, it is ignored.
		if (!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128))
		{
			debug_printf(DEBUG_NORMAL, "Unable to determine certificate name.\n");
		}
		else
		{
#ifdef CHECK_EKU
			if (CertGetEnhancedKeyUsage(pCertContext, 0, NULL, &size))
			{
				enhkey = malloc(size);
				if (enhkey == NULL)
				{
					debug_printf(DEBUG_NORMAL, "Unable to allocate memory to get EKU data!\n");
					return -1;
				}

				if (CertGetEnhancedKeyUsage(pCertContext, 0, enhkey, &size))
				{
					for (i = 0; i < enhkey->cUsageIdentifier; i++)
					{
						if (strcmp(enhkey->rgpszUsageIdentifier[i], szOID_PKIX_KP_CLIENT_AUTH) == 0)
#endif
							numcerts++;
#ifdef CHECK_EKU
					}
				}

				FREE(enhkey);
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Unable to determine EKU data size!\n");
				return -1;
			}
#endif
		}
	}

	debug_printf(DEBUG_CERTS, "There were %d cert(s) that can be used for user authentication.\n", numcerts);

	cert_handler_user_deinit();

	return numcerts;
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
		if (casa[i].certname != NULL) FREE(casa[i].certname);
		if (casa[i].friendlyname != NULL) FREE(casa[i].friendlyname);
		if (casa[i].issuer != NULL) FREE(casa[i].issuer);
	}

	free((*cas));
	(*cas) = NULL;
}

char *do_sha1(char *tohash, int size)
{
  EVP_MD_CTX ctx;
  char *hash_ret;
  int evp_ret_len;

  if (!xsup_assert((tohash != NULL), "tohash != NULL", FALSE))
    return NULL;

  if (!xsup_assert((size > 0), "size > 0", FALSE))
    return NULL;

  hash_ret = (char *)Malloc(21);  // We should get 20 bytes returned.
  if (hash_ret == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for 'hash_ret' in "
		   "%s().\n", __FUNCTION__);
      return NULL;
    }
 
  EVP_DigestInit(&ctx, EVP_sha1());
  EVP_DigestUpdate(&ctx, tohash, size);
  EVP_DigestFinal(&ctx, hash_ret, (int *)&evp_ret_len);

  if (evp_ret_len != 20)
    {
      debug_printf(DEBUG_NORMAL, "Invalid result from OpenSSL SHA calls! "
		   "(%s:%d)\n", __FUNCTION__, __LINE__);
      return NULL;
    }

  return hash_ret;
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
	PCCERT_CONTEXT  pCertContext = NULL;
	int certidx = 0;
	int i = 0;
	char pszNameString[256];
	char pszSubjectString[1024];
	DWORD size = 0;
	CERT_ENHKEY_USAGE *enhkey = NULL;
	cert_enum *casa = NULL;
	SYSTEMTIME systime;
	uint8_t *sha1hash = NULL;
	char *temp = NULL;

	if (hCertStore != NULL)
	{
		cert_handler_deinit();
		cert_handler_init();
	}

	casa = Malloc((sizeof(cert_enum) * ((*numcas)+1)));
	if (casa == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store certificate enumeration.\n");
		return -1;
	}

	// Enumerate all of the certificates, and count only the ones that have the
	// server authentication EKU set.
	while ((hCertStore != NULL) && (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) &&
		(pCertContext != NULL))
	{
		// We only check this certificate if we can get it's name.  If not, it is ignored.
		if (!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, sizeof(pszNameString)))
		{
			debug_printf(DEBUG_NORMAL, "Unable to determine certificate name.\n");
		}
		else
		{
			// Everything in this enum is out of the windows cert store.
			casa[certidx].storetype = _strdup("WINDOWS");

			sha1hash = do_sha1(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
			temp = convert_hex_to_str(sha1hash, 20);
			casa[certidx].location = temp;
			FREE(sha1hash);

#ifdef CHECK_EKU
			if (CertGetEnhancedKeyUsage(pCertContext, 0, NULL, &size))
			{
				enhkey = malloc(size);
				if (enhkey == NULL)
				{
					debug_printf(DEBUG_NORMAL, "Unable to allocate memory to get EKU data!\n");
					return -1;
				}

				if (CertGetEnhancedKeyUsage(pCertContext, 0, enhkey, &size))
				{
					for (i = 0; i < enhkey->cUsageIdentifier; i++)
					{
						if (strcmp(enhkey->rgpszUsageIdentifier[i], szOID_PKIX_KP_SERVER_AUTH) == 0)
						{
#endif
							casa[certidx].certname = _strdup(pszNameString);
							
							// Get the subject name for this certificate.

							if (CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszSubjectString, sizeof(pszSubjectString)) > 0)
							{
								casa[certidx].friendlyname = _strdup(pszSubjectString);
							}

							memset(&pszSubjectString, 0x00, sizeof(pszSubjectString));

							if (CertGetNameString(pCertContext, CERT_NAME_DNS_TYPE, 0, NULL, pszSubjectString, sizeof(pszSubjectString)) > 0)
							{
								casa[certidx].commonname = _strdup(pszSubjectString);
							}

							// Get the issuer name for this certificate.
							if (CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, pszSubjectString, sizeof(pszSubjectString)) > 0)
							{
								casa[certidx].issuer = _strdup(pszSubjectString);
							}

							memset(&systime, 0x00, sizeof(systime));

							if (FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &systime) != 0)
							{
								casa[certidx].day = systime.wDay;
								casa[certidx].month = systime.wMonth;
								casa[certidx].year = systime.wYear;
							}

							certidx++;
#ifdef CHECK_EKU
						}
					}
				}

				FREE(enhkey);
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Unable to determine EKU data size!\n");
				return -1;
			}
#endif
		}
	}

	debug_printf(DEBUG_CERTS, "There were %d cert(s) that can be used for server authentication.\n", certidx);
	(*cas) = casa;

	return certidx;
}

/**
 * \brief Add a certificate to our certificate store.
 *
 * @param[in] path_to_cert  The full path name to the certificate we want to add to our store.
 *
 * \retval 0 on success
 **/
int cert_handler_add_cert_to_store(char *path_to_cert)
{
	HANDLE hFile;
	PCCERT_CONTEXT	pCertContext;
	BYTE			pbBuffer[8096];
	DWORD			cbBuffer;
	DWORD			dwErr;
	LPVOID			lastErrStr;
	int				retval = 0;

	if ((hFile = CreateFile( path_to_cert,
							GENERIC_READ,
							0,
							NULL,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							NULL ) ) != INVALID_HANDLE_VALUE )
	{
		cbBuffer = 0;

		memset( pbBuffer, 0, sizeof( pbBuffer ) );

		if (ReadFile( hFile,
						pbBuffer,
						sizeof( pbBuffer ),
						&cbBuffer,
						NULL ) )
		{

			if ((pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
															pbBuffer, 
															cbBuffer) ) )
			{
				if (hCertStore)
				{
					if (!CertAddCertificateContextToStore( hCertStore, 
															pCertContext, 
															CERT_STORE_ADD_NEW, 
															NULL ) )
					{
						dwErr = GetLastError();

						if (dwErr ==  CRYPT_E_EXISTS )
						{
							//
							// Certificate already exists
							//
						}
						else
						{
							lastErrStr = GetLastErrorStr(dwErr);
							debug_printf(DEBUG_NORMAL, "Unable to add certificate to store.  Windows error was '%d'.\n", lastErrStr);
							LocalFree(lastErrStr);
							retval = IPC_EVENT_ERROR_CANT_ADD_CERT_TO_STORE;
						}
					}
				}
				else
				{
					debug_printf(DEBUG_NORMAL, "Certificate store isn't open!\n");
					retval = IPC_EVENT_ERROR_FAILED_ROOT_CA_LOAD;
				}

				CertFreeCertificateContext( pCertContext );

				pCertContext = NULL;
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Unable to read certificate file!\n");
				retval = IPC_EVENT_ERROR_CANT_READ_FILE;
			}
		}
		else
		{
			debug_printf(DEBUG_NORMAL, "Unable to open certificate file!\n");
			retval = IPC_EVENT_ERROR_CANT_READ_FILE;
		}

		CloseHandle( hFile );
	}
	else
	{
		retval = IPC_EVENT_ERROR_CANT_READ_FILE;
	}

	return retval;
}

/**
 * \brief Enumerate user certificates that are in the store that
 *        can be used for authentication.
 *
 * @param[in] numcer   An integer the specifies the number of user certificates we are expected to
 *                     return.  This value should come from the cert_handler_num_user_certs().
 *                     On return, this will contain the number of certificates that are actually in
 *                     the array.
 *
 * @param[in,out] cer   An array of certificates that contains the number of certificates defined
 *                      by numcer.
 *
 * \retval -1 on error
 * \retval 0 on success
 **/
int cert_handler_enum_user_certs(int *numcer, cert_enum **cer)
{
	PCCERT_CONTEXT  pCertContext = NULL;
	int certidx = 0;
	int i = 0;
	char pszNameString[256];
	char pszSubjectString[1024];
	DWORD size = 0;
	CERT_ENHKEY_USAGE *enhkey = NULL;
	cert_enum *certs = NULL;
	SYSTEMTIME systime;
	uint8_t *sha1hash = NULL;
	char *temp = NULL;

	if (hCertUserStore != NULL)
	{
		cert_handler_user_deinit();
		cert_handler_user_init();
	}
	else
	{
		cert_handler_user_init();
	}

	certs = Malloc((sizeof(cert_enum) * ((*numcer)+1)));
	if (certs == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store certificate enumeration.\n");
		return -1;
	}

	// Enumerate all of the certificates, and count only the ones that have the
	// server authentication EKU set.
	while ((hCertUserStore != NULL) && (pCertContext = CertEnumCertificatesInStore(hCertUserStore, pCertContext)) &&
		(pCertContext != NULL))
	{
		// We only check this certificate if we can get it's name.  If not, it is ignored.
		if (!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, sizeof(pszNameString)))
		{
			debug_printf(DEBUG_NORMAL, "Unable to determine certificate name.\n");
		}
		else
		{
			// Everything in this enum is out of the windows cert store.
			certs[certidx].storetype = _strdup("WINDOWS");

			sha1hash = do_sha1(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
			temp = convert_hex_to_str(sha1hash, 20);
			certs[certidx].location = temp;
			FREE(sha1hash);

#ifdef CHECK_EKU
			if (CertGetEnhancedKeyUsage(pCertContext, 0, NULL, &size))
			{
				enhkey = malloc(size);
				if (enhkey == NULL)
				{
					debug_printf(DEBUG_NORMAL, "Unable to allocate memory to get EKU data!\n");
					return -1;
				}

				if (CertGetEnhancedKeyUsage(pCertContext, 0, enhkey, &size))
				{
					for (i = 0; i < enhkey->cUsageIdentifier; i++)
					{
						if (strcmp(enhkey->rgpszUsageIdentifier[i], szOID_PKIX_KP_CLIENT_AUTH) == 0)
						{
#endif
							certs[certidx].certname = _strdup(pszNameString);
							
							// Get the subject name for this certificate.

							if (CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszSubjectString, sizeof(pszSubjectString)) > 0)
							{
								certs[certidx].friendlyname = _strdup(pszSubjectString);
							}

							memset(&pszSubjectString, 0x00, sizeof(pszSubjectString));

							if (CertGetNameString(pCertContext, CERT_NAME_DNS_TYPE, 0, NULL, pszSubjectString, sizeof(pszSubjectString)) > 0)
							{
								certs[certidx].commonname = _strdup(pszSubjectString);
							}

							// Get the issuer name for this certificate.
							if (CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, pszSubjectString, sizeof(pszSubjectString)) > 0)
							{
								certs[certidx].issuer = _strdup(pszSubjectString);
							}

							memset(&systime, 0x00, sizeof(systime));

							if (FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &systime) != 0)
							{
								certs[certidx].day = systime.wDay;
								certs[certidx].month = systime.wMonth;
								certs[certidx].year = systime.wYear;
							}

							certidx++;
#ifdef CHECK_EKU
						}
					}
				}

				FREE(enhkey);
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Unable to determine EKU data size!\n");
				return -1;
			}
#endif
		}
	}

	debug_printf(DEBUG_CERTS, "There were %d cert(s) that can be used for user authentication.\n", certidx);
	(*cer) = certs;

	cert_handler_user_deinit();

	return certidx;
}

/**
 * \brief Provide the public key encryption method for OpenSSL when using RSA.
 *
 * \note Not implemented because it isn't needed.
 **/
static int rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to,
						RSA *rsa, int padding)
{
	return 0;
}

/* verify arbitrary data */
static int rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
						RSA *rsa, int padding)
{
	return 0;
}

/* decrypt */
static int rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, 
						RSA *rsa, int padding)
{
	return 0;
}

/* sign arbitrary data */
static int rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, 
						RSA *rsa, int padding)
{
	struct tls_vars *mytls_vars = (struct tls_vars *)rsa->meth->app_data;
	HCRYPTHASH hash;
	DWORD hash_size, len, i;
	unsigned char *buf = NULL;
	HCRYPTPROV *hcProv = NULL;

	// Verify that we have all of the information we need to sign data.
	if (mytls_vars == NULL) 
	{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (padding != RSA_PKCS1_PADDING) 
	{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
		return 0;
	}

	if (flen != 36) 
	{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_INVALID_MESSAGE_LENGTH);
		return 0;
	}

	hcProv = (HCRYPTPROV *)mytls_vars->hcProv;

	if (!CryptCreateHash((*hcProv), CALG_SSL3_SHAMD5, 0, 0, &hash)) 
	{
		debug_printf(DEBUG_NORMAL, "CryptCreateHash() failed!\n");
		return 0;
	}

	len = sizeof(hash_size);
	if (!CryptGetHashParam(hash, HP_HASHSIZE, (BYTE *) &hash_size, &len, 0)) 
	{
		debug_printf(DEBUG_NORMAL, "CryptGetHashParam() failed!\n");
		CryptDestroyHash(hash);
		return 0;
	}

	if ((int)hash_size != flen) 
	{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_INVALID_MESSAGE_LENGTH);
		CryptDestroyHash(hash);
		return 0;
	}

	if (!CryptSetHashParam(hash, HP_HASHVAL, (BYTE * ) from, 0)) 
	{
		debug_printf(DEBUG_NORMAL, "CryptSetHashParam() failed!\n");
		CryptDestroyHash(hash);
		return 0;
	}

	len = RSA_size(rsa);
	buf = Malloc(len);
	if (buf == NULL) 
	{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_MALLOC_FAILURE);
		CryptDestroyHash(hash);
		return 0;
	}

	if (!CryptSignHash(hash, mytls_vars->pdwKeyspec, NULL, 0, buf, &len)) 
	{
		debug_printf(DEBUG_NORMAL, "CryptSignHash() failed!\n");
		CryptDestroyHash(hash);
		FREE(buf);
		return 0;
	}

	for (i = 0; i < len; i++) to[i] = buf[len - i - 1];
	FREE(buf);

	CryptDestroyHash(hash);
	return len;
}

/* called at RSA_free */
static int finish(RSA *rsa)
{
	struct tls_vars *mytls_vars = (struct tls_vars *)rsa->meth->app_data;
	HCRYPTPROV *hcProv = NULL;

	if (mytls_vars == NULL) return 0;

	if ((mytls_vars->hcProv != NULL) && (mytls_vars->pfCallerFreeProv == TRUE))
	{
		hcProv = (HCRYPTPROV *)mytls_vars->hcProv;

		// We need to free the CSP.
		CryptReleaseContext((*hcProv), 0);
		mytls_vars->hcProv = NULL;
	}

	FREE((char *)rsa->meth);
	
	return 1;
}

int win_cert_handler_load_user_cert(struct tls_vars *mytls_vars, PCCERT_CONTEXT mycert)
{
	X509 *wincert = NULL;
	unsigned long err = 0;
	int reason = 0;
	char *tempptr = NULL;
	RSA_METHOD *rsa_meth = NULL;
	RSA *rsa = NULL, *pub_rsa = NULL;

	tempptr = mycert->pbCertEncoded;

	ERR_clear_error();  // Clear the error queue for this thread.
	wincert = d2i_X509(NULL, &tempptr, mycert->cbCertEncoded);
	if (wincert == NULL)
	{
		err = ERR_get_error();
		debug_printf(DEBUG_NORMAL, "Couldn't load certificate from Windows certificate store!\n");
		debug_printf(DEBUG_AUTHTYPES, "OpenSSL error is : %s\n", ERR_error_string(err, NULL));
		return -1;
	}

	ERR_clear_error();

	// Then, load the private key.
	if (CryptAcquireCertificatePrivateKey(mycert, CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &mytls_vars->hcProv, 
		&mytls_vars->pdwKeyspec, &mytls_vars->pfCallerFreeProv) == FALSE)
	{
		debug_printf(DEBUG_NORMAL, "Unable to load the user private key data!\n");
		X509_free(wincert);
		return -1;
	}

	rsa_meth = Malloc(sizeof(RSA_METHOD));
	if (rsa_meth == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory to create replacement RSA methods.\n");
		X509_free(wincert);
		return -1;
	}

	// Set up the function pointers to our replacement functions.
	rsa_meth->name = _strdup("CryptoAPI RSA Replacement");
	rsa_meth->rsa_priv_dec = rsa_priv_dec;
	rsa_meth->rsa_priv_enc = rsa_priv_enc;
	rsa_meth->rsa_pub_dec = rsa_pub_dec;
	rsa_meth->rsa_pub_enc = rsa_pub_enc;
	rsa_meth->finish = finish;
	rsa_meth->flags = RSA_METHOD_FLAG_NO_CHECK;
	rsa_meth->app_data = (char *)mytls_vars;

	rsa = RSA_new();
	if (rsa == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Unable to allocate memory with RSA_new().\n");
		X509_free(wincert);
		return -1;
	}

	if (mytls_vars->ctx == NULL)
	{
		debug_printf(DEBUG_NORMAL, "No SSL context established!\n");
		X509_free(wincert);
		RSA_free(rsa);
		return -1;
	}

	if (!SSL_CTX_use_certificate(mytls_vars->ctx, wincert))
	{
		debug_printf(DEBUG_NORMAL, "Unable to use selected user certificate!\n");
		X509_free(wincert);
		RSA_free(rsa);
		return -1;
	}
	X509_free(wincert);

	pub_rsa = wincert->cert_info->key->pkey->pkey.rsa;

	rsa->n = BN_dup(pub_rsa->n);
	rsa->e = BN_dup(pub_rsa->e);

	if (!RSA_set_method(rsa, rsa_meth))
	{
		RSA_free(rsa);
		debug_printf(DEBUG_NORMAL, "Couldn't set the OpenSSL RSA method!\n");
		return -1;
	}

	if (!SSL_CTX_use_RSAPrivateKey(mytls_vars->ctx, rsa))
	{
		RSA_free(rsa);
		debug_printf(DEBUG_NORMAL, "Couldn't set the OpenSSL RSA Private Key method!\n");
		return -1;
	}

	RSA_free(rsa);

	return 0;
}

