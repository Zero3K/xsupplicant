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
#include "cardif_windows.h"

//  #define CHECK_EKU   1      // Only show root certs with the server EKUs.  (Same as Windows XP defaults.)

HCERTSTORE hCertStore = NULL;

/**
 * \brief Initialize the Windows certificate store.
 *
 * \retval XENONE on success
 * \retval XEGENERROR on failure
 **/
int cert_handler_init()
{
	debug_printf(DEBUG_CERTS, "Starting Certificate Services...\n");
	if (hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
									NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT"))
	{
		return XEGENERROR;
	}

	return XENONE;
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
	uint8_t *hashData;

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

