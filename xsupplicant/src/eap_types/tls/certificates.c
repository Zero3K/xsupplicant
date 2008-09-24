/**
 * Trusted Server (Server Certificate) handler
 * 
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file certificates.c
 *
 * \author chris@open1x.org
 **/

#include <stdio.h>
#include <string.h>

#ifdef WINDOWS
#include <windows.h>
#include <wincrypt.h>

#include "../../stdintwin.h"
#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_structs.h"
#include "../../context.h"
#include "tls_funcs.h"
#include "certificates.h"
#include "../../ipc_events.h"
#include "../../ipc_events_index.h"
#include "tls_funcs.h"

/**
 * \brief Locate the trusted server block that the profile has asked us to use.
 *
 * @param[in] svrs   A linked list of all of the available trusted servers.
 * @param[in] trusted_servername   The "<Name>" of the trusted server that we are looking for.
 *
 * \retval NULL on error
 * \retval ptr to the desired trusted server on success
 **/
struct config_trusted_server *certificates_find_trusted_server(struct config_trusted_servers *svrs, char *trusted_servername)
{
	struct config_trusted_server *cur = NULL;

	if (trusted_servername == NULL) return NULL;

	if (svrs == NULL) return NULL;

	cur = svrs->servers;

	while ((cur != NULL) && (strcmp(cur->name, trusted_servername) != 0))
	{
		cur = cur->next;
	}

	if (cur == NULL) return NULL;

	return cur;
}

#ifdef WINDOWS
/**
 * \brief Add a certificate from Windows in to the OpenSSL store in memory.
 *
 * @param[in] mytls_vars  The TLS context information for this session.
 *
 * \retval 0 on success
 **/
int certificates_windows_add_cert_to_ossl_mem_store(struct tls_vars *mytls_vars, PCCERT_CONTEXT mycert)
{
	X509 *wincert = NULL;
	unsigned long err = 0;
	int reason = 0;
	char *tempptr = NULL;

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

	if ((mytls_vars == NULL) || (mytls_vars->ctx == NULL))
	{
		debug_printf(DEBUG_NORMAL, "No SSL context available.  Unable to load your certificates.\n");
		return -1;
	}

	if (!X509_STORE_add_cert(mytls_vars->ctx->cert_store, wincert))
	{
		err = ERR_get_error();
		if (err != 0)
		{
			reason = ERR_GET_REASON(err);

			if (reason == X509_R_CERT_ALREADY_IN_HASH_TABLE)
			{
				debug_printf(DEBUG_AUTHTYPES, "Certificate was already in the hash table!\n");
			}
			else
			{
				debug_printf(DEBUG_NORMAL, "Failed to add certificate to the OpenSSL store!\n");
				debug_printf(DEBUG_AUTHTYPES, "OpenSSL error is : %s\n", ERR_error_string(err, NULL));
				return -1;
			}
		}
	}

	return 0;
}

/**
 * \brief Log the certification chain failure error.
 *
 * @param[in] dwErr  An error value from the dwErrorStatus member of the CERT_TRUST_STATUS structure.
 **/
void certificates_log_error(DWORD dwErr)
{
	switch (dwErr)
	{
	case CERT_TRUST_NO_ERROR:
		debug_printf(DEBUG_NORMAL, "There was no error reading the certificate chain.\n");
		break;

	case CERT_TRUST_IS_NOT_TIME_VALID:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain is not time valid.  (It either becomes valid in the future, or has expired.)\n");
		break;

	case CERT_TRUST_IS_NOT_TIME_NESTED:
		debug_printf(DEBUG_NORMAL, "The certificates in the chain are not properly time nested.\n");
		break;

	case CERT_TRUST_IS_REVOKED:
		debug_printf(DEBUG_NORMAL, "Trust for at least one certificate in the chain has been revoked.\n");
		break;

	case CERT_TRUST_IS_NOT_SIGNATURE_VALID:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain does not have a valid signature.\n");
		break;

	case CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
		debug_printf(DEBUG_NORMAL, "The certificate chain is not valid for use with 802.1X.\n");
		break;

	case CERT_TRUST_IS_UNTRUSTED_ROOT:
		debug_printf(DEBUG_NORMAL, "The certificate chain is built off of an untrusted root certificate.\n");
		break;

	case CERT_TRUST_REVOCATION_STATUS_UNKNOWN:
		debug_printf(DEBUG_NORMAL, "The revocation status of at least one certificate in the chain is unknown.\n");
		break;

	case CERT_TRUST_IS_CYCLIC:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain was issued by a certification authority that the original certificate had certified.  (The chain is cyclic.)\n");
		break;

	case CERT_TRUST_INVALID_EXTENSION:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain had an extension that is not valid.\n");
		break;

	case CERT_TRUST_INVALID_POLICY_CONSTRAINTS:
		debug_printf(DEBUG_NORMAL, "The certificate or one of the certificates in the certificate chain has a policy constraints extension, and one of the issued certificates has a disallowed policy mapping extension or does not have a required issuance policies extension.\n");
		break;

	case CERT_TRUST_INVALID_BASIC_CONSTRAINTS:
		debug_printf(DEBUG_NORMAL, "The certificate or one of the certificates in the certificate chain has a basic constraints extension, and either the certificate cannot be used to issue other certificates, or the chain path length has been exceeded.\n");
		break;

	case CERT_TRUST_INVALID_NAME_CONSTRAINTS:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain has a name constraints extension that is not valid.\n");
		break;

	case CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain has a name constraints extension that contains unsupported fields.\n");
		break;

	case CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain has a name constraints extension and a name constraint is missing fro one of the name choices in the end certificate.\n");
		break;

	case CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain has a name constraints extension and a name constraint is missing from one of the name choices in the end certificate.\n");
		break;

	case CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT:
		debug_printf(DEBUG_NORMAL, "One of the certificates in the chain has a name constraints extension, and one of the name choices in the end certificate is explicitly excluded.\n");
		break;

	case CERT_TRUST_IS_OFFLINE_REVOCATION:
		debug_printf(DEBUG_NORMAL, "The recovation status of the certificate or one of the certificates in the certificate chain is either offline or stale.\n");
		break;

	case CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY:
		debug_printf(DEBUG_NORMAL, "The end certificate does not have any resultant issuance policies, and one of the issuing certification authority certificates has a policy constraints extension requiring it.\n");
		break;

	case CERT_TRUST_IS_EXPLICIT_DISTRUST:
		debug_printf(DEBUG_NORMAL, "A certificate in the chain is explicitly distrusted.\n");
		break;

	case CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT:
		debug_printf(DEBUG_NORMAL, "A certificate in the chain does not support a critical extension.\n");
		break;

	default:
		debug_printf(DEBUG_NORMAL, "Unknown/Unexpected certificate error : %04x\n", dwErr);
		break;
	}
}

/**
 * \brief Build an certificate chain from the Windows cert store, and put it in to
 *        OpenSSL's in memory certificate store.
 *
 * @param[in] mytls_vars   The TLS context information for this session.
 * @param[in] mycert   The Windows certificate store context for the trusted certificate we want to
 *                     build a chain with.
 *
 * \retval 0 on success
 **/
int certificates_windows_build_ossl_mem_chain(struct tls_vars *mytls_vars, 	PCCERT_CONTEXT mycert)
{
	CERT_CHAIN_PARA myPara;
	PCCERT_CHAIN_CONTEXT pChainContext = NULL;
	PCERT_SIMPLE_CHAIN pChain = NULL;
	PCERT_CHAIN_ELEMENT pElement = NULL;
	int i = 0;
	int c = 0;

	myPara.cbSize = sizeof(CERT_CHAIN_PARA);
	myPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
	myPara.RequestedUsage.Usage.cUsageIdentifier = 0;
	myPara.RequestedUsage.Usage.rgpszUsageIdentifier = NULL;

	if (CertGetCertificateChain(HCCE_LOCAL_MACHINE, mycert,	NULL, NULL, &myPara, 
								CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
								NULL, &pChainContext) == 0)
	{
		debug_printf(DEBUG_NORMAL, "Unable to create certificate chain from Windows certificate store!  (Error was : %d)\n", GetLastError());
		return -1;
	}

	if (pChainContext == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Windows returned a NULL chain context, but didn't return an error!?\n");
		return -1;
	}

	// Otherwise, we should have the chain, so load it in to OpenSSL.
	// Ignore the complaint that certificates are not valid for a specific usage.
	if (pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR)
	{
		certificates_log_error(pChainContext->TrustStatus.dwErrorStatus);
		CertFreeCertificateChain(pChainContext);
		return -1;
	}

	debug_printf(DEBUG_AUTHTYPES, "There are %d chain(s) in the structure.\n", pChainContext->cChain);

	for (i = 0; i < pChainContext->cChain; i++)
	{
		pChain = pChainContext->rgpChain[i];

		if (pChain == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Windows returned a NULL simple chain context?\n");
			CertFreeCertificateChain(pChainContext);
			return -1;
		}

		debug_printf(DEBUG_AUTHTYPES, "There are %d certificate(s) in this chain.\n", pChain->cElement);
		for (c = 0; c < pChain->cElement; c++)
		{
			pElement = pChain->rgpElement[c];

			if (pElement == NULL)
			{
				debug_printf(DEBUG_NORMAL, "Windows returned a NULL element in a simple chain context!?\n");
				CertFreeCertificateChain(pChainContext);
				return -1;
			}

			if (certificates_windows_add_cert_to_ossl_mem_store(mytls_vars, pElement->pCertContext) != 0)
			{
				debug_printf(DEBUG_NORMAL, "Failed to load one of the certificates in the chain.  Aborting.\n");
				CertFreeCertificateChain(pChainContext);
				return -1;
			}
		}
	}

	CertFreeCertificateChain(pChainContext);

	return 0;
}

/**
 * \brief Locate the certificate that we want to load, and load it in to OpenSSL.
 *
 * @param[in] mytls_vars   The TLS context information for this session.
 * @param[in] location   The location information used to locate the certificate.
 *
 * \retval XENONE on success
 * \retval !XENONE on error
 **/
int certificates_windows_load_root_certs(struct tls_vars *mytls_vars, char *location)
{
	PCCERT_CONTEXT mycert = NULL;

	if (mytls_vars == NULL)
	{
		debug_printf(DEBUG_NORMAL, "mytls_vars was NULL in %s() at %d!\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (location == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Attempt to load a root certificate that doesn't have a location set!?\n");
		return -1;
	}

	mycert = win_cert_handler_get_from_win_store("WINDOWS", location);
	if (mycert == NULL)
	{ 
		debug_printf(DEBUG_NORMAL, "Couldn't locate the certificate!\n");
		return -1;
	}
	else
	{
		debug_printf(DEBUG_AUTHTYPES, "Located the certificate for '%s'!\n", location);
	}

	return certificates_windows_build_ossl_mem_chain(mytls_vars, mycert);
}
#endif

/**
 * \brief Attempt to load the certificate(s) for the trusted server in to OpenSSL.
 *
 * @param[in] trusted_servername   The <Trusted_Server> setting from the configuration file.
 * @param[in] mytls_vars   The TLS context information for this session.
 *
 * \retval XENONE on success
 * \retval !XENONE on error
 **/
int certificates_load_root(struct tls_vars *mytls_vars, char *trusted_servername)
{
	struct config_trusted_server *svr = NULL;
	int i = 0;

	svr = certificates_find_trusted_server(config_get_trusted_servers(), trusted_servername);
	if (svr == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't locate the server '%s'!\n", trusted_servername);
		return XECANTFINDSERVER;   
	}

	// Set up the CN match, and if it should be exact.
	mytls_vars->cncheck = svr->common_name;
	mytls_vars->cnexact = svr->exact_common_name;

	if (strcmp(svr->store_type, "WINDOWS") == 0)
	{
#ifndef WINDOWS
		return -1;
#else
		// Get the certificate out of the WINDOWS certificate store.  (If we are using Windows. ;)
		for (i = 0; i < svr->num_locations; i++)
		{
			if (certificates_windows_load_root_certs(mytls_vars, svr->location[i]) != XENONE)
			{
				debug_printf(DEBUG_NORMAL, "Unable to load the root certificate from the Windows "
						"certificate store!\n");
				ipc_events_error(NULL, IPC_EVENT_ERROR_FAILED_ROOT_CA_LOAD, NULL);
				return -1;
			}
		}

		return XENONE;
#endif
	}

	if (strcmp(svr->store_type, "FILE") == 0)
	{
		// Get the certificate out of a FILE on the filesystem.
		for (i = 0; i < svr->num_locations; i++)
		{
			if (tls_funcs_load_root_certs(mytls_vars, svr->location[i], NULL, NULL) != XENONE)
				{
				  debug_printf(DEBUG_NORMAL, "Unable to load the root certificate from file "
					  "'%s'!\n", svr->location[i]);
				  ipc_events_error(NULL, IPC_EVENT_ERROR_FAILED_ROOT_CA_LOAD, NULL);
				  return -1;
				}
		}

		return XENONE;
	}

	if (strcmp(svr->store_type, "DIRECTORY") == 0)
	{
		// Get the certificate out of an OpenSSL directory.
		for (i = 0; i < svr->num_locations; i++)
		{
			if (tls_funcs_load_root_certs(mytls_vars, NULL, svr->location[i], NULL) != XENONE)
				{
				  debug_printf(DEBUG_NORMAL, "Unable to load the root certificate from directory "
					  "'%s'!\n", svr->location[i]);
				  ipc_events_error(NULL, IPC_EVENT_ERROR_FAILED_ROOT_CA_LOAD, NULL);
				  return -1;
				}
		}
		return XENONE;
	}

	return -1;
}
