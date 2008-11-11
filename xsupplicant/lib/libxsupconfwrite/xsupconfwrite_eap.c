/**
 * Implementation for converting variables that make up the <EAP> section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap.c
 *
 * \author chris@open1x.org
 **/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <string.h>
#include <libxml/parser.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "libxsupconfig/xsupconfig_vars.h"
#include "xsupconfwrite_pwd_only.h"
#include "xsupconfwrite_eap_tls.h"
#include "xsupconfwrite_eap_sim.h"
#include "xsupconfwrite_eap_aka.h"
#include "xsupconfwrite_eap_mschapv2.h"
#include "xsupconfwrite_eap_tnc.h"
#include "xsupconfwrite_eap_ttls.h"
#include "xsupconfwrite_eap_peap.h"
#include "xsupconfwrite_eap_fast.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
 #define WRITE_EAP_CONFIG 1


/**
 * \brief Create the <EAP> block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] method  A config_eap_method structure that contains all of the
 *                    variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the <EAP> tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_create_tree(struct config_eap_method *method, 
										 char write_all)
{
	xmlNodePtr eapnode = NULL;
	xmlNodePtr eapdata = NULL;
	struct config_eap_mschapv2 *mscv2 = NULL;
		
	if (method == NULL) return NULL;

	// Create the root node for the <EAP> block.
	eapnode = xmlNewNode(NULL, (xmlChar *)"EAP");
	if (eapnode == NULL)
	{
#ifdef WRITE_EAP_CONFIG
		printf("Couldn't allocate memory to store <EAP> block!\n");
#endif
		return NULL;
	}

	switch (method->method_num)
	{
	case EAP_TYPE_MD5:
		eapdata = xsupconfwrite_pwd_only_create_tree("MD5", method->method_data, write_all); 
  	    break;

	case EAP_TYPE_OTP:
		eapdata = xmlNewNode(NULL, (xmlChar *)"Type");
		if (eapdata != NULL)
		{
			xmlNodeAddContent(eapdata, (xmlChar *)"OTP");
		}
		break;

	case EAP_TYPE_GTC:
		eapdata = xsupconfwrite_pwd_only_create_tree("GTC", method->method_data, write_all);
		break;

	case EAP_TYPE_TLS:
		eapdata = xsupconfwrite_eap_tls_create_tree(method->method_data, write_all);
		break;

#ifdef ENABLE_LEAP
	case EAP_TYPE_LEAP:
		eapdata = xsupconfwrite_pwd_only_create_tree("LEAP", method->method_data, write_all);
		break;
#endif  // ENABLE_LEAP

	case EAP_TYPE_SIM:
		eapdata = xsupconfwrite_eap_sim_create_tree(method->method_data, write_all);
		break;

	case EAP_TYPE_TTLS:
		eapdata = xsupconfwrite_eap_ttls_create_tree(method->method_data, write_all);
		break;

	case EAP_TYPE_AKA:
		eapdata = xsupconfwrite_eap_aka_create_tree(method->method_data, write_all);
		break;

	case EAP_TYPE_PEAP:
		eapdata = xsupconfwrite_eap_peap_create_tree(method->method_data, write_all);
		break;

	case EAP_TYPE_MSCHAPV2:
		mscv2 = (struct config_eap_mschapv2 *)method->method_data;

		// Don't write the config out if it is flagged volatile.
		if (!TEST_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_VOLATILE))
		{
			eapdata = xsupconfwrite_eap_mschapv2_create_tree(method->method_data, write_all);
		}
		break;

	case EAP_TYPE_TNC:
		eapdata = xsupconfwrite_eap_tnc_create_tree(method->method_data, write_all);
		break;

	case EAP_TYPE_FAST:
		eapdata = xsupconfwrite_eap_fast_create_tree(method->method_data, write_all);
		break;

	case EAP_TYPE_PSK:
		eapdata = xsupconfwrite_pwd_only_create_tree("PSK", method->method_data, write_all); 
  	    break;

	default:
		// Unknown!  Return an error.
		xmlFreeNode(eapnode);
		return NULL;
		break;
	}

	if (eapdata == NULL)
	{
#ifdef WRITE_EAP_DEBUG
		printf("Couldn't create EAP method node!\n");
#endif
		xmlFreeNode(eapnode);
		return NULL;
	}

	if (xmlAddChild(eapnode, eapdata) == NULL)
	{
#ifdef WRITE_EAP_DEBUG
		printf("Couldn't add EAP child node to <EAP> block!\n");
#endif
		xmlFreeNode(eapnode);
		return NULL;
	}

	return eapnode;
}
