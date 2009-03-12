/**
 * Implementation for converting variables that make up the TNC configuration section
 * to the libxml2 format that can be written to disk, or manipulated in other ways.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfwrite_eap_tnc.c
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfwrite_eap_tnc.c,v 1.3 2007/10/17 07:00:46 galimorerpg Exp $
 * $Date: 2007/10/17 07:00:46 $
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
#include "xsupconfwrite_common.h"
#include "xsupconfwrite.h"

// Uncomment the #define below to enable textual debug output.
// #define WRITE_EAP_TNC_DEBUG 1

/**
 * \brief Create an EAP-TNC block for the configuration file in a format
 *        that libxml2 can understand.
 *
 * @param[in] tncdata  A config_eap_tnc structure that contains all of the
 *                     variables that we want to convert to XML.
 * @param[in] write_all   If set to TRUE, we will write all of the configuration
 *                        options to the XML node tree, no matter if their values
 *                        are set to the default or not.
 *
 * \retval NULL on error
 * \retval xmlNodePtr containing the TNC configuration tree in a format that is used by 
 *         libxml2.
 **/
xmlNodePtr xsupconfwrite_eap_tnc_create_tree(struct config_eap_tnc * tncdata,
					     char write_all)
{
	xmlNodePtr tncnode = NULL;
	char tempstatic[10];

	if (tncdata == NULL)
		return NULL;

	tncnode = xsupconfwrite_common_newSibling(NULL, "Type", "TNC");
	if (tncnode == NULL) {
#ifdef WRITE_EAP_TNC_DEBUG
		printf("Couldn't create <Type> node for TNC!\n");
#endif
		return NULL;
	}

	if ((write_all == TRUE) || (tncdata->frag_size)) {
		sprintf((char *)&tempstatic, "%d", tncdata->frag_size);
		if (xsupconfwrite_common_newSibling
		    (tncnode, "Chunk_Size", tempstatic) == NULL) {
#ifdef WRITE_EAP_TNC_DEBUG
			printf("Couldn't create <Chunk_Size> node for TNC.\n");
#endif
			return NULL;
		}
	}

	return tncnode;
}
