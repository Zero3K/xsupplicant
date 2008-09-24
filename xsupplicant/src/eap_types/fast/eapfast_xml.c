/**
 * Implementation of XML functions used to handle PACs for EAP fast.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file eapfast_xml.c
 *
 * \author chris@open1x.org
 *
 * \todo Add IPC error message signaling.
 **/

#ifdef EAP_FAST

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "xsupconfig.h"
#include "eap_sm.h"
#include "eap_types/eap_type_common.h"
#include "eapfast_phase2.h"
#include "eapfast_xml.h"
#include "xsup_common.h"
#include "xsup_debug.h"
#include "eap_types/mschapv2/mschapv2.h"

#define XSUP_PAC_ROOT_ELEMENT  "XsupplicantPACs"

/****************************************************************
 *
 *  Create a new XML document that contains the root node needed to 
 *  identify it as a valid Xsupplicant PAC document.
 *
 ****************************************************************/
xmlDocPtr eapfast_xml_create_pac_struct()
{
  xmlDocPtr doc;
  xmlNodePtr root_node;

  doc = xmlNewDoc("1.0");

  if (doc == NULL) return NULL;

  root_node = xmlNewNode(NULL, XSUP_PAC_ROOT_ELEMENT);

  xmlDocSetRootElement(doc, root_node);

  return doc;
}

/*****************************************************************
 *
 *  Add a single content node to a parent node.
 *
 *****************************************************************/
void eapfast_xml_add_content(xmlNodePtr node, char *name, char *content)
{
  xmlNodePtr cur_node;

  cur_node = xmlNewChild(node, NULL, name, NULL);
  xmlNodeAddContent(cur_node, content);
}

/****************************************************************
 *
 *  Search through the XML file looking for the AID.
 *
 ****************************************************************/
xmlNodePtr eapfast_xml_find_pac(xmlDocPtr doc, char *aid)
{
  xmlNodePtr root_node, cur_node;
  int done = FALSE;
  xmlChar *prop;

  if (!xsup_assert((doc != NULL), "doc != NULL", FALSE))
    return NULL;

  if (!xsup_assert((aid != NULL), "aid != NULL", FALSE))
    return NULL;

  // Search XML space to find the string.
  root_node = xmlDocGetRootElement(doc);

  if (root_node == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No root node available!\n");
      return NULL;
    }

  cur_node = root_node->children;

  while ((cur_node) && (done == 0))
    {
      prop = xmlGetProp(cur_node, "AID");

      if (prop != NULL)
        {
          // See if this is what we are looking for.
          if (strcmp(prop, aid) == 0)
            {
              done = TRUE;
            }
          else
            {
              xmlFree(prop);
            }
        }
      else
        {
          xmlFree(prop);
        }

      if (done == FALSE) cur_node = cur_node->next;
    }

  if (cur_node != NULL) return cur_node;

  return NULL;
}

/****************************************************************
 *
 *  Check to see if we already have a node for this AID.  If we do,
 *  then we need to clear it out, and return.  (If we don't, just
 *  return.
 *
 ****************************************************************/
void eapfast_xml_check_clear_node(xmlDocPtr doc, char *aid)
{
  xmlNodePtr cur_node;

  cur_node = eapfast_xml_find_pac(doc, aid);

  // This AID isn't known yet.
  if (cur_node == NULL) return;

  xmlUnlinkNode(cur_node);
  xmlFreeNode(cur_node);
}

/****************************************************************
 *
 *  Add a new PAC to the XML document.
 *
 ****************************************************************/
int eapfast_xml_add_pac(xmlDocPtr doc, struct pac_values *pacs)
{
  xmlNodePtr root_node, cur_node;
  char *temp;
  char num[3];

  root_node = xmlDocGetRootElement(doc);

  if (root_node == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No root XML node available!!\n");
      return -1;
    }

  if (strcmp(root_node->name, XSUP_PAC_ROOT_ELEMENT) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid root element!\n");
      return -1;
    }

  temp = eap_type_common_convert_hex(pacs->pacinfo.aid, pacs->pacinfo.aid_len);
  eapfast_xml_check_clear_node(doc, temp);

  cur_node = xmlNewChild(root_node, NULL, "PAC", NULL);

  if (cur_node == NULL) return -1;

  xmlNewProp(cur_node, "AID", temp);
  FREE(temp);

  temp = eap_type_common_convert_hex(pacs->pac_key, 32);
  eapfast_xml_add_content(cur_node, "PAC_key", temp);
  FREE(temp);

  temp = eap_type_common_convert_hex(pacs->pac_opaque, pacs->pac_opaque_len);
  eapfast_xml_add_content(cur_node, "PAC_opaque", temp);
  FREE(temp);

  temp = eap_type_common_convert_hex(pacs->pacinfo.cred_lifetime, 4);
  eapfast_xml_add_content(cur_node, "Cred_Lifetime", temp);
  FREE(temp);

  temp = eap_type_common_convert_hex(pacs->pacinfo.iid, pacs->pacinfo.iid_len);
  eapfast_xml_add_content(cur_node, "IID", temp);
  FREE(temp);

  temp = eap_type_common_convert_hex(pacs->pacinfo.aid_info,
				     pacs->pacinfo.aid_info_len);
  eapfast_xml_add_content(cur_node, "AID_Info", temp);
  FREE(temp);

  memset(num, 0x00, 3);
  snprintf(num, 3, "%d", pacs->pacinfo.pac_type);
  eapfast_xml_add_content(cur_node, "PAC_Type", num);

  return 0;
}

/**************************************************************
 *
 *  Write out the XML document to a file.
 *
 **************************************************************/
int eapfast_xml_save(char *filename, xmlDocPtr doc)
{
  xmlSaveFormatFile(filename, doc, 1);

  return 0;
}

/**************************************************************
 *
 *  Set up libxml to be used.
 *
 **************************************************************/
void eapfast_xml_init()
{
  LIBXML_TEST_VERSION
}

/**************************************************************
 *
 *  Clean up libxml.
 *
 **************************************************************/
void eapfast_xml_deinit(xmlDocPtr doc)
{
  xmlFreeDoc(doc);

  xmlCleanupParser();
}

/**************************************************************
 *
 *  Open (and parse) an XML document containing PACs.
 *
 **************************************************************/
xmlDocPtr eapfast_xml_open_pac(char *filename)
{
  xmlDocPtr doc;
  xmlNodePtr node;

  if (filename == NULL) return NULL;

  doc = xmlReadFile(filename, NULL, 0);
  if (doc == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error reading EAP-FAST PAC file.\n");
      return NULL;
    }

  node = xmlDocGetRootElement(doc);
  
  if (node == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No root element!\n");
      xmlFreeDoc(doc);
      return NULL;
    }

  if (strcmp(XSUP_PAC_ROOT_ELEMENT, node->name) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid PAC file!\n");
      xmlFreeDoc(doc);
      return NULL;
    }

  return doc;
}

/***********************************************************************
 *
 *  Locate a PAC and return it's data.  (Returns 0 on success.)
 *
 ***********************************************************************/
int eapfast_xml_find_pac_data(xmlDocPtr doc, char *aid, 
			      struct pac_values *pacs)
{
  xmlNodePtr cur_node;
  int done = 0;
  xmlChar *prop;

  // Check values passed in

  // Search XML space to find the string.
  cur_node = eapfast_xml_find_pac(doc, aid);

  // Read out the values for the PACs and return them.
  if (cur_node != NULL)
    {
      done = 0;

      cur_node = cur_node->children;

      while (cur_node)
	{
	  if (strcmp(cur_node->name, "PAC_key") == 0)
	    {
	      prop = xmlNodeGetContent(cur_node);
	      if (((strlen(prop) % 2) != 0) || (strlen(prop) != 64))
		{
		  // We didn't get a valid string.
		  debug_printf(DEBUG_NORMAL, "Value stored in PAC_key is "
			       "invalid!\n");
		  return -1;
		}
	      process_hex(prop, strlen(prop), pacs->pac_key);
	      // No need to save the length here.  It should ALWAYS be 32!
	    }

	  if (strcmp(cur_node->name, "Cred_Lifetime") == 0)
	    {
	      prop = xmlNodeGetContent(cur_node);
	      if (((strlen(prop) % 2) != 0) || (strlen(prop) != 8))
		{
		  debug_printf(DEBUG_NORMAL, "Invalid setting stored for "
			       "credential lifetime!\n");
		  return -1;
		}
	      process_hex(prop, strlen(prop), pacs->pacinfo.cred_lifetime);
	    }

	  if (strcmp(cur_node->name, "IID") == 0)
	    {
	      prop = xmlNodeGetContent(cur_node);
	      if ((strlen(prop) % 2) != 0)
		{
		  debug_printf(DEBUG_NORMAL, "Invalid settings stored for "
			       "Identity Identifier.\n");
		  return -1;
		}
	      pacs->pacinfo.iid = Malloc((strlen(prop)/2)+1);
	      if (pacs->pacinfo.iid == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to "
			       "store IID data.\n");
		  return -1;
		}
	      process_hex(prop, strlen(prop), pacs->pacinfo.iid);
	      pacs->pacinfo.iid_len = (strlen(prop) / 2);
	    }

	  if (strcmp(cur_node->name, "AID_Info") == 0)
	    {
	      prop = xmlNodeGetContent(cur_node);
	      if ((strlen(prop) % 2) != 0)
		{
		  debug_printf(DEBUG_NORMAL, "Invalid information stored for "
			       "AID Information setting!\n");
		  return -1;
		}
	      pacs->pacinfo.aid_info = Malloc((strlen(prop)/2)+1);
	      if (pacs->pacinfo.aid_info == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Invalid value stored for "
			       "AID Information data!\n");
		  return -1;
		}

	      process_hex(prop, strlen(prop), pacs->pacinfo.aid_info);
	      pacs->pacinfo.aid_info_len = (strlen(prop) / 2);
	    }

	  if (strcmp(cur_node->name, "PAC_Type") == 0)
	    {
	      prop = xmlNodeGetContent(cur_node);
	      pacs->pacinfo.pac_type = atoi(prop);
	    }

	  if (strcmp(cur_node->name, "PAC_opaque") == 0)
	    {
	      prop = xmlNodeGetContent(cur_node);
	      if ((strlen(prop) % 2) != 0)
		{
		  // We didn't get a valid string.
		  debug_printf(DEBUG_NORMAL, "Invalid string stored for "
			       "PAC_opaque!\n");
		  return -1;
		}

	      pacs->pac_opaque = Malloc((strlen(prop)/2) + 1);
	      if (pacs->pac_opaque == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to "
			       "store PAC Opaque!\n");
		  return -1;
		}

	      process_hex(prop, strlen(prop), pacs->pac_opaque);
	      pacs->pac_opaque_len = (strlen(prop) / 2);
	    }

	  cur_node = cur_node->next;
	}
    }
  else
    {
      return -1;
    }

  pacs->pacinfo.aid = Malloc((strlen(aid) / 2) + 1);
  if (pacs->pacinfo.aid == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to store AID!\n");
      return -1;
    }

  process_hex(aid, strlen(aid), pacs->pacinfo.aid);
  pacs->pacinfo.aid_len = (strlen(aid) / 2);

  return 0;
}


#if 0
int main()
{
  xmlDocPtr doc;
  char *packey, *pacopaque;

  // Create a file.
  eapfast_xml_init();

  doc = eapfast_xml_create_pac_struct();

  eapfast_xml_add_pac(doc, "aid1", "packey1", "pacopaque1");
  eapfast_xml_add_pac(doc, "aid2", "packey2", "pacopaque2");
  eapfast_xml_add_pac(doc, "aid4", "packey4", "pacopaque4");

  eapfast_xml_save("testfile.xml", doc);

  eapfast_xml_deinit(doc);

  // Read it back and add to it.
  eapfast_xml_init();

  doc = eapfast_xml_open_pac("testfile.xml");

  if (eapfast_xml_find_pac_data(doc, "aid2", &packey, &pacopaque) == 0)
    {
      printf("PAC_key = %s\n", packey);
      printf("PAC_opaque = %s\n", pacopaque);
    }

  /*
  eapfast_xml_add_pac(doc, "aid3", "packey3", "pacopaque3");
  eapfast_xml_add_pac(doc, "aid5", "packey5", "pacopaque5");

  eapfast_xml_save("testfile2.xml", doc);
  */

  eapfast_xml_deinit(doc);
 
}
#endif


#endif // EAP_FAST
