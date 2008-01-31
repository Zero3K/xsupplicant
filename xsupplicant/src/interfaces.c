/**
 * Interface cache implementation.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file interfaces.c
 *
 * \author chris@open1x.org
 *
 * $Id: interfaces.c,v 1.4 2007/10/21 21:54:16 galimorerpg Exp $
 * $Date: 2007/10/21 21:54:16 $
 **/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "libxsupconfig/xsupconfig_structs.h"
#include "xsup_common.h"
#include "libxsupconfig/xsupconfig.h"
#include "context.h"
#include "xsup_debug.h"
#include "interfaces.h"
#include "xsup_err.h"
#include "ipc_events.h"
#include "ipc_events_index.h"

struct interfaces *interface_cache = NULL;

/**
 * Allocate a new space in our linked list to store an interface entry.
 **/
struct interfaces *interfaces_alloc(struct interfaces **root_int)
{
	struct interfaces *cur;

	cur = (*root_int);

	if (cur == NULL)
	{
		// We don't have any interfaces in memory right now.
		cur = Malloc(sizeof(struct interfaces));
		if (cur == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Unable to allocate memory for the interface cache!\n");
			ipc_events_malloc_failed(NULL);
			return NULL;
		}

		(*root_int) = cur;
	}
	else
	{
		while (cur->next != NULL) cur = cur->next;

		cur->next = Malloc(sizeof(struct interfaces));
		if (cur == NULL)
		{
			debug_printf(DEBUG_NORMAL, "Unable to allocate additional memory for the interface cache!\n");
			return NULL;
		}

		cur = cur->next;
	}

	return cur;
}

/**
 *  Add information about an interface to our interface cache.
 **/
int interfaces_add(char *intname, char *desc, char *mac, unsigned char is_wireless)
{
	struct interfaces *cur = NULL;

	cur = interfaces_alloc(&interface_cache);
	if (cur == NULL)
	{
		debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for interface cache!\n");
		return -1;
	}

	cur->intname = _strdup(intname);
	cur->desc = _strdup(desc);
	memcpy(&cur->mac, mac, 6);
	cur->is_wireless = is_wireless;
	cur->next = NULL;

	return XENONE;
}

/**
 *  Return the interface cache "head" pointer.
 **/
struct interfaces *interfaces_get_cache_head()
{
	return interface_cache;
}

/**
 *  Given a MAC address, locate the node in the linked list that contains
 * information about the interface we are looking for.
 **/
struct interfaces *interfaces_get_by_mac(char *mac)
{
	struct interfaces *cur;

	cur = interface_cache;

	while ((cur != NULL) && (memcmp(cur->mac, mac, 6) != 0))
			cur = cur->next;

	return cur;
}

/**
 *  Get the interface name based on the MAC address.
 **/
char *interfaces_get_name_from_mac(char *mac)
{
	struct interfaces *cur;

	cur = interfaces_get_by_mac(mac);

	if (cur == NULL) return NULL;

	return cur->intname;
}

/**
 *  Get the interface description based on the MAC address.
 **/
char *interfaces_get_desc_from_mac(char *mac)
{
	struct interfaces *cur;

	cur = interfaces_get_by_mac(mac);

	if (cur == NULL) return NULL;

	return cur->desc;
}

/**
 *  Dump the interface cache.
 **/
void interfaces_dump_cache()
{
	struct interfaces *cur;

	cur = interface_cache;

	debug_printf(DEBUG_INT, "\n\n\nInterface Cache : \n\n");
	while (cur != NULL)
	{
		debug_printf(DEBUG_INT, "Description : %s\n", cur->desc);
		debug_printf(DEBUG_INT, "\tDevice Name : %s\n", cur->intname);
		debug_printf(DEBUG_INT, "\tMAC address : ");
		debug_hex_printf(DEBUG_INT, (uint8_t *)cur->mac, 6);
		debug_printf_nl(DEBUG_INT, "\n");

		cur = cur->next;
	}
}

/**
 * \brief Delete the contents of a single node.  It is up to the caller to delete the node itself.
 *
 * @param[in] todel   The node that we want to delete the contents of.
 **/
void interfaces_delete_node(struct interfaces *todel)
{
	FREE(todel->desc);
	FREE(todel->intname);
}

/**
 * \brief Delete an interface based on it's interface name.  
 *
 * @param[in] intdesc    The interface description to delete.
 *
 * \retval 1 if interface was found and deleted
 * \retval 0 if the interface was not found
 * \retval -1 on error
 **/
int interfaces_delete(char *intdesc)
{
	struct interfaces *cur = NULL, *last = NULL;

	if (intdesc == NULL) return -1;

	interfaces_dump_cache();

	cur = interface_cache;

	if (cur == NULL) return -1;

	if (strcmp(cur->desc, intdesc) == 0)
	{
		interface_cache = cur->next;

		interfaces_delete_node(cur);
		FREE(cur);

		return 1;
	}

	last = cur;
	cur = cur->next;

	while ((cur != NULL) && (strcmp(cur->desc, intdesc) != 0))
	{
		last = cur;
		cur = cur->next;
	}

	if (cur == NULL) return 0;     // Interface wasn't found.

	// Otherwise, delete it from the tree.
	last->next = cur->next;
	interfaces_delete_node(cur);
	FREE(cur);

	return 1;
}

/**
 *  Flush the interface cache.
 **/
void interfaces_flush_cache()
{
	struct interfaces *cur, *next;

	cur = interface_cache;

	while (cur != NULL)
	{
		next = cur->next;

		interfaces_delete_node(cur);

		FREE(cur);

		cur = next;
	}
}

/**
 *  Given a description, locate the node in the linked list that contains
 * information about the interface we are looking for.
 **/
struct interfaces *interfaces_get_by_desc(char *desc)
{
	struct interfaces *cur = NULL;

	cur = interface_cache;

	while ((cur != NULL) && (cur->desc != NULL) && (strcmp(cur->desc, desc) != 0))
			cur = cur->next;

	return cur;
}
