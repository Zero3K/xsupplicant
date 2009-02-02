/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsupconfig_devices.c
 *
 * \author chris@open1x.org
 **/

#include <stdio.h>
#include <stdlib.h>

#ifndef WINDOWS
#include <stdint.h>
#endif

#include "xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "src/xsup_debug.h"
#include "xsupconfig_devices.h"
#include "xsupconfig.h"
#include "xsupconfig_vars.h"
#include "liblist/liblist.h"

/**
 * \brief Initialize the devices structure so that it can be populated.
 *
 * Make sure that if we have any memory already allocated for the devices
 * structure that we free it.  When this function terminates, we should have
 * a clean slate to work on.
 **/
void xsupconfig_devices_init()
{
	debug_printf(DEBUG_INIT, "Init devices structure.\n");

	// If there is already something in memory, clean it up.
	if (conf_devices != NULL)
	{
		xsupconfig_devices_deinit(&conf_devices);
	}
}

/**
 * \brief Clean up the interfaces list in memory.
 *
 * Clean out the "interfaces" sub-structure in the devices structure.
 *
 * @param[in] ints   A pointer to the node in the list that contains the
 *                   interface we want to free.
 **/
void xsupconfig_devices_clear_interface(void **inptr)
{
	struct xsup_interfaces *ints = (*inptr);

	FREE(ints->description);
	FREE(ints->driver_type);

	FREE((*inptr));
}

/**
 * \brief Free the memory that is used to store the devices
 *        structure in memory.
 *
 * Go through all of the elements in xsup_devs and free
 * any memory that was allocated.
 *
 * @param[in] xsup_devs   The pointer to the head of the devices structure
 *                        that we need to free.
 **/
void xsupconfig_devices_deinit(struct xsup_devices **xsup_devs)
{
	debug_printf(DEBUG_INIT, "Clearing out devices structure.\n");

	if ((*xsup_devs) == NULL) return;

	// Clear out any interfaces that we may have allocated.
	liblist_delete_list((genlist **)&(*xsup_devs)->interf, xsupconfig_devices_clear_interface);
	(*xsup_devs)->interf = NULL;
	if ((*xsup_devs) != NULL) 
	{
		free((*xsup_devs));
		(*xsup_devs) = NULL;
	}
}

/**
 * \brief Dump all information about interfaces we know about.
 *
 * @param[in] data   A pointer to the head of the interfaces structure
 *                   that we want to dump to the screen/log file.
 **/
void xsupconfig_devices_dump_interfaces(struct xsup_interfaces *data)
{
	struct xsup_interfaces *cur = NULL;
	uint8_t i = 0;

	cur = data;

	while (cur != NULL)
	{
		printf("\t---------- Interface -------------\n");
		printf("\tDescription : %s\n", cur->description);

		printf("\tMAC Address : ");
		for (i=0; i<6; i++)
		{
			printf("%02X", cur->mac[i]);
			if (i != 5) printf(":");
		}
		printf("\n");

		printf("\tDriver Type : %s\n", cur->driver_type);
		printf("\t----------------------------------\n");

		cur = cur->next;
	}
}

/**
 * \brief Dump all information that we know about devices in our structure.
 *
 * @param[in] data   A pointer to the devices structure that we want to dump all 
 *                   of the information for.
 **/
void xsupconfig_devices_dump(struct xsup_devices *data)
{
	if (data == NULL) return;

	xsupconfig_devices_dump_interfaces(data->interf);
}

/**
 * \brief Return a pointer to the interfaces component of the devices structure.
 *
 * \retval NULL if no interfaces exist in the list, or on error
 * \retval ptr to the head of the interfaces list.
 **/
struct xsup_interfaces *xsupconfig_devices_get_interfaces()
{
	if (conf_devices == NULL)
	{
		printf("No devices found in the configuration!\n");
		return NULL;
	}

	return conf_devices->interf;
}
