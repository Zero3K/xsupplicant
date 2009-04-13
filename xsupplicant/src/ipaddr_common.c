/**
*
* Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
*
* \file ipaddr_common.c
*
* \author chris@open1x.org
*
**/  

#ifdef WINDOWS
#include <windows.h>
#endif				

#include "xsup_common.h"
#include "ipaddr_common.h"

/**
* \brief Validate that an IP address is valid.  (i.e. Not 0.0.0.0 or 255.255.255.255)
*
* @param[in] ipaddr   A string that contains the IP address to be validated.
*
* \retval TRUE if it is valid
* \retval FALSE if it isn't.
**/ 
int ipaddr_common_ip_is_valid(char *ipaddr) 
{
	if (ipaddr == NULL)
		return FALSE;

	if (strcmp(ipaddr, "0.0.0.0") == 0)
		return FALSE;

	if (strcmp(ipaddr, "255.255.255.255") == 0)
		return FALSE;

	return TRUE;
}


/**
* \brief Check to see if a netmask is valid.
*
* \retval TRUE if it is.
* \retval FALSE if it isn't.
**/ 
int ipaddr_common_is_netmask_valid(char *netmask) 
{
	uint32_t addr = 0;
	int ones = TRUE;
	int i = 0;
	int x = 0;

	if (netmask == NULL)
		return FALSE;

	addr = inet_addr(netmask);
	if (addr == 0)
		return FALSE;

	addr = ntohl(addr);

	if ((addr & 0x80000000) != 0x80000000)
	{
		// Our first bit isn't 1, this mask is invalid.
		return FALSE;
	}

	for (i = 31; i >= 0; i--)
	{
		x = 0;
		x = (1 << i);
		if ((x & addr) == x)
		{
			if (ones != TRUE)
				return FALSE;	// We got an "out of place" 1.
		}
		else
		{
			if (ones == TRUE)
			{
				ones = FALSE;	// From here on out, everything should be a 0.
			}
		}
	}

	return TRUE;
}


/**
* \brief Determine if the gateway provided is in the same subnet as the address provided.
*
* @param[in] addr   A string representation of the IP address we want to use.
* @param[in] netmask   A string representation of the netmask we want to use.
* @param[in] gateway   A string representation of the gateway we want to use.
*
* \retval TRUE if the gateway is in the same network as the network address.
* \retval FALSE if it isn't.
**/ 
int ipaddr_common_is_gw_in_subnet(char *addr, char *netmask, char *gateway) 
{
	uint32_t addr_n = 0, netmask_n = 0, gateway_n = 0;
	uint32_t addr_net_part = 0;
	uint32_t gw_net_part = 0;

	if ((addr == NULL) || (netmask == NULL) || (gateway == NULL))
		return FALSE;

	addr_n = inet_addr(addr);
	netmask_n = inet_addr(netmask);
	gateway_n = inet_addr(gateway);

	if ((addr_n == 0) || (netmask_n == 0) || (gateway_n == 0))
		return FALSE;

	addr_net_part = addr_n & netmask_n;
	gw_net_part = gateway_n & netmask_n;

	if (addr_net_part != gw_net_part)
		return FALSE;	// They are in different subnets.

	return TRUE;
}


/**
* \brief Determine if the IP address provided is a broadcast address
*
* @param[in] addr   A string representation of the IP address we want to use.
* @param[in] netmask   A string representation of the netmask we want to use.
*
* \retval TRUE if the IP address is a broadcast address (0s or 1s.)
* \retval FALSE if it isn't.
**/ 
int ipaddr_common_is_broadcast(char *addr, char *netmask) 
{
	uint32_t addr_n = 0, netmask_n = 0;
	uint32_t addr_host_part = 0;

	if ((addr == NULL) || (netmask == NULL))
		return FALSE;

	addr_n = inet_addr(addr);
	netmask_n = inet_addr(netmask);

	if ((addr_n == 0) || (netmask_n == 0))
		return FALSE;

	netmask_n = ~netmask_n;
	addr_host_part = addr_n & netmask_n;

	if ((addr_host_part == 0) || (addr_host_part == netmask_n))
		return TRUE;

	return FALSE;
}


