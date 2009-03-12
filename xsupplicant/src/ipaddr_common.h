/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/  
#ifndef __IPADDR_COMMON_H__
#define __IPADDR_COMMON_H__
int ipaddr_common_is_gw_in_subnet(char *addr, char *netmask, char *gateway);
int ipaddr_common_is_netmask_valid(char *netmask);
int ipaddr_common_ip_is_valid(char *ipaddr);
int ipaddr_common_is_broadcast(char *addr, char *netmask);

#endif				// __IPADDR_COMMON_H__
