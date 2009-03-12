/**
 * Windows IP address manipulation functions.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file win_ip_manip.h
 *
 * \author chris@open1x.org
 *
 */  
    
#ifndef _WIN_IP_MANIP_H_
int win_ip_manip_set_dns_domain(context * ctx, char *newdomain);
int win_ip_manip_set_dns_servers(context * ctx, char *dns1, char *dns2,
				  char *dns3);
void win_ip_manip_release_ip(context * ctx);
void win_ip_manip_renew_ip(context * ctx);
void win_ip_manip_release_renew_ip(context * ctx);
int win_ip_manip_set_static_ip(context * ctx, char *addr, char *netmask,
				char *gateway);

#endif				// _WIN_IP_MANIP_H_
