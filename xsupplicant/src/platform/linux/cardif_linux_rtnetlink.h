/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_linux_rtnetlink.h
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _CARDIF_LINUX_RTNETLINK_H_
#define _CARDIF_LINUX_RTNETLINK_H_

#ifndef IF_LINK_MODE_DORMANT
#define IF_LINK_MODE_DORMANT  1
#endif

#ifndef IF_LINK_MODE_DEFAULT
#define IF_LINK_MODE_DEFAULT  0
#endif

#define ASSOCREQIE_LENGTH_WITH_PMKID 54

void cardif_linux_rtnetlink_init();
void cardif_linux_rtnetlink_cleanup();
int cardif_linux_rtnetlink_check_event(context *, int);
void cardif_linux_rtnetlink_do_link(struct nlmsghdr *, int, int);
void cardif_linux_rtnetlink_ifla_wireless(int, char *, int);

void cardif_linux_rtnetlink_ifla_operstate(int, char *, int);

void cardif_linux_rtnetlink_check_custom(context *, char *);
int cardif_linux_rtnetlink_get_we_ver(context *);
uint8_t cardif_linux_rtnetlink_scancheck(context *);
void cardif_linux_rtnetlink_set_linkmode(context *, uint8_t);
void cardif_linux_rtnetlink_set_operstate(context *, uint8_t);

#endif
