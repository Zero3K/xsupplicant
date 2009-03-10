/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_linux.c
 *
 * \author chris@open1x.org
 *
 **/

#ifndef _CARDIF_LINUX_H_
#define _CARDIF_LINUX_H_

// We need a couple of pieces of data to make use of this interface.
// Define them here.
struct lin_sock_data {
  int sockInt;
  struct sockaddr_ll sll;
  uint8_t flag_link_state;
};

void cardif_linux_add_interface(char *ifname, int ifindex);
int cardif_linux_get_mac_by_name_no_ctx(char *intname, char *intmac);

#endif
