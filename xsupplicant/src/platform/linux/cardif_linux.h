/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * File: cardif_linux.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef _CARDIF_LINUX_H_
#define _CARDIF_LINUX_H_

// We need a couple of pieces of data to make use of this interface.
// Define them here.
struct lin_sock_data {
  int sockInt;
  struct sockaddr_ll sll;
};

#endif
