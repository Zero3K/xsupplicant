/*******************************************************************
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * File: cardif_freebsd.c
 *
 * Authors: Fernando Schapachnik <fernando@mecon.gov.ar>, based
 * on the work of Ivan Voras <ivoras@fer.hr> and the Linux version by
 * Chris.Hessing@utah.edu.
 *
 *******************************************************************/

#ifndef _CARDIF_FREEBSD_H_
#define _CARDIF_FREEBSD_H_


#include <sys/types.h>
#include <netinet/in.h>
#include <net/if_dl.h>

// We need a couple of pieces of data to make use of this interface.
// Define them here.
struct fbsd_sock_data {
  int sockInt;
  int   bpf;		// bpf handle
  char  *buf;
  int   buf_size;
  struct sockaddr_dl sdl;
};

#endif
