/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file cardif_macosx.c
 *
 * \author Fernando Schapachnik <fernando@mecon.gov.ar>, based
 * on the work of Ivan Voras <ivoras@fer.hr> and the Linux version by
 * chris@open1x.org
 *
 * \author chris@open1x.org, derived from work by authors above.
 *
 *******************************************************************/

#ifndef _CARDIF_MACOSX_H_
#define _CARDIF_MACOSX_H_


#include <sys/types.h>
#include <netinet/in.h>
#include <net/if_dl.h>

// We need a couple of pieces of data to make use of this interface.
// Define them here.
struct darwin_sock_data {
  int sockInt;
  char *wireless_blob;
};

int cardif_macosx_manual_events(context *);
#endif
