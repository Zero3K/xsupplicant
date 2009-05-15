/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file sim.h
 *
 * \author chris@open1x.org
 */
#ifndef _SIM_H_
#define _SIM_H_

int sim_get_imsi(char **imsi);
int sim_do_2g_auth(unsigned char *challenge, unsigned char *response, unsigned char *ckey);

#endif // _SIM_H_