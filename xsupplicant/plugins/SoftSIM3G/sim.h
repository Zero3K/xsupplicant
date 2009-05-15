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

int sim_do_3g_auth(unsigned char *Rand, unsigned char *autn, unsigned char *c_auts, unsigned char *res_len, unsigned char *c_sres, unsigned char *c_ck, unsigned char *c_ik, unsigned char *c_kc);

#endif // _SIM_H_