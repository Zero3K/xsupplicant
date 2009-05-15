/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file config_manager.h
 *
 * \author chris@open1x.org
 */
#ifndef _CONFIG_MANAGER_H_
#define _CONFIG_MANAGER_H_

int load_sim_config();
int get_imsi(char **imsi);
int get_k(char **k);
int get_sqn(char **sqn);
int get_amf(char **amf);
int get_oc(char **oc);
int write_sim_config();
int set_sqn(char *sqn);
int free_sim_config();

#endif // _CONFIG_MANAGER_H_