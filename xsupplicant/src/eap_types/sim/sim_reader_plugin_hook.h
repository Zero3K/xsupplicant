/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file sim_reader_plugin_hook.h
 *
 * \author chris@open1x.org
 *
 **/
#ifndef _SIM_READER_PLUGIN_HOOK_H_
#define _SIM_READER_PLUGIN_HOOK_H_

#define SUPPORT_2G_SIM			BIT(0)
#define SUPPORT_3G_SIM			BIT(1)

int sim_reader_plugin_hook_available();
void sim_reader_plugin_update_reader_list(char **readername);
int sim_reader_plugin_gs_supported();
int sim_reader_plugin_is_my_reader(char *);
int sim_reader_plugin_hook_get_2g_imsi(SCARDHANDLE *card_hdl, char reader_mode, char *pin, char **imsi);
int sim_reader_plugin_hook_get_3g_imsi(SCARDHANDLE *card_hdl, char reader_mode, char *pin, char **imsi);
int sim_reader_plugin_hook_3g_pin_needed(SCARDHANDLE *card_hdl, char reader_mode);
long sim_reader_plugin_hook_card_connect(SCARDCONTEXT *card_ctx, SCARDHANDLE *card_hdl, char *cardreader);
int sim_reader_plugin_hook_card_disconnect(SCARDHANDLE *card_hdl);

int sim_reader_plugin_hook_do_3g_auth(SCARDHANDLE *card_hdl, char reader_mode, 
			  unsigned char *Rand, unsigned char *autn, 
			  unsigned char *c_auts, char *res_len, 
			  unsigned char *c_sres, unsigned char *c_ck, 
			  unsigned char *c_ik, unsigned char *c_kc);

int sim_reader_plugin_hook_do_2g_auth(SCARDHANDLE *card_hdl, char reader_mode, 
			  unsigned char *challenge, unsigned char *response, 
			  unsigned char *ckey);

#endif // _SIM_READER_PLUGIN_HOOK_H_
