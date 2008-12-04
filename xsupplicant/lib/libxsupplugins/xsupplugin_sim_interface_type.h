/**
 * Header for all possible functions that can be provided through a PLUGIN_TYPE_SIM_INTERFACE
 *	plugin.
 *
 * \note It is not necessary to include this file in your plugin unless you want to.  It's
 *			main purpose is to track different entry points, and document them for other
 *			developers to use.
 *
 * Licensed under a dual GPL/BSD license.   (See LICENSE file for more info.)
 *
 * \file xsupconfig_vars.h
 *
 * \author chris@open1x.org
 *
 **/
#ifndef XSUPPLUGIN_SIM_INTERFACE_TYPE_H_
#define XSUPPLUGIN_SIM_INTERFACE_TYPE_H_

void sim_hook_update_reader_list(char **readerlist);		// MANDATORY
int sim_hook_reader_gs_supported(void *card_hdl);			// MANDATORY
int sim_hook_get_2g_imsi(void *cardhdl, char reader_mode, char *pin, char **imsi);  // OPTIONAL
int sim_hook_get_3g_imsi(void *cardhdl, char reader_mode, char *pin, char **imsi);	// OPTIONAL
int sim_hook_2g_pin_needed(void *card_hdl, char reader_mode);		// OPTIONAL
int sim_hook_3g_pin_needed(void *card_hdl, char reader_mode);		// OPTIONAL
int sim_hook_card_connect(void *card_ctx, void *card_hdl, char *cardreader);	// MANDATORY
int sim_hook_card_disconnect(void *card_hdl);									// MANDATORY
int sim_hook_wait_card_ready(SCARDHANDLE *card_hdl, int waittime);				// MANDATORY

int sim_hook_do_3g_auth(void *card_hdl, char reader_mode, unsigned char *Rand, unsigned char *autn,
		unsigned char *c_auts, char *res_len, unsigned char *c_sres, unsigned char *c_ck,
		unsigned char *c_ik, unsigned char *c_kc);								// OPTIONAL

int sim_hook_do_2g_auth(void *card_hdl, char reader_mode, unsigned char *challenge, unsigned char *response,
		unsigned char *ckey);													// OPTIONAL

#endif // XSUPPLUGIN_SIM_INTERFACE_TYPE_H_