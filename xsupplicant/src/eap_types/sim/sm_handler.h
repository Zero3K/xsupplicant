/*********************************************************************
 *
 * SIM Card Handler for PC/SC lite library
 *
 * This code was developed by Chris Hessing, using code written by :
 *
 * Michael Haberler mah@eunet.at 
 * based on original work by marek@bmlv.gv.at 2000
 * make it work with pcsclite-1.0.1: Vincent Guyot <vguyot@inf.enst.fr>  2002-07-12
 * some parts Chris Hessing chris.hessing@utah.edu
 *
 *
 * This code is released under dual BSD/GPL license.
 *
 **********************************************************************/

#ifdef EAP_SIM_ENABLE

#ifndef _SM_HANDLER_H_
#define _SM_HANDLER_H_

int sm_handler_init_ctx(SCARDCONTEXT *);
char *sm_handler_get_readers(SCARDCONTEXT *);
long sm_handler_card_connect(SCARDCONTEXT *, SCARDHANDLE *, char *);
int sm_handler_wait_card_ready(SCARDHANDLE *, int);
char *sm_handler_2g_imsi(SCARDHANDLE *, char, char *);
int sm_handler_do_2g_auth(SCARDHANDLE *, char, unsigned char *, 
			  unsigned char *, unsigned char *);

char *sm_handler_3g_imsi(SCARDHANDLE *, char, char *);
int sm_handler_do_3g_auth(SCARDHANDLE *, char reader_mode,
			  unsigned char *, unsigned char *,
			  unsigned char *, char *, unsigned char *,
			  unsigned char *, unsigned char *,
			  unsigned char *);

int sm_handler_card_disconnect(SCARDHANDLE *);

int sm_handler_close_sc(SCARDHANDLE *, SCARDCONTEXT *);
#endif
#endif
