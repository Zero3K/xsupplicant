/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file win_cert_handler.h
 *
 * \author chris@open1x.org
 **/
#ifndef _WIN_CERT_HANDLER_H_
#define _WIN_CERT_HANDLER_H_

PCCERT_CONTEXT win_cert_handler_get_from_win_store(char *storetype,
						   char *location);
PCCERT_CONTEXT win_cert_handler_get_from_user_store(char *storetype,
						    char *location);
int win_cert_handler_load_user_cert(struct tls_vars *mytls_vars,
				    PCCERT_CONTEXT mycert);

#endif				// _WIN_CERT_HANDLER_H_
