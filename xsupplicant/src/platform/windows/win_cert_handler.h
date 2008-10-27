/**
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file win_cert_handler.h
 *
 * \author chris@open1x.org
 **/
#ifndef _WIN_CERT_HANDLER_H_
#define _WIN_CERT_HANDLER_H_

PCCERT_CONTEXT win_cert_handler_get_from_win_store(char *storetype, char *location);

#endif // _WIN_CERT_HANDLER_H_