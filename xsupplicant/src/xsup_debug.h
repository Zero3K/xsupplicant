/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsup_debug.h
 *
 * \author chris@open1x.org
 *
 **/
#ifndef XSUP_DEBUG_H_
#define XSUP_DEBUG_H_

#ifndef WINDOWS
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#else
#include "xsup_common.h"
#endif

#ifdef CALL_TRACE
#define TRACE debug_printf(DEBUG_NORMAL, "Function : %s()\n", __FUNCTION__);
#else
#define TRACE
#endif

// New debug levels
#define DEBUG_NORMAL         BIT(0)
#define DEBUG_INT            BIT(1)
#define DEBUG_PHYSICAL_STATE BIT(2)
#define DEBUG_DOT1X_STATE    BIT(3)
#define DEBUG_1X_BE_STATE    BIT(4)
#define DEBUG_EAP_STATE      BIT(5)
#define DEBUG_KEY_STATE      BIT(6)
#define DEBUG_KEY            BIT(7)
#define DEBUG_AUTHTYPES      BIT(8)
#define DEBUG_CONFIG_PARSE   BIT(9)
#define DEBUG_CONFIG_WRITE   BIT(10)
#define DEBUG_SMARTCARD      BIT(11)
#define DEBUG_SNMP           BIT(12)
#define DEBUG_IPC            BIT(13)
#define DEBUG_INIT           BIT(14)
#define DEBUG_DEINIT         BIT(15)
#define DEBUG_CONTEXT        BIT(16)
#define DEBUG_EVENT_CORE     BIT(17)
#define DEBUG_TLS_CORE       BIT(18)
#define DEBUG_TIMERS         BIT(19)
#define DEBUG_CERTS          BIT(20)
#define DEBUG_TNC            BIT(21)
#define DEBUG_TNC_IMC        BIT(22)
#define DEBUG_PLUGINS        BIT(23)
#define DEBUG_VERBOSE        BIT(24)    // Debug Normal (and then some. ;)
#define DEBUG_NULL           BIT(25)    // Special debug level for sending messages to plugins, but not the log (This one should always be last in order to allow our test program to be a success.)



#define DEBUG_ALL            0x7fffffff  // Enable ALL flags that are defined above.

int logpath_changed(char *newpath);
int logfile_setup();
void logfile_cleanup();
void lowercase(char *);
void debug_setdaemon(int);
void debug_printf(uint32_t, char *, ...);
void debug_printf_nl(uint32_t, char *, ...);
void debug_hex_printf(uint32_t, uint8_t *, int);
void debug_hex_dump(uint32_t, uint8_t *, int);
void debug_alpha_set_flags(char *);
int xsup_assert_long(int, char *, int, char *, int, const char *);
int debug_getlevel();
void xsup_debug_clear_level();
void xsup_debug_set_level(uint32_t);
void xsup_debug_check_log_roll();

void xsup_debug_tracefile_cleanup();
void xsup_debug_create_tracefile(char *tracefilename);

#define xsup_assert(tf, desc, terminal) xsup_assert_long(tf, desc, terminal,\
                                                         __FILE__, __LINE__,\
							 __FUNCTION__)

#endif
