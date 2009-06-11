/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsup_ipc.h
 *
 * \author chris@open1x.org, terry.simons@open1x.org
 *
 **/

#ifndef _XSUP_IPC_H_
#define _XSUP_IPC_H_

#ifndef WINDOWS
#include <inttypes.h>
#endif

#define IPC_MSG_COMPLETE       0x00	///< With this packet, the IPC message is complete.
#define IPC_MSG_TOTAL_SIZE     BIT(0)	///< The four bytes in the header indicate the total size of the message.
#define IPC_MSG_MORE_FRAGS     BIT(1)	///< There are additional fragments coming.
#define IPC_MSG_FRAG_SIZE      BIT(2)	///< The four bytes in the header indicate the total size of this fragment.

#ifdef WINDOWS
#pragma pack(1)
#endif

#ifdef WINDOWS
typedef struct {
	uint8_t flag_byte;
	uint32_t length;
} ipc_header;
#else
struct _struct_ipc_header {
	uint8_t flag_byte;
	uint32_t length;
} __attribute__ ((__packed__));

typedef struct _struct_ipc_header ipc_header;
#endif

#ifdef WINDOWS
#pragma pack()
#endif

#define CMD_VERSION  "1.0"

int xsup_ipc_init();
int xsup_ipc_send_all(char *, int);
void xsup_ipc_send_eap_notify(char *);
void xsup_ipc_send_log(int, char *);
void xsup_ipc_cleanup();
int xsup_ipc_new_socket(context *, int);

#endif
