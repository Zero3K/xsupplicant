/**
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
 **********************************************************************
 * --- BSD License ---
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  - All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *       This product includes software developed by the University of
 *       Maryland at College Park and its contributors.
 *  - Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Smart card handler functions.
 * 
 * \file sm_handler.c
 *
 * \author chris@open1x.org
 *
 * \todo Add IPC error events
 *
 **/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/

/* Interface to Smart Cards using PCSC with 802.1X.  */

#ifdef EAP_SIM_ENABLE

#include <stdio.h>
#include <winscard.h>
#include <string.h>
#include <ctype.h>

#ifndef WINDOWS
#include <strings.h>
#include <unistd.h>
#endif

#include <stdlib.h>

#include "../../xsup_debug.h"
#include "../../xsup_err.h"
#include "sm_handler.h"
#include "sim_reader_plugin_hook.h"
#include "../../xsup_common.h"

#ifdef USE_EFENCE
#include <efence.h>
#endif

#ifndef MAX_ATR_SIZE
#define MAX_ATR_SIZE    32	// This isn't defined on Windows for some reason.
#endif

#ifndef WINDOWS
#define _snprintf snprintf
#endif

// 2G bytecodes
#define SELECT_MF       "A0A40000023F00"
#define SELECT_DF_GSM   "A0A40000027F20"
#define SELECT_EF_IMSI  "A0A40000026F07"
#define RUN_GSM         "A088000010"
#define GET_IMSI        "A0B0000009"

// 3G bytecodes
#define SELECT_MF_USIM  "00A4000C"
#define SELECT_EF_ICCID "00A40004022FE2"
#define SELECT_FCP      "00A4000C"
#define SELECT_EFDIR    "00A40004022F00"
#define EFDIR_READREC1  "00B20104FF"
#define CHV_RETRIES     "0020000100"
#define CHV_UNBLOCK     "002C000110"
#define CHV_ATTEMPT     "0020000108"
#define USELECT_EF_IMSI "00A40904026F07"
#define READ_IMSI       "00B0000009"

#define MODE2G          1
#define MODE3G          0

#define DO_DEBUG        1

#define MAXBUFF         512

typedef unsigned char u8;

/* structure of the EFdir AID (application ID) */
typedef struct t_efdir {
	u8 tag61;
	u8 length;

	u8 tag4f;
	u8 aid_len;

	/* application identifier value */
	u8 rid[5];
	u8 app_code[2];		/* 0x1002 for 3G USIM app */
	u8 country_code[2];
	u8 prov_code[3];
	u8 prov_field[4];

	u8 tag50;
	u8 al_len;
	u8 app_label[16];	/* like "Mobilkom Austria", 0xff padded */
} t_efdir;

typedef struct {
  u8 msk[2], rsp[2];
  char *text;
} t_response;

const t_response response[] = {

	{{0xff, 0xff}, {0x90, 0x00}, "Ok"},

	{{0xff, 0xff}, {0x98, 0x02}, "no CHV initialized"},
	{{0xff, 0xff}, {0x98, 0x04}, "access condition not fulfilled"},
	{{0xff, 0xff}, {0x98, 0x08}, "in contradiction with CHV status"},
	{{0xff, 0xff}, {0x98, 0x10},
	 "in contradiction with invalidation status"},
	{{0xff, 0xff}, {0x98, 0x40},
	 "unsuccessful CHV verification, no attempts left"},

	{{0xff, 0xff}, {0x98, 0x50},
	 "decrease cannot be performed, maximum value reached"},
	{{0xff, 0xff}, {0x98, 0x62}, "verify if MAC  == XMAC"},
	{{0xff, 0xff}, {0x98, 0x64}, "Service not available"},

	{{0xff, 0x00}, {0x9f, 0x00}, "%d response bytes available"},

	{{0xff, 0x00}, {0x61, 0x00}, "%d response bytes available"},

	{{0xff, 0xff}, {0x62, 0x00}, "curent file is already activated"},
	{{0xff, 0xff}, {0x62, 0x81}, "returned data may be corrupt"},
	{{0xff, 0xff}, {0x62, 0x82}, "EOF reached prematurely"},
	{{0xff, 0xff}, {0x62, 0x83}, "selected file invalid"},
	{{0xff, 0xff}, {0x62, 0x84}, "FCI not formated"},
	{{0xff, 0x00}, {0x62, 0x00}, "nvmem unchanged"},

	{{0xff, 0x00}, {0x63, 0x81}, "file filled up by last write"},
	{{0xff, 0xf0}, {0x63, 0xc0}, "Counter=%1.1X"},
	{{0xff, 0x00}, {0x63, 0x00}, "nvmem changed1"},

	{{0xff, 0xff}, {0x64, 0x00},
	 "nvmem unchanged or no active application"},
	{{0xff, 0x00}, {0x64, 0x00}, "nvmem unchanged - RFU"},

	{{0xff, 0xff}, {0x65, 0x00}, "nvmem changed2"},
	{{0xff, 0xff}, {0x65, 0x81}, "nvmem changed - memory failure"},
	{{0xff, 0x00}, {0x65, 0x00}, "nvmem changed - unknown?"},

	{{0xff, 0x00}, {0x66, 0x00}, "security related %d"},

	{{0xff, 0xff}, {0x67, 0x00}, "wrong length"},
	{{0xff, 0x00}, {0x67, 0x00}, "wrong length - %d expected"},

	{{0xff, 0xff}, {0x68, 0x81},
	 "wrong cla - logical channel not supported"},
	{{0xff, 0xff}, {0x68, 0x82},
	 "wrong cla - secure messaging not supported"},
	{{0xff, 0x00}, {0x68, 0x00}, "cla not supported"},

	{{0xff, 0xff}, {0x69, 0x81},
	 "command incompatible with file structure"},
	{{0xff, 0xff}, {0x69, 0x82}, "security status not satisfied (PIN1)"},
	{{0xff, 0xff}, {0x69, 0x83},
	 "authentication method blocked - no PIN attempts left"},
	{{0xff, 0xff}, {0x69, 0x84}, "referenced data invalid"},
	{{0xff, 0xff}, {0x69, 0x85}, "conditions of use not satisfied"},
	{{0xff, 0xff}, {0x69, 0x86}, "command not allowed - no current EF"},
	{{0xff, 0xff}, {0x69, 0x87}, "expected SM data objects missing"},
	{{0xff, 0xff}, {0x69, 0x88}, "SM data objects incorrect"},
	{{0xff, 0x00}, {0x69, 0x00}, "command not allowed"},

	{{0xff, 0xff}, {0x6a, 0x80},
	 "P1-P2: incorrect parameters in data field"},
	{{0xff, 0xff}, {0x6a, 0x81}, "P1-P2: function not supported"},
	{{0xff, 0xff}, {0x6a, 0x82}, "P1-P2: file/search pattern not found"},
	{{0xff, 0xff}, {0x6a, 0x83}, "P1-P2: record not found"},
	{{0xff, 0xff}, {0x6a, 0x84}, "P1-P2: not enough memory space in file"},
	{{0xff, 0xff}, {0x6a, 0x85}, "P1-P2: Lc inconsistent with TLV"},
	{{0xff, 0xff}, {0x6a, 0x86}, "P1-P2 incorrect (out of range)"},
	{{0xff, 0xff}, {0x6a, 0x87}, "P1-P2 inconsistent with Lc"},
	{{0xff, 0xff}, {0x6a, 0x88},
	 "verify if EFkeyop exists attached to current file"},

	{{0xff, 0xff}, {0x6a, 0x88}, "Referenced data not found"},
	{{0xff, 0xff}, {0x6a, 0x89}, "File already exists in current DF"},

	{{0xff, 0x00}, {0x6a, 0x00}, "P1-P2 invalid"},

	{{0xff, 0x00}, {0x6b, 0x00}, "P1-P2 invalid"},

	{{0xff, 0x00}, {0x6c, 0x00}, "wrong length -  %d expected"},

	{{0xff, 0x00}, {0x6d, 0x00}, "INS code not supported or invalid"},

	{{0xff, 0x00}, {0x6e, 0x00}, "CLA %02X not supported"},

	{{0xff, 0xff}, {0x6f, 0x01}, "no active application"},
	{{0xff, 0xff}, {0x6f, 0x06}, "FCP formatting aborted"},
	{{0xff, 0xff}, {0x6f, 0x19}, "no valid key attached to current file"},

	{{0xff, 0xff}, {0x6f, 0x00}, "EF or DF integrity error"},
	{{0xff, 0xff}, {0x6f, 0x03},
	 "Decrements number of the unblock mechanism (if not 0xff)"},
	{{0xff, 0xff}, {0x6f, 0x07}, "incorrect child number"},
	{{0xff, 0xff}, {0x6f, 0x0d},
	 "Reset PIN/ADM retry counter or disable EFpin or EFadm"},
	{{0xff, 0xff}, {0x6f, 0x0e},
	 "Reset UNBLOCK PIN error counter to maximum value"},
	{{0xff, 0xff}, {0x6f, 0x15}, "PIN/ADM enable/disable not allowed"},
	{{0xff, 0xff}, {0x6f, 0x16}, "incorrect UNBLOCK pin"},
	{{0xff, 0xff}, {0x6f, 0x17},
	 "number of unblock mechanism is not equal to 0x00"},
	{{0xff, 0xff}, {0x6f, 0x1e}, "no data waiting for GET RESPONSE"},
	{{0xff, 0xff}, {0x6f, 0x1f}, "File deactivated"},
	{{0xff, 0xff}, {0x6f, 0x22}, "length of search pattern > 128 bytes"},
	{{0xff, 0x00}, {0x6f, 0x00}, "no precise diagnosis"},

	{{0x00, 0x00}, {0x00, 0x00}, "Unknown response"}
};

void print_sc_error(long err)
{
	switch (err) {
	case SCARD_E_CANCELLED:
		debug_printf(DEBUG_NORMAL, "Error : Card Request Cancelled!\n");
		break;
	case SCARD_E_CANT_DISPOSE:
		debug_printf(DEBUG_NORMAL, "Error : Can't dispose (!?)\n");
		break;
	case SCARD_E_INSUFFICIENT_BUFFER:
		debug_printf(DEBUG_NORMAL, "Error : Insufficient Buffer\n");
		break;
	case SCARD_E_INVALID_ATR:
		debug_printf(DEBUG_NORMAL, "Error : Invalid ATR\n");
		break;
	case SCARD_E_INVALID_HANDLE:
		debug_printf(DEBUG_NORMAL, "Error : Invalid handle\n");
		break;
	case SCARD_E_INVALID_PARAMETER:
		debug_printf(DEBUG_NORMAL, "Error : Invalid parameter\n");
		break;
	case SCARD_E_INVALID_TARGET:
		debug_printf(DEBUG_NORMAL, "Error : Invalid target\n");
		break;
	case SCARD_E_INVALID_VALUE:
		debug_printf(DEBUG_NORMAL, "Error : Invalid Value\n");
		break;
	case SCARD_E_NO_MEMORY:
		debug_printf(DEBUG_NORMAL, "Error : No memory\n");
		break;
	case SCARD_F_COMM_ERROR:
		debug_printf(DEBUG_NORMAL, "Error : Communication error \n");
		break;
	case SCARD_F_INTERNAL_ERROR:
		debug_printf(DEBUG_NORMAL, "Error : Internal error\n");
		break;
	case SCARD_F_WAITED_TOO_LONG:
		debug_printf(DEBUG_NORMAL, "Error : Waited too long\n");
		break;
	case SCARD_E_UNKNOWN_READER:
		debug_printf(DEBUG_NORMAL, "Error : Unknown reader\n");
		break;
	case SCARD_E_TIMEOUT:
		debug_printf(DEBUG_NORMAL, "Error : Timeout\n");
		break;
	case SCARD_E_SHARING_VIOLATION:
		debug_printf(DEBUG_NORMAL, "Error : Sharing Violation\n");
		break;
	case SCARD_E_NO_SMARTCARD:
		debug_printf(DEBUG_NORMAL, "Error : No smartcard!\n");
		break;
	case SCARD_E_UNKNOWN_CARD:
		debug_printf(DEBUG_NORMAL, "Error : Unknown card!\n");
		break;
	case SCARD_E_PROTO_MISMATCH:
		debug_printf(DEBUG_NORMAL, "Error : Protocol mismatch!\n");
		break;
	case SCARD_E_NOT_READY:
		debug_printf(DEBUG_NORMAL, "Error : Not ready!\n");
		break;
	case SCARD_E_SYSTEM_CANCELLED:
		debug_printf(DEBUG_NORMAL, "Error : System Cancelled\n");
		break;
	case SCARD_E_NOT_TRANSACTED:
		debug_printf(DEBUG_NORMAL, "Error : Not Transacted\n");
		break;
	case SCARD_E_READER_UNAVAILABLE:
		debug_printf(DEBUG_NORMAL, "Error : Reader unavailable\n");
		break;
	case SCARD_F_UNKNOWN_ERROR:
	default:
		debug_printf(DEBUG_NORMAL, "Unknown error!\n");
		break;
	}
}

int sm_handler_init_ctx(SCARDCONTEXT * card_ctx)
{
	long ret;

	if (!card_ctx) {
		debug_printf(DEBUG_NORMAL,
			     "Invalid memory location for card context!\n");
		return -1;
	}

	*card_ctx = 0;

	ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, card_ctx);
	if (ret != SCARD_S_SUCCESS) {
		if (sim_reader_plugin_hook_available() != FALSE)
		{
			debug_printf(DEBUG_NORMAL, "Unable to initialize any hardware smartcard readers.  But at least one software reader is available.\n");
			return 0;
		}

		debug_printf(DEBUG_NORMAL,
			     "Couldn't establish Smart Card context!  "
			     "(Is pcscd loaded?)\n");
		print_sc_error(ret);
		return -1;
	}

	return 0;
}

char *sm_handler_get_readers(SCARDCONTEXT * card_ctx)
{
	unsigned long readerstrlen = 0;
	char *readername = NULL;
	int ret = 0;

	ret = SCardListReaders(*card_ctx, NULL, NULL, &readerstrlen);
	if (ret != SCARD_S_SUCCESS) {
		if (sim_reader_plugin_hook_available() != TRUE) {
			debug_printf(DEBUG_NORMAL,
				     "Error requesting list of smart card "
				     "readers!\n");
			print_sc_error(ret);
			return NULL;
		}
	}

	if (readerstrlen > 0) {
		readername = (char *)Malloc(readerstrlen + 1);
		if (readername == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't allocate memory for reader name! "
				     "(%s:%d)\n", __FUNCTION__, __LINE__);
			return NULL;
		}

		ret = SCardListReaders(*card_ctx, NULL, readername,
				     &readerstrlen);
		if (ret != SCARD_S_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Error requesting list of smart card "
				     "readers!\n");
			print_sc_error(ret);
			return NULL;
		}
	}

	if (sim_reader_plugin_hook_available() == TRUE) {
		// Give our SIM reader plugin the chance to modify our list.
		sim_reader_plugin_update_reader_list(&readername);
	}

	return readername;
}

long sm_handler_card_connect(SCARDCONTEXT * card_ctx, SCARDHANDLE * card_hdl,
			     char *cardreader)
{
        long ret;
        unsigned long activeprotocol;
	int result;

	debug_printf(DEBUG_AUTHTYPES, "Using reader : %s\n", cardreader);

	if (sim_reader_plugin_hook_available() == TRUE) {
		// Process it through our plugin.
		result =
		    sim_reader_plugin_hook_card_connect(card_ctx, card_hdl,
							cardreader);
		debug_printf(DEBUG_AUTHTYPES, "%s() plugin returns - %d\n",
			     __FUNCTION__, result);
		if (result >= 0)
			return result;
	}

	while (1) {
		ret = SCardConnect(*card_ctx, cardreader, SCARD_SHARE_SHARED,
				   SCARD_PROTOCOL_T0, card_hdl,
				   &activeprotocol);
		if (ret == SCARD_S_SUCCESS)
			break;

		if (ret == SCARD_E_NO_SMARTCARD) {
			// XXX This should be changed when we attach a GUI to Xsupplicant.
			debug_printf(DEBUG_NORMAL,
				     "Please insert a smart card!\n");

			// XXX The sleep commands below need to be removed!
#ifndef WINDOWS
			sleep(2);
#else
			Sleep(2);
#endif
		} else {
			debug_printf(DEBUG_NORMAL,
				     "Error attempting to connect to the "
				     "smart card!  \n");
			print_sc_error(ret);
			return -1;
			break;
		}
	}
	return 0;
}

int sm_handler_wait_card_ready(SCARDHANDLE * card_hdl, int waittime)
{
	DWORD dwState, dwProtocol, dwAtrLen, size;
	BYTE pbAtr[MAX_ATR_SIZE];
	int loopcnt, ret;
	LPSTR mszReaders;
	int result = 0;

	loopcnt = 0;

	if (sim_reader_plugin_hook_available() == TRUE) {
		// Process it through our plugin.
		result =
		    sim_reader_plugin_hook_wait_card_ready(card_hdl, waittime);
		if (result >= 0)
			return result;
	}

	while (1) {
		dwState = 0;
		dwProtocol = 0;
		dwAtrLen = MAX_ATR_SIZE;
		size = 150;

		mszReaders = (LPSTR) Malloc(size);
		if (mszReaders == NULL) {
			debug_printf(DEBUG_NORMAL,
				     "Error trying to allocate memory for "
				     "mszReaders!  (%s:%d)\n", __FUNCTION__,
				     __LINE__);
			return XEMALLOC;
		}

		memset(&pbAtr, 0x00, MAX_ATR_SIZE);
		ret =
		    SCardStatus(*card_hdl, mszReaders, &size, &dwState,
				&dwProtocol, pbAtr, &dwAtrLen);
		if (ret != SCARD_S_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Error getting smart card status! ");
			print_sc_error(ret);
			FREE(mszReaders);

			return -1;
		}
		// XXX We should pass these up to the GUI when we get that going!
		switch (dwState) {
		case SCARD_ABSENT:
			debug_printf(DEBUG_NORMAL,
				     "There is no card in the reader!\n");
			break;

		case SCARD_PRESENT:
			debug_printf(DEBUG_NORMAL,
				     "The card needs to be moved to a position"
				     " that the reader can use!\n");
			break;

		case SCARD_SWALLOWED:
			debug_printf(DEBUG_NORMAL,
				     "Card is ready, but not powered!\n");
			break;

		case SCARD_POWERED:
			debug_printf(DEBUG_NORMAL,
				     "Card is powered, but in an unknown "
				     "mode!\n");
			break;

		default:
			FREE(mszReaders);
			return XENONE;
		}

		FREE(mszReaders);

		if ((loopcnt >= waittime) && (waittime != 0)) {
			return -1;
		}
		// XXX Need to remove this in order to make life happy!
#ifndef WINDOWS
		sleep(1);
#else
		Sleep(1);
#endif
	}
}

int hextoint(u8 x)
{
	x = toupper(x);
	if (x >= 'A' && x <= 'F')
		return x - 'A' + 10;
	else if (x >= '0' && x <= '9')
		return x - '0';
	fprintf(stderr, "bad input.\n");
	exit(1);
}

/* convert commands of format 'A00001' or 'A0 00 01' to binary form */
int strtohex(u8 * src, u8 * dest, int *blen)
{
	int i, len;
	unsigned char *p, *q;
	unsigned char buf[512];

	p = src;
	q = buf;
	while (*p) {		/* squeeze out any whitespace */
		if (!isspace(*p)) {
			*q++ = *p;
		}
		p++;
	}
	*q = '\0';
	src = buf;
	if ((len = strlen((char *)src)) & 0x01) {	/* oops, odd number of nibbles */
		debug_printf(DEBUG_NORMAL,
			     "strtohex: odd number of nibbles!\n");
		return -1;
	}
	len /= 2;
	for (i = 0; i < len; i++, src += 2)
		dest[i] = (hextoint(*src) << 4) | hextoint(*(src + 1));
	*blen = len;
	return 0;
}

int sm_check_response(uint8_t s1, uint8_t s2)
{
	uint8_t t;

	switch (s1) {
	case 0x67:
		debug_printf(DEBUG_NORMAL, "SIM : incorrect parameter P3\n");
		break;

	case 0x6B:
		debug_printf(DEBUG_NORMAL,
			     "SIM : incorrect parameter P1 or P2\n");
		break;

	case 0x6D:
		debug_printf(DEBUG_NORMAL,
			     "SIM : unknown instruction code given in the command\n");
		break;

	case 0x6E:
		debug_printf(DEBUG_NORMAL,
			     "SIM : wrong instruction class given in the command\n");
		break;

	case 0x6F:
		debug_printf(DEBUG_NORMAL,
			     "SIM : technical problem with no diagnostic gien\n");
		break;

	case 0x6C:
		debug_printf(DEBUG_SMARTCARD,
			     "SIM : Invalid length.  Should have been %d.\n",
			     s2);
		break;

	case 0x92:
		if (s2 == 0x40) {
			debug_printf(DEBUG_NORMAL, "SIM : memory problem\n");
		} else {
			debug_printf(DEBUG_NORMAL,
				     "SIM : command successful but after using an internal update retry routine %d time(s)\n",
				     s2);
		}
		break;

	case 0x94:
		switch (s2) {
		case 0x00:
			debug_printf(DEBUG_NORMAL, "SIM : no EF selected\n");
			break;

		case 0x02:
			debug_printf(DEBUG_NORMAL,
				     "SIM : out of range (invalid address)\n");
			break;

		case 0x04:
			debug_printf(DEBUG_NORMAL,
				     "SIM : file ID, or pattern, not found\n");
			break;

		case 0x08:
			debug_printf(DEBUG_NORMAL,
				     "SIM : file is inconsistent with the command\n");
			break;

		default:
			return -1;
			break;
		}
		break;

	case 0x98:
		switch (s2) {
		case 0x02:
			debug_printf(DEBUG_NORMAL,
				     "SIM : no CHV initialised\n");
			break;

		case 0x04:
			debug_printf(DEBUG_NORMAL,
				     "SIM : access condition not fulfilled\n");
			break;

		case 0x08:
			debug_printf(DEBUG_NORMAL,
				     "SIM : in contradiction with CHV status\n");
			break;

		case 0x10:
			debug_printf(DEBUG_NORMAL,
				     "SIM : in contradiction with invalidation status\n");
			break;

		case 0x40:
			debug_printf(DEBUG_NORMAL,
				     "SIM : unsuccessful CHV verification, no attempt left\n");
			break;

		case 0x50:
			debug_printf(DEBUG_NORMAL,
				     "SIM : increase cannot be performed, max value reached\n");
			break;

		default:
			return -1;
			break;
		}
		break;

	case 0x69:
		switch (s2) {
		case 0x82:
			debug_printf(DEBUG_NORMAL,
				     "SIM : Security status not satisfied\n");
			break;

		case 0x85:
			debug_printf(DEBUG_NORMAL,
				     "SIM : Conditions of use not satisfied\n");
			break;

		default:
			return -1;
			break;
		}

	case 0x6a:
		switch (s2) {
		case 0x88:
			debug_printf(DEBUG_NORMAL,
				     "SIM : reference data not found\n");
			break;

		default:
			if ((s2 & 0x80) == 0x80) {
				debug_printf(DEBUG_SMARTCARD,
					     "Invalid P1-P2 value.\n");
			} else {
				return -1;
			}
		}
		break;

	case 0x63:
		switch (s2) {
		case 0x00:
			debug_printf(DEBUG_NORMAL,
				     "SIM : authentication failed\n");
			break;

		case 0x01:
			debug_printf(DEBUG_NORMAL,
				     "SIM : synchronisation failure\n");
			break;

		default:
			if ((s2 & 0xc0) == 0xc0) {
				t = s2 - 0xc0;
				debug_printf(DEBUG_NORMAL,
					     "%d pin attempts remain.\n", t);
			} else {
				return -1;
			}
		}
		break;

	default:
		return -1;
	}

	return 0;
}

/* card_io -
 *    send a command to the card
 *    if return code indicates a GET RESPONSE is needed,
 *    it is exceuted - depending on context (2G, 3G) with
 *    the appropriate class byte.
 *    the data and length is returned.
 */
int
cardio(SCARDHANDLE * card_hdl, char *cmd, long reader_protocol, char mode2g,
       LPBYTE outbuff, LPDWORD olen, char debug)
{
	static char getresponse[5] = { 0xa0, 0xc0, 0x00, 0x00, 0x00 };
	int cmdlen, ret, p;
	u8 bcmd[MAXBUFF];
	SCARD_IO_REQUEST scir;

	strtohex((unsigned char *)cmd, bcmd, &cmdlen);
	*olen = MAXBUFF;	/* hm... */

	scir.dwProtocol = reader_protocol;
	scir.cbPciLength = sizeof(scir);

	memset(outbuff, 0, MAXBUFF);

	if ((ret = SCardTransmit(*card_hdl,
			   reader_protocol ==
			   SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 : SCARD_PCI_T0,
			   bcmd, cmdlen, &scir, (BYTE *) outbuff,
			   olen)) != SCARD_S_SUCCESS) {
		debug_printf(DEBUG_NORMAL,
			     "Error sending commands to the smart card!\n");
		print_sc_error(ret);
		return ret;
	}

	if (*olen == 2) {
		switch ((u8) outbuff[0]) {
		case 0x61:
		case 0x9f:
			if (outbuff[1] == 0) {	/* nothing returned */
				debug_printf(DEBUG_NORMAL,
					     "Nothing was returned when something was "
					     "expected!\n");
				break;
			}
			getresponse[4] = outbuff[1];	/* cmd ok, set length for GET RESPONSE  */
			if (mode2g == 1) {
				getresponse[0] = 0xa0;	/* set class byte for card  */
			} else {
				getresponse[0] = 0x00;
			}

			*olen = MAXBUFF;
			if ((ret = SCardTransmit(*card_hdl,
						 reader_protocol == SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 : SCARD_PCI_T0,
						 (unsigned char *)getresponse,
						 sizeof(getresponse), &scir,
						 (BYTE *) outbuff,
						 olen)) != SCARD_S_SUCCESS) {
				debug_printf(DEBUG_NORMAL,
					     "Error sending commands to the smart "
					     "card!  ");
				print_sc_error(ret);
				return ret;
			}
		}
	}

	if (*olen >= 2) {
		t_response *t = (t_response *) & response;
		int found = 0;

		p = *olen - 2;

		if ((outbuff[p] != 0x90) && (outbuff[p + 1] != 0x00)) {
			while (t->msk[0]) {
				if ((t->rsp[0] == (t->msk[0] & outbuff[p])) &&
				    (t->rsp[1] ==
				     (t->msk[1] & outbuff[p + 1]))) {

				  debug_printf(DEBUG_NORMAL, (char *)t->text,
						     outbuff[p + 1] & ~t->msk[1]);
					found++;
				}
				break;
			}
			t++;

			if (!found) {
				if (sm_check_response
				    (outbuff[p], outbuff[p + 1]) != 0) {
					debug_printf(DEBUG_NORMAL,
						     "Sim Card Response : %2.2X %2.2X (unknown response)\n",
						     outbuff[p],
						     outbuff[p + 1]);
					debug_printf(DEBUG_AUTHTYPES,
						     "Full response : (%d)\n",
						     (*olen));
					debug_hex_dump(DEBUG_AUTHTYPES, outbuff,
						       (*olen));
				}
			} else {
				debug_printf(DEBUG_NORMAL, "\n");
			}
		}
	}
	return 0;
}

unsigned char hinibble(unsigned char c)
{
	unsigned char k;

	k = (c >> 4) & 0x0f;
	if (k == 0x0f)
		return 0;
	else
		return (k + '0');
}

unsigned char lonibble(unsigned char c)
{
	unsigned char k;

	k = c & 0x0f;
	if (k == 0x0f)
		return 0;
	else
		return (k + '0');
}

char *decode_imsi(unsigned char *imsibytes)
{
	unsigned char *imsi, *s;
	int i;

	imsi = (unsigned char *)Malloc(20);
	if (imsi == NULL) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to allocate temporary "
			     "memory for IMSI!\n");
		return NULL;
	}

	s = imsi;

	*s++ = hinibble(imsibytes[0]);
	for (i = 1; i < 8; i++) {
		*s++ = lonibble(imsibytes[i]);
		*s++ = hinibble(imsibytes[i]);
	}
	*s = '\0';

	return (char *)imsi;
}

int sm_handler_2g_pin_needed(SCARDHANDLE * card_hdl, char reader_mode)
{
	unsigned long len;
	unsigned char buf[512];
	int result;

	if ((sim_reader_plugin_hook_available() == TRUE) &&
	    ((sim_reader_plugin_gs_supported(card_hdl) & SUPPORT_2G_SIM) ==
	     SUPPORT_2G_SIM)) {
		// Process it through our plugin.
		result = sim_reader_plugin_hook_2g_pin_needed(card_hdl, reader_mode);
		if (result >= -1)
			return result;
	}

	if (!card_hdl) {
		debug_printf(DEBUG_NORMAL, "Invalid card handle passed to "
			     "sm_handler_2g_pin_needed()!\n");
		return SM_HANDLER_ERROR_INVALID_CARD_CTX;
	}
	// Select the card master file in 2g mode.
	len = MAXBUFF;
	if (cardio(card_hdl, (char *)SELECT_MF, reader_mode, 
		   MODE2G, (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error trying to select the master file! "
			     "(%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_GETTING_MF;
	}

	if (cardio(card_hdl, (char *)SELECT_DF_GSM, reader_mode, 
		   MODE2G, (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error selecting GSM authentication! " "(%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_NO_GSM;
	}

	if (buf[13] & 0x80)
		return FALSE;

	return TRUE;
}

int sm_handler_2g_imsi(SCARDHANDLE * card_hdl, char reader_mode, char *pin,
		       char **imsi)
{
	unsigned long len;
	unsigned char buf[512], buf2[512], buf3[8];
	int i;
	int result;

	if ((sim_reader_plugin_hook_available() == TRUE) &&
	    ((sim_reader_plugin_gs_supported(card_hdl) & SUPPORT_2G_SIM) ==
	     SUPPORT_2G_SIM)) {
		// Process it through our plugin.
		result =
		    sim_reader_plugin_hook_get_2g_imsi(card_hdl, reader_mode,
						       pin, imsi);
		if (result >= -1)
			return result;
	}

	if (!card_hdl) {
		debug_printf(DEBUG_NORMAL, "Invalid card handle passed to "
			     "sm_handler_2g_imsi()!\n");
		return SM_HANDLER_ERROR_INVALID_CARD_CTX;
	}

	if (strlen(pin) > 8) {
		debug_printf(DEBUG_NORMAL, "PIN is too long!  Aborting!\n");
		return SM_HANDLER_ERROR_PIN_TOO_LONG;
	}
	// Select the card master file in 2g mode.
	len = MAXBUFF;
	if (cardio(card_hdl, (char *)SELECT_MF, reader_mode, 
		   MODE2G, (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error trying to select the master file! "
			     "(%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_GETTING_MF;
	}

	if (cardio(card_hdl, (char *)SELECT_DF_GSM, reader_mode, 
		   MODE2G, (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error selecting GSM authentication! " "(%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_NO_GSM;
	}

	if (!(buf[13] & 0x80)) {
		if (pin == NULL)
			return -1;

		xsup_common_strcpy((char *)&buf2, 512, "A020000108");
		for (i = 0; i < strlen(pin); i++) {
			memset((char *)&buf3, 0x00, 8);
			_snprintf((char *)buf3, 8, "%02X", pin[i]);
			if (Strcat((char *)buf2, sizeof(buf2), (char *)buf3) != 0) {
				fprintf(stderr,
					"Refusing to overflow string!\n");
				return SM_HANDLER_ERROR_GENERAL;
			}
		}
		for (i = strlen(pin); i < 8; i++) {
		  if (Strcat((char *)buf2, sizeof(buf2), "FF") != 0) {
				fprintf(stderr,
					"Refusing to overflow string!\n");
				return SM_HANDLER_ERROR_GENERAL;
			}
		}

		len = MAXBUFF;
		if (cardio(card_hdl, (char *)buf2, reader_mode, 
			   MODE2G, (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
			debug_printf(DEBUG_NORMAL,
				     "Error sending PIN to smart card! "
				     "(%s:%d)\n", __FUNCTION__, __LINE__);
			return SM_HANDLER_ERROR_SENDING_PIN;
		}
		// XXX When we get a GUI going, this should be sent to it.
		if ((len == 2) && (buf[0] = 0x98)) {
			if (buf[1] == 0x04) {
				debug_printf(DEBUG_NORMAL,
					     "Incorrect PIN, at least one attempt "
					     "remaining!\n");
				debug_printf(DEBUG_NORMAL,
					     "%d attempts remain.\n", buf[2]);
				return SM_HANDLER_ERROR_BAD_PIN_MORE_ATTEMPTS;
			} else if (buf[1] == 0x40) {
				debug_printf(DEBUG_NORMAL,
					     "Incorrect PIN, no attempts "
					     "remaining!\n");
				return SM_HANDLER_ERROR_BAD_PIN_CARD_BLOCKED;
			}
		}
	}

	len = MAXBUFF;
	if (cardio(card_hdl, (char *)SELECT_EF_IMSI, reader_mode, 
		   MODE2G, (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to select the IMSI on the"
			     " smart card!  (%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_IMSI_SELECTION_FAILED;
	}

	len = MAXBUFF;
	memset((char *)&buf, 0x00, 512);
	if (cardio(card_hdl, (char *)GET_IMSI, reader_mode, MODE2G, 
		   (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to get the IMSI from the "
			     "smart card! (%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_IMSI_SELECTION_FAILED;
	}

	(*imsi) = decode_imsi((unsigned char *)&buf[1]);

	return SM_HANDLER_ERROR_NONE;
}

int sm_handler_do_2g_auth(SCARDHANDLE * card_hdl, char reader_mode,
			  unsigned char *challenge, unsigned char *response,
			  unsigned char *ckey)
{
	unsigned char buf[MAXBUFF], buff2[MAXBUFF], buff3[MAXBUFF];
	int i;
	DWORD len;
	int result = 0;

	if ((!challenge) || (!response) || (!ckey)) {
		debug_printf(DEBUG_NORMAL, "Invalid data passed to "
			     "sm_handler_do_2g_auth!\n");
		return -1;
	}

	if ((sim_reader_plugin_hook_available() == TRUE) &&
	    ((sim_reader_plugin_gs_supported(card_hdl) & SUPPORT_2G_SIM) ==
	     SUPPORT_2G_SIM)) {
		// Process it through our plugin.
		result =
		    sim_reader_plugin_hook_do_2g_auth(card_hdl, reader_mode,
						      challenge, response,
						      ckey);
		if (result >= 0)
			return result;
	}

	xsup_common_strcpy((char *)buff2, MAXBUFF, RUN_GSM);
	memset(&buff3, 0x00, MAXBUFF);

	for (i = 0; i < 16; i++) {
	  _snprintf((char *)buff3, 8, "%02X", challenge[i]);
		if (Strcat((char *)buff2, sizeof(buff2), (char *)buff3) != 0) {
			fprintf(stderr, "Refusing to overflow string!\n");
			return -1;
		}
	}

	len = MAXBUFF;
	if (cardio(card_hdl, (char *)buff2, reader_mode, 
		   MODE2G, (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to run the GSM algorithm!\n");
		return -1;
	}

	memcpy(response, &buf[0], 4);

	memcpy(ckey, &buf[4], 8);
	return XENONE;
}

/**
 * \brief Parse the TLVs returned from the AID file, and see if PIN1 is listed 
 *			as being required.
 *
 * The AID data format is specified in ETSI TS 102 221, section 11.1.1.3.
 **/
int sm_handler_parse_aid_pin_needed(uint8_t * aiddata, uint16_t aidlen)
{
	int i = 0;

	if (aiddata == NULL) {
		debug_printf(DEBUG_NORMAL, "Invalid AID data!\n");
		return -1;
	}

	if (aiddata[0] != 0x62) {
		debug_printf(DEBUG_NORMAL,
			     "AID data doesn't start with a valid header!\n");
		return -1;
	}
	// +4 because the length doesn't include the 0x62 above, the length byte itself, and the 0x90 0x00 at the end.
	if ((aiddata[1] + 4) != aidlen) {
		debug_printf(DEBUG_NORMAL,
			     "AID length isn't what was expected.\n");
		return -1;
	}

	i = 2;
	while (i < aidlen) {
		if (aiddata[i] != 0xc6)	// PIN DO.
		{
			i += aiddata[i + 1];	// Skip the data part
			i += 2;	// And the tag and length bytes.
		} else {
			if (aiddata[i + 1] < 3)	// Our DO isn't big enough.
			{
				debug_printf(DEBUG_NORMAL,
					     "D0 data was invalid!\n");
				return -1;
			}

			if (aiddata[i + 2] != 0x90) {
				debug_printf(DEBUG_NORMAL,
					     "Unsure how to parse the pin information.  We will assume a PIN is required.\n");
				return TRUE;
			}

			if (aiddata[i + 3] != 0x01) {
				debug_printf(DEBUG_NORMAL,
					     "The length is more than it should be!  Assuming a PIN is required.\n");
				return TRUE;
			}
			// The bits in i+4 indicate which PINs are required.  We only care about PIN1, so we check the high bit.
			if ((aiddata[i + 4] & 0x80) == 0x80) {
				return TRUE;
			} else {
				return FALSE;
			}
		}
	}

	// If we get here, then we aren't sure, so we assume a PIN is needed.
	return TRUE;
}

/**
 * \brief Do the card initialization and see if a PIN needs to be presented.  Calling this
 *			function will also get the card in a state to complete an AUTHENTICATE call.
 *
 * \retval int  Number of PIN retries remaining, -1 if no pin is needed, or SM_* error code.
 **/
int sm_handler_3g_pin_needed(SCARDHANDLE * card_hdl, char reader_mode)
{
	DWORD len;
	unsigned char buf[MAXBUFF], buf2[MAXBUFF], aid[MAXBUFF], temp[MAXBUFF],
	    *p = NULL;
	unsigned char cmd[MAXBUFF];
	int i, l, q, foundaid = 0, pinretries = 0;
	unsigned char threeG[2] = { 0x10, 0x02 };
	struct t_efdir *t = NULL;
	int result = 0;

	if (!card_hdl) {
		debug_printf(DEBUG_NORMAL, "Invalid card handle passed to "
			     "sm_handler_3g_imsi()!\n");
		return SM_HANDLER_ERROR_INVALID_CARD_CTX;
	}

	if ((sim_reader_plugin_hook_available() == TRUE) &&
	    ((sim_reader_plugin_gs_supported(card_hdl) & SUPPORT_3G_SIM) ==
	     SUPPORT_3G_SIM)) {
		// Process it through our plugin.
		result =
		    sim_reader_plugin_hook_3g_pin_needed(card_hdl, reader_mode);
		if (result >= -1)
			return result;
	}
	// Select the USIM master file.
	if (cardio
	    (card_hdl, SELECT_MF_USIM, reader_mode, MODE3G, (LPBYTE) & buf,
	     &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to select the master file "
			     "on the SIM card! (%s:%d)\n", __FUNCTION__,
			     __LINE__);
		return SM_HANDLER_ERROR_READ_FAILURE;
	}

	if (buf[0] == 0x6e) {
		debug_printf(DEBUG_NORMAL,
			     "3G mode not supported by this card!\n");
		return SM_HANDLER_ERROR_3G_NOT_SUPPORTED;
	}
	// Select the ICCID of the card.
	if (cardio
	    (card_hdl, SELECT_EF_ICCID, reader_mode, MODE3G, (LPBYTE) & buf,
	     &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to select the ICCID of "
			     "this SIM card! (%s:%d)\n", __FUNCTION__,
			     __LINE__);
		return SM_HANDLER_ERROR_READ_FAILURE;
	}

	if (cardio
	    (card_hdl, SELECT_FCP, reader_mode, MODE3G, (LPBYTE) & buf, &len,
	     DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to select the FCP of this "
			     "SIM card!  (%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_READ_FAILURE;
	}

	if (cardio
	    (card_hdl, SELECT_EFDIR, reader_mode, MODE3G, (LPBYTE) & buf, &len,
	     DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error selecting the EFDIR on this SIM card!"
			     " (%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_READ_FAILURE;
	}

	if (cardio
	    (card_hdl, EFDIR_READREC1, reader_mode, MODE3G, (LPBYTE) & buf,
	     &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to read record #1 from "
			     "this SIM card! (%s:%d)\n", __FUNCTION__,
			     __LINE__);
		return SM_HANDLER_ERROR_READ_FAILURE;
	}

	l = buf[len - 1];
	i = 1;

	// Loop over EFdir
	do {

	  _snprintf((char *)buf, MAXBUFF, "00B2%2.2X04%2.2X", i, l);
		if (cardio(card_hdl, (char *)buf, reader_mode, 
			   MODE3G, (LPBYTE) & buf2, &len, DO_DEBUG) != 0) {
			debug_printf(DEBUG_NORMAL,
				     "Error attempting to read a record from "
				     "this SIM card! (%s:%d)\n", __FUNCTION__,
				     __LINE__);
			return SM_HANDLER_ERROR_GENERAL;
		}
		i++;
		t = (struct t_efdir *)&buf2;

		if (!memcmp(&t->app_code, &threeG, 2)) {
			memset((unsigned char *)&aid, 0x00, MAXBUFF);

			p = (unsigned char *)&t->rid;
			for (q = 0; q < 12; q++) {
			  _snprintf((char *)temp, MAXBUFF, "%02X", *p++);
				if (Strcat((char *)aid, sizeof(aid), 
					   (char *)temp) != 0) {
					fprintf(stderr,
						"Refusing to overflow string!\n");
					return SM_HANDLER_ERROR_GENERAL;
				}
			}
			foundaid = 1;
		}

	} while (((buf2[len - 2] == 0x90) && (buf2[len - 1] == 0))
		 && (foundaid != 1));

	// Select the USIM aid.
	xsup_common_strcpy((char *)cmd, MAXBUFF, "00A404040C");
	if (Strcat((char *)cmd, sizeof(cmd), (char *)aid) != 0) {
		fprintf(stderr, "Refusing to overflow string!\n");
		return SM_HANDLER_ERROR_GENERAL;
	}

	if (cardio(card_hdl, (char *)cmd, reader_mode, MODE3G, 
		   (LPBYTE) & buf2, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Couldn't select the USIM application ID! "
			     "(%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_NO_USIM;
	}

	debug_printf(DEBUG_AUTHTYPES, "USIM AID read :\n");
	debug_hex_dump(DEBUG_AUTHTYPES, buf2, len);

	result = sm_handler_parse_aid_pin_needed(buf2, len);
	if (result == FALSE) {
		debug_printf(DEBUG_AUTHTYPES, "No PIN required!\n");
		return -1;	// No PIN is needed.
	}

	debug_printf(DEBUG_AUTHTYPES, "PIN needed.\n");

	// Determine remaining CHV retires.
	if (cardio
	    (card_hdl, CHV_RETRIES, reader_mode, MODE3G, (LPBYTE) & buf, &len,
	     DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error requesting the remaining number of "
			     "PIN attempts from this SIM!  (%s:%d)\n",
			     __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_GENERAL;
	}

	if ((buf[0] == 0x63) && ((buf[1] & 0xc0) == 0xc0)) {
		pinretries = buf[1] & 0x0f;
	}

	debug_printf(DEBUG_AUTHTYPES, "CHV output : \n");
	debug_hex_printf(DEBUG_AUTHTYPES, buf, len);

	return pinretries;
}

int sm_handler_3g_imsi(SCARDHANDLE * card_hdl, char reader_mode, char *pin,
		       char **imsi)
{
	DWORD len;
	unsigned char buf[MAXBUFF], buf2[MAXBUFF], buf3[MAXBUFF];
	int i, pinretries = 0;
	int retval = 0;

	if ((sim_reader_plugin_hook_available() == TRUE) &&
	    ((sim_reader_plugin_gs_supported(card_hdl) & SUPPORT_3G_SIM) ==
	     SUPPORT_3G_SIM)) {
		// Process it through our plugin.
		retval =
		    sim_reader_plugin_hook_get_3g_imsi(card_hdl, reader_mode,
						       pin, imsi);
		if (retval >= 0)
			return retval;
	}

	if (!card_hdl) {
		debug_printf(DEBUG_NORMAL, "Invalid card handle passed to "
			     "sm_handler_3g_imsi()!\n");
		return SM_HANDLER_ERROR_INVALID_CARD_CTX;
	}

	if ((pin != NULL) && (strlen(pin) > 8)) {
		// XXX This should be returned to a GUI when we have one!
		debug_printf(DEBUG_NORMAL, "PIN is too long!\n");
		return SM_HANDLER_ERROR_PIN_TOO_LONG;
	}

	pinretries = sm_handler_3g_pin_needed(card_hdl, reader_mode);

	if (pinretries >= 0) {
		if (pinretries == 0) {
			debug_printf(DEBUG_NORMAL,
				     "No PIN retries remaining!\n");
			return SM_HANDLER_ERROR_BAD_PIN_CARD_BLOCKED;
		}
		// Otherwise, enter the PIN.
		xsup_common_strcpy((char *)buf2, MAXBUFF, CHV_ATTEMPT);
		for (i = 0; i < strlen(pin); i++) {
			memset((char *)&buf3, 0x00, 8);
			_snprintf((char *)buf3, MAXBUFF, "%02X", pin[i]);
			if (Strcat((char *)buf2, sizeof(buf2), 
				   (char *)buf3) != 0) {
				fprintf(stderr,
					"Refusing to overflow string!\n");
				return SM_HANDLER_ERROR_GENERAL;
			}
		}
		for (i = strlen(pin); i < 8; i++) {
		  if (Strcat((char *)buf2, sizeof(buf2), "FF") != 0) {
				fprintf(stderr,
					"Refusing to overflow string!\n");
				return SM_HANDLER_ERROR_GENERAL;
			}
		}

		if (cardio(card_hdl, (char *)buf2, reader_mode, MODE3G, 
			   (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
			debug_printf(DEBUG_NORMAL,
				     "Invalid PIN! (%d tries remain.)\n",
				     pinretries - 1);

			if ((pinretries - 1) <= 0)
				return SM_HANDLER_ERROR_BAD_PIN_CARD_BLOCKED;
			return SM_HANDLER_ERROR_BAD_PIN_MORE_ATTEMPTS;
		}
	}
	// Now, get the IMSI
	if (cardio
	    (card_hdl, USELECT_EF_IMSI, reader_mode, MODE3G, (LPBYTE) & buf,
	     &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to select the IMSI for this"
			     " SIM card! (%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_IMSI_SELECTION_FAILED;
	}
	// XXX For now, assume that IMSIs are 9 bytes.
	if (cardio
	    (card_hdl, READ_IMSI, reader_mode, MODE3G, (LPBYTE) & buf, &len,
	     DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error reading the IMSI on this SIM card! "
			     "(%s:%d)\n", __FUNCTION__, __LINE__);
		return SM_HANDLER_ERROR_IMSI_SELECTION_FAILED;
	}

	(*imsi) = decode_imsi((unsigned char *)&buf[1]);

	return SM_HANDLER_ERROR_NONE;
}

/* tack on a sequence of hex command bytes to a string
 * buffer is assumed to already contain a zero-terminated string
 */
int addhex(u8 * buffer, unsigned int buflen, const u8 * bytes, int len)
{
	u8 temp[5];
	int i = 0;

	for (i = 0; i < len; i++) {
	  _snprintf((char *)temp, 5, "%02X", *bytes++);
	  if (Strcat((char *)buffer, buflen, (char *)temp) != 0) {
			fprintf(stderr, "Refusing to overflow string!\n");
			return -1;
		}
	}

	return 0;
}

// return -2 on sync failure. -1 for all other errors.
int sm_handler_do_3g_auth(SCARDHANDLE * card_hdl, char reader_mode,
			  unsigned char *Rand, unsigned char *autn,
			  unsigned char *c_auts, char *res_len,
			  unsigned char *c_sres, unsigned char *c_ck,
			  unsigned char *c_ik, unsigned char *c_kc)
{
	unsigned char cmd[MAXBUFF], buf[MAXBUFF], sw1, sw2, *s = NULL;
	DWORD len;
	int result = 0;

	if ((sim_reader_plugin_hook_available() == TRUE) &&
	    ((sim_reader_plugin_gs_supported(card_hdl) & SUPPORT_3G_SIM) ==
	     SUPPORT_3G_SIM)) {
		// Process it through our plugin.
		result =
		    sim_reader_plugin_hook_do_3g_auth(card_hdl, reader_mode,
						      Rand, autn, c_auts,
						      res_len, c_sres, c_ck,
						      c_ik, c_kc);
		if (result >= 0)
			return result;
	}

	if (Strncpy((char *)cmd, sizeof(cmd), "008800812210", 13) != 0) {
		fprintf(stderr, "Refusing to overflow string!\n");
		return -1;
	}

	if (addhex(cmd, sizeof(cmd), Rand, 16) != 0) {
		fprintf(stderr, "Refusing to overflow string!\n");
		return -1;
	}

	if (Strcat((char *)cmd, sizeof(cmd), "10") != 0) {
		fprintf(stderr, "Refusing to overflow string!\n");
		return -1;
	}

	if (addhex(cmd, sizeof(cmd), autn, 16) != 0) {
		fprintf(stderr, "Refusing to overflow string!\n");
		return -1;
	}

	debug_printf(DEBUG_SMARTCARD, "Sending in '%s'\n", cmd);

	len = MAXBUFF;

	if (cardio(card_hdl, (char *)cmd, reader_mode, MODE3G, 
		   (LPBYTE) & buf, &len, DO_DEBUG) != 0) {
		debug_printf(DEBUG_NORMAL,
			     "Error attempting to execute 3G "
			     "authentication! (%s:%d)\n", __FUNCTION__,
			     __LINE__);
		return -1;
	}

	debug_printf(DEBUG_AUTHTYPES, "Result : \n");
	debug_hex_printf(DEBUG_AUTHTYPES, buf, len);

	sw1 = buf[len - 2];
	sw2 = buf[len - 1];

	if ((sw1 == 0x90) && (sw2 == 0x00) && (buf[0] == 0xdc)) {
		debug_printf(DEBUG_NORMAL,
			     "Sync failure! (Result length = %d)\n", len);
		memcpy(c_auts, buf + 2, len);
		return -2;
	}

	if ((sw1 == 0x90) && (sw2 == 0x00) && (buf[0] == 0xdb)) {
		// Success.
		s = buf + 1;
		*res_len = *s;
		memcpy(c_sres, s + 1, *s);
		s += (*s + 1);	// Step over TLV vectors
		memcpy(c_ck, s + 1, *s);
		s += (*s + 1);	// Ditto.
		memcpy(c_ik, s + 1, *s);
		s += (*s + 1);
		memcpy(c_kc, s + 1, *s);
		s += *s;
		return 0;
	}
	// Otherwise, we failed.
	return -1;
}

int sm_handler_card_disconnect(SCARDHANDLE * card_hdl)
{
	long ret = 0;
	int result = 0;

	if (sim_reader_plugin_hook_available() == TRUE) {
		// Process it through our plugin.
		result = sim_reader_plugin_hook_card_disconnect(card_hdl);
		if (result >= 0)
			return result;
	}

	if (card_hdl) {
		ret = SCardDisconnect(*card_hdl, SCARD_UNPOWER_CARD);
		if (ret != SCARD_S_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't disconnect from Smart Card! ");
			print_sc_error(ret);
		} else {
			card_hdl = NULL;
		}
	}

	return ret;
}

int sm_handler_close_sc(SCARDHANDLE * card_hdl, SCARDCONTEXT * card_ctx)
{
	long ret = 0;

	if ((sim_reader_plugin_hook_available() == TRUE) && (card_ctx != NULL)
	    && (sim_reader_plugin_ctx_is_plugin((void **)card_ctx) == TRUE)) {
		// This is a plug-in context, call it to clean up.
		return sim_reader_plugin_deinit_ctx(card_hdl, card_ctx);
	}

	if (card_hdl) {
		ret = SCardDisconnect(*card_hdl, SCARD_UNPOWER_CARD);
		if (ret != SCARD_S_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't disconnect from Smart Card! ");
			print_sc_error(ret);
		}
	}

	if (card_ctx) {
		ret = SCardReleaseContext(*card_ctx);
		if (ret != SCARD_S_SUCCESS) {
			debug_printf(DEBUG_NORMAL,
				     "Couldn't release Smart Card context!  ");
			print_sc_error(ret);
		}
	}

	return 0;
}
#endif
