/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file xsup_gui_trace.h
 *
 * \author chris@open1x.org
 *
 * $Id: xsup_gui_trace.h,v 1.2 2007/09/24 02:12:22 galimorerpg Exp $
 * $Date: 2007/09/24 02:12:22 $
 */

#ifndef _XSUP_GUI_TRACE_H_
#define _XSUP_GUI_TRACE_H_

#define TEMP_LOG_BUF_SIZE 2048

int xsup_gui_trace_enable(char *filename);
int xsup_gui_trace_disable();
void xsup_gui_trace(char *fmt, ...);

#endif
