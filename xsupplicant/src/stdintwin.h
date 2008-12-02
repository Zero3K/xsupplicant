/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file stdintwin.h
 *
 * \author chris@open1x.org
 */
#ifndef __STDINTWIN_H__
#define __STDINTWIN_H__

#ifdef WINDOWS
#define uint8_t  unsigned __int8
#define uint16_t unsigned __int16
#define uint32_t unsigned __int32
#define uint64_t unsigned __int64

#define int8_t  __int8
#define int16_t __int16
#define int32_t __int32
#endif

#endif // __STDINTWIN_H__
