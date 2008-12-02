/**
 * A header file that includes some boilerplate bits for building plugins.
 *
 * Licensed under the dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file win_plugin_includes.h
 *
 * \author galimorerpg@users.sourceforge.net
 *
 **/

#ifndef _WIN_PLUGIN_INCLUDES_H_
#define _WIN_PLUGIN_INCLUDES_H_

#ifdef WIN32
#include <windows.h>
#include <stdintwin.h>
#ifdef _DLL
#define DLLMAGIC __declspec(dllexport)

#define strdup	_strdup

#else
#define DLLMAGIC __declspec(dllimport)
#endif 	// _DLL
#endif // WIN32

#ifndef WIN32  // Non-Windows platforms need a stub
#include <stdint.h>
#define DLLMAGIC 
#endif //WIN32

#endif // _WIN_PLUGIN_INCLUDES_H_