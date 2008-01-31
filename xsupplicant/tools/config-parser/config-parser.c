/**
 * A client-side 802.1x implementation 
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2002 Bryan D. Payne & Nick L. Petroni Jr.
 * All Rights Reserved
 *
 * --- GPL Version 2 License ---
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
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
 **/

/*******************************************************************
 * The driver function for a test configuration parser 
 *
 * File: config-parser.c
 *
 * Authors: npetroni@cs.umd.edu
 *
 *******************************************************************/
#include <stdlib.h>

#ifndef WINDOWS
#include <unistd.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#ifdef WINDOWS
#include "src/stdintwin.h"
#endif

#include "src/xsup_err.h"
#include "lib/libxsupconfig/xsupconfig_structs.h"
#include "src/xsup_common.h"
#include "lib/libxsupconfig/xsupconfig.h"
#include "src/context.h"
#include "lib/libxsupconfwrite/xsupconfwrite.h"
#include "src/xsup_debug.h"
#include "src/getopts.h"

#define CONFIG_PARSE_VERBOSE    0x00000001
#define CONFIG_PARSE_HAVE_FILE  0x00000002
#define CONFIG_PARSE_WRITE_FILE 0x00000004

void usage(char *prog)
{
  printf("Usage: %s [-v] [-h] [-f file] [-o file]"
	       "\n\t-f  file to parse (required)"
	       "\n\t-h  print this message"
	       "\n\t-v  verbose"
	       "\n\t-o  rewrite the config to file"
	       "\n", prog);
}

/***************************************
 *
 * The main body of the program.  We should keep this simple!  Process any
 * command line options that were passed in, set any needed variables.
 *
 ***************************************/
int main(int argc, char *argv[])
{
  struct options opts[] =
  {
	  { 1, "file",  "Load a specific config file", "f", 1 },
	  { 2, "output", "Rewrite the configuration file", "o", 1 },
	  { 3, "verbose", "Verbose output", "v", 0 },
	  { 4, "help", "Display help", "h", 0 },

	  { 0, NULL, NULL, NULL, 0 }
  };

  int op;
  char *args = NULL;
  char *config_fname = NULL, *config_ofname = NULL;
  int flags = 0x00000000;
  int retval = 0;

  // We should have at least one argument passed in!
  if (argc<2)
    {
      usage(argv[0]);
      exit(0);
    }

  // Process any arguments we were passed in.

  while ((op = getopts(argc, argv, opts, &args)) != 0) 
    {
      switch (op)
	{
	case 1:
	  config_fname = args;
	  flags |= CONFIG_PARSE_HAVE_FILE;
	  break;
	case 3:
	  flags |= CONFIG_PARSE_VERBOSE;
	  break;
	case 4:
	  usage(argv[0]);
	  exit(0);
	  break;
	case 2:
	  config_ofname = args;
	  flags |= CONFIG_PARSE_WRITE_FILE;
	  break;
	default:
	  usage(argv[0]);
	  exit(0);
	  break;
	}
    }
  if (config_fname == NULL) {
    printf("No filename given!\n");
    usage(argv[0]);
    exit(0);
  }
  
  if (config_setup(config_fname) == XENONE) {
    if (flags & CONFIG_PARSE_VERBOSE)
      {
	printf("Dumping config.\n");
	dump_config_data();
      }
    printf("Parsed successfully.\n");

    if (flags & CONFIG_PARSE_WRITE_FILE)
      {
		retval = xsupconfwrite_write_config(config_ofname);
		if (retval != XSUPCONFWRITE_ERRNONE)
		{
			debug_printf(DEBUG_NORMAL, "Error writing config file.\n");
		} else {
			debug_printf(DEBUG_NORMAL, "File written.\n");
		} 
      }
    printf("Exiting.\n");
    config_destroy();
  }
  else {
    printf("Failed to Parse \"%s\". Exiting.\n", 
		 config_fname);
  }
  
  
  return XENONE;
}
