#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sigsegv.h"
#include "crash_handler.h"

char *dumploc = NULL;

void crash_handler_install(char *dumpname)
{
#ifndef ENABLE_MOKO
  if (dumploc != NULL)
    free(dumploc);

  dumploc = strdup(dumpname);

  setup_sigsegv();
#endif
}

void crash_handler_cleanup()
{
#ifndef ENABLE_MOKO
  free(dumploc);
#endif
}

