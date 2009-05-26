/**
 * This source file is used to print out a stack-trace when your program
 * segfaults.  It is relatively reliable and spot-on accurate.
 *
 * This code is in the public domain.  Use it as you see fit, some credit
 * would be appreciated, but is not a prerequisite for usage.  Feedback
 * on it's use would encourage further development and maintenance.
 *
 * Author:  Jaco Kroon <jaco@kroon.co.za>
 *
 * Copyright (C) 2005 - 2008 Jaco Kroon
 */

#ifndef ENABLE_MOKO

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#define NO_CPP_DEMANGLE
#define SIGSEGV_NO_AUTO_INIT

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <execinfo.h>
#ifndef NO_CPP_DEMANGLE
#include <cxxabi.h>
#endif

#if defined(REG_RIP)
# define SIGSEGV_STACK_IA64
# define REGFORMAT "%016lx"
#elif defined(REG_EIP)
# define SIGSEGV_STACK_X86
# define REGFORMAT "%08x"
#else
# define SIGSEGV_STACK_GENERIC
# define REGFORMAT "%x"
#endif

// This is defined in lin_crash_handler.c
extern char *dumploc;

// Defined in xsup_driver.c
extern void global_sigseg();

static void signal_segv(int signum, siginfo_t* info, void*ptr) {
    static const char *si_codes[3] = {"", "SEGV_MAPERR", "SEGV_ACCERR"};

    size_t i;
    ucontext_t *ucontext = (ucontext_t*)ptr;

#if defined(SIGSEGV_STACK_X86) || defined(SIGSEGV_STACK_IA64)
    int f = 0;
    Dl_info dlinfo;
    void **bp = 0;
    void *ip = 0;
#else
    void *bt[20];
    char **strings;
    size_t sz;
#endif
    FILE *fh = NULL;

    fh = fopen(dumploc, "w");
    if (fh == NULL)
      {
	fprintf(stderr, "Unable to open crash dump file.  Sending to stderr instead!\n");
	fh = stderr;
      }

    fprintf(fh, "Segmentation Fault!\n");
    fprintf(fh, "info.si_signo = %d\n", signum);
    fprintf(fh, "info.si_errno = %d\n", info->si_errno);
    fprintf(fh, "info.si_code  = %d (%s)\n", info->si_code, si_codes[info->si_code]);
    fprintf(fh, "info.si_addr  = %p\n", info->si_addr);
    // NGREG not defined on Mac OS X...
#ifndef __APPLE__
    for(i = 0; i < NGREG; i++)
        fprintf(fh, "reg[%02d]       = 0x" REGFORMAT "\n", i, ucontext->uc_mcontext.gregs[i]);
#else
    fprintf(fh, "NGREG Not available on Mac OS X.\n");
#endif

#if defined(SIGSEGV_STACK_X86) || defined(SIGSEGV_STACK_IA64)
# if defined(SIGSEGV_STACK_IA64)
    ip = (void*)ucontext->uc_mcontext.gregs[REG_RIP];
    bp = (void**)ucontext->uc_mcontext.gregs[REG_RBP];
# elif defined(SIGSEGV_STACK_X86)
    ip = (void*)ucontext->uc_mcontext.gregs[REG_EIP];
    bp = (void**)ucontext->uc_mcontext.gregs[REG_EBP];
# endif

    fprintf(fh, "Stack trace:\n");
    while(bp && ip) {
        if(!dladdr(ip, &dlinfo))
            break;

        const char *symname = dlinfo.dli_sname;
#ifndef NO_CPP_DEMANGLE
        int status;
        char *tmp = __cxa_demangle(symname, NULL, 0, &status);

        if(status == 0 && tmp)
            symname = tmp;
#endif

        fprintf(fh, "% 2d: %p <%s+%u> (%s)\n",
                ++f,
                ip,
                symname,
                (unsigned)(ip - dlinfo.dli_saddr),
                dlinfo.dli_fname);

#ifndef NO_CPP_DEMANGLE
        if(tmp)
            free(tmp);
#endif

        if(dlinfo.dli_sname && !strcmp(dlinfo.dli_sname, "main"))
            break;

        ip = bp[1];
        bp = (void**)bp[0];
    }
#else
    fprintf(fh, "Stack trace (non-dedicated):\n");
    sz = backtrace(bt, 20);
    strings = backtrace_symbols(bt, sz);

    for(i = 0; i < sz; ++i)
        fprintf(fh, "%s\n", strings[i]);
#endif
    fprintf(fh, "End of stack trace\n");
    if (fh != stderr) fclose(fh);

    // This should exit, but include the exit after it just to be safe.
    global_sigseg();
    exit (-1);
}

int setup_sigsegv() {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = signal_segv;
    action.sa_flags = SA_SIGINFO;
    if(sigaction(SIGSEGV, &action, NULL) < 0) {
        perror("sigaction");
        return 0;
    }

    return 1;
}

#ifndef SIGSEGV_NO_AUTO_INIT
static void __attribute((constructor)) init(void) {
    setup_sigsegv();
}
#endif

#endif // ENABLE_MOKO
