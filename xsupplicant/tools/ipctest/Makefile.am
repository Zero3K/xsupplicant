CORELIBS = @CORELIBS@
MORELIBS = @MORELIBS@ 
MOREDEFS = @MOREDEFS@ 
DEFS = @DEFS@ $(MOREDEFS) 

bin_PROGRAMS = ipctest

ipctest_CFLAGS  = -I${top_srcdir}/src/ -I${top_srcdir}/src/cardif

ipctest_SOURCES	= ipctest.c ${top_srcdir}/src/getopts.c \
		  ${top_srcdir}/src/xsup_debug.c 

ipctest_LDADD	= $(CORELIBS) $(MORELIBS) \
		  -L${top_builddir}/lib/libxsupgui -lxsupgui \
		  -L${top_builddir}/lib/libxsupconfig -lxsupconfig \
		  -L${top_builddir}/lib/libxsupconfwrite -lxsupconfwrite
