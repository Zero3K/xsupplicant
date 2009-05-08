CORELIBS = @CORELIBS@
MORELIBS = @MORELIBS@ 
#MOREDEFS = @MOREDEFS@ 
DEFS = @DEFS@ $(MOREDEFS) 

bin_PROGRAMS = ipcevents
ipcevents_SOURCES = ipcevents.c
ipcevents_CFLAGS  = -I${top_srcdir}/src/
ipcevents_LDADD	  = -L${top_builddir}/lib/libxsupgui -lxsupgui $(MORELIBS)
