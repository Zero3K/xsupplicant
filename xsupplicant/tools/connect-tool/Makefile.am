CORELIBS = @CORELIBS@
MORELIBS = @MORELIBS@ 
MOREDEFS = @MOREDEFS@ 
DEFS = @DEFS@ $(MOREDEFS) 

bin_PROGRAMS = connect-tool

connect_tool_CFLAGS  = -I${top_srcdir}/src/ -I${top_srcdir}/src/cardif \
		-I${top_srcdir}/lib/libxsupgui

connect_tool_SOURCES	= connect-tool.c ${top_srcdir}/src/getopts.c \
		  ${top_srcdir}/src/xsup_debug.c 

connect_tool_LDADD	= $(CORELIBS) \
		  -L${top_builddir}/lib/libxsupgui -lxsupgui \
		  -L${top_builddir}/lib/libxsupconfig -lxsupconfig \
		  -L${top_builddir}/lib/libxsupconfwrite -lxsupconfwrite \
		  -L${top_builddir}/lib/liblist -llist ${MORELIBS}
