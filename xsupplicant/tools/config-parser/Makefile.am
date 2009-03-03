#CORELIBS = @CORELIBS@
#MORELIBS = @MORELIBS@ -L${top_srcdir}/lib/libxsupconfig -l xsupconfig -L${top_srcdir}/lib/libxsupgui -lxsupgui  -L${top_srcdir}/lib/liblist -l list
#MOREDEFS = @MOREDEFS@ 
DEFS = @DEFS@ $(MOREDEFS) -DEXTERNAL_USE

CLEANFILES= config_grammar.c config_lexicon.c config_grammar.h

bin_PROGRAMS = config-parser
config_parser_SOURCES = config-parser.c ${top_srcdir}/src/xsup_debug.c \
			${top_srcdir}/src/xsup_common.c \
			${top_srcdir}/src/getopts.c 

config_parser_CFLAGS  = -I${top_srcdir}/src/ -I${top_srcdir}/src/cardif

config_parser_LDADD   = $(MORELIBS) \
			-L${top_builddir}/lib/libxsupconfig -lxsupconfig \
			-L${top_builddir}/lib/libxsupconfwrite \
			-lxsupconfwrite -L${top_builddir}/lib/libxsupgui \
			-lxsupgui -L${top_srcdir}/lib/liblist -llist
