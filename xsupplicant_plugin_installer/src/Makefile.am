MORELIBS = @MORELIBS@

sbin_PROGRAMS = xsupplicant_plugin_installer

xsupplicant_plugin_installer_CFLAGS = -I${top_srcdir}/../xsupplicant/lib
xsupplicant_plugin_installer_LDADD = -L${top_srcdir}/../xsupplicant/lib/libxsupconfig -L${top_srcdir}/../xsupplicant/lib/libxsupconfwrite -L${top_srcdir}/../xsupplicant/lib/liblist -lxsupconfig -lxsupconfwrite -llist $(MORELIBS)
xsupplicant_plugin_installer_SOURCES = getopts.h getopts.c main.c ${top_srcdir}/../xsupplicant/src/xsup_common.c

