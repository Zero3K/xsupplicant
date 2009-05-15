### We now run ./gen_version.sh to get our version number so that we can 
# control that variable from the build system.
AC_INIT([xsupplicant_plugin_installer],m4_esyscmd(../xsupplicant/gen_version.sh), [], [xsupplicant_plugin_installer])


AC_PREREQ(2.59)
AM_INIT_AUTOMAKE([dist-bzip2] [dist-zip] [foreign])
AC_PROG_CC
AC_PROG_LIBTOOL

# Host environment specific tests
AC_CANONICAL_HOST
AC_C_BIGENDIAN

# Enable all warnings for gcc (what about other compilers?)
if test -n "$GCC"; then
  CFLAGS="-Wall -fno-strict-aliasing $CFLAGS"
fi

GGDBFLAGS=""

########### CONFIGURE OPTIONS #############

AC_MSG_CHECKING([user defined path to libxml2 libraries])
AC_ARG_WITH(libxml-libs,
  AS_HELP_STRING([--with-libxml-libs],
    [location of the libxml2 libraries]),
    [LDFLAGS="$LDFLAGS -L${with_libxml_libs}"])
AC_MSG_RESULT([$with_libxml_libs])
AC_SUBST(with_libxml_libs)

AC_MSG_CHECKING([user defined path to libxml2 headers])
AC_ARG_WITH(libxml-headers,
  AS_HELP_STRING([--with-libxml-headers],
    [location of the libxml2 headers]),
    [CPPFLAGS="$CPPFLAGS -I${with_libxml_headers} -I${with_libxml_headers}/include"])

AC_ARG_ENABLE(static-libxml,
  AS_HELP_STRING([--enable-static-libxml],
    [statically link libxml2 libraries]),
  [AS_IF([test -n "$with_libxml_libs" && test -n "$with_libxml_headers"],
  	       [enable_static_libxml="yes" ],
	       [AC_MSG_ERROR("You must use --with-libxml-libs and --with-libxml-headers to use static libxml2 libraries.")])])

AC_MSG_CHECKING([for libxml-2.0])
AS_IF([test "$enable_static_libxml" != yes], [
if `pkg-config libxml-2.0 --exists`; then
     LIBS=`pkg-config libxml-2.0 --libs $LIBS`
     AM_CPPFLAGS=`pkg-config libxml-2.0 --cflags $AM_CPPFLAGS`
     AC_MSG_RESULT([found with pkg-config])
elif test -e /usr/lib/libxml2.dylib; then
     dnl Mac OS X doesn't have pkg-config.  So check in the defaut location.
     LIBS="-L/usr/lib -lxml2 $LIBS"
     AM_CPPFLAGS="-I/usr/include/libxml2 $AM_CPPFLAGS"
     AC_MSG_RESULT([found in default location for Mac OS X])
else
     AC_MSG_ERROR([Xsupplicant requires libxml.  You need to either install libxml\
, or set PKG_CONFIG_PATH to point to the location of the libxml-2.0.pc file.])
fi
], [AS_IF([test -f "${with_libxml_libs}/libxml2.a"], 
   [MORELIBS="$MORELIBS ${with_libxml_libs}/libxml2.a -lm";AS_IF([test "$enable_static_libz"], [], [MORELIBS="$MORELIBS -lz"])],
   [AC_MSG_ERROR([libxml2.a was not found at the path specified!])])])

AC_SUBST(LDFLAGS)
AC_SUBST(AM_CPPFLAGS)
AC_SUBST(MORELIBS)

AC_CONFIG_FILES([Makefile
		src/Makefile
		])
AC_OUTPUT
