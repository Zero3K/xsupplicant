AC_INIT([XSupplicant],[1.9.5.071009],[],[xsupplicant])
AC_PREREQ(2.59)
AM_INIT_AUTOMAKE([dist-bzip2] [dist-zip] [foreign])
AC_PROG_RANLIB
AC_PROG_CC

# Host environment specific tests
AC_CANONICAL_HOST
AC_C_BIGENDIAN

# Enable all warnings for gcc (what about other compilers?)
if test -n "$GCC"; then
  CFLAGS="-Wall -fno-strict-aliasing $CFLAGS"
fi

GGDBFLAGS=""

########### CONFIGURE OPTIONS #############
dnl Does this belong elsewhere?

AC_ARG_WITH(old-iwlib,
  AS_HELP_STRING([--with-old-iwlib],
    [use older 2-param IWLIB calls]),
  [AC_DEFINE(OLD_IWLIB)])

AC_MSG_CHECKING([user defined path to libpcap])
AC_ARG_WITH(libpcap,
  AS_HELP_STRING([--with-libpcap],
    [location of libpcap/winpcap root development tree]),
  [LDFLAGS="$LDFLAGS -L${with_libpcap}/lib";CPPFLAGS="$CPPFLAGS -I${with_libpcap}/include"])
AC_MSG_RESULT([$with_libpcap])

AC_MSG_CHECKING([user defined path to libpcap libraries])
AC_ARG_WITH(libpcap-libs,
  AS_HELP_STRING([--with-libpcap-libs],
      [location of libpcap libraries]),
  [LDFLAGS="$LDFLAGS -L${with_libpcap_libs}"])
AC_MSG_RESULT([$with_libpcap_libs])
AC_SUBST(with_libpcap_libs)

AC_MSG_CHECKING([user defined path to libpcap includes])
AC_ARG_WITH(libpcap-includes,
  AS_HELP_STRING([--with-libpcap-includes],
    [location of libpcapc includes]),
  [CPPFLAGS="$CPPFLAGS -I${with_libpcap_includes}"])
AC_MSG_RESULT([$with_libpcap_includes])

#
# Got Openssl?
#
AC_MSG_CHECKING([user defined path to OpenSSL])
AC_ARG_WITH(openssl,
  AS_HELP_STRING([--with-openssl],
    [location of openssl root tree]),
  [LDFLAGS="$LDFLAGS -L${with_openssl}/lib";CPPFLAGS="$CPPFLAGS -I${with_openssl}/include"])
AC_MSG_RESULT([$with_openssl])

AC_MSG_CHECKING([user defined path to OpenSSL libraries])
AC_ARG_WITH(openssl-libs,
  AS_HELP_STRING([--with-openssl-libs],
    [location of openssl libraries]),
  [LDFLAGS="$LDFLAGS -L${with_openssl_libs}"])
AC_MSG_RESULT([$with_openssl_libs])
AC_SUBST(with_openssl_libs)

AC_MSG_CHECKING([user defined path to OpenSSL headers])
AC_ARG_WITH(openssl-headers,
  AS_HELP_STRING([--with-openssl-headers],
    [location of openssl header files]),
  [CPPFLAGS="$CPPFLAGS -I${with_openssl_headers}"])
AC_MSG_RESULT([$with_openssl_headers])

AC_ARG_ENABLE(experimental,
  AS_HELP_STRING([--enable-experimental],
    [enable the use of experimental features/code.]),
  [],
  [enable_experimental="no"])

AC_ARG_ENABLE(gnutls,
  AS_HELP_STRING([--enable-gnutls],
    [enable the use of GNU-TLS 1.4.0 or later.]),
  [],
  [enable_gnutls="no"])

AC_ARG_ENABLE(osc-tnc,
  AS_HELP_STRING([--enable-osc-tnc],
    [enable use of the libtnc IMC libraries for run-time Network Access ]\
    [Control with Radiator TNC plug-in modules]),
  [],
  [enable_osc_tnc="no"])

AC_ARG_ENABLE(tnc,
  AS_HELP_STRING([--enable-tnc],
    [enable use of the libtnc IMC libraries for run-time Network Access ]\
    [Control with compliant TNC plug-in modules]),
  [],
  [enable_tnc="no"])

AC_ARG_ENABLE(efence,
  AS_HELP_STRING([--enable-efence],
    [enable use of Electric Fence for memory debugging.]),
  [],
  [enable_efence="no"])

AC_ARG_ENABLE(direct-radius,
  AS_HELP_STRING([--enable-direct-radius],
    [communicate directly with RADIUS.  (Only useful for testing/debugging.)]),
  [],
  [enable_direct_radius="no"])

AC_ARG_ENABLE(eap-fast,
  AS_HELP_STRING([--enable-eap-fast],
    [enable use of EAP-FAST]),
  [],
  [enable_eap_fast="no"])

AC_ARG_ENABLE(eap-sim,
  AS_HELP_STRING([--enable-eap-sim],
    [enable use of (U)SIM card for authentication]),
  [],
  [enable_eap_sim="no"])

AC_ARG_ENABLE(aka-test,
  AS_HELP_STRING([--enable-aka-test],
    [enable use of test vectors.  (Doesn't require a SIM card, and is ]\
    [compatible with Radiator.)]),
  [],
  [enable_aka_test="no"])

AC_ARG_ENABLE(parser-debug,
  AS_HELP_STRING([--enable-parser-debug],
    [enable the parser debug (will log and print usernames and passwords!!!)]),
  []
  [enable_parser_debug="no"])

AC_ARG_ENABLE(generic-framer,
  AS_HELP_STRING([--enable-generic-framer],
    [enable the use of PCAP instead of native handler.]),
  [],
  [enable_generic_framer="no"])

AC_ARG_ENABLE(static-openssl,
  AS_HELP_STRING([--enable-static-openssl],
    [enable static linking of OpenSSL]),
  [],
  [enable_static_openssl="no"])

AC_ARG_ENABLE(panther-binary,
  AS_HELP_STRING([--enable-panther-binary],
    [build as Panther-compatible binary (Mac OS X Only)]),
  [],
  [enable_panther_binary="no"])

AC_ARG_ENABLE(universal-binary,
  AS_HELP_STRING([--enable-universal-binary],
    [build as Universal Binary (Mac OS X Only)]),
  [],
  [enable_universal_binary="no"])




########### CONFIGURE TESTS #############

dnl enable experimental code? (not currently used)
AS_IF([test "$enable_experimental" = yes], AC_DEFINE(EXPERIMENTAL), [])

dnl check for osc-tnc
AS_IF([test "$enable_osc_tnc" = yes],
  [ AC_CHECK_HEADER(libtnc.h,
      [ MORELIBS="$MORELIBS -ltnc" ],
      AC_MSG_ERROR([The TNC library is required to use TNC support!])) 
    AC_DEFINE(HAVE_OSC_TNC)],
  [])

dnl check for tnc
AS_IF([test "$enable_tnc" = yes],
  [ AC_CHECK_HEADER(libtnc.h,
      [ MORELIBS="$MORELIBS -ltnc" ],
      AC_MSG_ERROR([The TNC library is required to use TNC support!]))
    AC_DEFINE(HAVE_TNC)],
  [])

dnl check for efence
AS_IF([test "$enable_efence" = yes],
  [ AC_CHECK_HEADER(efence.h,
      [MORELIBS="$MORELIBS -lefence" ],
      AC_MSG_ERROR([You must have Electric Fence installed to use it!]))
    AC_DEFINE(USE_EFENCE)],
  [])

dnl check for gnutls (needs a better check)
AS_IF([test "$enable_gnutls" = yes],
  [AC_DEFINE(USE_GNUTLS) LIBS="$LIBS -lgnutls"],
  [])

dnl check for direct radius
AS_IF([test "$enable_direct_radius" = yes],
  [AC_DEFINE(USE_DIRECT_RADIUS) RADIUS="yes"],
  [RADIUS="no"])

dnl check for eap-fast
AS_IF([test "$enable_eap_fast" = yes], AC_DEFINE(EAP_FAST), [])
			  
dnl check for eap-sim
AS_IF([test "$enable_eap_sim" = yes],
  [ AC_DEFINE(EAP_SIM_ENABLE)
    AC_MSG_CHECKING([for libpcsclite])
    if `pkg-config libpcsclite --exists`; then
      LIBS=`pkg-config libpcsclite --libs $LIBS`
      AM_CPPFLAGS=`pkg-config libpcsclite --cflags $AM_CPPFLAGS`
    else
      AC_MSG_ERROR([libpcsclite is required to use EAP-SIM/AKA support. If you believe that you have it, but it isn't being located, you may want to set the PKG_CONFIG_PATH to point to the location of libpcsclite.pc.])
    fi],
  [])

dnl enable aka test?
AS_IF([test "$enable_aka_test" = yes], AC_DEFINE(RADIATOR_TEST), [])

dnl enable parser debug?
AS_IF([test "$enable_parser_debug" = yes], AC_DEFINE(PARSER_DEBUG), [])

dnl check for static ossl
AS_IF([test "$enable_static_ossl" = yes],
  [LDFLAGS="-static $LDFLAGS" STATIC_OSSL="yes"],
  [STATIC_OSSL="no"])

AC_MSG_CHECKING([for libxml-2.0])
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

dnl Below turns off Kerberos support in OpenSSL, to avoid compile errors.
AC_DEFINE(OPENSSL_NO_KRB5)

AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [], [AC_MSG_ERROR([library 'crypto' is required for Open1x])])
AC_CHECK_LIB(ssl,    SSL_library_init, [], [AC_MSG_ERROR([library 'ssl' is required for Open1x])])
AC_CHECK_HEADER(openssl/ssl.h, [], [AC_MSG_ERROR([header file <openssl/ssl.h> is required for Open1x])])
AC_CHECK_HEADER(openssl/err.h, [], [AC_MSG_ERROR([header file <openssl/err.h> is required for Open1x])])

dnl Determine the operating system and the framer
case "$host_os" in
   *linux*)
      framer="linux"
      platform="linux"
      AC_DEFINE(LINUX)
      MORELIBS="${MORELIBS} -liw"

      AC_CHECK_HEADERS(sys/socket.h, [], [AC_MSG_ERROR([header file \
        <sys/socket.h> is required for Xsupplicant.])],)

      AC_CHECK_HEADERS(iwlib.h, [],
        [AC_MSG_ERROR([header file <iwlib.h> is required for Xsupplicant])],)
   ;;

   *darwin*)
      framer="darwin"
      platform="darwin"
      AC_DEFINE(DARWIN)

      AC_CHECK_FILE([$srcdir/lib/libdarwinwireless/libdarwinwireless.a],[
         AC_DEFINE(DARWIN_WIRELESS)
         AC_DEFINE(TOTAL_WIRELESS_CONTROL)
         AC_MSG_RESULT([Build for wireless!])
         DARWINLIBS=" -F/System/Library/PrivateFrameworks -framework Apple80211 -framework CoreFoundation "'-L${top_srcdir}/lib/libdarwinwireless'" -ldarwinwireless -lresolv"
         DARWININCS=' -I${top_srcdir}/lib/libdarwinwireless'
      ],[
         AC_MSG_RESULT([Building for wired support only!])
         DARWINLIBS=" -framework CoreFoundation -lresolv"
      ])

      user_defined_sysroot="no"

      AS_IF([test "$enable_panther_binary" = "yes"],[
         user_defined_sysroot="yes"
         sysroot_sdk="MacOSX10.3.9.sdk"
         macosx_version_min="10.3"
      ], [])

      AS_IF([test "$enable_universal_binary" = "yes"],[
         user_defined_sysroot="yes"
         sysroot_sdk="MacOSX10.4u.sdk"
         macosx_version_min="10.4"

         CFLAGS="$CFLAGS -arch i386 -arch ppc "
         LDFLAGS="$LDFLAGS -arch i386 -arch ppc"
      ], [])

      AS_IF([test "$user_defined_sysroot" = "yes"],[
         # Check to see if the system has xcode-select (Mac OS X 10.5 "Leopard" or later).
         # This is necessary if the user has installed their development SDKs somewhere
         # other than the default location (/Developer)
         # if xcode-select doesn't exist, assume the tools are in /Developer
         AC_CHECK_FILE([/usr/bin/xcode-select],[         
            sysroot=`/usr/bin/xcode-select -print-path`
         ],[
	    sysroot="/Developer"
	 ])

         AC_MSG_CHECKING([For Mac OS X SDK Path])
         AC_MSG_RESULT([$sysroot])

         CFLAGS="$CFLAGS -isysroot $sysroot/SDKs/${sysroot_sdk} -mmacosx-version-min=${macosx_version_min}"
      ], [])

   ;;

   *freebsd*)
      framer="freebsd"
      AC_DEFINE(__BSD__)
      AC_DEFINE(FREEBSD)
   ;;

   *openbsd*)
      framer="freebsd"
      AC_DEFINE(__BSD__)
      AC_DEFINE(OPENBSD)
   ;;

   *windows* | *cygwin* | *mingw*)
      framer="windows"
      platform="windows"
   ;;

   *)
      framer="generic"
   ;;
esac

AS_IF([test "$enable_direct_radius" = "yes"], [framer="radius"], [])
AS_IF([test "$enable_generic_framer" = "yes"], [framer="generic"], [])

AC_MSG_CHECKING([for native frame interface])
AC_MSG_RESULT($framer)

AC_MSG_CHECKING([for platform OS])
AC_MSG_RESULT($platform)

AS_IF([test $framer = "linux"],
  [ MORELIBS="${MORELIBS} -lm"
    AC_MSG_CHECKING([for procfs support])
    if test -r /proc/net/dev; then
      AC_MSG_RESULT(okay)
    else
      AC_MSG_ERROR([You must have ProcFS enabled in your kernel!]);
    fi],
  [])

AS_IF([test $framer = "generic"],
  MORELIBS="${MORELIBS} -lwpcap -lpcap -ldnet",
  [])

AM_CONDITIONAL([FRAMER_GENERIC], [test "$framer" = generic])
AM_CONDITIONAL([FRAMER_LINUX],   [test "$framer" = linux])
AM_CONDITIONAL([FRAMER_FREEBSD], [test "$framer" = freebsd])
AM_CONDITIONAL([FRAMER_DARWIN],  [test "$framer" = darwin])
AM_CONDITIONAL([FRAMER_RADIUS],  [test "$framer" = radius])
AM_CONDITIONAL([FRAMER_WINDOWS], [test "$framer" = windows])

AM_CONDITIONAL([LINUX],   [test "$platform" = linux])
AM_CONDITIONAL([DARWIN],  [test "$platform" = darwin])
AM_CONDITIONAL([WINDOWS], [test "$platform" = windows])

CFLAGS="$GGDBFLAGS $CFLAGS"
AM_CPPFLAGS="$AM_CPPFLAGS "'-I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/src'

AC_SUBST(MORELIBS)
AC_SUBST(DARWINLIBS)
AC_SUBST(CORELIBS)
AC_SUBST(MOREDEFS)
AC_SUBST(LDFLAGS)
AC_SUBST(AM_CPPFLAGS)
AC_SUBST(DARWININCS)
AC_SUBST(PREFIX)
AC_CONFIG_FILES([Makefile
		src/Makefile
		src/platform/Makefile
		tools/Makefile
		doc/Makefile
		doc/Doxyfile
		etc/Makefile
		tools/config-parser/Makefile
		tools/ntpwdhash/Makefile
		lib/Makefile
		lib/libxsupgui/Makefile
		lib/libxsupconfig/Makefile
		lib/libxsupconfwrite/Makefile
		lib/libxsupconfcheck/Makefile
		tools/ipctest/Makefile
		tools/ipcevents/Makefile
		tools/connect-tool/Makefile
		lib/liblist/Makefile
		lib/libsupdetect/Makefile
		])
AC_OUTPUT
