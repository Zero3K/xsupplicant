### We now run ./gen_version.sh to get our version number so that we can 
# control that variable from the build system.
AC_INIT([XSupplicant],m4_esyscmd(./gen_version.sh), [], [xsupplicant])


AC_PREREQ(2.59)
AM_INIT_AUTOMAKE([dist-bzip2] [dist-zip] [foreign])
LT_INIT
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

AC_ARG_WITH(old-iwlib,
  AS_HELP_STRING([--with-old-iwlib],
    [use older 2-param IWLIB calls]),
  [AC_DEFINE(OLD_IWLIB)])

#AC_MSG_CHECKING([user defined path to libpcap])
#AC_ARG_WITH(libpcap,
#  AS_HELP_STRING([--with-libpcap],
#    [location of libpcap/winpcap root development tree]),
#  [LDFLAGS="$LDFLAGS -L${with_libpcap}/lib";CPPFLAGS="$CPPFLAGS -I${with_libpcap}/include"])
#AC_MSG_RESULT([$with_libpcap])

#AC_MSG_CHECKING([user defined path to libpcap libraries])
#AC_ARG_WITH(libpcap-libs,
#  AS_HELP_STRING([--with-libpcap-libs],
#      [location of libpcap libraries]),
#  [LDFLAGS="$LDFLAGS -L${with_libpcap_libs}"])
#AC_MSG_RESULT([$with_libpcap_libs])
#AC_SUBST(with_libpcap_libs)

#AC_MSG_CHECKING([user defined path to libpcap includes])
#AC_ARG_WITH(libpcap-includes,
#  AS_HELP_STRING([--with-libpcap-includes],
#    [location of libpcapc includes]),
#  [CPPFLAGS="$CPPFLAGS -I${with_libpcap_includes}"])
#AC_MSG_RESULT([$with_libpcap_includes])

#
# Got Openssl?
#
AC_MSG_CHECKING([user defined path to OpenSSL])
AC_ARG_WITH(openssl,
  AS_HELP_STRING([--with-openssl],
    [location of openssl root tree]),
  [LDFLAGS="$LDFLAGS -L${with_openssl}/lib -L${with_openssl}";CPPFLAGS="$CPPFLAGS -I${with_openssl}/include";MORELIBS="$MORELIBS -L${with_openssl}/lib -L${with_openssl}"])
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

AC_MSG_CHECKING([user defined path to pcsclite libraries])
AC_ARG_WITH(pcsclite-libs,
  AS_HELP_STRING([--with-pcsclite-libs],
    [location of pcsclite libraries]),
  [LDFLAGS="$LDFLAGS -L${with_pcsclite_libs}"])
AC_MSG_RESULT([$with_pcsclite_libs])
AC_SUBST(with_pcsclite_libs)

AC_MSG_CHECKING([user defined path to pcsclite headers])
AC_ARG_WITH(pcsclite-headers,
  AS_HELP_STRING([--with-pcsclite-headers],
    [location of the pcsclite headers]),
  [CPPFLAGS="$CPPFLAGS -I${with_pcsclite_headers}"])
AC_MSG_RESULT([$with_openssl_headers])

AC_MSG_CHECKING([user defined path to iwlib])
AC_ARG_WITH(iwlib-path,
  AS_HELP_STRING([--with-iwlib-path],
    [location of the iwlib headers and libraries]),
  [CPPFLAGS="$CPPFLAGS -I${with_iwlib_path} -I${with_iwlib_path}/include";MORELIBS="$MORELIBS -L${with_iwlib_path}/lib -L${with_iwlib_path}"])
AC_MSG_RESULT([$with_iwlib_path])

AC_MSG_CHECKING([user defined path to iwlib libraries])
AC_ARG_WITH(iwlib-lib-path,
  AS_HELP_STRING([--with-iwlib-lib-path],
    [location of the iwlib library]),
    [LDFLAGS="$LDFLAGS -L${with_iwlib_lib_path}"])
AC_MSG_RESULT([$with_iwlib_lib_path])
AC_SUBST(with_iwlib_lib_path)

AC_MSG_CHECKING([user defined path to iwlib headers])
AC_ARG_WITH(iwlib-headers,
  AS_HELP_STRING([--with-iwlib-headers],
    [location of the iwlib headers]),
    [CPPFLAGS="$CPPFLAGS -I${with_iwlib_headers} -I${with_iwlib_headers}/include"])
AC_MSG_RESULT([$with_iwlib_headers])
AC_SUBST(with_iwlib_headers)

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

AC_ARG_ENABLE(static-openssl,
  AS_HELP_STRING([--enable-static-openssl],
    [statically link openssl libraries]),
  [AS_IF([test -n "$with_openssl_libs" && test -n "$with_openssl_headers"], 
  	       [enable_static_openssl="yes" ], 
  	       [AC_MSG_ERROR("You must use --with-openssl-libs and --with-openssl-headers to use static OpenSSL support.")])])

AC_ARG_ENABLE(static-iwlib,
  AS_HELP_STRING([--enable-static-iwlib],
    [statically link Linux wireless libraries]),
  [AS_IF([test -n "$with_iwlib_lib_path" && test -n "$with_iwlib_headers"],
  	       [enable_static_iwlib="yes" ],
	       [AC_MSG_ERROR("You must use --with-iwlib-lib-path and --with-iwlib-headers to use static Linux wireless library support.")])])

AC_ARG_ENABLE(unsafe-dumps,
  AS_HELP_STRING([--enable-unsafe-dumps],
    [enable dumpping of data that may contain things such as passwords and private keys.  (This is *REALLY* unsafe and should only be used for debugging!)]),
  [AC_DEFINE(UNSAFE_DUMPS)])

AC_ARG_ENABLE(static-libxml,
  AS_HELP_STRING([--enable-static-libxml],
    [statically link libxml2 libraries]),
  [AS_IF([test -n "$with_libxml_libs" && test -n "$with_libxml_headers"],
  	       [enable_static_libxml="yes" ],
	       [AC_MSG_ERROR("You must use --with-libxml-libs and --with-libxml-headers to use static libxml2 libraries.")])])

AC_ARG_ENABLE(static-pcsclite,
  AS_HELP_STRING([--enable-static-pcsclite],
    [statically link libpcsclite libraries]),
  [AS_IF([test -n "$with_pcsclite_libs" && test -n "$with_pcsclite_headers"],
  	       [enable_static_pcsclite="yes" ],
	       [AC_MSG_ERROR("You must user --with-pcsclite-libs and --with-pcsclite-headers to use static pcsc lite libraries.")])])

AC_ARG_ENABLE(experimental,
  AS_HELP_STRING([--enable-experimental],
    [enable the use of experimental features/code.]),
  [],
  [enable_experimental="no"])

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

AC_ARG_ENABLE(net80211,
  AS_HELP_STRING([--enable-net80211],
    [build without the Linux Net 802.11 extensions]),
  [disable_net80211="no"],
  [disable_net80211="yes"])

AC_ARG_ENABLE(moko-support,
  AS_HELP_STRING([--enable-moko-support],
    [build with extra tweaks needed to run on the Moko platform]),
    [disable_net80211="yes" enable_moko="yes"],
    [])

########### CONFIGURE TESTS #############

dnl enable experimental code? (not currently used)
AS_IF([test "$enable_experimental" = yes], AC_DEFINE(EXPERIMENTAL), [])

dnl check for tnc
AS_IF([test "$enable_tnc" = yes],
  [ AC_CHECK_HEADER(libtnc.h,
      [ TNCLIB="-ltnc" ],
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

dnl check for direct radius
AS_IF([test "$enable_direct_radius" = yes],
  [AC_DEFINE(USE_DIRECT_RADIUS) RADIUS="yes"],
  [RADIUS="no"])

dnl check for moko features
AS_IF([test "$enable_moko" = yes],
  [AC_DEFINE(ENABLE_MOKO)],
  [])

dnl check for eap-fast
AS_IF([test "$enable_eap_fast" = yes], AC_DEFINE(EAP_FAST), [])
			  
dnl check for eap-sim
AS_IF([test "$enable_eap_sim" = yes],
  [ AC_DEFINE(EAP_SIM_ENABLE)
  AS_IF([test "$enable_static_pcsclite" = yes],
  [AS_IF([test -f "${with_pcsclite_libs}/libpcsclite.a"], 
   [MORELIBS="$MORELIBS ${with_pcsclite_libs}/libpcsclite.a -lpthread"],
   [AC_ERROR(["Unable to locate libpcsclite.a in the directory provided!"])])
   AS_IF([test -f "${with_pcsclite_headers}/winscard.h"],
   [AM_CPPFLAGS="-I${with_pcsclite_headers} $AM_CPPFLAGS"],
   [AC_ERROR(["Unable to locate winscard.h in the header directory provided!"])])],
  [
    AC_MSG_CHECKING([for libpcsclite])
    if `pkg-config libpcsclite --exists`; then
      PCSCLIBS=`pkg-config libpcsclite --libs`
      LIBS="$PCSCLIBS $LIBS"
      PCSCFLAGS=`pkg-config libpcsclite --cflags`
      AM_CPPFLAGS="$PCSCFLAGS $AM_CPPFLAGS"
    else
      AC_MSG_ERROR([libpcsclite is required to use EAP-SIM/AKA support. If you believe that you have it, but it isn't being located, you may want to set the PKG_CONFIG_PATH to point to the location of libpcsclite.pc.])
    fi],
  [])
  ])

dnl enable aka test?
AS_IF([test "$enable_aka_test" = yes], AC_DEFINE(RADIATOR_TEST), [])

dnl enable parser debug?
AS_IF([test "$enable_parser_debug" = yes], AC_DEFINE(PARSER_DEBUG), [])

AC_MSG_CHECKING([for libxml-2.0])
AS_IF([test "$enable_static_libxml" != yes], [
if `pkg-config libxml-2.0 --exists`; then
     XML2LIBS=`pkg-config libxml-2.0 --libs`
     LIBS="$XML2LIBS $LIBS"
     XML2FLAGS=`pkg-config libxml-2.0 --cflags`
     AM_CPPFLAGS="$XML2FLAGS $AM_CPPFLAGS"
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
   [MORELIBS="$MORELIBS ${with_libxml_libs}/libxml2.a";AS_IF([test "$enable_static_libz"], [], [MORELIBS="$MORELIBS -lz"])],
   [AC_MSG_ERROR([libxml2.a was not found at the path specified!])])])

AS_IF([test "$disable_net80211" != yes],
	    [AC_MSG_CHECKING([for libnl-1])
	    if `pkg-config libnl-1 --exists`; then
	    if `pkg-config libnl-1 --exact-version=1.0-pre8` || `pkg-config libnl-1 --atleast-version=1.0`; then
	         LIBNLLIBS="`pkg-config libnl-1 --libs`"
		 LIBNLCFLAGS="`pkg-config libnl-1 --cflags`"
		 LIBS="$LIBS $LIBNLLIBS"
		 CFLAGS="$CFLAGS $LIBNLCFLAGS"
		 AC_MSG_RESULT([found with pkg-config])
	    else
		 AC_MSG_ERROR([Xsupplicant requires libnl version >=1.0-pre8.])
	    fi
	   else
                AC_MSG_ERROR([Xsupplicant requires libnl.  You need to either install libnl, or set PKG_CONFIG_PATH to point to the location of the libnl-1.0.pc file.])
     	 fi], [AC_DEFINE(DISABLE_LIBNL)])

dnl Below turns off Kerberos support in OpenSSL, to avoid compile errors.
AC_DEFINE(OPENSSL_NO_KRB5)

AS_IF([test "$enable_static_openssl" != yes], [
	    AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [MORELIBS="${MORELIBS} -lcrypto"], [AC_MSG_ERROR([library 'crypto' is required for Open1x])])
	    AC_CHECK_LIB(ssl,    SSL_library_init, [MORELIBS="${MORELIBS} -lssl"], [AC_MSG_ERROR([library 'ssl' is required for Open1x])])], 
[AS_IF([test -f "$with_openssl_libs/libssl.a"], [MORELIBS="${MORELIBS} ${with_openssl_libs}/libssl.a"], [AC_MSG_ERROR(libssl.a was not found in ${with_openssl_libs}!)])
AS_IF([test -f "$with_openssl_libs/libcrypto.a"], [MORELIBS="${MORELIBS} ${with_openssl_libs}/libcrypto.a -ldl"], [AC_MSG_ERROR([libcrypto.a was not found in ${with_openssl_libs}!])])])

AC_CHECK_HEADER(openssl/ssl.h, [], [AC_MSG_ERROR([header file <openssl/ssl.h> is required for Open1x])])
AC_CHECK_HEADER(openssl/err.h, [], [AC_MSG_ERROR([header file <openssl/err.h> is required for Open1x])])

dnl Determine the operating system and the framer
case "$host_os" in
   *linux*)
      framer="linux"
      platform="linux"
      AC_DEFINE(LINUX)

      AC_CHECK_HEADER(sys/socket.h, [], [AC_MSG_ERROR([header file \
        <sys/socket.h> is required for Xsupplicant.])])

      AS_IF([test "$enable_static_iwlib" != yes], 
      		  [AC_CHECK_HEADER([iwlib.h], 
		  	[MORELIBS="${MORELIBS} -liw"], [AC_MSG_ERROR([header file <iwlib.h> is required for XSupplicant.])])],
		[AS_IF([test -f "$with_iwlib_lib_path/libiw.a"],
		       [MORELIBS="${MORELIBS} ${with_iwlib_lib_path}/libiw.a"],
		       [AC_MSG_ERROR([libiw.a was not found in ${with_iwlib_lib_path}])])
		 AS_IF([test -f "$with_iwlib_headers/iwlib.h"],
		       [],
		       [AC_MSG_ERROR([iwlib.h was not found in ${with_iwlib_headers}])])
		 ])

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
AM_CPPFLAGS="$AM_CPPFLAGS "'-I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/../lib -I${top_srcdir}/src -I${top_srcdir}/../src'

AC_SUBST(MORELIBS)
AC_SUBST(DARWINLIBS)
AC_SUBST(CORELIBS)
AC_SUBST(TNCLIB)
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
		lib/libcrashdump/Makefile
		tools/ipctest/Makefile
		tools/ipcevents/Makefile
		tools/connect-tool/Makefile
		lib/liblist/Makefile
		lib/libsupdetect/Makefile
		plugins/Makefile
		plugins/SoftSIM2G/Makefile
		plugins/SoftSIM3G/Makefile
		])
AC_OUTPUT
