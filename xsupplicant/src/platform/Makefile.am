noinst_LIBRARIES = libplatform.a

if FRAMER_LINUX
  FRAMER_SRCS = linux/cardif_linux.h linux/cardif_linux_rtnetlink.h \
		linux/cardif_linux_wext.h linux/netlink.h linux/rtnetlink.h \
		\
		linux/cardif_linux.c linux/cardif_linux_rtnetlink.c \
		linux/cardif_linux_wext.c
endif
if FRAMER_DARWIN
  FRAMER_SRCS = macosx/cardif_macosx.h macosx/cardif_macosx_wireless.h \
		macosx/ndrv_socket.h \
		\
		macosx/cardif_macosx.c macosx/cardif_macosx_wireless.c \
		macosx/ndrv_socket.c
endif
if FRAMER_FREEBSD
  FRAMER_SRCS = freebsd/cardif_freebsd.h freebsd/cardif_freebsd.c
endif
if FRAMER_GENERIC
  FRAMER_SRCS = generic/cardif_generic.h generic/cardif_generic.c
endif
if FRAMER_RADIUS
  FRAMER_SRCS = radius/cardif_radius.h radius/cardif_radius.c
endif
if FRAMER_WINDOWS
  FRAMER_SRCS = windows/cardif_windows_dot11.h windows/cardif_windows.h \
		windows/cardif_windows_wireless.h \
		windows/cardif_windows_wmi_async.h \
		windows/cardif_windows_wmi.h windows/windows_eapol_ctrl.h \
		windows/wzc_ctrl.h \
		\
		windows/cardif_windows.c windows/cardif_windows_dot11.c \
		windows/cardif_windows_wireless.c \
		windows/cardif_windows_wmi_async.c \
		windows/cardif_windows_wmi.c windows/windows_eapol_ctrl.c \
		windows/wzc_ctrl.c
endif

if LINUX
  PLATFORM_SRCS = linux/lin_cert_handler.c linux/plugin_handler_linux.c
endif
if DARWIN
  PLATFORM_SRCS = macosx/darwin_cert_handler.c macosx/plugin_handler_macosx.c
endif
if WINDOWS
  PLATFORM_SRCS = windows/win_cert_handler.c windows/plugin_handler_windows.c
endif

libplatform_a_SOURCES = cardif.h cert_handler.h plugin_handler.h \
			$(FRAMER_SRCS) $(PLATFORM_SRCS)



