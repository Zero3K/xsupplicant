include_HEADERS      = xsupgui.h xsupgui_events.h xsupgui_events_state.h
lib_LIBRARIES        = libxsupgui.a
libxsupgui_a_CFLAGS  = @DARWININCS@ -DEXTERNAL_USE
libxsupgui_a_LIBS    = @LDFLAGS@
libxsupgui_a_SOURCES = ipc_events_errors.h xsupgui_mac_utils.h \
			xsupgui_request.h xsup_gui_trace.h xsupgui_ud.h \
			xsupgui_windows.h xsupgui_xml_common.h \
			\
			xsupgui.c ${top_srcdir}/src/xsup_common.c xsupgui_ud.c \
			xsupgui_xml_common.c xsupgui_request.c \
			xsupgui_events.c xsupgui_events_state.c \
			xsupgui_request2.c xsupgui_request3.c \
			xsupgui_request4.c xsupgui_request5.c \
			xsupgui_request6.c xsupgui_ud.c xsupgui_mac_utils.c \
			xsupgui_request7.c 

