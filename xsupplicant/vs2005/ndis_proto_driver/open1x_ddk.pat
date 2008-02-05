--- C:/WinDDK/3790.1830/src/network/ndis/ndisprot/sys/sources	Tue Dec 05 10:37:40 2006
+++ C:/xsup_dev/xsupplicant/vs2005/ndis_proto_driver/sources	Mon Dec 04 15:22:23 2006
@@ -1,4 +1,4 @@
-TARGETNAME=ndisprot
+TARGETNAME=open1x
 TARGETPATH=obj
 TARGETTYPE=DRIVER
 
--- C:/WinDDK/3790.1830/src/network/ndis/ndisprot/sys/recv.c	Fri Feb 18 08:31:58 2005
+++ C:/xsup_dev/xsupplicant/vs2005/ndis_proto_driver/recv.c	Fri Dec 08 15:55:21 2006
@@ -479,11 +479,22 @@
                                   pLookaheadBuffer,
                                   LookaheadBufferSize,
                                   pOpenContext->MacOptions);
-            //
-            //  Queue this up for receive processing, and
-            //  try to complete some read IRPs.
-            //
-            ndisprotQueueReceivePacket(pOpenContext, pRcvPacket);
+
+            if ((pRcvData[12] == 0x88) && (pRcvData[13] == 0x8e))
+            {
+                //
+                //  Queue this up for receive processing, and
+                //  try to complete some read IRPs.
+                //
+                ndisprotQueueReceivePacket(pOpenContext, pRcvPacket);
+            }
+            else
+            {
+                // Free the buffer.
+                ndisprotFreeReceivePacket(pOpenContext, pRcvPacket);
+                Status = NDIS_STATUS_NOT_ACCEPTED;
+                break;
+            }
         }
         else
         {
--- C:/WinDDK/3790.1830/src/network/ndis/ndisprot/sys/ntdisp.c	Fri Feb 18 08:31:58 2005
+++ C:/xsup_dev/xsupplicant/vs2005/ndis_proto_driver/ntdisp.c	Mon Dec 04 15:25:35 2006
@@ -67,7 +67,7 @@
 {
     NDIS_PROTOCOL_CHARACTERISTICS   protocolChar;
     NTSTATUS                        status = STATUS_SUCCESS;
-    NDIS_STRING                     protoName = NDIS_STRING_CONST("NdisProt");     
+    NDIS_STRING                     protoName = NDIS_STRING_CONST("Open1X");     
     UNICODE_STRING                  ntDeviceName;
     UNICODE_STRING                  win32DeviceName;
     BOOLEAN                         fSymbolicLink = FALSE;
--- C:/WinDDK/3790.1830/src/network/ndis/ndisprot/sys/ndisprot.h	Fri Feb 18 08:31:58 2005
+++ C:/xsup_dev/xsupplicant/vs2005/ndis_proto_driver/ndisprot.h	Thu Dec 07 12:01:18 2006
@@ -24,8 +24,8 @@
 #define __NDISPROT__H
 
 
-#define NT_DEVICE_NAME          L"\\Device\\NdisProt"
-#define DOS_DEVICE_NAME         L"\\DosDevices\\NdisProt"
+#define NT_DEVICE_NAME          L"\\Device\\Open1X"
+#define DOS_DEVICE_NAME         L"\\DosDevices\\Open1X"
 
 //
 //  Abstract types
@@ -179,8 +179,7 @@
 
 
 #define NUIOO_PACKET_FILTER  (NDIS_PACKET_TYPE_DIRECTED|    \
-                              NDIS_PACKET_TYPE_MULTICAST|   \
-                              NDIS_PACKET_TYPE_BROADCAST)
+                              NDIS_PACKET_TYPE_MULTICAST)
 
 //
 //  Send packet pool bounds
