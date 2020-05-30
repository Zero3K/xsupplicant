--- ndisbind.c	Fri Feb 18 08:31:58 2005
+++ ndisbind.c	Thu Mar 06 13:32:31 2008
@@ -2071,7 +2071,15 @@
             pIrpSp = IoGetCurrentIrpStackLocation(pIrp);            
             pIndicateStatus = pIrp->AssociatedIrp.SystemBuffer;
             inBufLength = pIrpSp->Parameters.DeviceIoControl.InputBufferLength;
-            outBufLength = pIrpSp->Parameters.DeviceIoControl.OutputBufferLength;            
+            outBufLength = pIrpSp->Parameters.DeviceIoControl.OutputBufferLength;
+
+            //
+            // Filter out messages that we don't care about.  (Some wireless drivers get pretty chatty.)
+            //
+            if ((GeneralStatus > 0x40000000L) &&
+                (GeneralStatus < 0x40040000L) &&
+                (GeneralStatus != 0x40010017L)) 
+                {
             //
             // Clear the cancel routine.
             //
@@ -2121,6 +2129,11 @@
                 // Cancel rotuine is running. Leave the irp alone.
                 //
                 pIrp = NULL;
+            }
+            } else {
+                // Don't cancel the IRP yet.
+                pIrp = NULL;
+//                ntStatus = STATUS_SUCCESS;
             }
         }
     }while(FALSE);
--- ndisprot.h	Fri Feb 18 08:31:58 2005
+++ ndisprot.h	Tue Jan 08 10:29:38 2008
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
--- ntdisp.c	Fri Feb 18 08:31:58 2005
+++ ntdisp.c	Tue Jan 08 10:29:38 2008
@@ -67,7 +67,7 @@
 {
     NDIS_PROTOCOL_CHARACTERISTICS   protocolChar;
     NTSTATUS                        status = STATUS_SUCCESS;
-    NDIS_STRING                     protoName = NDIS_STRING_CONST("NdisProt");     
+    NDIS_STRING                     protoName = NDIS_STRING_CONST("Open1X");     
     UNICODE_STRING                  ntDeviceName;
     UNICODE_STRING                  win32DeviceName;
     BOOLEAN                         fSymbolicLink = FALSE;
--- recv.c	Fri Feb 18 08:31:58 2005
+++ recv.c	Tue Jan 08 10:29:38 2008
@@ -453,6 +453,13 @@
             break;
         }
 
+        if (((PNDISPROT_ETH_HEADER)pHeaderBuffer)->EthType != 0x8e88)
+        {
+            // We don't want it!
+            Status = NDIS_STATUS_NOT_ACCEPTED;
+            break;
+        }
+
         //
         //  Allocate resources for queueing this up.
         //
@@ -479,6 +486,7 @@
                                   pLookaheadBuffer,
                                   LookaheadBufferSize,
                                   pOpenContext->MacOptions);
+
             //
             //  Queue this up for receive processing, and
             //  try to complete some read IRPs.
@@ -740,6 +748,14 @@
                 ("ReceivePacket: Open %p, runt pkt %p, first buffer length %d\n",
                     pOpenContext, pNdisPacket, BufferLength));
 
+            Status = NDIS_STATUS_NOT_ACCEPTED;
+            break;
+        }
+
+        // If we ever find a Windows version that is big endian, this won't
+        // work!!!!!  (But how likely is that? ;)
+        if (pEthHeader->EthType != 0x8e88)
+        {
             Status = NDIS_STATUS_NOT_ACCEPTED;
             break;
         }
--- sources	Fri Feb 18 08:31:58 2005
+++ sources	Tue Jan 08 10:29:38 2008
@@ -1,4 +1,4 @@
-TARGETNAME=ndisprot
+TARGETNAME=open1x
 TARGETPATH=obj
 TARGETTYPE=DRIVER
 
--- debug.c	Fri Feb 18 08:31:58 2005
+++ debug.c	Tue Jan 08 10:29:39 2008
--- debug.h	Fri Feb 18 08:31:58 2005
+++ debug.h	Tue Jan 08 10:29:39 2008
--- excallbk.c	Fri Feb 18 08:31:58 2005
+++ excallbk.c	Tue Jan 08 10:29:39 2008
--- macros.h	Fri Feb 18 08:31:58 2005
+++ macros.h	Tue Jan 08 10:29:39 2008
--- makefile	Fri Feb 18 08:31:58 2005
+++ makefile	Tue Jan 08 10:29:39 2008
--- ndisprot.rc	Fri Feb 18 08:31:58 2005
+++ ndisprot.rc	Tue Jan 08 10:29:39 2008
--- nuiouser.h	Fri Feb 18 08:31:58 2005
+++ nuiouser.h	Tue Jan 08 10:29:39 2008
--- precomp.h	Fri Feb 18 08:31:58 2005
+++ precomp.h	Tue Jan 08 10:29:38 2008
--- send.c	Fri Feb 18 08:31:58 2005
+++ send.c	Tue Jan 08 10:29:39 2008
