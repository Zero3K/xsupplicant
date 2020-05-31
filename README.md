# XSupplicant

AUTHORS:
========
Bryan D. Payne (bdpayne@cs.umd.edu)    
Nick L. Petroni Jr. (npetroni@cs.umd.edu)    
Chris Hessing  (chris@open1x.org)    
Terry Simons   (Terry.Simons@open1x.org)    

This work funded by a grant from National Institute of Standards and
Technology Critical Infrastructure Grants Program.

GENERAL OVERVIEW:
=================
This software allows a GNU/Linux or BSD workstation to authenticate with
a RADIUS server using 802.1x and various EAP protocols.  The intended 
use is for computers with wireless LAN connections to complete a strong
authentication before joining the network.

Note: BSD support is not yet complete.

This provides a good complement to WEP, which provides confidentiality.
Even though it is well documented that WEP has technical flaws, it is still
better than simply sending data in the clear.  Therefore, we recommend using
this software (802.1x) for authentication *and* WEP, WPA, or WPA2/802.11i
for confidentiality. And, as always, be prepared to update your network(s) as 
better security solutions become available.

INSTALLATION:
=============

For a basic, no frills installation :

1. ./configure    
2. make    
3. make install    

DEPENDENCIES:
=============
The following packages must be installed before configuring and building
this software package:
Openssl 0.9.7 (or greater) http://www.openssl.org

OS SPECIFIC DEPENDENCIES:
=========================

Linux - The iwconfig library that comes as part of the wireless_tools package
	is required.

Mac OS X - For wireless support, libdarwinwireless is required.  (As of this
	writing, libdarwinwireless cannot be released to the public due to
	restrictions on the Airport API.)


PROGRAM USAGE:
==============
xsupplicant [-i <interface>] [-c <config file> ]
	    [-d <debug_level>] [-w] [-f] [-D <driver name>] [-z] [-t]
            [-q] [-a]

   -i provide the interface on which to listen for EAPOL packets
   -c configuration file to use (/etc/xsupplicant.conf default)
   -d display different levels of debug information.
   -w don't attempt to use WPA support
   -f run in the forground
   -D use WPA support for driver <driver name>
   -z zero WEP keys on roam (Needed for Orinoco and some other drivers)
   -t don't use IW_ENCODE_TEMP when setting keys
   -q terminate when defaulting to authenticated state
   -a what (interface index)-1 for wireless events (needed for hostap driver)

While the program can be started from the command line directly,
it will most commonly be used as part of a script to bring up
a network interface and be started in daemon mode. Example network
scripts ifup and ifdown have been provided and tested in FreeBSD4.4, 
RedHat Linux, and Debian Linux and have been written to work on any
system with ifconfig and either dhcpcd or pump. It is suggested that
these scripts be used in place of the usual ones whenever bringing
up or down an interface for 802.1X authentication. Furthermore, for
802.11 networks it is recommended that the interface is brought
down and back up in the case of changing networks (going to a new
essid). 

NOTE: if you are using dynamic WEP, you may need to specify the -z command
	line option for Xsupplicant to work properly.

CONFIGURATION FILE:
===================
An example configuration file has been provided. The default path for
the configuration file is /etc/xsupplicant.conf, however, a different file
can be specified at startup with the -c flag. 

Please see the example config files in the etc directory.

x.509 FORMATS:
==============
More on certificates can be found in README.certificates
The following formats MUST be used at this time for the respective 
certificates/keys. Openssl can be used to convert certificate formats
and an example script called pkcs12toDERandPEM.sh has been provided. This
script takes a single argument of a pkcs#12 file, containing the user's
certificate and private key, and produces the files key.pem and cert.cer
to be used by xsupplicant. The following are the required formats:

User Certificate:       DER format
User Private Key:       PEM format
Root Certificate store: PEM format

PROTOCOL SPECIFIC INFORMATION :
===============================

EAP-MD5: This form of authentication should not be used on wireless 
	 connections!  MD5 cannot be used to generate keying material.

EAP-SIM: Is not enabled by default.  To enable it, you will need to add the
	 --enable-eap-sim argument to configure.  Turning EAP-SIM on, also
	 requires the following additional libraries : PCSC 
	 (http://www.musclecard.com), and pthreads.

EAP-AKA: Is not enabled by default.  To enable it, you will need to add the
	 --enable-eap-sim argument to configure.  Turning EAP-AKA on, also
	 requires the following additional libraries : PCSC
	 (http://www.musclecard.com), and pthreads.

WPA/WPA2/802.11i:  Wireless extensions 18, or special driver support is 
                   required to use WPA/WPA2/802.11i.  Please see the
		   README.wpa in the doc directory.

EAP-TNC: Requires that the libtnc library be installed to work properly.
         Please download this from the libtnc web page at 
	 http://sourceforge.net/projects/libtnc


