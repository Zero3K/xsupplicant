This directory contains the files that are needed to create the installer used by XSupplicant.  Note that you will need to 
provide your own versions of the QT files, since the ones used in the official releases are licensed to the XSupplicant
developers.

You will also need to find the processworks.dll plugin for NSIS and put that in your plug-ins folder.  If you have any problems
locating this file, please ask on the list.

NOTE: In order to use this installer data you currently need to have it in a directory at the same level as the xsupplicant and ui
directories.  You will probably also need to comment out the checksupsapp.exe lines.