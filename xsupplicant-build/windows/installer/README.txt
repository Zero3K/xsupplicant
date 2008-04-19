This directory contains the files that are needed to create the installer used by XSupplicant.  Note that you will need to 
provide your own versions of the Qt files, since the ones used in the official releases are licensed to the XSupplicant
developers.

NOTE: In order to use this installer data you currently need to have it in a directory at the same level as the xsupplicant and ui
directories.  You will probably also need to comment out the checksupsapp.exe lines.

You will need to install the following additional plugins in order to build the XSupplicant installer:

processwork.dll (http://www.esanu.name/programs/NSISKillProcess.html)
UAC.dll         (http://nsis.sourceforge.net/UAC_plug-in)
GetVersion.dll  (http://nsis.sourceforge.net/GetVersion_%28Windows%29_plug-in)