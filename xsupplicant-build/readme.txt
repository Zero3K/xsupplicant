Recurring builds are created with a command like:

schtasks /Create /SC DAILY /ST 01:00:00 /SD 11/17/2008 /TN SeaAnt-Nightly /TR "C:\ant\bin\ant.bat -f C:\OpenSEA\build.xml"

You can delete a scheduled task with:

schtasks /Delete /TN SeaAntNightly

See the following for more information:

schtasks /?
schtasks /Create /?
schtasks /Query /?

Build Script Notes:

The main build script is located in https://open1x.svn.sourceforge.net/svnroot/open1x/trunk/xsupplicant-build/build.xml

Because the script has mechanisms to download the build tree, it's best if the build file be copied to a static location for automating nightly builds.  The default location on the build server is C:\OpenSEA.

Additionally, you will need to copy the windows.build.properties file to C:\OpenSEA as well.  By default the build.xml file tries to read this file from the same directory it is located in, so just make sure that both files end up in the same place.

To invoke, you can simply issue:

C:\OpenSEA> ant

Ant, by default, reads the build.xml directory from the location you invoke it.

Note that when using the schtasks command, however, the full path needs to be issued, such as in the above example.  Also note that when using schtasks you need to use the -f switch with Ant to explicitly call out the build.xml file.

There is also a private build properties file (private.build.properties).  This file mainly differs in the build type (private instead of nightly or release), and it has (by default) publish (e-mail and ftp/scp upload) disabled.  This is helpful in a few ways:

Setting the build type to private explicitly disables the Checkout target (which deletes/downloads the specified tree from SVN).  This is done for the safety of the developer's tree mainly, but it is also unlikely that developers want a script automatically attempting to patch their tree from SVN before building it... so we allow the user to do this manually, or not at all as per their own needs.

The build.xml file, by default, specifies a patch level (${open1x.version.patch}) of private, which means that unless the build is explicitly kicked off with -Dopen1x.build.type=nightly or -Dopen1x.build.type=release, the user can't accidentally delete their tree with the Checkout target.  Still, it might be a good idea to expose an option to explicitly force SVN tree deletion and update for extra measure.

If a build type (${open1x.build.type}) of either nightly or private is specified, the patch level will be nightly, or private respectively unless that value is explicitly overwritten by the -Dopen1x.build.patch=<whatever> option.  If this option is ommitted, then a build version would look something like:  2.1.nightly or 2.1.private.

When specifying a release build (${open1x.build.type=release}) the patch version must be specified (-Dopen1x.version.patch=<whatever), otherwise the patch will default to private for the reasons described above.

A list of all XSupplicant build.xml options follow:

Note that options in the build properties file are prefixed with "open1x." for convenience, while options passed with -D must be full.  i.e. build.path in the build properties file would be -Dopen1x.build.path when passed to Ant via the command line.  Do not prefix options in the config with "open1x." otherwise the option won't be expanded properly (open1x.build.properties would expand to open1x.open1x.build.properties).

Options passed with -D to Ant override any values in the properties file, except property file options that are expanded.

All options can be set in the properties file unless otherwise specified.

basedir=<path> 
	Defaults to "." which is the same directory as the script is running in.

open1x.property.file =<path> 
	Path to the property file to use to build the requested installer.  
	Defaults to ${basedir}\windows.build.properties on Windows systems.

open1x.build.preclean
	This option doesn't take any value arguments.
	If this is enabled either in the properties file (build.preclean), or with -Dopen1x.build.preclean
	then the build script will be called with the Reset flag which will force a resetting of certain build 
	related environment variables.  Note that this option is *NOT* used by default in builds.
	See the xsupplicant-build/windows/scripts/build_open1x.bat file for details on which variables get flushed.

open1x.build.noclean
	This option doesn't take any value arguments.
	If this is enabled either in the properties file (build.noclean), or with -Dopen1x.build.noclean then the Checkout target won't run.

open1x.build.name=<value>
	This option is used in the build E-mail and to name the build log file.
	Defaults to "SeaAnt".

open1x.build.path=<value>
	This option specifies the root of the open1x SVN checkout.
	The directory *must* contain xsupplicant, xsupplicant-ui, xsupplicant-build.
	Defaults to "C:\OpenSea\${open1x.build.name}" on Windows systems.

open1x.build.script.path=<value>
	This option specifies the path to where the open1x build script resides.
	Defaults to ${open1x.build.path}\xsupplicant-build\windows\scripts on Windows systems. 
	i.e.: C:\OpenSEA\SeaAnt\xsupplicant-build\windows\scripts
	You probably don't want to mess with this option.

open1x.build.script=<value>
	The script to run in ${open1x.build.script.path} to build XSupplicant.
	Defaults to build_open1x.bat.
	You probably don't want to mess with this option.

open1x.version.major=<value>
	The major revision.  It's the "X" value in xsupplicant-setup-vX.Y.Z.exe
	Defaults to "2" (for now).
	Not configurable via the properties file.  Override with -Dopen1x.version.major=<value>

open1x.version.minor=<value>
	The minor revision.  It's the "Y" value in xsupplicant-setup-vX.Y.Z.exe
	Defaults to "1" (for now).
	Not configurable via the properties file.  Override with -Dopen1x.version.minor=<value>

open1x.version.patch=<value>
	The patch revision.  It's the "Z" value in xsupplicant-setup-vX.Y.Z.exe
	Defaults to "${open1x.build.type}" for nightly and private build types.
	See the above notes about how a build is affected by the build type.
	Not configurable via the properties file.  Override with -Dopen1x.version.patch=<value>

open1x.version=<value>
	The full version.  It's the "X.Y.Z" value in xsupplicant-setup-vX.Y.Z.exe
	Defaults to "${open1x.version.major}.${open1x.version.minor}.${open1x.version.patch}".
	Not configurable via the properties file.  Override with -Dopen1x.version=<value>.
	Note that if this is overridden, version.major, version.minor, and version.patch will be irrelevant.
	This value also shows up in the About dialog in the UI.

open1x.installer.file=<value>
	The full installer name of the resulting installer package.
	Defaults to "${open1x.installer.prefix}${open1x.revision}.${revision.max}.${open1x.installer.postfix}"
	You probably don't want to mess with this option.  If you do, you won't be able to have the SVN revision in your filename.

open1x.installer.path=<value>
	The path to the install files for packaging up the installer.
	Defaults to "${open1x.build.path}\xsupplicant-build\windows\installer".
	You probably don't want to mess with this option.

open1x.installer.prefix=<value>
	The prefix for the installer file.
	Defaults to "xsupplicant-setup-v" on Windows systems.

open1x.installer.postfix=<value>
	The postfix for the installer file.
	Defaults to "exe" on Windows systems.

open1x.svn.disabled
	This option doesn't take any value arguments.
	If this is enabled either in the properties file (svn.disabled), or with -Dopen1x.svn.disable then the Checkout target won't run.

open1x.svn.username=<value>
	The username for the SVN server.
	Defaults to being empty.

open1x.svn.password=<value>
	The password for the SVN server.
	Defaults to being empty.

open1x.svn.revision=<value>
	The SVN revision to check out.
	Defaults to HEAD.

open1x.svn.repository=<value>
	The SVN repository to check out.
	Defaults to https://open1x.svn.sourceforge.net/svnroot/open1x

open1x.svn.branch=<value>
	The SVN branch to check out.
	Defaults to "trunk".  

open1x.publish.disabled
	This option doesn't take any value arguments.
	If this is enabled either in the properties file (publish.disabled), or with -Dopen1x.publish.disable then 
	the Publish target won't run.  This will also prevent E-mail from being sent, currently.
	If not set, then the target ${open1x.publish.type} will be invoked.

open1x.publish.type=<value>
	This option specifies the publish type.  Legitimate values are "ftp" and "svn".
	This controls which publish target is called when the build is finished.

open1x.publish.username=<value>
	The username for the publish server.
	Not defined by default.

open1x.publish.password=<value>
	The password for the publish server.
	Not defined by default.

open1x.publish.server=<value>
	The remote server to upload the installer to.
	Not defined by default.

open1x.publish.path=<value>
	The remote path to upload the installer to.
	Not defined by default.

open1x.publish.ftp.disabled
	Thos option doesn't take any value arguments.
	If this is enabled either in the properties file (publish.ftp.disabled), or with -Dopen1x.publish.ftp.disabled then
	the ftp target won't run.
	Useful for turning off FTP while leaving your configuration intact and calling the publish target to generate the build E-mail.

open1x.publish.scp.disabled
	This option doesn't take any value arguments.
	If this is enabled either in the properties file (publish.scp.disabled), or with -Dopen1x.publish.scp.disabled then
	the scp target won't run.
	Useful for turning off FTP while leaving you configuration intact and calling the publish target to generate the build E-mail.

