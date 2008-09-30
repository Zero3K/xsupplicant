#!/bin/sh
# This script will call batch scripts to run the XSupplicant build. 
# This script will also do the svn update, save it to a file and get the revision number

vdate=`date '+%m%d'`
fdate=`date '+%Y%m%d'`
branch=trunk
relative_src=../../..
cd $relative_src
src=`pwd`
build_script_dir=xsupplicant-build/windows/scripts
install_script_dir=xsupplicant-build/windows/installer
update=false
build=true
revision="head"
supplicant_version=2.1.4
supplicant_installer_prefix=xsupplicant-setup-v
btype=Release
bflag=

###########################
# Variable holding path to the SVN application.
###########################
SVN="svn"

echo ${SVN}

log_dir=$src/../builds/logs

build_code=nightly

usage ()
{
	echo "-help 	display this message"
	echo "-btype    BUILD_TYPE"
	echo "-bflag 	BUILD_FLAG"
	echo "-c	build_code"
	echo "-b	BRANCH"
	echo "-v	version"
	echo "-r	revision"
	exit;
}


while [ $# -gt 0 ]
do
	case "$1" in
	"-help")
		usage;
	;;
	"-b")
		shift;
		if [ $# -ge 1 ]
		then
			BRANCH=$1
		else

			echo "-b requires BRANCH"
			usage;
		fi;
	;;
	"-v")
		shift;
		if [ $# -ge 1 ]
		then
			supplicant_version=$1
		else
			echo "-v requires version"
			usage;
		fi;

	;;

	"-r")
		shift;
		if [ $# -ge 1 ]
		then
			revision=$1
		else
			echo "-r requires revision"
			usage;
		fi;

	;;


	"-btype")
		shift;
		if [ $# -ge 1 ]
		then
			BUILD_TYPE=$1
		else
			echo "-btype requires build_type [release or debug]"
			usage;

		fi;
	;;
	
	"-bflag")
		shift;
		if [ $# -ge 1 ]
		then
			BUILD_FLAG=$1
		else
			echo "-bflag requires build_flag"
			usage;

		fi;
	;;

	"-c")
	    shift;
	    if [ $# -ge 1 ]
	    then
		build_code=$1
	    else
		echo "-c requires build_code [nightly/release]"
		usage;

	fi;
	;;
	*)
		echo "option $1 does not support"
		usage;
	;;
	esac
	shift
done

echo Logging to: ${log_dir}

mkdir -p $log_dir
mkdir -p $log_dir/mail/

echo `pwd`

echo "Relative Src: $relative_src"
echo "Src: $src"

if [ $update == "true" ]
then
	echo "About to update `pwd`..."
	lastrevision=`${SVN} info . | grep "Revision" | awk '{print $2}'`
	echo "Last Revision: $lastrevision"
	echo "Supplicant Previous Revision: $lastrevision " >>${log_dir}/mail/ui_supplicant.txt

cd $src

#rm -rf ${src}/xsupplicant-ui
#rm -rf ${src}/xsupplicant

#SVN_CLEANUP_OUTPUT=`${SVN} cleanup`
#SVN_UPDATE_OUTPUT=`${SVN} update`

#if [ $? -ne 0 ]
#then
#	echo "SVN Update Failed"
#	echo "SVN Cleanup: $SVN_CLEANUP_OUTPUT"
#	echo "SVN Update: $SVN_UPDATE_OUTPUT"
#	echo "The update log is in: ${log_dir}/update_supplicant_${lastrevision}.txt"
#	echo "Svn update failed" >> ${log_dir}/mail/ui_supplicant.txt
#	echo "The update log is in: ${log_dir}/update_supplicant_${lastrevision}.txt" >> ${log_dir}/mail/ui_supplicant.txt

#	else
#		echo "Svn update succeeded"
#		echo "The update log is in: ${log_dir}/buildlog_supplicant${lastrevision}.txt"
#fi

fi

echo "${SVN} info"

# Set the Build Number into buildnum.h file
current_vers=`${SVN} info . | grep Revision | awk '{print $2}'`

echo "Current Revision: ${current_vers}"
echo "Supplicant Current Revision: ${current_vers}" >> ${log_dir}/mail/ui_supplicant.txt

echo '#define BUILDNUM "'${current_vers}'"' > ${src}/xsupplicant-ui/xsupptray/buildnum.h
echo '#define BUILDNUM "'${current_vers}'"' > ${src}/xsupplicant/src/buildnum.h

echo '#define VERSION "'${supplicant_version}'"' > ${src}/xsupplicant-ui/xsupptray/version.h
echo '#define VERSION "'${supplicant_version}'"' > ${src}/xsupplicant/src/version.h

# Define the supplicant installer name:
supplicant_installer_name=${supplicant_installer_prefix}${supplicant_version}.${current_vers}

echo "Installer Name: $supplicant_installer_name\n"

if [ $revision == "head" ]
then 
	revision=${current_vers}
	echo "Using the current revision (${revision}) as the folder name."
fi;

echo "Supplicant build revision: $revision"
echo "Supplicant current revision: $revision" >> ${log_dir}/mail/ui_supplicant.txt

cd ${src}/${build_script_dir}

./build_open1x.bat Release /Clean

# remove old installation files
rm -rf ${src}/${install_script_dir}/${supplicant_installer_name}*.exe

./build_open1x.bat $btype $bflag | tee $log_dir/build_$vdate.txt

echo "Building installer (${supplicant_installer_name}.exe)..."

cd ${src}/${install_script_dir}

echo `pwd`

# Take a look at the top of xsupinstall.nsi to see what variables are available
makensis /DVERSION=${supplicant_version}.${current_vers} /DINSTALLER_NAME_PREFIX=${supplicant_installer_prefix} xsupinstall.nsi >&  ${log_dir}/supplicant_buildlog_${revision}.txt

if [ $? -ne 0 ]
then
	echo "Supplicant installer build failed"
	echo "The supplicant installer build log is in: ${log_dir}/supplicant_buildlog_$revision.txt"
	echo "Supplicant installer build failed. " >> ${log_dir}/mail/ui_supplicant.txt
	echo "Supplicant installer build log is in: ${log_dir}/supplicant_buildlog_$revision.txt" >> $log_dir/mail/ui_supplicant.txt
else
	echo "Supplicant installer succeeded"
	echo "The supplicant installer build log is in: ${log_dir}/buildlog_$revision.txt"
	echo "Supplicant installer succeeded. " >>${log_dir}/mail/ui_supplicant.txt
	
	if [ -e ${supplicant_installer_name}*.exe ]
	then
		echo "Installer build succeeded"
	else 	
		echo "Installer build failed"
	fi
fi 
