rem XSupplicant Build Script
rem Author: Terry Simons (galimorerpg@users.sourceforge.net)

echo on
set BUILD_ROOT=c:\xsup_dev\OpenSEA\SeaAnt
set QTDIR=C:\Qt\4.3.3-opensource
set QMAKESPEC=win32-msvc2005
set BUILD_SDK=C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2

rem ---- Open1X ----
set OPEN1X_ENGINE=%BUILD_ROOT%\xsupplicant\vs2005
set OPEN1X_ENGINE_PLUGINS=%BUILD_ROOT%\xsupplicant\plugins\vs2005
set OPEN1X_GUI=%BUILD_ROOT%\ui
set OPEN1X_GUI_PLUGINS=%BUILD_ROOT%\ui\plugins
set OPEN1X_PROTINSTALL=%BUILD_ROOT%\ProtInstall

rem ---- OEM ----

rem set OEM_GUI_PLUGINS=%BUILD_ROOT%\OEM\UI Plugins
rem set OEM_ENGINE_PLUGINS=%BUILD_ROOT%\OEM\Engine Plugins 

set BUILD_TYPE=%1
set BUILD_FLAGS=%2

rem Set the /RETAIL or /DEBUG flags depending on which release type we're using:
rem BUILD_TYPE=[Debug|Release]
if [%BUILD_TYPE%]==[Release] goto:Release
if [%BUILD_TYPE%]==[Debug] goto:Debug

rem Otherwise, squawk, then set the build type to release
echo Unknown Build Type: "%BUILD_TYPE%" - Setting to "Release"
set BUILD_TYPE=Release
goto Release

:Release
set BUILD_FLAGS=/XP32 /RETAIL %BUILD_FLAGS%
goto Done

:Debug
set BUILD_FLAGS=/XP32 /DEBUG %BUILD_FLAGS%
goto Done

:Done

REM Source the Microsoft development environment...
Call "%BUILD_SDK%\SetEnv.Cmd" %BUILD_FLAGS%

echo on

rem Dump the environment variables for debugging purposes
set

echo off

set BUILD_PROJECT="Open1X Engine"
vcbuild /time "%OPEN1X_ENGINE%\Xsupplicant.sln" "%BUILD_TYPE% as Service with TNC|Win32" %BUILD_FLAGS%

set BUILD_ERROR=%ERRORLEVEL%

if NOT [%BUILD_ERROR%]==[0] goto FAIL

set BUILD_STATUS=PASS

echo %BUILD_PROJECT% Status: %BUILD_STATUS%

rem ----------------------------------------------

set BUILD_PROJECT="Open1X GUI"
vcbuild /time "%OPEN1X_GUI%\xsupplicant_gui.sln" "%BUILD_TYPE%|Win32" %BUILD_FLAGS%

set BUILD_ERROR=%ERRORLEVEL%

if NOT [%BUILD_ERROR%]==[0] goto FAIL

set BUILD_STATUS=PASS

echo %BUILD_PROJECT% Status: %BUILD_STATUS%

rem ----------------------------------------------

set BUILD_PROJECT="Open1X Engine Plugins"
vcbuild /time "%OPEN1X_ENGINE_PLUGINS%\Plugins.sln" "%BUILD_TYPE%|Win32" %BUILD_FLAGS%

set BUILD_ERROR=%ERRORLEVEL%

if NOT [%BUILD_ERROR%]==[0] goto FAIL

set BUILD_STATUS=PASS

echo %BUILD_PROJECT% Status: %BUILD_STATUS%

rem ----------------------------------------------

rem set BUILD_PROJECT="Open1X GUI Plugins"
rem vcbuild /time "%OPEN1X_GUI_PLUGINS%\Plugins.sln" "%BUILD_TYPE%|Win32" %BUILD_FLAGS%

rem set BUILD_ERROR=%ERRORLEVEL%

rem if NOT [%BUILD_ERROR%]==[0] goto FAIL

rem set BUILD_STATUS=PASS

rem echo %BUILD_PROJECT% Status: %BUILD_STATUS%

rem ----------------------------------------------

rem set BUILD_PROJECT="Open1X Protocol Installer"
rem vcbuild /time "%OPEN1X_PROTINSTALL%\ProtInstall.sln" "%BUILD_TYPE%|Win32" %BUILD_FLAGS%

set BUILD_ERROR=%ERRORLEVEL%

if NOT [%BUILD_ERROR%]==[0] goto FAIL

set BUILD_STATUS=PASS

echo %BUILD_PROJECT% Status: %BUILD_STATUS%

rem ----------------------------------------------

echo All projects built successfullly.

goto DONE

:FAIL
set BUILD_STATUS=FAIL
echo %BUILD_PROJECT% Status: %BUILD_STATUS%

:DONE
