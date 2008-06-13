/**
 * The XSupplicant User Interface is Copyright 2007, 2008 Identity Engines.
 * Identity Engines provides the XSupplicant User Interface under dual license terms.
 *
 *   For open source projects, if you are developing and distributing open source 
 *   projects under the GPL License, then you are free to use the XSupplicant User 
 *   Interface under the GPL version 2 license.
 *
 *  --- GPL Version 2 License ---
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License, Version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License, Version 2 for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.  
 *  You may also find the license at the following link
 *  http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt .
 *
 *
 *   For commercial enterprises, OEMs, ISVs and VARs, if you want to distribute or 
 *   incorporate the XSupplicant User Interface with your products and do not license
 *   and distribute your source code for those products under the GPL, please contact
 *   Identity Engines for an OEM Commercial License.
 **/

#include <QMessageBox>

#include "stdafx.h" 
#include "Emitter.h"
#include "xsupcalls.h"
#include "LoggingConsole.h"
#include "TrayApp.h"
#include "AboutDlg.h"
#include "LoginMainDlg.h"
#include "MyMessageBox.h"
#include "helpbrowser.h"
#include "EventListenerThread.h"
#include "ConfigDlg.h"
#include "FormLoader.h"
#include "version.h"
#include "buildnum.h"
#include "ConnectMgrDlg.h"
#include "ConnectDlg.h"

//! Constructor
/*!
  \param [in] app - the application
  \return Nothing
*/
TrayApp::TrayApp(QApplication &app):
  m_app(app),
  m_bSupplicantConnected(false),
  m_message(NULL),
  m_supplicant(NULL),
  m_commandLineOption(NONE)
{
  if (!m_supplicant.isOnlyInstance("XSupplicantUI"))
  {
    QMessageBox::critical(this, tr("Error on Startup"), tr("There is another instance of this program running.  You can only have one instance of this application running at a time."));
    exit(1);
  }

  m_pEventListenerThread	= NULL;
  m_pQuitAction				= NULL;
  m_pConfigAction			= NULL;
  m_pLoginAction			= NULL;
  m_pAboutAction			= NULL;
  m_pViewLogAction			= NULL;
  m_pTroubleticketAction	= NULL;
  m_pLoginDlg				= NULL;
  m_pAboutWindow			= NULL;
  m_pLoggingCon				= NULL;
  m_pConfDlg				= NULL;
  m_pEmitter				= NULL;
  m_pTrayIcon				= NULL;
  m_pTrayIconMenu			= NULL;
  m_pPlugins				= NULL;
  m_pIntCtrl				= NULL;
  m_pCreateTT				= NULL;
  m_pCreds					= NULL;
  m_pConnMgr				= NULL;
  m_pConnectDlg				= NULL;

  uiCallbacks.launchHelpP = &HelpWindow::showPage;
}

//! Destructor
/*!
  \return Nothing
  \notes I don't think this ever gets called.  The slotExit() gets called instead
*/
TrayApp::~TrayApp()
{
	// Unload any plugins we might have loaded.
	unloadPlugins();

	if (m_pEmitter != NULL)
	{
		Util::myDisconnect(m_pEmitter, SIGNAL(signalSupErrorEvent(const QString &)), this, SLOT(slotSupError(const QString &)));
		Util::myDisconnect(m_pEmitter, SIGNAL(signalSupWarningEvent(const QString &)), this, SLOT(slotSupWarning(const QString &)));
		Util::myDisconnect(m_pEmitter, SIGNAL(signalShowConfig()), this, SLOT(slotLaunchConfig()));
		Util::myDisconnect(m_pEmitter, SIGNAL(signalShowLog()), this, SLOT(slotViewLog()));
		Util::myDisconnect(m_pEmitter, SIGNAL(signalRequestUPW(QString)), this, SLOT(slotRequestUPW(QString)));

		delete m_pEmitter;
		m_pEmitter = NULL;
	}

	if (m_pAboutWindow != NULL) 
	{
		delete m_pAboutWindow;  // Clean up any about window hanging around.
		m_pAboutWindow = NULL;
	}

	if (m_pConfDlg != NULL)
	{
		delete m_pConfDlg;
		m_pConfDlg = NULL;
	}

	if (m_pLoginDlg != NULL)
	{
		delete m_pLoginDlg;
		m_pLoginDlg = NULL;
	}
	
	if (m_pConnMgr != NULL)
	{
		delete m_pConnMgr;
		m_pConnMgr = NULL;
	}
	
	if (m_pConnectDlg != NULL)
	{
		delete m_pConnectDlg;
		m_pConnectDlg = NULL;
	}

  delete m_pEventListenerThread;
  delete m_pLoggingCon;
  delete m_pTrayIcon;
}

#ifdef WINDOWS
void TrayApp::checkOtherSupplicants()
{
	STARTUPINFO sInfo;
	PROCESS_INFORMATION pi;
	QString shortpath = QApplication::applicationDirPath();
	char *supcheckapp = NULL;
	char *temp = NULL;
	wchar_t *wsupcheckapp = NULL;
	config_globals *globals = NULL;

	if (m_supplicant.getConfigGlobals(&globals, false) == true)
	{
		// Make sure we want to run this.
		if ((globals->flags & CONFIG_GLOBALS_DETECT_ON_STARTUP) == 0)
		{
			m_supplicant.freeConfigGlobals(&globals);
			return;
		}
	}
	else
	{
		// We don't want to run the check if the engine isn't running.
		return;
	}

	m_supplicant.freeConfigGlobals(&globals);

	// If we are not set to control the interfaces, don't run the check.
	if ((m_p1XControl != NULL) && (m_p1XControl->isChecked() == false)) return;
	
	// Otherwise, move on.

	memset(&sInfo, 0x00, sizeof(sInfo));
	sInfo.cb = sizeof(STARTUPINFO);

	supcheckapp = (char *)malloc(255);
	if (supcheckapp == NULL)
	{
		QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Error allocating memory needed to build the path to the supplicant detection program."));
		return;
	}

	temp = _strdup(shortpath.toAscii());
	sprintf(supcheckapp, "\"%s\\checksuppsapp.exe\" -q", temp);
	free(temp);

	Util::useBackslash(supcheckapp);

	wsupcheckapp = (wchar_t *)malloc((strlen(supcheckapp)+4)*2);
	if (wsupcheckapp == NULL)
	{
		QMessageBox::critical(this, tr("Error"), tr("Unable to allocate memory to store the path to the supplicant check program."));
		free(supcheckapp);
		return;
	}

	MultiByteToWideChar(CP_ACP, 0, supcheckapp, strlen(supcheckapp)+1, wsupcheckapp, strlen(supcheckapp)+2);

	free(supcheckapp);

	if (CreateProcess(NULL, wsupcheckapp, NULL, NULL, false, 0, NULL, NULL, &sInfo, &pi) == false)
	{
		QMessageBox::critical(this, tr("Other Supplicant Detection"), tr("Failed to start the 'other supplicant detection' engine.  Error : %1").arg(GetLastError()));
	}
	else
	{
		// Close the file handles that were created, since we don't intend to do anything
		// with them.
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	free(wsupcheckapp);
}
#endif

//! init()
/*! 
  \brief Initialize the application
  \return false - if can't go on
*/
bool TrayApp::init(int argc)
{
  if (!checkCommandLineParams(argc))
  {
    return false;
  }

  createTrayActionsAndConnections();

  createTrayIcon();

  m_bConnectFailed = false;

  slotConnectToSupplicant();

  if(m_pTrayIcon != NULL) {
    m_pTrayIcon->show();
  }

  loadPlugins();
  
  return true;
}

//! slotRestart()
/*! 
  \brief When the XSupplicant goes down, the app will come here and wait
*/
void TrayApp::slotRestart()
{
  // clear the flag that we are connected
  m_bSupplicantConnected = false;

  if(m_pTrayIcon != NULL) {
    m_pTrayIcon->setToolTip(tr("The XSupplicant service isn't running.  Please restart it."));
    // Set the tray icon to disconnected
    setTrayIconState(ENGINE_DISCONNECTED);
  }

  // delete in reverse order of creation
  delete m_pLoginDlg;
  delete m_pConfDlg;
  delete m_pEventListenerThread;
  delete m_pLoggingCon;
  delete m_pIntCtrl;
  delete m_pConnMgr;
  delete m_pConnectDlg;

  m_pLoginDlg = NULL;
  m_pConfDlg = NULL;
  m_pEventListenerThread = NULL;
  m_pLoggingCon = NULL;
  m_pIntCtrl = NULL;
  m_pConnMgr = NULL;
  m_pConnectDlg = NULL;

  // Attempt to connect
  m_bConnectFailed = false;
  slotConnectToSupplicant();
  
  if (m_pTrayIcon != NULL) m_pTrayIcon->show();
}

//! slotConnectToSupplicant()
/*! 
  \brief Connect to the supplicant 
  If it fails, start the timer 
*/
void TrayApp::slotConnectToSupplicant()
{
  bool bcode = true;
  QString full, number;
  UIPlugins *plugin = m_pPlugins;

  m_timer.stop();
  if (!m_bSupplicantConnected)
  {
    bcode = m_supplicant.connectToSupplicant();
    if (!bcode)
    {
	  if(m_pEmitter != NULL)
	  {
		disconnect(m_pEmitter, SIGNAL(signalTNCReply(uint32_t, uint32_t, uint32_t, uint32_t, bool, int)), 
		  &m_supplicant, SLOT(TNCReply(uint32_t, uint32_t, uint32_t, uint32_t, bool, int)));
      }

      // Initialize and setup all the plugins...
      // We're sending NULL here as an instruction for any plugins with connected signals to
      // disconnect them.
      // We'll send a new emitter object when the supplicant channel comes back up.
      while(plugin != NULL)
      {
        plugin->setEmitter(NULL);

        plugin = plugin->next;
      }

      m_bConnectFailed = true;

	  m_pTrayIcon->setToolTip(tr("The XSupplicant service isn't running.  Please restart it."));
      setTrayIconState(ENGINE_DISCONNECTED);
      // disable the menu options
      setEnabledMenuItems(false);

      m_timer.start(1000); // wait one second and try again
    }
    else if (m_supplicant.getAndCheckSupplicantVersion(full, number) == false)
    {
      slotExit();
    }
    else
    {
	  setTrayIconState(ENGINE_CONNECTED);

#ifdef WINDOWS
	  checkOtherSupplicants();
#endif

      // Enable the menu items
      setEnabledMenuItems(true);
      m_bSupplicantConnected = true;
      postConnectActions();
      start(); // once connected - do this

	  // Initialize and setup all the plugins...
	  while(plugin != NULL)
	  {
			plugin->setEmitter(m_pEmitter);
			plugin->updateEngineVersionString(full);

			plugin = plugin->next;
	  }

	  connect(m_pEmitter, SIGNAL(signalTNCReply(uint32_t, uint32_t, uint32_t, uint32_t, bool, int)), 
		  &m_supplicant, SLOT(TNCReply(uint32_t, uint32_t, uint32_t, uint32_t, bool, int)));
    }
  }
}

void TrayApp::closeChildren()
{
	if (m_pLoginDlg)
	{
		delete m_pLoginDlg;
		m_pLoginDlg = NULL;
	}

	if (m_pConfDlg)
	{
		delete m_pConfDlg;
		m_pConfDlg = NULL;
	}

	if (m_pCreds)
	{
		delete m_pCreds;
		m_pCreds = NULL;
	}

	if (m_pCreateTT)
	{
		delete m_pCreateTT;
		m_pCreateTT = NULL;
	}
	
	if (m_pConnMgr != NULL)
	{
		delete m_pConnMgr;
		m_pConnMgr = NULL;
	}
	
	if (m_pConnectDlg != NULL)
	{
		delete m_pConnectDlg;
		m_pConnectDlg = NULL;
	}

	if (m_pLoggingCon != NULL) m_pLoggingCon->hide();
}

void TrayApp::setEnabledMenuItems(bool bEnable)
{
  m_pLoginAction->setEnabled(bEnable);
  m_pConfigAction->setEnabled(bEnable);
  m_pViewLogAction->setEnabled(bEnable);
  m_pTroubleticketAction->setEnabled(bEnable);
  m_p1XControl->setEnabled(bEnable);

  if (bEnable == false) closeChildren();
}

void TrayApp::slotHideLog()
{
	m_pLoggingCon->hide();
}

/**
 * \brief Walk the hash table and find the "highest" state that an interface is
 *        in.
 **/
void TrayApp::updateGlobalTrayIconState()
{
	int highest = -1;
	int itemp = 0;
	QString temp;
	bool valid;
	QHash<QString, QString>::const_iterator i = m_intStateHash.constBegin();
	QString tooltip = "XSupplicant ";
	int failed = 0;
	int authing = 0;
	int authed = 0;
	int connected = 0;
	int inactive = 0;
	
	tooltip += VERSION;
	tooltip += ".";
	tooltip += BUILDNUM;
	tooltip += "\nInterfaces :\n";

	while (i != m_intStateHash.constEnd()) {
		temp = i.value();

		itemp = temp.toInt(&valid);

		if (valid)
		{
			// At this point, itemp should have a numeric value that indicates
			// what 802.1X state it is in.  Based on this, we assign a new value
			// to the variable "highest" if the state needs us to show a higher
			// level icon.  The order of icon display is:

			// "Purple" (4) - Indicates that a user is in a quarentined state. 
			//                Some network access may be available, but it is
			//                likely restricted.  (This isn't implemented at this time!)

			// "Green" (3) - Indicates that a user should be able to access the network
			//				 and is only displayed when in AUTHENTICATED state or S_FORCE_AUTH state.
			
			// "Yellow" (2) - Indicates that an authentication is in progress. During
			//				  this time, a user may have network access.

			// "Red" (1) - Indicates that an authentication failed.  No network access
			//			   should be available.

			// "Blue" (0) - Indicates that the supplicant isn't doing anything with
			//				any interfaces.
			switch (itemp)
			{
			case RESTART:
			case CONNECTING:
			case ACQUIRED:
			case AUTHENTICATING:
				if (highest < 2) highest = 2;
				authing++;
				break;

			case HELD:
				if (highest < 1) highest = 1;
				failed++;
				break;

			case AUTHENTICATED:
				if (highest < 3) highest = 3;
				authed++;
				break;

			case S_FORCE_AUTH:
				if (highest < 3) highest = 3;
				connected++;
				break;

			case LOGOFF:
			case DISCONNECTED:
			default:
				if (highest < 0) highest = 0;
				inactive++;
				break;
			}
		}

		++i;
	}

	temp.setNum(authed);
	tooltip += " - Authenticated : "+temp+"\n";
	temp.setNum(connected);
	tooltip += " - Connected : "+temp+"\n";
	temp.setNum(authing);
	tooltip += " - Authenticating : "+temp+"\n";
	temp.setNum(failed);
	tooltip += " - Failed : "+temp+"\n";
	temp.setNum(inactive);
	tooltip += " - Idle : "+temp;

	switch (highest)
	{
	default:
	case 0:
		setTrayIconState(ENGINE_CONNECTED);
		break;

	case 1:
		setTrayIconState(AUTHENTICATION_FAILED);
		break;

	case 2:
		setTrayIconState(AUTHENTICATION_IN_PROCESS);
		break;

	case 3:
		setTrayIconState(AUTHENTICATION_SUCCESS);
		break;

	case 4:
		setTrayIconState(AUTHENTICATION_NAC_NON_COMPLIANT);
		break;
	}

	m_pTrayIcon->setToolTip(tooltip);
}

/**
 * \brief An interface was inserted.  Update our QHash to track it.
 *
 * @param[in] intName   The OS specific name of the interface that was
 *                      inserted.
 **/
void TrayApp::slotInterfaceInserted(char *intName)
{
	char *devDesc = NULL;

	if (xsupgui_request_get_devdesc(intName, &devDesc) == REQUEST_SUCCESS)
	{
		populateGlobalTrayData(intName, devDesc);
		updateGlobalTrayIconState();
	}
}

/**
 * \brief An interface was removed.  Update our QHash to no longer track it.
 *
 * @param[in] intDesc   The vanity name of the interface that was removed.
 **/
void TrayApp::slotInterfaceRemoved(char *intDesc)
{
	QString m_myKey;

	m_myKey = m_intStateHash.key(intDesc);
	m_intStateHash.remove(m_myKey);
	updateGlobalTrayIconState();
}

/**
 * \brief Connect the signals that we would use to monitor the global tray
 *        icon data.
 **/
void TrayApp::connectGlobalTrayIconSignals()
{
	if (m_pEmitter != NULL)
	{
		Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
			this, SLOT(slotStateChange(const QString &, int, int, int, unsigned int)));

		Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(slotInterfaceInserted(char *)));
		Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceRemoved(char *)), this, SLOT(slotInterfaceRemoved(char *)));
		Util::myConnect(m_pEmitter, SIGNAL(signalPostConnectTimeout(QString)), this, SLOT(slotConnectionTimeout(QString)));
	}
}

/**
 * \brief Disconnect the signals that we would use to monitor the global tray
 *        icon data.
 **/
void TrayApp::disconnectGlobalTrayIconSignals()
{
	if (m_pEmitter != NULL)
	{
		Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
			this, SLOT(slotStateChange(const QString &, int, int, int, unsigned int)));

		Util::myDisconnect(m_pEmitter, SIGNAL(interfaceInserted(char *)), this, SLOT(slotInterfaceInserted(char *)));
		Util::myDisconnect(m_pEmitter, SIGNAL(interfaceRemoved(char *)), this, SLOT(slotInterfaceRemoved(char *)));
		Util::myDisconnect(m_pEmitter, SIGNAL(signalPostConnectTimeout(QString)), this, SLOT(slotConnectionTimeout(QString)));
	}
}

/**
 * \brief Catch a state change event, and update our state hash.
 *
 **/
void TrayApp::slotStateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid)
{
	QString temp, desc;
	QList<QString> valList;
	bool done = false;
	int i, x;

	if (sm == IPC_STATEMACHINE_8021X)
	{
		valList = m_intStateHash.values(intName);
		desc = "";
		
		for (i = 0; i < valList.size(); ++i)
		{
			temp = valList.at(i);

			x = temp.toInt(&done);

			if (!done)   // This should be the description, not the state value.
			{
				desc = temp;
				break;
			}
		}

		// Remove the old values.
		m_intStateHash.remove(intName);

		m_intStateHash.insert(intName, desc);
		temp.setNum(newstate);
		m_intStateHash.insert(intName, temp);

		updateGlobalTrayIconState();
	}
}

/**
 * \brief Add data about one interface to the hash used to determine the
 *        icon color state.
 *
 * @param[in] intName   The OS specific interface name that we want to add.
 * @param[in] intDesc   The vanity description for the interface we want to add.
 **/
void TrayApp::populateGlobalTrayData(QString intName, QString intDesc)
{
	int state = -1;
	QString temp;
	char *ctemp = NULL;

	m_intStateHash.insert(intName, intDesc);
	ctemp = _strdup(intName.toAscii());
	if (xsupgui_request_get_1x_state(ctemp, &state) == REQUEST_SUCCESS)
	{
		// Add the state to our table.
		temp.setNum(state);

		m_intStateHash.insert(intName, temp);
	}
	else
	{
		// Couldn't determine the state, so skip it and hope we get an event later.
		temp.setNum(-1);
		m_intStateHash.insert(intName, temp);
	}

	free(ctemp);
}

/**
 * \brief Enumerate all of the interfaces and determine the authentication state
 *        to display in the tray.
 *
 * We need to enumerate interfaces, then determine their authentication state.
 * Once we know the state, we decide which one is "highest" and change the icon
 * to that color.  (If needed.)  Once our table is built, we can then maintain
 * it using signals from the supplicant engine.
 **/
void TrayApp::setGlobalTrayIconState()
{
	int_enum *intlist = NULL;
	int i = 0;
	QString temp;

	// Make sure our hash is empty before we start.
	m_intStateHash.clear();

	if (xsupgui_request_enum_live_ints(&intlist) == REQUEST_SUCCESS)
	{
		// Build our "snapshot" table in memory.
		while (intlist[i].name != NULL)
		{
			populateGlobalTrayData(intlist[i].name, intlist[i].desc);
			i++;
		}
	}
	
	updateGlobalTrayIconState();
	connectGlobalTrayIconSignals();
}

/**
 * \brief Determine if the engine is trying to control interfaces or not.  And update the check mark
 *        on the UI pop-up accordingly.
 *
 **/
void TrayApp::updateIntControlCheck()
{
	config_globals *globals = NULL;

	if (m_supplicant.getConfigGlobals(&globals, false) == true)
	{
		if ((globals->flags & CONFIG_GLOBALS_NO_INT_CTRL) == CONFIG_GLOBALS_NO_INT_CTRL)
		{
			m_p1XControl->setChecked(false);
		}
		else
		{
			m_p1XControl->setChecked(true);
		}

		m_supplicant.freeConfigGlobals(&globals);

		setTrayMenuBasedOnControl();
	}
}

//! postConnectActions
/*!
  \return false - if can't start event listener - can't go on if this is the case
*/
bool TrayApp::postConnectActions()
{
  m_supplicant.updateAdapters(false);

  m_pEmitter = new Emitter();

  m_pLoggingCon = new LogWindow(NULL, m_pEmitter); // no parent
  if (m_pLoggingCon != NULL)
  {
	  if (m_pLoggingCon->create() == true)
	  {
		  Util::myConnect(m_pLoggingCon, SIGNAL(signalSupplicantDownRestart()), this, SLOT(slotRestart()));
		  if (!startEventListenerThread())
		  {
		    slotExit();
		  }

		  Util::myConnect(m_pLoggingCon, SIGNAL(close()), this, SLOT(slotHideLog()));
	  }
	  else
	  {
		  QMessageBox::critical(this, tr("Error Loading Form"), tr("Unable to load the logging dialog form.  Logging will not be functional."));
	  }
  }

  Util::myConnect(m_pEmitter, SIGNAL(signalSupErrorEvent(const QString &)), this, SLOT(slotSupError(const QString &)));
  Util::myConnect(m_pEmitter, SIGNAL(signalSupWarningEvent(const QString &)), this, SLOT(slotSupWarning(const QString &)));
  Util::myConnect(m_pEmitter, SIGNAL(signalShowConfig()), this, SLOT(slotLaunchConfig()));
  Util::myConnect(m_pEmitter, SIGNAL(signalShowLog()), this, SLOT(slotViewLog()));  
  Util::myConnect(m_pEmitter, SIGNAL(signalRequestUPW(QString)), this, SLOT(slotRequestUPW(QString)));

  updateIntControlCheck();
  setGlobalTrayIconState();

  return true;
}

//! checkCommandLineParams()
/*!
  \return true - continue, false - stop
*/
bool TrayApp::checkCommandLineParams(int argc)
{
  QStringList args = m_app.arguments();
  if (argc > 1)
  {
    if (argc > 2)
    {
      // only one argument is permitted for now
      QMessageBox::information(this, tr("Too many command line options"),
        tr("You have entered too many options. Only one option is allowed.\nThe command line options are:\n"
        "-l\tLogin window\n"
        "-c\tConfiguration Window\n"
        "-d\tView the Debug Log Window\n"
        "-a\tView the About Dialog\n"
        "The application will close."));
      return false;
    }
    else
    {
      QStringList args = m_app.arguments();
      if (args.at(1).compare("-D", Qt::CaseInsensitive) == 0)
      {
        m_commandLineOption = START_LOG;
      }
      else if (args.at(1).compare("-L", Qt::CaseInsensitive) == 0)
      {
        m_commandLineOption = START_LOGIN;
      }
      else if (args.at(1).compare("-C", Qt::CaseInsensitive) == 0)
      {
        m_commandLineOption = START_CONFIG;
      }
      else if (args.at(1).compare("-A", Qt::CaseInsensitive) == 0)
      {
        m_commandLineOption = START_ABOUT;
      }
      else
      {
        // only one argument is permitted for now
	QMessageBox::critical(this, tr("Invalid Command-line options"),
          tr("You have entered an incorrect command-line option.\nThe command line options are (one only):\n"
          "-l\tLogin window\n"
          "-c\tConfiguration Window\n"
          "-d\tView the Debug Log Window\n"
          "-a\tView the About Dialog\n"
          "\nThe application will close."));
        return false;
      }
    }
  }
  return true;
}

//! start()
/*! 
  \brief Starts the specified application
  \return nothing
*/
void TrayApp::start()
{
  bool bValue = true;

  if (!m_bSupplicantConnected)
  {
    return;
  }

  switch(m_commandLineOption)
  {
    case NONE:
      break;
    case START_LOG:
        // display the log window - needs to be queued up - don't call immediately
      bValue = QMetaObject::invokeMethod(this, "slotViewLog", Qt::QueuedConnection);
      break;

    case START_LOGIN:
      // display the log window - needs to be queued up - don't call immediately
      bValue = QMetaObject::invokeMethod(this, "slotLaunchLogin", Qt::QueuedConnection);
      break;

    case START_CONFIG:
      // display the log window - needs to be queued up - don't call immediately
      bValue = QMetaObject::invokeMethod(this, "slotLaunchConfig", Qt::QueuedConnection);
      break;

    case START_ABOUT:
      // display the log window - needs to be queued up - don't call immediately
      bValue = QMetaObject::invokeMethod(this, "slotAbout", Qt::QueuedConnection);
      break;

    default:
      break;
  }
  if (!bValue)
  {
    // what to do if this ever happens? Right now, nothing - just display a debug message
    Q_ASSERT_X(false, "TrayApp", "Couldn't invoke method");
  }

}

//! 
/*!
  \return 
*/
void TrayApp::slotSupError(const QString &error)
{
	QMessageBox::critical(this, QString(tr("Supplicant Error")), error);
}

void TrayApp::slotSupWarning(const QString &warning)
{
	QMessageBox::warning(this, QString(tr("Supplicant Warning")), warning);
}

//! 
/*!
  \return 
*/
void TrayApp::createTrayActionsAndConnections()
{
  QPixmap p;

  m_pLoginAction = new QAction(tr("&Connect..."), this);
  //Util::myConnect(this->m_pLoginAction, SIGNAL(triggered()), this, SLOT(showConnectDlg()));
  Util::myConnect(this->m_pLoginAction, SIGNAL(triggered()), this, SLOT(slotLaunchLogin()));

  m_pConfigAction = new QAction(tr("&Configure..."), this);
  Util::myConnect(m_pConfigAction, SIGNAL(triggered()), this, SLOT(slotLaunchConfig()));
  
  m_pViewLogAction = new QAction(tr("&View Log..."), this);
  Util::myConnect(m_pViewLogAction, SIGNAL(triggered()), this, SLOT(slotViewLog()));

#ifdef WINDOWS
  m_p1XControl = new QAction(tr("Manage interfaces with XSupplicant"), this);
  Util::myConnect(m_p1XControl, SIGNAL(triggered()), this, SLOT(slotControlInterfaces()));
  m_p1XControl->setCheckable(true);
#endif

  m_pAboutAction = new QAction(tr("&About"), this);
  Util::myConnect(m_pAboutAction, SIGNAL(triggered()), this, SLOT(slotAbout()));

  m_pQuitAction = new QAction(tr("&Quit"), this);
  Util::myConnect(m_pQuitAction, SIGNAL(triggered()), this, SLOT(slotExit()));

  m_pTroubleticketAction = new QAction(tr("&Create Troubleticket..."), this);
  Util::myConnect(m_pTroubleticketAction, SIGNAL(triggered()), this, SLOT(slotCreateTroubleticket()));

  Util::myConnect(&m_timer, SIGNAL(timeout()), this, SLOT(slotConnectToSupplicant()));

}

void TrayApp::slotControlInterfaces()
{
	if (m_pIntCtrl != NULL)
	{
		delete m_pIntCtrl;
		m_pIntCtrl = NULL;
	}

	Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceControl(bool)), this, SLOT(slotControlInterfacesDone(bool)));

	m_pIntCtrl = new InterfaceCtrl(m_p1XControl->isChecked(), m_pEmitter, &m_supplicant, this);

	m_pIntCtrl->show();
	if (m_pIntCtrl->updateSupplicant() != true)
	{
		Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceControl(bool)), this, SLOT(slotControlInterfacesDone(bool)));
		delete m_pIntCtrl;
		m_pIntCtrl = NULL;
	}
	else
	{
		m_pIntCtrl->exec();
	}
}

void TrayApp::setTrayMenuBasedOnControl()
{
	if (m_p1XControl->isChecked())
	{
		// Turn on the tray icon options.
		setEnabledMenuItems(true);
	}
	else
	{
		// Turn off the tray icon options.
		setEnabledMenuItems(false);
		m_p1XControl->setEnabled(true);
		setTrayIconState(ENGINE_CONNECTED);  // Set us to our default icon color.
	}
}

void TrayApp::slotControlInterfacesDone(bool xsupCtrl)
{
	if (m_pIntCtrl != NULL)
	{
		delete m_pIntCtrl;
		m_pIntCtrl = NULL;
	}

	Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceControl(bool)), this, SLOT(slotControlInterfacesDone(bool)));

	setTrayMenuBasedOnControl();
}

//! 
/*!
  \return 
*/
void TrayApp::createTrayIcon()
{
  m_pTrayIconMenu = new QMenu(this);
  m_pTrayIconMenu->addAction(m_pLoginAction);
  m_pTrayIconMenu->addSeparator();
  m_pTrayIconMenu->addAction(m_pConfigAction);
  m_pTrayIconMenu->addAction(m_pViewLogAction);
  //m_pTrayIconMenu->addAction(m_pTroubleticketAction);
  m_pTrayIconMenu->addSeparator();
#ifdef WINDOWS
  m_pTrayIconMenu->addAction(m_p1XControl);
  m_pTrayIconMenu->addSeparator();
#endif
  m_pTrayIconMenu->addAction(m_pAboutAction);
  m_pTrayIconMenu->addSeparator();
  m_pTrayIconMenu->addAction(m_pQuitAction);

  m_pTrayIcon = new QSystemTrayIcon(this);
  m_pTrayIcon->setContextMenu(m_pTrayIconMenu);

  Util::myConnect(m_pTrayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
          this, SLOT(slotIconActivated(QSystemTrayIcon::ActivationReason)));

  m_pTrayIcon->setToolTip(tr("The XSupplicant service isn't running.  Please restart it."));
  setTrayIconState(ENGINE_DISCONNECTED);

  m_pTrayIcon->show();       // Even if the icon couldn't be loaded, we will at least get a blank spot on the tray.
}

/**
 * \brief Change the tray icon to display a current global state.  The states
 *        are defined by the \ref iconState enum in \ref TrayApp.h.
 *
 * @param[in] curState   A member of the iconState enum that identifies the 
 *                       icon state that we should display for the user.
 **/
void TrayApp::setTrayIconState(int curState)
{
  QPixmap *p = NULL;
  QString icon_to_load;

  icon_to_load = "";

  switch (curState)
  {
  case ENGINE_DISCONNECTED:
	  icon_to_load = "prod_no_engine.png";
	  break;

  case ENGINE_CONNECTED:
	  icon_to_load = "prod_eng_connected.png";
	  break;

  case AUTHENTICATION_FAILED:
	  icon_to_load = "prod_red.png";
	  break;

  case AUTHENTICATION_IN_PROCESS:
	  icon_to_load = "prod_yellow.png";
	  break;

  case AUTHENTICATION_SUCCESS:
	  icon_to_load = "prod_green.png";
	  break;

  case AUTHENTICATION_NAC_NON_COMPLIANT:
	  icon_to_load = "prod_purple.png";
	  break;
  }

  if (icon_to_load == "") return;   // Unknown state.  Leave it the way it was.

  p = FormLoader::loadicon(icon_to_load);

  if (p != NULL)
  {
    QIcon icon((*p));
    if (m_pTrayIcon != NULL) m_pTrayIcon->setIcon(icon);
	m_pTrayIcon->show();
  }

  delete p;
}


//! 
/*!
  \return 
*/
void TrayApp::slotIconActivated(QSystemTrayIcon::ActivationReason reason)
{
  switch (reason) 
  {
    case QSystemTrayIcon::DoubleClick:
      if (m_bSupplicantConnected)
      {
		  if (m_p1XControl->isChecked())
		  {
			this->showConnectDlg();
			//slotLaunchLogin();
		  }
		  else
		  {
			  QMessageBox::information(this, tr("Interface Management"), tr("XSupplicant is not currently managing your interfaces.  If you wish to have XSupplicant manage your interfaces, please right-click the icon, and select \"Manage Interfaces with XSupplicant\"."));
		  }
      }
      else
      {
        slotAbout();
      }
      break;
    default:
      break;
  }
}


//! 
/*!
  \return 
*/
void TrayApp::slotLaunchConfig()
{
	// TODO: check settings to see which config to launch
	if (m_pConfDlg != NULL && m_pConfDlg->isVisible())
		m_pConfDlg->bringToFront();
	else if (m_pConnMgr != NULL && m_pConnMgr->isVisible())
		m_pConnMgr->bringToFront();
	else
		this->showBasicConfig();
	// this->showAdvancedConfig();
}

void TrayApp::slotCleanupConfig()
{
	if (m_pConfDlg == NULL) return;  // This shouldn't be possible!

	Util::myDisconnect(m_pConfDlg, SIGNAL(close(void)), this, SLOT(slotCleanupConfig(void)));

	//delete m_pConfDlg;

	m_pConfDlg->deleteLater();

	m_pConfDlg = NULL;
}

void TrayApp::slotCleanupLogin()
{
	if (m_pLoginDlg == NULL) return;  // This shouldn't be possible!

	Util::myDisconnect(m_pLoginDlg, SIGNAL(close(void)), this, SLOT(slotCleanupLogin(void)));

	delete m_pLoginDlg;

	m_pLoginDlg = NULL;
}

//! 
/*!
  \return 
*/
void TrayApp::slotLaunchLogin()
{
  if (!m_bSupplicantConnected)
  {
    QMessageBox::critical(this, tr("XSupplicant not connected yet."),
      tr("You can't run the Login module until the XSupplicant is connected"));
  }
  else
  {
	  // If we aren't controlling the interface, don't allow the window to be displayed.
	  if (!m_p1XControl->isChecked()) return;

	  if (m_pLoginDlg == NULL)
	  {
		  m_pLoginDlg = new LoginMainDlg(m_supplicant, m_pEmitter, this);
		  if (m_pLoginDlg->create() == false)
		  {
			  QMessageBox::critical(this, tr("Form Creation Error"), tr("The Login Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
			  delete m_pLoginDlg;
			  m_pLoginDlg = NULL;
		  }
		  else
		  {
			  m_pLoginDlg->show();

			  Util::myConnect(m_pLoginDlg, SIGNAL(close(void)), this, SLOT(slotCleanupLogin(void)));
		  }
	  }
	  else
	  {
		  m_pLoginDlg->show();
	  }
  }
}

//! 
/*!
  \return 
*/
void TrayApp::slotViewLog()
{
  if (!m_bSupplicantConnected)
  {
    QMessageBox::warning(this, tr("XSupplicant not connected yet."),
      tr("You can't view the log file until the XSupplicant is connected"));
  }
  else
  {
    // This one is a little more work - I need to get the message going in a separate thread
    m_pLoggingCon->showLog();
  }
}

//! 
/*!
  \return 
*/
void TrayApp::slotAbout()
{
  if (m_pAboutWindow == NULL)
  {
	  m_pAboutWindow = new AboutWindow(this);
	  if (m_pAboutWindow->create() == false)
	  {
		  QMessageBox::critical(this, tr("Form Creation Error"), tr("The About Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
		  delete m_pAboutWindow;
		  m_pAboutWindow = NULL;
	  }
	  else
	  {
		  m_pAboutWindow->show();

		  Util::myConnect(m_pAboutWindow, SIGNAL(close(void)), this, SLOT(slotCleanupAbout(void)));
	  }
  }
  else
  {
	  m_pAboutWindow->show();
  }
}

/**
 * \brief When the About Dialog emits a close() signal, we want
 *        to free the memory.
 **/
void TrayApp::slotCleanupAbout()
{
	if (m_pAboutWindow == NULL) return;  // This shouldn't be possible!

	Util::myDisconnect(m_pAboutWindow, SIGNAL(close(void)), this, SLOT(slotCleanupAbout(void)));

	delete m_pAboutWindow;

	m_pAboutWindow = NULL;
}

//! 
/*!
  \return 
*/
void TrayApp::slotExit()
{
  m_timer.stop();
  // Stop the supplicant
  // m_supplicant.goQuiet();
  // then exit
  delete m_pLoginDlg;
  delete m_pTrayIcon;
  m_pTrayIcon = NULL;
  close();

  this->m_app.exit(0);
}

void TrayApp::slotRequestUPW(QString connName)
{
	// Only do something if it isn't already showing.
	if (m_pCreds == NULL)
	{
		m_pCreds = new CredentialsPopUp(connName, this, m_pEmitter);
		if (m_pCreds == NULL)
		{
			QMessageBox::critical(this, tr("Error"), tr("There was an error creating the credentials pop up."));
			return;
		}

		if (m_pCreds->create() == false)
		{
			// The create method should have displayed any error dialogs needed.
			delete m_pCreds;
			m_pCreds = NULL;
			return;
		}

		Util::myConnect(m_pCreds, SIGNAL(close()), this, SLOT(slotCleanupUPW()));

		m_pCreds->show();
	}
}

void TrayApp::slotCleanupUPW()
{
	Util::myDisconnect(m_pCreds, SIGNAL(close()), this, SLOT(slotCleanupUPW()));
	delete m_pCreds;
	m_pCreds = NULL;
}

void TrayApp::slotConnectionTimeout(QString devName)
{
	char *conname = NULL;
	char *devname = NULL;
	QString temp;

	devname = _strdup(devName.toAscii());

	if (xsupgui_request_get_conn_name_from_int(devname, &conname) == REQUEST_SUCCESS)
	{
		temp = conname;
		if (QMessageBox::information(this, tr("Connection Lost"), tr("The connection '%1' has been lost.  Would you like the supplicant to attempt to connect to other priority networks?").arg(temp),
			QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes) == QMessageBox::Yes)
		{
			if (xsupgui_request_set_connection_lock(devname, FALSE) != REQUEST_SUCCESS)
			{
				QMessageBox::critical(this, tr("Error"), tr("Unable to configure the interface to automatically select a new connection.  You will have to connect manually."));
			}
			else
			{
				QMessageBox::information(this, tr("Information"), tr("The supplicant will now look for other priority networks to connect to.  This may take several seconds."));
			}
		}

		free(conname);
	}

	free(devname);
}

void TrayApp::slotCreateTroubleticket()
{
    int err = 0;
    QString filePath = QDir::toNativeSeparators((QDir::homePath().append(tr("/Desktop/XSupplicant Trouble Ticket.zip"))));

    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Trouble ticket"), filePath, tr("Archives (*.zip)"));

	if (fileName == "") return;

    char *path = _strdup(fileName.toAscii());

#ifdef WINDOWS
    Util::useBackslash(path);
#endif

	if (m_pCreateTT != NULL)
	{
		delete m_pCreateTT;
		m_pCreateTT = NULL;
	}

    err = m_supplicant.createTroubleTicket((char *)path, "c:\\", 1);

    switch(err)
	{
	case REQUEST_SUCCESS:
		m_pCreateTT = new CreateTT(m_pEmitter, &m_supplicant, this);
		m_pCreateTT->show();

		Util::myConnect(m_pEmitter, SIGNAL(signalTroubleTicketDone()), this, SLOT(slotCreateTroubleticketDone()));
		Util::myConnect(m_pEmitter, SIGNAL(signalTroubleTicketError()), this, SLOT(slotCreateTroubleticketError()));
		break;

	case REQUEST_TIMEOUT:
		QMessageBox::information(this, tr("Trouble ticket"), tr("XSupplicant experienced a timeout attempting to create the Trouble ticket!\n"));
		break;

	case REQUEST_FAILURE:
	    QMessageBox::information(this, tr("Trouble ticket"), tr("XSupplicant failed while attempting to create the Trouble ticket!\n"));
		break;

	default:
        QMessageBox::information(this, tr("Trouble ticket"), tr("XSupplicant got an unexpected error (%1) when attempting to create the Trouble ticket!\n").arg(err));
		break;
	}

    if(path != NULL)
        free(path);
}

void TrayApp::slotCreateTroubleticketDone()
{
	disconnectTTSignals();

	QMessageBox::information(this, tr("Troubleticket Created"), tr("Your trouble ticket was created successfully."));
}

void TrayApp::disconnectTTSignals()
{
	Util::myDisconnect(m_pEmitter, SIGNAL(signalTroubleTicketDone()), this, SLOT(slotCreateTroubleticketDone()));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalTroubleTicketError()), this, SLOT(slotCreateTroubleticketError()));

	if (m_pCreateTT != NULL)
	{
		delete m_pCreateTT;
		m_pCreateTT = NULL;
	}
}

void TrayApp::slotCreateTroubleticketError()
{
	disconnectTTSignals();

	QMessageBox::critical(this, tr("Troubleticket Error"), tr("There was an error creating your troubleticket.  The troubleticket file may not exist, or may be incomplete."));
}

//! 
/*!
  \return 
*/
bool TrayApp::startEventListenerThread()
{
  bool bValue = false;

  // Now start the event listener thread
  // Kill the old one, which disconnects the event listener
  if (m_pEventListenerThread)
  {
    m_pEventListenerThread->quit();
    delete m_pEventListenerThread;
    m_pEventListenerThread = NULL;
    m_bListenerStarted = false;
  }

  // If the supplicant is not connected or we can't connect the event listener, nothing to do - so stop
  if (!m_bSupplicantConnected)
  {
    return false;
  }

  Q_ASSERT_X(m_pLoggingCon != NULL, "TrayApp", "Logging Console must be initialized first");

  // Create new thread
  m_pEventListenerThread = new EventListenerThread(&m_supplicant, m_pEmitter, this);
  
  if (m_pEventListenerThread == NULL)
  {
    QMessageBox::critical(this, tr("XSupplicant Event Listener Error"), 
        tr("Can't create the EventListenerThread object.  You must shut down the XSupplicant UI and restart."));
      return false;
  }

  if (!m_pEventListenerThread->connectXSupEventListener(true))
  {
    QMessageBox::critical(this, tr("XSupplicant Event Message Error"), 
      tr("The utility can't connect to the event system from the XSupplicant."
      "You must shut down the XSupplicant UI and restart. Contact IDEngines support if this occurs."));

    delete m_pEventListenerThread;
    m_pEventListenerThread = NULL;
    bValue = false;
  }
  else
  {
    m_pEventListenerThread->start();
    m_bListenerStarted = true;
    bValue = true;
  }


  return bValue;
}

//! 
/*!
  \return 
*/
void TrayApp::slotHelp()
{
  HelpWindow::showPage("xsupphelp.html", "xsupuserguide");
}

void TrayApp::slotLaunchHelp(const QString &file, const QString &page)
{
	HelpWindow::showPage(file, page);
}

void TrayApp::loadPlugins()
{
	int pluginStatus = PLUGIN_LOAD_FAILURE;
	char *plugin_path = NULL;
	QString qplugin_path = QApplication::applicationDirPath() + "/Modules/";
	QString posture_path;
	UIPlugins *nextPlugin = NULL;
	QString update_path;
	QString version;
	QString full;  

	if (m_bSupplicantConnected)
	{
		m_supplicant.getAndCheckSupplicantVersion(full, version, true);
	}
	else
	{
		version = "";
	}

	m_pPlugins = new UIPlugins(m_pEmitter, &m_supplicant);

	if(m_pPlugins != NULL)
	{
		posture_path = qplugin_path + "PostureRemediationDialog.dll";
		plugin_path = _strdup(posture_path.toAscii());

#ifdef WINDOWS
		Util::useBackslash(plugin_path);
#endif

		pluginStatus = m_pPlugins->loadPlugin(plugin_path);

		if(pluginStatus == PLUGIN_LOAD_SUCCESS)
		{
			m_pPlugins->setType(PLUGIN_TYPE_STARTUP);

			m_pPlugins->instantiateWidget();
			m_pPlugins->updateEngineVersionString(version);
			m_pPlugins->setCallbacks(uiCallbacks);

			m_pluginVersionString = m_pPlugins->getPluginVersionString();

			if(m_pEmitter != NULL)
			{
				m_pEmitter->sendUIMessage(tr("Plugin load succeeded for %1.\n").arg(plugin_path));
			}
		}
		else
		{
			if(m_pEmitter != NULL)
			{
				//m_pEmitter->sendUIMessage(tr("Plugin load failed for %1. Error code: %2\n").arg(plugin_path).arg(pluginStatus));
			}

			delete m_pPlugins;
			m_pPlugins = NULL;
		}
		
		free(plugin_path);

		// Try to load the update plugin.
		if (m_pPlugins != NULL)
		{
			m_pPlugins->next = new UIPlugins(m_pEmitter, &m_supplicant);
			nextPlugin = m_pPlugins->next;
		}
		else
		{
			m_pPlugins = new UIPlugins(m_pEmitter, &m_supplicant);
			nextPlugin = m_pPlugins;
		}

		if (nextPlugin != NULL)
		{
			update_path = qplugin_path + "update_plugin.dll";
			plugin_path = _strdup(update_path.toAscii());

#ifdef WINDOWS
			Util::useBackslash(plugin_path);
#endif

			pluginStatus = nextPlugin->loadPlugin(plugin_path);

			if(pluginStatus == PLUGIN_LOAD_SUCCESS)
			{
				nextPlugin->setType(PLUGIN_TYPE_STARTUP);
	
				nextPlugin->instantiateWidget();
				nextPlugin->updateEngineVersionString(version);

				if(m_pEmitter != NULL)
				{
					m_pEmitter->sendUIMessage(tr("Plugin load succeeded for %1.\n").arg(plugin_path));
				}
			}
			else
			{
				if(m_pEmitter != NULL)
				{
					//m_pEmitter->sendUIMessage(tr("Plugin load failed for %1. Error code: %2\n").arg(plugin_path).arg(pluginStatus));
				}
			
				if (m_pPlugins->next == nextPlugin)
				{
					delete m_pPlugins->next;
					m_pPlugins->next = NULL;
                    nextPlugin = NULL;
				}
				else if(m_pPlugins == nextPlugin)
				{
					delete m_pPlugins;
                    m_pPlugins = NULL;
                    nextPlugin = NULL;
				}
                else
                {
                    delete nextPlugin;
                    nextPlugin = NULL;
                }
			}

			free(plugin_path);
		}	
	}
}

void TrayApp::unloadPlugins()
{
	UIPlugins *currentPlugin = m_pPlugins;

	while(currentPlugin != NULL)
	{
		m_pPlugins = m_pPlugins->next;

		delete currentPlugin;

		currentPlugin = m_pPlugins;
	}

	m_pPlugins = NULL;
}

void TrayApp::showBasicConfig(void)
{
	if (!m_bSupplicantConnected)
	{
		QMessageBox::warning(this,  tr("Service not connected yet."),
		tr("You can't run the Configuration module until the service is connected"));
	}
	else
	{
		if (m_pConnMgr == NULL)
		{
			m_pConnMgr = new ConnectMgrDlg(this, NULL, m_pEmitter, this);
			if (m_pConnMgr == NULL || m_pConnMgr->create() == false)
			{
				QMessageBox::critical(this, tr("Form Creation Error"), tr("The Connection Manager Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
				if (m_pConnMgr != NULL)
				{
					delete m_pConnMgr;
					m_pConnMgr = NULL;
				}
			}
			else
			{
				m_pConnMgr->show();
			}
		}
		else
		{
			m_pConnMgr->show();
		}
	}
}

void TrayApp::showAdvancedConfig(void)
{
	if (!m_bSupplicantConnected)
	{
		QMessageBox::warning(this,  tr("Service not connected yet."),
		tr("You can't run the Configuration module until the service is connected"));
	}
	else
	{
		if (m_pConfDlg == NULL)
		{
			m_pConfDlg = new ConfigDlg(m_supplicant, m_pEmitter, this);
			if (m_pConfDlg == NULL || m_pConfDlg->create() == false)
			{
				QMessageBox::critical(this, tr("Form Creation Error"), tr("The Configuration Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
				if (m_pConfDlg != NULL)
				{
					delete m_pConfDlg;
					m_pConfDlg = NULL;
				}
			}
			else
			{
				m_pConfDlg->show();
				Util::myConnect(m_pConfDlg, SIGNAL(close(void)), this, SLOT(slotCleanupConfig(void)));
			}
		}
		else
		{
			m_pConfDlg->show();
		}
	}
}

void TrayApp::showConnectDlg(void)
{
	if (!m_bSupplicantConnected)
	{
		QMessageBox::warning(this,  tr("Service not connected yet."),
		tr("You can't run the Configuration module until the service is connected"));
	}
	else
	{
		if (m_pConnectDlg == NULL)
		{
			m_pConnectDlg = new ConnectDlg(this, NULL, m_pEmitter, this);
			if (m_pConnectDlg == NULL || m_pConnectDlg->create() == false)
			{
				QMessageBox::critical(this, tr("Form Creation Error"), tr("The Connect Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
				if (m_pConnectDlg != NULL)
				{
					delete m_pConnectDlg;
					m_pConnectDlg = NULL;
				}			
			}
			else
			{
				m_pConnectDlg->show();
			}
		}
		else
		{
			m_pConnectDlg->show();
		}
	}
}
