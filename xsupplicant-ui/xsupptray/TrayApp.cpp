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

  m_pEventListenerThread = NULL;
  m_pQuitAction          = NULL;
  m_pConfigAction        = NULL;
  m_pLoginAction         = NULL;
  m_pAboutAction         = NULL;
  m_pViewLogAction       = NULL;
  m_pTroubleticketAction = NULL;
  m_pLoginDlg            = NULL;
  m_pAboutDlg            = NULL;
  m_pLoggingCon          = NULL;
  m_pConfDlg             = NULL;
  m_pEmitter             = NULL;
  m_pTrayIcon            = NULL;
  m_pTrayIconMenu        = NULL;
  m_pPlugins             = NULL;
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

		delete m_pEmitter;
		m_pEmitter = NULL;
	}

	if (m_pAboutDlg != NULL) 
	{
		delete m_pAboutDlg;  // Clean up any about window hanging around.
		m_pAboutDlg = NULL;
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

  qInstallMsgHandler(0);
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

	m_supplicant.freeConfigGlobals(&globals);
	
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
  qInstallMsgHandler(myMsgHandler);

  if (!checkCommandLineParams(argc))
  {
    return false;
  }

  createTrayActionsAndConnections();

  createTrayIcon();

  m_bConnectFailed = false;

  slotConnectToSupplicant();

  m_pTrayIcon->show();

  loadPlugins();
  
#ifdef WINDOWS
  checkOtherSupplicants();
#endif

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
  // Set the tray icon to disconnected
  setTrayIconDisconnected();

  // delete in reverse order of creation
  delete m_pLoginDlg;
  delete m_pConfDlg;
  delete m_pEventListenerThread;
  delete m_pLoggingCon;

  m_pLoginDlg = NULL;
  m_pConfDlg = NULL;
  m_pEventListenerThread = NULL;
  m_pLoggingCon = NULL;

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
      setTrayIconDisconnected();
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
	  setTrayIconConnected();
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


void TrayApp::setEnabledMenuItems(bool bEnable)
{
  m_pLoginAction->setEnabled(bEnable);
  m_pConfigAction->setEnabled(bEnable);
  m_pViewLogAction->setEnabled(bEnable);
  m_pTroubleticketAction->setEnabled(bEnable);
}

void TrayApp::slotHideLog()
{
	m_pLoggingCon->hide();
}

//! postConnectActions
/*!
  \return false - if can't start event listener - can't go on if this is the case
*/
bool TrayApp::postConnectActions()
{
  m_supplicant.updateAdapters(false);

  m_pEmitter = new Emitter();

  m_pLoggingCon = new LoggingConsole(NULL, m_pEmitter); // no parent
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

  m_pLoginAction = new QAction(tr("&Login..."), this);
  Util::myConnect(this->m_pLoginAction, SIGNAL(triggered()), this, SLOT(slotLaunchLogin()));

  m_pConfigAction = new QAction(tr("&Configure..."), this);
  Util::myConnect(m_pConfigAction, SIGNAL(triggered()), this, SLOT(slotLaunchConfig()));
  
  m_pViewLogAction = new QAction(tr("&View Log..."), this);
  Util::myConnect(m_pViewLogAction, SIGNAL(triggered()), this, SLOT(slotViewLog()));

  m_pAboutAction = new QAction(tr("&About"), this);
  Util::myConnect(m_pAboutAction, SIGNAL(triggered()), this, SLOT(slotAbout()));

  m_pQuitAction = new QAction(tr("&Exit"), this);
  Util::myConnect(m_pQuitAction, SIGNAL(triggered()), this, SLOT(slotExit()));

  m_pTroubleticketAction = new QAction(tr("&Create Troubleticket..."), this);
  Util::myConnect(m_pTroubleticketAction, SIGNAL(triggered()), this, SLOT(slotCreateTroubleticket()));

  Util::myConnect(&m_timer, SIGNAL(timeout()), this, SLOT(slotConnectToSupplicant()));

}

//! 
/*!
  \return 
*/
void TrayApp::createTrayIcon()
{
  m_pTrayIconMenu = new QMenu(this);
  m_pTrayIconMenu->addAction(m_pLoginAction);
  m_pTrayIconMenu->addAction(m_pConfigAction);
  m_pTrayIconMenu->addAction(m_pViewLogAction);
  m_pTrayIconMenu->addAction(m_pTroubleticketAction);
  m_pTrayIconMenu->addSeparator();
  m_pTrayIconMenu->addAction(m_pAboutAction);
  m_pTrayIconMenu->addAction(m_pQuitAction);

  m_pTrayIcon = new QSystemTrayIcon(this);
  m_pTrayIcon->setContextMenu(m_pTrayIconMenu);
  Util::myConnect(m_pTrayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
          this, SLOT(slotIconActivated(QSystemTrayIcon::ActivationReason)));
  setTrayIconDisconnected();
  m_pTrayIcon->show();       // Even if the icon couldn't be loaded, we will at least get a blank spot on the tray.
}

//! 
/*!
  \return 
*/
void TrayApp::setTrayIconConnected()
{
  QPixmap *p = NULL;

  p = FormLoader::loadicon("prod_color.png");

  if (p != NULL)
  {
    QIcon icon((*p));
    m_pTrayIcon->setIcon(icon);
    setWindowIcon(icon);
	m_pTrayIcon->show();
  }

  delete p;
}

//! 
/*!
  \return 
*/
void TrayApp::setTrayIconDisconnected()
{
  QPixmap *p = NULL;

  p = FormLoader::loadicon("prod_red.png");

  if (p != NULL)
  {
    QIcon icon((*p));
    if (m_pTrayIcon != NULL) m_pTrayIcon->setIcon(icon);
    setWindowIcon(icon);
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
        slotLaunchLogin();
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
  // this will list the current adapters (interfaces) on this machine
  // and add any that are not in the configuration file

  // These dialogs must stay in scope the entire time.
  // They won't get able to get the focus until the main
  // window loses focus - what to do about this?
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
		  if (m_pConfDlg->create() == false)
		  {
			  QMessageBox::critical(this, tr("Form Creation Error"), tr("The Login Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
			  delete m_pConfDlg;
			  m_pConfDlg = NULL;
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
  if (m_pAboutDlg == NULL)
  {
	  m_pAboutDlg = new AboutDlg(this);
	  if (m_pAboutDlg->create() == false)
	  {
		  QMessageBox::critical(this, tr("Form Creation Error"), tr("The About Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
		  delete m_pAboutDlg;
		  m_pAboutDlg = NULL;
	  }
	  else
	  {
		  m_pAboutDlg->show();

		  Util::myConnect(m_pAboutDlg, SIGNAL(close(void)), this, SLOT(slotCleanupAbout(void)));
	  }
  }
  else
  {
	  m_pAboutDlg->show();
  }
}

/**
 * \brief When the About Dialog emits a close() signal, we want
 *        to free the memory.
 **/
void TrayApp::slotCleanupAbout()
{
	if (m_pAboutDlg == NULL) return;  // This shouldn't be possible!

	Util::myDisconnect(m_pAboutDlg, SIGNAL(close(void)), this, SLOT(slotCleanupAbout(void)));

	delete m_pAboutDlg;

	m_pAboutDlg = NULL;
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

void TrayApp::slotCreateTroubleticket()
{
    int err = 0;
    QString filePath = QDir::toNativeSeparators((QDir::homePath().append(tr("/Desktop/XSupplicant Trouble Ticket.zip"))));

    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Trouble ticket"), filePath, tr("Archives (*.zip)"));

    char *path = _strdup(fileName.toAscii());

#ifdef WINDOWS
    Util::useBackslash(path);
#endif

    err = m_supplicant.createTroubleTicket((char *)path, "c:\\", 1);

    switch(err)
	{
	case REQUEST_SUCCESS:
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
  HelpBrowser::showPage("xsupphelp.html", "xsupuserguide");
}

void TrayApp::slotLaunchHelp(const QString &file, const QString &page)
{
	HelpBrowser::showPage(file, page);
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
