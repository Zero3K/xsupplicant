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

#include "stdafx.h"

#include "LoginMainDlg.h"
#include "LoggingConsole.h"
#include "StackedLoginConfig.h"
#include "FormLoader.h"
#include "helpbrowser.h"

//! Constructor
/*!
   \brief Constructs the Login Dialog
 
   \param [in] supplicant 
   \param [in] pLog
   \param [in] parent 
 
   \note Stuff goes here
   \warning more stuff
*/
LoginMainDlg::LoginMainDlg(XSupCalls &sup, Emitter *e, QWidget *parent)
   : QWidget(parent), 
   m_pParent(parent), 
   m_supplicant(sup), 
   m_message(this),
   m_pEmitter(e)
{
  m_pConns = NULL;
  m_pSSIDInfoBox = NULL;
  m_pLoginStack = NULL;
  m_pStack = NULL;
  m_pRealForm = NULL;

  m_bCredsConnected = false;
}

//! Destructor
/*!
   \brief Destructor
   \note Frees the connection enumeration and sets the pointer to NULL
   \sa other functions
*/
LoginMainDlg::~LoginMainDlg()
{
  m_supplicant.freeEnumPossibleConnections(&m_pConns);
  m_pConns = NULL;

  if (m_pLoginStack != NULL)
  {
	Util::myDisconnect(m_pConnectionComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(slotConnectionChangedEvent(int)));
  }

  Util::myDisconnect(m_pConnectDisconnectButton, SIGNAL(clicked()), this, SLOT(slotConnectDisconnect()));

	// If m_pClose is NULL, then there isn't a close button.  We don't consider that to be a problem, so don't complain.
	if (m_pCloseButton != NULL)
	{
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), this, SIGNAL(close()));
	}

	// If m_pHelpButton is NULL, then there isn't a help button.  We don't consider this to be a problem, so don't complain.
	if (m_pHelpButton != NULL)
	{
	    Util::myDisconnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotShowHelp()));
	}

	// If m_pConfigureButton is NULL, then there isn't a help button.  We don't consider this to be a problem, so don't complain.
	if (m_pConfigureButton != NULL)
	{
	    Util::myDisconnect(m_pConfigureButton, SIGNAL(clicked()), m_pEmitter, SIGNAL(signalShowConfig()));
	}

	// If m_pShowLogButton is NULL, then there isn't a help button.  We don't consider this to be a problem, so don't complain.
	if (m_pShowLogButton != NULL)
	{
	    Util::myDisconnect(m_pShowLogButton, SIGNAL(clicked()), m_pEmitter, SIGNAL(signalShowLog()));
	}

	Util::myDisconnect(m_pEmitter, SIGNAL(signalScanCompleteMessage(const QString &)), this, SLOT(slotNewScanData(const QString &)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(slotUpdateConnections()));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalProfConfigUpdate()), this, SLOT(slotUpdateProfiles()));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(slotInterfaceInserted(char *)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceRemoved(char *)), this, SLOT(slotInterfaceRemoved(char *)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalLinkUp(char *)), this, SLOT(slotLinkUp(char *)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalLinkDown(char *)), this, SLOT(slotLinkDown(char *)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalBadPSK(const QString &)), this, SLOT(slotBadPSK(const QString &)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalAuthTimeout(const QString &)), this, SLOT(slotAuthTimeout(const QString &)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotStateChange(const QString &, int, int, int, unsigned int)));
    Util::myDisconnect(this, SIGNAL(signalShowConfig()), m_pEmitter, SIGNAL(signalShowConfig()));

  if (m_pLoginStack != NULL)
  {
	  delete m_pLoginStack;
	  m_pLoginStack = NULL;
  }

  if (m_pRealForm != NULL) 
  {
	  Util::myDisconnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));
	  delete m_pRealForm;
  }
}

bool LoginMainDlg::create()
{
	QPixmap *p = NULL;

	m_pRealForm = FormLoader::buildform("LoginWindow.ui");

    if (m_pRealForm == NULL) return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pConnectionComboBox = qFindChild<QComboBox*>(m_pRealForm, "dataComboConnections");
	if (m_pConnectionComboBox == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form loaded for the 'Login Dialog' did not contain the 'dataComboConnections' combo box.  This is needed to select a connection!"));
	}

	m_pConnectDisconnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonConnect");
	if (m_pConnectDisconnectButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form loaded for the 'Login Dialog' did not contain the 'buttonConnect' push button.  This is needed to connect to, or disconnect from, a connection!"));
	}
	else
	{
		Util::myConnect(m_pConnectDisconnectButton, SIGNAL(clicked()), this, SLOT(slotConnectDisconnect()));
	}

	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");

	// If m_pClose is NULL, then there isn't a close button.  We don't consider that to be a problem, so don't complain.
	if (m_pCloseButton != NULL)
	{
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), this, SIGNAL(close()));
	}

	m_pHelpButton = qFindChild<QPushButton*>(m_pRealForm, "buttonHelp");

	// If m_pHelpButton is NULL, then there isn't a help button.  We don't consider this to be a problem, so don't complain.
	if (m_pHelpButton != NULL)
	{
	    Util::myConnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotShowHelp()));
	}

	m_pConfigureButton = qFindChild<QPushButton*>(m_pRealForm, "buttonConfig");

	// If m_pConfigureButton is NULL, then there isn't a help button.  We don't consider this to be a problem, so don't complain.
	if (m_pConfigureButton != NULL)
	{
	    Util::myConnect(m_pConfigureButton, SIGNAL(clicked()), m_pEmitter, SIGNAL(signalShowConfig()));
	}

	m_pShowLogButton = qFindChild<QPushButton*>(m_pRealForm, "buttonShowLog");

	// If m_pShowLogButton is NULL, then there isn't a help button.  We don't consider this to be a problem, so don't complain.
	if (m_pShowLogButton != NULL)
	{
	    Util::myConnect(m_pShowLogButton, SIGNAL(clicked()), m_pEmitter, SIGNAL(signalShowLog()));
	}

	p = FormLoader::loadicon("wired.png");
	if (p != NULL)
	{
		m_wiredIcon.addPixmap((*p));
	}
	delete p;

	p = FormLoader::loadicon("wireless.png");
	if (p != NULL)
	{
      m_wirelessIcon.addPixmap((*p));
    }
	delete p;

	if (setupLoginStack() == false) return false;

	setupWindow();

	connectControls();

	Util::myConnect(m_pEmitter, SIGNAL(signalScanCompleteMessage(const QString &)), this, SLOT(slotNewScanData(const QString &)));
	Util::myConnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(slotUpdateConnections()));
	Util::myConnect(m_pEmitter, SIGNAL(signalProfConfigUpdate()), this, SLOT(slotUpdateProfiles()));
	Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(slotInterfaceInserted(char *)));
	Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceRemoved(char *)), this, SLOT(slotInterfaceRemoved(char *)));
	Util::myConnect(m_pEmitter, SIGNAL(signalLinkUp(char *)), this, SLOT(slotLinkUp(char *)));
	Util::myConnect(m_pEmitter, SIGNAL(signalLinkDown(char *)), this, SLOT(slotLinkDown(char *)));
	Util::myConnect(m_pEmitter, SIGNAL(signalBadPSK(const QString &)), this, SLOT(slotBadPSK(const QString &)));
	Util::myConnect(m_pEmitter, SIGNAL(signalAuthTimeout(const QString &)), this, SLOT(slotAuthTimeout(const QString &)));
	Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotStateChange(const QString &, int, int, int, unsigned int)));
    Util::myConnect(this, SIGNAL(signalShowConfig()), m_pEmitter, SIGNAL(signalShowConfig()));

	return true;
}

bool LoginMainDlg::setupLoginStack()
{
	m_pStack = qFindChild<QStackedWidget*>(m_pRealForm, "widgetStackLogin");

	if (m_pStack == NULL) 
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The design file for the 'Login Dialog' is missing the 'widgetStackLogin'.  You cannot use this program without it!"));
		return false;
	}
	
	return true;
}

void LoginMainDlg::slotUpdateProfiles()
{
	m_pLoginStack->update(true);
}

void LoginMainDlg::setupWindow()
{
	Qt::WindowFlags flags;

  // Create the title and other fields on parent dialog
	flags = m_pRealForm->windowFlags();
	flags &= (~Qt::WindowContextHelpButtonHint);
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);

	m_pStack->setCurrentIndex(0);
	populateConnectionBox(true);
}

void LoginMainDlg::show()
{
	if (m_pRealForm->isVisible() == true) m_pRealForm->hide();

	m_pRealForm->show();
}

//! setInfo()
/*!
   \brief Sets the information for this dialog
   \param[in] bDisplayMessage - whether or not to display error messages
   \return nothing
*/
bool LoginMainDlg::setInfo(bool bDisplayMessage)
{
  Util::myDisconnect(m_pConnectionComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(slotConnectionChangedEvent(int)));

  bool bcode = populateConnectionBox(bDisplayMessage);

  Util::myConnect(m_pConnectionComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(slotConnectionChangedEvent(int)));

  m_currentConnection = "";

  return bcode;
}


void LoginMainDlg::connectControls()
{
    // First connect the event
  Util::myConnect(m_pConnectionComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(slotConnectionChangedEvent(int)));
}

//! enumPossibleConnections
/*!
   \brief Get the list of "possible" connections
*/
bool LoginMainDlg::enumPossibleConnections()
{
  // Free the previous list, if any
  m_supplicant.freeEnumPossibleConnections(&m_pConns);
  
  return m_supplicant.enumAndSortPossibleConnections(&m_pConns, true);
}

//! populateConnectionBox
/*!
   \brief Adds data to the connection box initially
   \param[in] bDisplayMessage - whether or not to display the "no connections" message - sometimes we call this after updating the connections
   \note Call this after all the layout is done
*/
bool LoginMainDlg::populateConnectionBox(bool bDisplayMessage)
{
  int i = 0;
  int defaultConn = -1;
  m_currentConnection = "";

  // Get the connections 
  enumPossibleConnections();
  
  m_pConnectionComboBox->clear();

  if (m_pLoginStack == NULL)
  {
	 m_pLoginStack = new StackedLoginConfig(m_pConns, m_pStack, this, m_pEmitter);
  }

  if ((!m_pConns) || (m_pConns[0].name == NULL))
  {
    if (bDisplayMessage)
    {
      // Display no connections dialog - can't go on
	  QMessageBox::information(this, tr("No Connections Defined"), tr("Please create at least one connection before attempting to log in."));
	  emit signalShowConfig();   // Display the config window so the user can create a connection.		
	  m_pConnectDisconnectButton->setEnabled(false);
      return false;
    }
  }
  else
  {
    while (m_pConns[i].name != NULL)
    {
      if (m_pConns[i].dev_desc == NULL)
      {
	QMessageBox::critical(this, tr("Invalid Configuration"), tr("No adapter description for connection '%1'.  You will need to modify the configuration of this connection in order to use it.").arg(m_pConns[i].name));
      }
      else
      {
        if (m_pConns[i].flags & POSS_CONN_IS_WIRELESS)
        {
          m_pConnectionComboBox->addItem(m_wirelessIcon, m_pConns[i].name);
        }
        else
        {
          m_pConnectionComboBox->addItem(m_wiredIcon, m_pConns[i].name);
        }
        if (defaultConn == -1)
        {

          // Check to see if this connection with its associated SSID is connected
          if (isCurrentConnectionActive(m_pConns[i]))
          {
            defaultConn = i;
          }
        }
      }
      i++;
    }

    // Then set the current index - this should call the connectionChangedEvent to set the value
    if (defaultConn != -1)
    {
      // Switch to the status screen
      m_pConnectionComboBox->setCurrentIndex(defaultConn);
      slotConnectionChangedEvent(defaultConn);
    }
    else
    {
      m_pConnectionComboBox->setCurrentIndex(0);
      slotConnectionChangedEvent(0);
    }
  }
  return true;
}

//! slotConnectionChangedEvent
/*!
   \brief Get the connection information
   Calls getConnectionInformation()
   \param[in] selection - the selection that changed
   \note (none)
*/
void LoginMainDlg::slotConnectionChangedEvent(int index)
{
  // The index in the combo-box is always the same as in the m_pConns array
  m_connsIndex = index;

  // If same connection - stay where we are - otherwise proceed here
  if (m_currentConnection != m_pConnectionComboBox->currentText())
  {
    // Can't select this configuration if the device name can't be found
    // See if the connection is already connected - if so, switch to the status screen
    // otherwise, go to the login window
    m_currentConnection = m_pConns[m_connsIndex].name;
    m_deviceDescription = m_pConns[m_connsIndex].dev_desc;

    // Get the device information
    bool bDeviceNameFound = m_supplicant.getDeviceName(m_pConns[m_connsIndex].dev_desc, m_deviceName, false);
    if (bDeviceNameFound && isCurrentConnectionActive(m_pConns[m_connsIndex]))
    {
      // Set the info and the buttons
      setButtons(false); 

      // switch to status screen
      m_pLoginStack->setCurrent(StackedLoginConfig::LOGIN_STATUS, 
		  false,
        m_currentConnection, 
        m_deviceDescription, 
        m_deviceName,
        m_bWireless,
        &m_pConns[m_connsIndex]);
    }
    else // not authenticated
    {
      // Set the info and the buttons
      setButtons(true);

      // switch to login screen
      m_pLoginStack->setCurrent(StackedLoginConfig::LOGIN_GET_INFO, 
		  false,
        m_currentConnection, 
        m_deviceDescription, 
        m_deviceName,
        m_bWireless, 
        &m_pConns[m_connsIndex]);
    }
  }
}

//! setButtons()
/*!
   \brief Set the button information
   \param [in] bShowInfo - whether or not to show this information
   \note (none)
*/
void LoginMainDlg::setButtons(bool bShowInfo)
{
  m_bWireless = false;
  //XXX: This will crash if m_pConns is NULL.
  if (m_pConns[m_connsIndex].flags & POSS_CONN_IS_WIRELESS)
  {
    m_bWireless = true;
  }

  if (bShowInfo)
  {
    m_pConnectDisconnectButton->setText(tr("Connect"));
    if (m_pSSIDInfoBox != NULL) m_pSSIDInfoBox->show();

    if (m_pConns[m_connsIndex].flags & POSS_CONN_INT_AVAIL)
    {
      m_pConnectDisconnectButton->setEnabled(true);
    }
    else if (m_pConns[m_connsIndex].flags & POSS_CONN_INT_UNKNOWN)
    {
      m_pConnectDisconnectButton->setEnabled(false);
    }
    else
    {
      m_pConnectDisconnectButton->setEnabled(false);
    }
  }
  else
  {
    m_pConnectDisconnectButton->setText(tr("Disconnect"));
    if (m_pSSIDInfoBox != NULL) m_pSSIDInfoBox->hide();
  }
}

//! getUserName
/*!
   \brief Get function to get the user name
   \return the name of the user
   \note (none)
*/
const QString LoginMainDlg::getUserName()
{
  return m_pLoginStack->getUserName();
}

//! getPassword
/*!
   \brief Get function to get the user name
   \return the name of the user
   \note (none)
*/
const QString LoginMainDlg::getPassword()
{
  return m_pLoginStack->getPassword();
}
//! getUserName
/*!
   \brief Get function to get the current connection
   \return current connection
   \note (none)
*/
const QString &LoginMainDlg::getConnection()
{
  return m_currentConnection;
}

//! getDeviceDescription
/*!
   \brief Get function to get the device description
   \return device description
   \note (none)
*/
const QString &LoginMainDlg::deviceDescription()
{
  return m_deviceDescription;
}

//! getDeviceName
/*!
   \brief Get function to get the device name
   \return device name
   \note (none)
*/
const QString &LoginMainDlg::deviceName()
{
  return m_deviceName;
}

//! slotUpdateConnections
/*!
   \brief Is called when the configuration editor finishes editing a connection
   \return nothing
   \note (none)
*/
void LoginMainDlg::slotUpdateConnections()
{
  // Now update the connections when the configuration closes
  setInfo(false);
}

void LoginMainDlg::slotSaveCreds(const QString &intName, int sm, int oldstate, int newstate, unsigned int imcState)
{
	if (((sm == IPC_STATEMACHINE_8021X) && (newstate == AUTHENTICATED)) ||
		((sm == IPC_STATEMACHINE_8021X) && (newstate == S_FORCE_AUTH)))
	{
		if (saveCredentials() == true)
		{
			m_pEmitter->sendUIMessage(tr("Your credentials have been saved."));
		}

		if (m_bCredsConnected == true)
		{
			Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotSaveCreds(const QString &, int, int, int, unsigned int)));
			m_bCredsConnected = false;
		}
	}
}

//! slotDisconnect
/*!
  \brief Called when the user presses the Disconnect button
  Calls the supplicant to disconnect from the current connection.
  \return nothing
*/
void LoginMainDlg::slotConnectDisconnect()
{
  int index = m_pStack->currentIndex();
  m_currentConnection = m_pConnectionComboBox->currentText();

  if (m_pConns[m_connsIndex].name == NULL)
  {
	  QMessageBox::critical(this, tr("No connections defined"), tr("There appear to be no connections currently defined.  Please define one and try again."));
	  return;
  }

  switch (index)
  {
  case StackedLoginConfig::LOGIN_GET_INFO:
      // If this succeeds, go to the status window
	  if (m_pConns[m_connsIndex].auth_type == AUTH_EAP)
	  {
		  if ((m_pConns[m_connsIndex].flags & POSS_CONN_NO_PWD) == POSS_CONN_NO_PWD)
		  {
			  if (m_pLoginStack->getUserName() == "")
			  {
				  QMessageBox::information(this, tr("Username Needed"), tr("Please enter a valid username before attempting to connect to this network."));
				  return;
			  }
		  }
		  else
		  {
			if ((m_pLoginStack->getUserName() == "") || (m_pLoginStack->getPassword() == ""))
			{
				QMessageBox::information(this, tr("Username/Password Needed"), tr("Please enter a valid username and password before attempting to connect to this network."));
				return;
			}	
		  }
	  }
	  else if (m_pConns[m_connsIndex].auth_type == AUTH_PSK)
	  {
		  if (m_pLoginStack->getPassword() == "")
		  {
			  QMessageBox::information(this, tr("PSK Needed"), tr("Please enter a valid pre-shared key (PSK) before attempting to connect to this network."));
			  return;
		  }
	  }
	  // Otherwise, we shouldn't have a username/password field.

      if (networkConnect())
      {
		  if (m_pLoginStack->getCacheCredentialsFlag())
		  {
			  // We want to save our creds when it is time.
			  m_userName = m_pLoginStack->getUserName();
			  m_password = m_pLoginStack->getPassword();
		
			  if (m_bCredsConnected == false)
			  {
				  Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotSaveCreds(const QString &, int, int, int, unsigned int)));
				  m_bCredsConnected = true;
			  }
		  }
		  else
		  {
			  if (m_bCredsConnected == true)
			  {
				  Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotSaveCreds(const QString &, int, int, int, unsigned int)));
				  m_bCredsConnected = false;
			  }
		  }

        m_pConnectDisconnectButton->setText(tr("Disconnect"));
        setButtons(false); // don't show the window

        // switch to status screen
        m_pLoginStack->setCurrent(StackedLoginConfig::LOGIN_STATUS, 
			true,
          m_currentConnection, 
          m_deviceDescription, 
          m_deviceName,
          m_bWireless, 
          &m_pConns[m_connsIndex]);
      }
      else  // otherwise - return to login window
      {
        m_pConnectDisconnectButton->setText(tr("Connect"));
        setButtons(true); // show the window

        // switch to info screen
        m_pLoginStack->setCurrent(StackedLoginConfig::LOGIN_GET_INFO, 
			false,
          m_currentConnection, 
          m_deviceDescription, 
          m_deviceName,
          m_bWireless, 
          &m_pConns[m_connsIndex]);
      }
      break;

  case StackedLoginConfig::LOGIN_STATUS:
      networkDisconnect();

      if(m_pConnectDisconnectButton != NULL)
        m_pConnectDisconnectButton->setText(tr("Connect"));

      setButtons(true);

      // switch to status screen
      m_pLoginStack->setCurrent(StackedLoginConfig::LOGIN_GET_INFO, 
		  false,
        m_currentConnection, 
        m_deviceDescription, 
        m_deviceName,
        m_bWireless, 
        &m_pConns[m_connsIndex]);
      break;
  }

}

//! networkConnect()
/*!
   \brief Connect to the network
   \return nothing
*/
bool LoginMainDlg::networkConnect()
{
  bool bValue = true;
  // If already connected to this ssid 
  int index = m_pConnectionComboBox->currentIndex();

  m_connsIndex = index;
  m_currentConnection = m_pConnectionComboBox->currentText();
  if (!isCurrentConnectionActive(m_pConns[m_connsIndex])) 
  {
    // Check to see whether we should set this information
	bValue = m_supplicant.setUserNameAndPassword(m_currentConnection, m_pLoginStack->getUserName(), 
		m_pLoginStack->getPassword(), m_pConns[m_connsIndex].auth_type);
    if (bValue == true)
    {
      // For this device, use this connection from the configuration file
      bValue = m_supplicant.setConnection(m_deviceName, m_currentConnection);
    }
  }
  return bValue;
}

//! networkDisconnect()
/*!
   \brief Disconnect from the network
   \return nothing
*/
bool LoginMainDlg::networkDisconnect()
{
  return m_supplicant.networkDisconnect(m_deviceName, m_deviceDescription, m_bWireless);
}

//! isCurrentConnectionActive
/*!
   \brief Attempt to determine which connection was used to connect to the network.
   \param[in] conn - the connection enumeration
   \return nothing
    #define WIRELESS_UNKNOWN_STATE         0
    #define WIRELESS_UNASSOCIATED          1
    #define WIRELESS_ASSOCIATED            2
    #define WIRELESS_ACTIVE_SCAN           3    // There may be a passive scan later.
    #define WIRELESS_ASSOCIATING           4    // Attempting to associate
    #define WIRELESS_ASSOCIATION_TIMEOUT_S 5
    #define WIRELESS_STATIC_ASSOCIATION    6    // Associated to a network with static wep, or
                                                // no keying.
    #define WIRELESS_PORT_DOWN             7    // The interface is down state.
    #define WIRELESS_NO_ENC_ASSOCIATION    8  
    #define WIRELESS_INT_RESTART           9    // Restart everything.
    #define WIRELESS_INT_STOPPED           10   // Stop answering requests.
    #define WIRELESS_INT_HELD              11   // Hold the authentication, waiting for an event.

*/
bool LoginMainDlg::isCurrentConnectionActive(poss_conn_enum &conn)
{
  bool bValue = false;
  QString liveSSID;
  int state;
  QString status;
  QString message;
  QString connName; 

  QString deviceDescription = conn.dev_desc;
  QString deviceName;
  // don't display the message, just go on to the next connection if the device name can't be retrieved
  if (!m_supplicant.getDeviceName(deviceDescription, deviceName, false))
  {
    return false;
  }

  // See if this device is associated with a connection from the connection table
  if (m_supplicant.getConfigConnectionName(deviceDescription, deviceName, connName))
  {
    // If Wireless to this...
    if (conn.flags & POSS_CONN_IS_WIRELESS)
    {
      // Get physical state is not INT_STOPPED or INT_HELD - then use this connection
      // This is a change from the initial implementation where we checked for the 802.1X state
      // having to be in authenticated state.
      if (m_supplicant.getPhysicalState(deviceDescription, deviceName, status, state, false))
      {
        if (state != WIRELESS_INT_STOPPED && state != WIRELESS_INT_HELD) 
        {
          if (connName.compare(conn.name) == 0)
          {
            bValue = true;
          }
        }
      }
    }
    else // wired - get 802.1X state
    {
      if (m_supplicant.get1xState(deviceDescription, deviceName, status, state, false))
      {
        if (state != DISCONNECTED) 
        {
          if (connName.compare(conn.name) == 0)
          {
            bValue = true;
          }
        }
      }
    }
  }
  return bValue;
}

//! saveCredentials()
/*!
   \brief Save the credentials
   \return nothing
*/
bool LoginMainDlg::saveCredentials()
{
    config_connection *pConfig = NULL;
    QString temp;

    if (m_supplicant.getConfigConnection(m_currentConnection, &pConfig) == true)
	{
	    if (pConfig->association.auth_type == AUTH_EAP) 
	    {
		  if (pConfig->profile && *pConfig->profile)
	      {
	        config_profiles *pProfile;

		temp = pConfig->profile;
	        if (m_supplicant.getConfigProfile(temp, &pProfile) && pProfile)
	        {
	          m_supplicant.setUserNameIntoProfile(pProfile, m_userName); 
	          m_supplicant.setPasswordIntoProfile(pProfile, m_password); 
	          m_supplicant.setConfigProfile(pProfile); 
	          m_supplicant.writeConfig(); 
			  m_supplicant.freeConfigConnection(&pConfig);
	          m_supplicant.freeConfigProfile(&pProfile); 
			  return true;
	        }
	      }
		}
		else if (pConfig->association.auth_type == AUTH_PSK)
		{
			if (pConfig->association.psk != NULL)
			{
				free(pConfig->association.psk);
				pConfig->association.psk = NULL;
			}

			pConfig->association.psk = _strdup(m_password.toAscii());
			m_supplicant.setConfigConnection(pConfig);
			m_supplicant.writeConfig();
			m_supplicant.freeConfigConnection(&pConfig);
			return true;
		}
	}

	return false;
}


//! slotHelp()
/*!
   \brief Opens the help file
   \return nothing
   \note (none)
*/
void LoginMainDlg::slotShowHelp()
{
	switch(m_pStack->currentIndex())
	{
	case StackedLoginConfig::LOGIN_GET_INFO:
		HelpWindow::showPage("xsupphelp.html", "xsuploginmain");
		break;

	case StackedLoginConfig::LOGIN_STATUS:
		HelpWindow::showPage("xsupphelp.html", "xsuploginmain");
		break;

	default:
		HelpWindow::showPage("xsupphelp.html", "xsupusing");
		break;
	}
}

void LoginMainDlg::slotNewScanData(const QString &intName)
{
	ssid_info_enum *pSSIDs = NULL;
	QString description;
	int i = 0;
	int x = 0;

	if (m_pConns == NULL) return; // If we don't have any connections, this isn't relevant. ;)

	if (m_supplicant.getDeviceDescription(intName, description, false) == true)
	{
		if (m_supplicant.getBroadcastSSIDs(description, &pSSIDs) == true)
		{
			while (m_pConns[i].name != NULL)
			{
				x = 0;

				if (m_pConns[i].ssid != NULL)
				{
					while ((pSSIDs[x].ssidname != NULL) && (strcmp(m_pConns[i].ssid, pSSIDs[x].ssidname) != 0))
					{
						x++;
					}

					if (pSSIDs[x].ssidname == NULL)
					{
						m_pConns[i].flags &= (~POSS_CONN_SSID_KNOWN);  // We no longer know the SSID for this connection.
					}
					else
					{
						m_pConns[i].flags |= (POSS_CONN_SSID_KNOWN);
					}
				}

				i++;
			}
		}

		m_supplicant.freeEnumSSID(&pSSIDs);

		m_pLoginStack->update(false);
	}
}

void LoginMainDlg::slotInterfaceInserted(char *intName)
{
	QString description;
	int i = 0;
	int state = 0;

	if (m_supplicant.getDeviceDescription(QString(intName), description) == true)
	{
		while (m_pConns[i].name != NULL)
		{
			if (QString(m_pConns[i].dev_desc) == description)
			{
				m_pConns[i].flags |= (POSS_CONN_INT_AVAIL);
				
				if (xsupgui_request_get_link_state_from_int(intName, &state) == REQUEST_SUCCESS)
				{
					if (state == 1)
					{
						m_pConns[i].flags |= (POSS_CONN_LINK_STATE);
					}
					else
					{
						m_pConns[i].flags &= (~POSS_CONN_LINK_STATE);
					}
				}
			}

			i++;
		}

		m_pLoginStack->update(false);

		if (m_pConns[m_pConnectionComboBox->currentIndex()].flags & POSS_CONN_INT_AVAIL)
		{
			// Enable the Connect/Disconnect button.
			m_pConnectDisconnectButton->setEnabled(true);

			// Set the interface name it uses.
			bool bDeviceNameFound = m_supplicant.getDeviceName(m_pConns[m_pConnectionComboBox->currentIndex()].dev_desc, m_deviceName, false);			
			if (bDeviceNameFound == false)
			{
				// Disable the connect button.  (We won't be able to connect anyway.)
				m_pConnectDisconnectButton->setEnabled(false);
			}
		}
		else
		{
			// Disable the Connect/Disconnect button.
			m_pConnectDisconnectButton->setEnabled(false);
		}
	}
}

void LoginMainDlg::slotInterfaceRemoved(char *intName)
{
	int i = 0;

	// For interface removal events, we will get the description here, instead of the OS specific interface name.
	while (m_pConns[i].name != NULL)
	{
		if (QString(m_pConns[i].dev_desc) == intName)
		{
			m_pConns[i].flags &= (~POSS_CONN_INT_AVAIL);
		}

		i++;
	}

	m_pLoginStack->update(false);

	m_currentConnection = "";   // Force it to refresh.
	slotConnectionChangedEvent(m_pConnectionComboBox->currentIndex());
}

void LoginMainDlg::slotLinkUp(char *intName)
{
	int i = 0;

	// For interface removal events, we will get the description here, instead of the OS specific interface name.
	while (m_pConns[i].name != NULL)
	{
		if (QString(m_pConns[i].dev_desc) == intName)
		{
			m_pConns[i].flags |= POSS_CONN_LINK_STATE;
		}

		i++;
	}

	m_pLoginStack->update(false);

	m_currentConnection = "";   // Force it to refresh.
	slotConnectionChangedEvent(m_pConnectionComboBox->currentIndex());
}

void LoginMainDlg::slotLinkDown(char *intName)
{
	int i = 0;

	// For interface removal events, we will get the description here, instead of the OS specific interface name.
	while (m_pConns[i].name != NULL)
	{
		if (QString(m_pConns[i].dev_desc) == intName)
		{
			m_pConns[i].flags &= (~POSS_CONN_LINK_STATE);
		}

		i++;
	}

	m_pLoginStack->update(false);

	m_currentConnection = "";   // Force it to refresh.
	slotConnectionChangedEvent(m_pConnectionComboBox->currentIndex());
}

void LoginMainDlg::slotBadPSK(const QString &intName)
{
	// See if it is on an interface we are displaying information for.  If it is do the following :
	//   1. Disconnect so that we don't beat the crap out of the AP trying to connect again.
	//   2. Display a message to the user indicating that they have an invalid PSK.
	//   3. Switch back to the login data gathering window so they can try again.
	if (m_deviceName == intName)
	{
		networkDisconnect();
		QMessageBox::critical(this, tr("Invalid PSK"), tr("The WPA or WPA2 preshared key is invalid.  Please correct this, and try again."));

		m_pConnectDisconnectButton->setText(tr("Connect"));
		setButtons(true);

		// switch to status screen
		m_pLoginStack->setCurrent(StackedLoginConfig::LOGIN_GET_INFO, 
			false,
			m_currentConnection, 
			m_deviceDescription, 
			m_deviceName,
			m_bWireless, 
			&m_pConns[m_connsIndex]);
	}
}

void LoginMainDlg::slotAuthTimeout(const QString &intName)
{
	if (intName == m_deviceName)
	{
		networkDisconnect();

		m_pEmitter->sendClearLoginPopups();

		m_pConnectDisconnectButton->setText(tr("Connect"));
		setButtons(true);

		// switch to status screen
		m_pLoginStack->setCurrent(StackedLoginConfig::LOGIN_GET_INFO, 
			false,
			m_currentConnection, 
			m_deviceDescription, 
			m_deviceName,
			m_bWireless, 
			&m_pConns[m_connsIndex]);
	}
}

void LoginMainDlg::slotStateChange(const QString &intname, int sm, int oldstate, int newstate, unsigned int tncconnectionid)
{
	if (intname == m_deviceName)
	{
		if (sm == IPC_STATEMACHINE_8021X)
		{
			if (newstate == AUTHENTICATED)
			{
		        m_pConnectDisconnectButton->setText(tr("Disconnect"));
		        setButtons(false); // don't show the window

				if (m_pLoginStack->getCurrent() != StackedLoginConfig::LOGIN_STATUS)
				{
					// switch to status screen
					m_pLoginStack->setCurrent(StackedLoginConfig::LOGIN_STATUS, 
						false,
						m_currentConnection, 
						m_deviceDescription, 
						m_deviceName,
						m_bWireless, 
						&m_pConns[m_connsIndex]);
				}
			}
		}
	}
}

