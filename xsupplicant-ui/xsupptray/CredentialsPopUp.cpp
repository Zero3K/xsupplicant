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

#include "FormLoader.h"
#include "CredentialsPopUp.h"
#include "xsupcalls.h"
#include "Util.h"
#include "XSupWrapper.h"
#include "Emitter.h"
#include "CredentialsManager.h"

extern "C"
{
#include "libxsupgui/xsupgui_request.h"
}


// initialize static member variable
CredentialsManager *CredentialsPopUp::m_pCredManager = NULL;

//! Constructor
/*!
  \brief Sets up the fields   

  \note  We don't build the proxied form here, because we need to be able to
         return a failure status if the form can't be loaded from the disk.

  \param[in] parent
  \return nothing
*/
CredentialsPopUp::CredentialsPopUp(QString connName, QWidget *parent, Emitter *e)
     : QWidget(parent),
     m_connName(connName), m_supplicant(this),
     m_pEmitter(e)
{
	m_pRealForm        = NULL;
	m_pDialog          = NULL;
	m_pDialogMsg		= NULL;
	m_pButtonBox		= NULL;
	m_pUsername			= NULL;
	m_pPassword			= NULL;
	p_user				= NULL;
	p_pass				= NULL;
	m_pWEPCombo			= NULL;
	m_pRememberCreds	= NULL;
	conn_type			= 0;

	if (m_pCredManager == NULL)
		m_pCredManager = new CredentialsManager(e);
}


//! Destructor
/*!
  \brief Clears out whatever needs to be cleared out
  \return nothing
*/
CredentialsPopUp::~CredentialsPopUp()
{
	if (p_user != NULL) free(p_user);
	if (p_pass != NULL) free(p_pass);

	if (m_pButtonBox != NULL)
	{
		Util::myDisconnect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(slotOkayBtn()));
		Util::myDisconnect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));
	}

	if (m_pWEPCombo != NULL)
		Util::myDisconnect(m_pWEPCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotWEPComboChange(int)));
		
	if (m_pRealForm != NULL) 
	{
		Util::myDisconnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));
		delete m_pRealForm;
	}
}

bool CredentialsPopUp::create()
{
	int authtype = 0;

	if (xsupgui_request_get_connection_upw(m_connName.toAscii().data(), &p_user, &p_pass, &authtype) != XENONE)
	{
		QMessageBox::critical(this, tr("Credentials Error"), tr("Unable to determine the type of network that needs credentials."));
		return false;
	}

	// Depending on the type of network in use, display the proper dialog.
	if (authtype == AUTH_PSK)
	{
		m_doingPsk = true;
		m_doingWEP = false;
		return createPSK();
	}
	else if (authtype == AUTH_EAP)
	{
		m_doingPsk = false;
		m_doingWEP = false;

		if (isPINType())
		{
			return createPIN();
		}
		else
		{
			return createUPW();
		}
	}
	else if (authtype == AUTH_NONE)
	{
		// WEP
		m_doingPsk = false;
		m_doingWEP = true;
		return createWEP();
	}
	return false;
}

/**
 * \brief Create the dialog to prompt for a PIN code.
 **/
bool CredentialsPopUp::createPIN()
{
	m_pRealForm = FormLoader::buildform("PINWindow.ui");

	if (m_pRealForm == NULL) return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pUsername = NULL;

	m_pPassword = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldPassword");

	if (m_pPassword == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'dataFieldPassword' label."));
		return false;
	}

	m_pButtonBox = qFindChild<QDialogButtonBox*>(m_pRealForm, "buttonBox");

	if (m_pButtonBox == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'buttonBox' DialogButtonBox"));
		return false;
	}
	else
	{
		Util::myConnect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(slotOkayBtn()));
		Util::myConnect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));
	}

	m_pDialogMsg = qFindChild<QLabel*>(m_pRealForm, "labelDialogMsg");

	if (m_pDialogMsg != NULL)
	{
		QString networkName="";
		
		// if we have the name of the connection, try to retrieve the SSID of the network
		// so that we can correctly prompt the user
		if (m_connName.isEmpty() == false)
		{
			config_connection *pConnection = NULL;
			conn_type = CONFIG_LOAD_USER;
			if (m_supplicant.getConfigConnection(conn_type, m_connName, &pConnection, false) == true)
			{
				if (pConnection != NULL && pConnection->ssid != NULL)
					networkName = pConnection->ssid;
				if (pConnection != NULL)
					m_supplicant.freeConfigConnection(&pConnection);
			}
			else
			{
				conn_type = CONFIG_LOAD_GLOBAL;
				if (m_supplicant.getConfigConnection(conn_type, m_connName, &pConnection, false) == true)
				{
					if (pConnection != NULL && pConnection->ssid != NULL)
						networkName = pConnection->ssid;
					if (pConnection != NULL)
						m_supplicant.freeConfigConnection(&pConnection);
				}
			}
		}

		// if we were able to get a meaningful SSID, use it in the prompt. Otherwise use a generic
		// prompt message
		QString dlgMsg;
		if (networkName.isEmpty() == false)
		{
			dlgMsg.append(tr("The network \""));
			dlgMsg.append(networkName);
			dlgMsg.append(tr("\" requires a (U)SIM PIN to connect"));
		}
		else
		{
			dlgMsg.append(tr("The network you are trying to connect to requires a (U)SIM PIN to connect"));
		}
		m_pDialogMsg->setText(dlgMsg);
	}

	setupWindow();

	// Then, populate some data.
	updateData();

	return true;
}

/**
 * \brief Determine if the EAP method used in this connection uses a PIN.
 *
 * \return true if this EAP method uses a PIN
 * \return false if it doesn't.
 **/
bool CredentialsPopUp::isPINType()
{
	config_connection *conn_config = NULL;
	config_profiles *prof_config = NULL;
	bool result = false;
	int resval = 0;
	
	if (conn_type == 0)
	{
		conn_type = CONFIG_LOAD_USER;
		resval = xsupgui_request_get_connection_config(conn_type, m_connName.toAscii().data(), &conn_config);
		if (resval != REQUEST_SUCCESS)
		{
			conn_type = CONFIG_LOAD_GLOBAL;
			resval = xsupgui_request_get_connection_config(conn_type, m_connName.toAscii().data(), &conn_config);
			if (resval != REQUEST_SUCCESS)
			{
				conn_type = 0;
			}
		}
	}
	else
	{
		resval = xsupgui_request_get_connection_config(conn_type, m_connName.toAscii().data(), &conn_config);
	}
	
	if (resval == REQUEST_SUCCESS)
	{
		resval = xsupgui_request_get_profile_config(CONFIG_LOAD_USER, conn_config->profile, &prof_config);
		if (resval != REQUEST_SUCCESS)
		{
			resval = xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, conn_config->profile, &prof_config);
		}

		if (resval == REQUEST_SUCCESS)
		{
			if ((prof_config->method != NULL) && 
				((prof_config->method->method_num == EAP_TYPE_SIM) || 
				(prof_config->method->method_num == EAP_TYPE_AKA)))
			{
				result = true;
			}

			xsupgui_request_free_profile_config(&prof_config);
		}

		xsupgui_request_free_connection_config(&conn_config);
	}

	return result;
}

bool CredentialsPopUp::createWEP()
{
	m_pRealForm = FormLoader::buildform("WEPWindow.ui");

	if (m_pRealForm == NULL) 
		return false;
	
	// cache off pointers to UI objects
	m_pDialogMsg = qFindChild<QLabel*>(m_pRealForm, "labelDialogMsg");
	m_pWEPCombo = qFindChild<QComboBox*>(m_pRealForm, "comboBoxKeyType");
	m_pPassword = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldPassword");
	if (m_pPassword == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'upwPassword' label."));
		return false;
	}	

	m_pRememberCreds = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxRemember");
	if (m_pRememberCreds == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'rememberCredentials' checkbox."));
		return false;
	}	

	m_pButtonBox = qFindChild<QDialogButtonBox*>(m_pRealForm, "buttonBox");

	if (m_pButtonBox == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'buttonBox' DialogButtonBox"));
		return false;
	}		
	
	// dynamically populate text
	QLabel *pLabel = qFindChild<QLabel*>(m_pRealForm, "labelKeyType");
	if (pLabel != NULL)
		pLabel->setText(tr("Password Type:"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelPassword");
	if (pLabel != NULL)
		pLabel->setText(tr("Password:"));
		
	if (m_pRememberCreds != NULL)
		m_pRememberCreds->setText(tr("Remember Password"));
		
	if (m_pWEPCombo != NULL)
	{
		m_pWEPCombo->clear();
		m_pWEPCombo->addItem(tr("40-bit HEX"));
		m_pWEPCombo->addItem(tr("104-bit HEX"));
	}

	if (m_pDialogMsg != NULL)
	{
		QString networkName="";
		
		// if we have the name of the connection, try to retrieve the SSID of the network
		// so that we can correctly prompt the user
		if (m_connName.isEmpty() == false)
		{
			config_connection *pConnection = NULL;
			conn_type = CONFIG_LOAD_USER;
			if (m_supplicant.getConfigConnection(conn_type, m_connName, &pConnection, false) == true)
			{
				if (pConnection != NULL && pConnection->ssid != NULL)
					networkName = pConnection->ssid;
				if (pConnection != NULL)
					m_supplicant.freeConfigConnection(&pConnection);
			}
			else
			{
				conn_type = CONFIG_LOAD_GLOBAL;
				if (m_supplicant.getConfigConnection(conn_type, m_connName, &pConnection, false) == true)
				{
					if (pConnection != NULL && pConnection->ssid != NULL)
						networkName = pConnection->ssid;
					if (pConnection != NULL)
						m_supplicant.freeConfigConnection(&pConnection);
				}
			}
		}

		// if we were able to get a meaningful SSID, use it in the prompt. Otherwise use a generic
		// prompt message
		QString dlgMsg;
		if (networkName.isEmpty() == false)
		{
			dlgMsg.append(tr("The network \""));
			dlgMsg.append(networkName);
			dlgMsg.append(tr("\" requires a WEP password to connect"));
		}
		else
		{
			dlgMsg.append(tr("The network you are trying to connect to requires a WEP password"));
		}
		m_pDialogMsg->setText(dlgMsg);
	}	
		
	// set up event handling	
		
	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));
	
	if (m_pButtonBox != NULL)
	{
		Util::myConnect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(slotOkayBtn()));
		Util::myConnect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));	
	}
	
	if (m_pWEPCombo != NULL) {
		Util::myConnect(m_pWEPCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotWEPComboChange(int)));
		m_pWEPCombo->setCurrentIndex(0);
		this->slotWEPComboChange(0);
	}
	
	setupWindow();
	
	return true;	
}

bool CredentialsPopUp::createUPW()
{
	m_pRealForm = FormLoader::buildform("UPWWindow.ui");

	if (m_pRealForm == NULL) return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pUsername = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldUserName");

	if (m_pUsername == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'upwUsername' label."));
		return false;
	}

	m_pPassword = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldPassword");

	if (m_pPassword == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'upwPassword' label."));
		return false;
	}
	
	m_pRememberCreds = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxRemember");
	if (m_pRememberCreds == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'rememberCredentials' checkbox."));
		return false;
	}	

	m_pButtonBox = qFindChild<QDialogButtonBox*>(m_pRealForm, "buttonBox");

	if (m_pButtonBox == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'buttonBox' DialogButtonBox"));
		return false;
	}
	else
	{
		Util::myConnect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(slotOkayBtn()));
		Util::myConnect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));
	}

	m_pDialogMsg = qFindChild<QLabel*>(m_pRealForm, "labelDialogMsg");

	if (m_pDialogMsg != NULL)
	{
		QString networkName="";
		
		// if we have the name of the connection, try to retrieve the SSID of the network
		// so that we can correctly prompt the user
		if (m_connName.isEmpty() == false)
		{
			config_connection *pConnection = NULL;
			conn_type = CONFIG_LOAD_USER;
			if (m_supplicant.getConfigConnection(conn_type, m_connName, &pConnection, false) == true)
			{
				if (pConnection != NULL && pConnection->ssid != NULL)
					networkName = pConnection->ssid;
				if (pConnection != NULL)
					m_supplicant.freeConfigConnection(&pConnection);
			}
			else
			{
				conn_type = CONFIG_LOAD_GLOBAL;
				if (m_supplicant.getConfigConnection(conn_type, m_connName, &pConnection, false) == true)
				{
					if (pConnection != NULL && pConnection->ssid != NULL)
						networkName = pConnection->ssid;
					if (pConnection != NULL)
						m_supplicant.freeConfigConnection(&pConnection);
				}
			}
		}

		// if we were able to get a meaningful SSID, use it in the prompt. Otherwise use a generic
		// prompt message
		QString dlgMsg;
		if (networkName.isEmpty() == false)
		{
			dlgMsg.append(tr("The 802.1X network \""));
			dlgMsg.append(networkName);
			dlgMsg.append(tr("\" requires a username and password to connect"));
		}
		else
		{
			dlgMsg.append(tr("The network you are attempting to connect to requires a username and password"));
		}
		m_pDialogMsg->setText(dlgMsg);
	}

	setupWindow();

	// Then, populate some data.
	updateData();

	return true;
}

bool CredentialsPopUp::createPSK()
{
	m_pRealForm = FormLoader::buildform("PSKWindow.ui");

	if (m_pRealForm == NULL) return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pUsername = NULL;

	m_pPassword = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldPassword");

	if (m_pPassword == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'dataFieldPassword' label."));
		return false;
	}

	m_pRememberCreds = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxRemember");
	
	if (m_pRememberCreds == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'rememberCredentials' checkbox."));
		return false;
	}	

	m_pButtonBox = qFindChild<QDialogButtonBox*>(m_pRealForm, "buttonBox");

	if (m_pButtonBox == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'buttonBox' DialogButtonBox"));
		return false;
	}
	else
	{
		Util::myConnect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(slotOkayBtn()));
		Util::myConnect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(slotDisconnectBtn()));
	}

	m_pDialogMsg = qFindChild<QLabel*>(m_pRealForm, "labelDialogMsg");

	if (m_pDialogMsg != NULL)
	{
		QString networkName="";
		
		// if we have the name of the connection, try to retrieve the SSID of the network
		// so that we can correctly prompt the user
		if (m_connName.isEmpty() == false)
		{
			config_connection *pConnection = NULL;
			conn_type = CONFIG_LOAD_USER;
			if (m_supplicant.getConfigConnection(conn_type, m_connName, &pConnection, false) == true)
			{
				if (pConnection != NULL && pConnection->ssid != NULL)
					networkName = pConnection->ssid;
				if (pConnection != NULL)
					m_supplicant.freeConfigConnection(&pConnection);
			}
			else
			{
				conn_type = CONFIG_LOAD_GLOBAL;
				if (m_supplicant.getConfigConnection(conn_type, m_connName, &pConnection, false) == true)
				{
					if (pConnection != NULL && pConnection->ssid != NULL)
						networkName = pConnection->ssid;
					if (pConnection != NULL)
						m_supplicant.freeConfigConnection(&pConnection);
				}
			}
		}

		// if we were able to get a meaningful SSID, use it in the prompt. Otherwise use a generic
		// prompt message
		QString dlgMsg;
		if (networkName.isEmpty() == false)
		{
			dlgMsg.append(tr("The network \""));
			dlgMsg.append(networkName);
			dlgMsg.append(tr("\" requires a WPA password to connect"));
		}
		else
		{
			dlgMsg.append(tr("The network you are trying to connect to requires a WPA password"));
		}
		m_pDialogMsg->setText(dlgMsg);
	}

	setupWindow();

	// Then, populate some data.
	updateData();

	return true;
}

void CredentialsPopUp::slotDisconnectBtn()
{
	config_connection *pConfig = NULL;
	char *pdevName = NULL;
	QString desc, dev;
	bool result = false;

	result = m_supplicant.getConfigConnection(CONFIG_LOAD_USER, m_connName, &pConfig, false);
	if (result == false) m_supplicant.getConfigConnection(CONFIG_LOAD_GLOBAL, m_connName, &pConfig, false);

	if (result == false)
	{
		QMessageBox::critical(this, tr("Error Disconnecting"), tr("There was an error getting the supplicant to disconnect the interface."));
	}
	else
	{
		if (xsupgui_request_get_devname(pConfig->device, &pdevName) != XENONE)
		{
			QMessageBox::critical(this, tr("Error Disconnecting"), tr("Unable to locate information for the connection '%1'.").arg(m_connName));
		}
		else
		{
			desc = pConfig->device;
			dev = pdevName;
			m_supplicant.networkDisconnect(dev, desc, true);
			free(pdevName);
		}

		m_supplicant.freeConfigConnection(&pConfig);
	}

	emit close();
}

void CredentialsPopUp::slotOkayBtn()
{
	config_connection *cconf = NULL;
	char *intName = NULL;
	int result = 0;

	if (m_doingWEP == true)
	{
		// check if valid key is input
		if (!m_pPassword->hasAcceptableInput())
		{
			int numDigits = 0;
			if (m_pWEPCombo->currentIndex() == 0)
				numDigits = 10;
			else if (m_pWEPCombo->currentIndex() == 1)
				numDigits = 26;
				
			QString message = tr("Please input a WEP password containing %1 hexadecimal (0-9, A-F) digits").arg(numDigits);
			QMessageBox::warning(m_pRealForm, tr("Invalid WEP Password"),message);

			return;
		}
		else
		{
			// Set our WEP password.		
			if (xsupgui_request_set_connection_pw(m_connName.toAscii().data(), m_pPassword->text().toAscii().data()) != XENONE)
			{
				QMessageBox::critical(this, tr("Error"), tr("Unable to set your WEP password."));
			}
			else
			{
				if (conn_type == 0)
				{
					conn_type = CONFIG_LOAD_USER;
					result = xsupgui_request_get_connection_config(CONFIG_LOAD_USER, m_connName.toAscii().data(), &cconf);
					if (result != REQUEST_SUCCESS) 
					{
						conn_type = CONFIG_LOAD_GLOBAL;
						result = xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, m_connName.toAscii().data(), &cconf);
						if (result != REQUEST_SUCCESS) conn_type = 0;
					}
				}
				else
				{
					result = xsupgui_request_get_connection_config(conn_type, m_connName.toAscii().data(), &cconf);
				}

				if (result != REQUEST_SUCCESS)
				{
					QMessageBox::critical(this, tr("Error"), tr("Couldn't determine which interface the desired connection is bound to!"));
				}
				else
				{		
					if (xsupgui_request_get_devname(cconf->device, &intName) != REQUEST_SUCCESS)
					{
						QMessageBox::critical(this, tr("Error"), tr("Couldn't determine the interface the desired connection is bound to!"));
					}
					else
					{
						if (xsupgui_request_set_connection(intName, m_connName.toAscii().data()) != REQUEST_SUCCESS)
						{
							QMessageBox::critical(this, tr("Error"), tr("Couldn't set connection!\n"));
						}
						else
						{
							// if "remember credentials" is checked, make sure this isn't marked as volatile
							if (m_pRememberCreds->checkState() == Qt::Checked)
							{
								// if "remember credentials" is checked, pass credentials to Credentials Manager to store off
								// if we connect successfully
								if (m_pCredManager != NULL)
									m_pCredManager->storeCredentials(conn_type, m_connName, QString(), m_pPassword->text());							
							}						
						}
						free(intName);
					}

					xsupgui_request_free_connection_config(&cconf);
				}
			}		
		}
	}
	
	else if (m_doingPsk)
	{
		if (m_pPassword->text() == "")
		{
			QMessageBox::information(this, tr("Invalid Credentials"), tr("Please enter a valid PSK before attempting to connect to this network."));
			return;
		}

		// Set our PSK.		
		if (xsupgui_request_set_connection_pw(m_connName.toAscii().data(), m_pPassword->text().toAscii().data()) != XENONE)
		{
			QMessageBox::critical(this, tr("Error"), tr("Unable to set your PSK password."));
		}
		else
		{
			if (conn_type == 0)
			{
				conn_type = CONFIG_LOAD_USER;
				result = xsupgui_request_get_connection_config(CONFIG_LOAD_USER, m_connName.toAscii().data(), &cconf);
				if (result != REQUEST_SUCCESS) 
				{
					conn_type = CONFIG_LOAD_GLOBAL;
					result = xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, m_connName.toAscii().data(), &cconf);
					if (result != REQUEST_SUCCESS) conn_type = 0;
				}
			}
			else
			{
				result = xsupgui_request_get_connection_config(conn_type, m_connName.toAscii().data(), &cconf);
			}

			if (result != REQUEST_SUCCESS)
			{
				QMessageBox::critical(this, tr("Error"), tr("Couldn't determine which interface the desired connection is bound to!"));
			}
			else
			{		
				if (xsupgui_request_get_devname(cconf->device, &intName) != REQUEST_SUCCESS)
				{
					QMessageBox::critical(this, tr("Error"), tr("Couldn't determine the interface the desired connection is bound to!"));
				}
				else
				{
					if ((result = xsupgui_request_set_connection(intName, m_connName.toAscii().data())) != REQUEST_SUCCESS)
					{
						switch (result)
						{
						case IPC_ERROR_INTERFACE_NOT_FOUND:
							QMessageBox::critical(this, tr("Connection Error"), tr("The requested interface is no longer available."));
							break;

						case IPC_ERROR_INVALID_CONN_NAME:
							QMessageBox::critical(this, tr("Connection Error"), tr("The connection name requested is invalid."));
							break;

						case IPC_ERROR_SSID_NOT_FOUND:
							QMessageBox::critical(this, tr("Connection Error"), tr("The requested wireless network was not found."));
							break;

						case IPC_ERROR_INVALID_PROF_NAME:
							QMessageBox::critical(this, tr("Connection Error"), tr("The connection you are attempting to connect to is missing a profile."));
							break;

						case IPC_ERROR_INVALID_CONTEXT:
							QMessageBox::critical(this, tr("Connection Error"), tr("The context for this connection is missing or corrupt."));
							break;

						default:
							QMessageBox::critical(this, tr("Connection Error"), tr("Unable to establish a wireless connection.  Error : %1").arg(result));
							break;
						}
					}
					else
					{
						if (m_pRememberCreds->checkState() == Qt::Checked)
						{
							// if "remember credentials" is checked, pass credentials to Credentials Manager to store off
							// if we connect successfully
							if (m_pCredManager != NULL)
								m_pCredManager->storeCredentials(conn_type, m_connName, QString(), m_pPassword->text());
						}					
					}
					free(intName);
				}

				xsupgui_request_free_connection_config(&cconf);
			}
		}
	}
	else
	{
		if (m_pUsername != NULL) 
		{
			if (m_pUsername->text() == "")
			{
				if (m_pPassword->text() == "")
				{
					QMessageBox::information(this, tr("Invalid Credentials"), tr("Please enter a user name and password before attempting to connect to this network."));
					return;
				}
				else
				{
					QMessageBox::information(this, tr("Invalid Credentials"), tr("Please enter a user name before attempting to connect to this network."));
					return;
				}
			}

			if (m_pPassword->text() == "")
			{
				QMessageBox::information(this, tr("Invalid Credentials"), tr("Please enter a password before attempting to connect to this network."));
				return;
			}
		}
		else
		{
			// It is acceptible to have no PIN needed on a (U)SIM.
			if (isPINType() == false)
			{
				QMessageBox::information(this, tr("Invalid Credentials"), tr("Please enter a valid password before attempting to connect to this network."));
				return;
			}
		}

		if (isPINType() == true)
		{
			result = xsupgui_request_set_connection_upw(m_connName.toAscii().data(), NULL, m_pPassword->text().toAscii().data());
		}
		else
		{
			result = xsupgui_request_set_connection_upw(m_connName.toAscii().data(), m_pUsername->text().toAscii().data(), m_pPassword->text().toAscii().data());
		}

		// Set our username/password.
		if (result != XENONE)
		{
			if (isPINType() == true)
			{
				QMessageBox::critical(this, tr("Error"), tr("Unable to set your PIN."));
			}
			else
			{
				QMessageBox::critical(this, tr("Error"), tr("Unable to set your username and password."));
			}
		}
		else
		{
			if (conn_type == 0)
			{
				conn_type = CONFIG_LOAD_USER;
				result = xsupgui_request_get_connection_config(CONFIG_LOAD_USER, m_connName.toAscii().data(), &cconf);
				if (result != REQUEST_SUCCESS) 
				{
					conn_type = CONFIG_LOAD_GLOBAL;
					result = xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, m_connName.toAscii().data(), &cconf);
					if (result != REQUEST_SUCCESS) conn_type = 0;
				}
			}
			else
			{
				result = xsupgui_request_get_connection_config(conn_type, m_connName.toAscii().data(), &cconf);
			}

			if (result != REQUEST_SUCCESS)
			{
				QMessageBox::critical(this, tr("Error"), tr("Couldn't determine which interface the desired connection is bound to!"));
			}
			else
			{									
				if (xsupgui_request_get_devname(cconf->device, &intName) != REQUEST_SUCCESS)
				{
					QMessageBox::critical(this, tr("Error"), tr("Couldn't determine the interface the desired connection is bound to!"));
				}
				else
				{
					if (xsupgui_request_set_connection(intName, m_connName.toAscii().data()) != REQUEST_SUCCESS)
					{
						QMessageBox::critical(this, tr("Error"), tr("Couldn't set connection!\n"));
					}
					else
					{
						// if "remember credentials" is checked, make sure this isn't marked as volatile
						if ((m_pRememberCreds != NULL) && (m_pRememberCreds->checkState() == Qt::Checked))
						{
							// if "remember credentials" is checked, pass credentials to Credentials Manager to store off
							// if we connect successfully
							if (m_pCredManager != NULL)
								m_pCredManager->storeCredentials(conn_type, m_connName, m_pUsername->text(), m_pPassword->text());						
						}					
					}
					free(intName);
				}

				xsupgui_request_free_connection_config(&cconf);
			}
		}
	}

	emit close();
}

void CredentialsPopUp::show()
{
	// This will cause the window to come to the front if it is already built.
	if (m_pRealForm->isVisible() == true) m_pRealForm->hide();

	m_pRealForm->show();
}

void CredentialsPopUp::setupWindow()
{
	Qt::WindowFlags flags;

	flags = m_pRealForm->windowFlags();
	flags &= (~Qt::WindowContextHelpButtonHint);
	m_pRealForm->setWindowFlags(flags);
}

/**
 * \brief Grab the connection data, and show the username field if it is populated.
 **/
void CredentialsPopUp::updateData()
{
	QString temp;

	if (p_user != NULL)
	{
		if (m_pUsername != NULL)
		{
			temp = p_user;
			m_pUsername->setText(temp);
		}
	}

	if (p_pass != NULL)  // Which it always should!
	{
		if (m_pPassword != NULL)
		{
			temp = p_pass;
			m_pPassword->setText(temp);
		}
	}
}

void CredentialsPopUp::slotWEPComboChange(int newVal)
{
	QLabel *pLabel = qFindChild<QLabel*>(m_pRealForm, "labelPasswordSize");
	if (newVal == 0)
	{
		// WEP 40
		 m_pPassword->setValidator(new QRegExpValidator(QRegExp("^[A-Fa-f0-9]{10}$"), m_pPassword));
		 if (pLabel != NULL)
			pLabel->setText(tr("(10 digits)"));
	}
	else if (newVal == 1)
	{
		// WEP 104
		m_pPassword->setValidator(new QRegExpValidator(QRegExp("^[A-Fa-f0-9]{26}$"), m_pPassword));
		 if (pLabel != NULL)
			pLabel->setText(tr("(26 digits)"));		
	}
}

