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

//! Constructor
/*!
  \brief Sets up the fields   

  \note  We don't build the proxied form here, because we need to be able to
         return a failure status if the form can't be loaded from the disk.

  \param[in] parent
  \return nothing
*/
CredentialsPopUp::CredentialsPopUp(QString connName, QWidget *parent)
     : QWidget(parent),
     m_connName(connName), m_supplicant(this)
{
	m_pRealForm        = NULL;
	m_pDialog          = NULL;
	m_pDisconnectBtn	= NULL;
	m_pOkayBtn			= NULL;
	m_pUsername			= NULL;
	m_pPassword			= NULL;
	p_user				= NULL;
	p_pass				= NULL;
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

	if (m_pOkayBtn != NULL)
	{
		QObject::disconnect(m_pOkayBtn, SIGNAL(clicked()), this, SLOT(slotOkayBtn()));
	}

	if (m_pDisconnectBtn != NULL)
	{
	    QObject::disconnect(m_pDisconnectBtn, SIGNAL(clicked()), this, SLOT(slotDisconnectBtn()));
	}

	if (m_pRealForm != NULL) 
	{
		Util::myDisconnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));
		delete m_pRealForm;
	}
}

bool CredentialsPopUp::create()
{
	QString temp;
	char *ptemp = NULL;
	int authtype = 0;

	ptemp = _strdup(m_connName.toAscii());
	if (xsupgui_request_get_connection_upw(ptemp, &p_user, &p_pass, &authtype) != XENONE)
	{
		QMessageBox::critical(this, tr("Credentials Error"), tr("Unable to determine the type of network that needs credentials."));
		return false;
	}

	// Depending on the type of network in use, display the proper dialog.
	if (authtype == AUTH_PSK)
	{
		m_doingPsk = true;
		return createPSK();
	}
	else
	{
		m_doingPsk = false;
		return createUPW();
	}
}

bool CredentialsPopUp::createUPW()
{
	m_pRealForm = FormLoader::buildform("UPWWindow.ui");

	if (m_pRealForm == NULL) return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pUsername = qFindChild<QLineEdit*>(m_pRealForm, "upwUsername");

	if (m_pUsername == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'upwUsername' label."));
		return false;
	}

	m_pPassword = qFindChild<QLineEdit*>(m_pRealForm, "upwPassword");

	if (m_pPassword == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'upwPassword' label."));
		return false;
	}

	m_pOkayBtn = qFindChild<QPushButton*>(m_pRealForm, "upwOkayBtn");

	if (m_pOkayBtn == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'upwOkayBtn' label."));
		return false;
	}
	else
	{
		QObject::connect(m_pOkayBtn, SIGNAL(clicked()), this, SLOT(slotOkayBtn()));
	}

	m_pConnName = qFindChild<QLabel*>(m_pRealForm, "upwConnName");

	if (m_pConnName != NULL)
	{
		m_pConnName->setText(m_connName);
	}

	m_pDisconnectBtn = qFindChild<QPushButton*>(m_pRealForm, "upwDisconnectBtn");

	// If m_pbuttonClose is NULL, then there isn't a close button.  We don't consider that to be a problem, so don't complain.
	if (m_pDisconnectBtn != NULL)
	{
	    QObject::connect(m_pDisconnectBtn, SIGNAL(clicked()), this, SLOT(slotDisconnectBtn()));
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
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pUsername = NULL;

	m_pPassword = qFindChild<QLineEdit*>(m_pRealForm, "pskEdit");

	if (m_pPassword == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'pskEdit' label."));
		return false;
	}

	m_pOkayBtn = qFindChild<QPushButton*>(m_pRealForm, "OkayBtn");

	if (m_pOkayBtn == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Credentials Popup' did not contain the 'OkayBtn' label."));
		return false;
	}
	else
	{
		QObject::connect(m_pOkayBtn, SIGNAL(clicked()), this, SLOT(slotOkayBtn()));
	}

	m_pConnName = qFindChild<QLabel*>(m_pRealForm, "pskConnName");

	if (m_pConnName != NULL)
	{
		m_pConnName->setText(m_connName);
	}

	m_pDisconnectBtn = qFindChild<QPushButton*>(m_pRealForm, "disconnectBtn");

	// If m_pDisconnectBtn is NULL, then there isn't a close button.  We don't consider that to be a problem, so don't complain.
	if (m_pDisconnectBtn != NULL)
	{
	    QObject::connect(m_pDisconnectBtn, SIGNAL(clicked()), this, SLOT(slotDisconnectBtn()));
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

	if (m_supplicant.getConfigConnection(m_connName, &pConfig, false) == false)
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
	char *temp = NULL;
	char *pwd = NULL;
	char *user = NULL;
	config_connection *cconf = NULL;
	char *intName = NULL;

	if (m_doingPsk)
	{
		// Set our PSK.
		temp = _strdup(m_connName.toAscii());
		pwd = _strdup(m_pPassword->text().toAscii());
		if (xsupgui_request_set_connection_pw(temp, pwd) != XENONE)
		{
			QMessageBox::critical(this, tr("Error"), tr("Unable to set your preshared key."));
		}
		else
		{
			if (xsupgui_request_get_connection_config(temp, &cconf) != REQUEST_SUCCESS)
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
					if (xsupgui_request_set_connection(intName, temp) != REQUEST_SUCCESS)
					{
						QMessageBox::critical(this, tr("Error"), tr("Couldn't set connection!\n"));
					}
					free(intName);
				}

				xsupgui_request_free_connection_config(&cconf);
			}
		}

		free(temp);
		free(pwd);
	}
	else
	{
		// Set our username/password.
		temp = _strdup(m_connName.toAscii());
		pwd = _strdup(m_pPassword->text().toAscii());
		user = _strdup(m_pUsername->text().toAscii());
		if (xsupgui_request_set_connection_upw(temp, user, pwd) != XENONE)
		{
			QMessageBox::critical(this, tr("Error"), tr("Unable to set your username and password."));
		}
		else
		{
			if (xsupgui_request_get_connection_config(temp, &cconf) != REQUEST_SUCCESS)
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
					if (xsupgui_request_set_connection(intName, temp) != REQUEST_SUCCESS)
					{
						QMessageBox::critical(this, tr("Error"), tr("Couldn't set connection!\n"));
					}
					free(intName);
				}

				xsupgui_request_free_connection_config(&cconf);
			}
		}

		free(temp);
		free(pwd);
		free(user);
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

	if (p_pass != NULL)  // Which is always should!
	{
		if (m_pPassword != NULL)
		{
			temp = p_pass;
			m_pPassword->setText(temp);
		}
	}
}

