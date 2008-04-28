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

#include "LoginGetInfo.h"
#include "xsupcalls.h"
#include "Util.h"

LoginGetInfo::LoginGetInfo(QString inDevName, poss_conn_enum *pConnEnum, QWidget *proxy, QWidget *parent, Emitter *e):
	m_pEmitter(e), m_pParent(parent), m_pStack(proxy), m_supplicant(NULL), pConn(pConnEnum)
{
	dataFrameProfilesUsername = NULL;
	dataFrameProfilesPassword = NULL;
	m_pSaveCreds = NULL;

	m_bSignalConnected = false;

	m_pAdapterInfo = qFindChild<QGroupBox*>(m_pStack, "dataFrameInterfaceStatus");

	m_pAdapterStat = qFindChild<QLabel*>(m_pStack, "dataFieldAdapterStatus");

	m_pSSIDStatLabel = qFindChild<QLabel*>(m_pStack, "labelSSIDStatus");

	m_pSSIDStat = qFindChild<QLabel*>(m_pStack, "dataFieldSSIDStatus");

	m_pWidgetStack = qFindChild<QStackedWidget*>(m_pStack, "widgetStackCredentials");
	if (m_pWidgetStack == NULL)
	{
		QMessageBox::critical(this, tr("Dialog Design Error"), tr("There is no 'widgetStackCredentials' found in the form.  You won't be able to enter a username and password!"));
	}

	updateWindow(true);
}

LoginGetInfo::~LoginGetInfo()
{
	if (m_bSignalConnected)
	{
		Util::myDisconnect(hideBtn, SIGNAL(clicked()), this, SLOT(slotUnhidePwd()));
	}
}

void LoginGetInfo::updateWindow(bool updateAll)
{
	QString username;
	QString password;
	int m_authType;
	QString temp;

	setAdapterInfo();

	temp = pConn->name;
    if (m_supplicant.getConnectionInformation(temp, m_authType, username, password, false))
    {
      switch (m_authType)
      {
        case AUTH_EAP:
			m_pWidgetStack->setCurrentIndex(LOGIN_CREDENTIALS_UPW_PAGE);
			if (updateAll) setEAPAuth(username, password, pConn->flags);
          break;

        case AUTH_PSK:
			m_pWidgetStack->setCurrentIndex(LOGIN_PSK_INFO_PAGE);
			if (updateAll) setPSKAuth(password);
          break;

        case AUTH_NONE:
			m_pWidgetStack->setCurrentIndex(LOGIN_NO_INFO_PAGE);
          break;

        default:
			// Do nothing.
         break;
      }
    }
}

void LoginGetInfo::setAdapterInfo()
{
	if (m_pAdapterInfo != NULL) m_pAdapterInfo->setTitle(Util::removePacketSchedulerFromName(pConn->dev_desc));

    if (pConn->flags & POSS_CONN_INT_AVAIL)
    {
		if (pConn->flags & POSS_CONN_IS_WIRELESS)
		{
			if (m_pAdapterStat != NULL) m_pAdapterStat->setText(tr("Available"));
		}
		else
		{
			if (pConn->flags & POSS_CONN_LINK_STATE)
			{
				if (m_pAdapterStat != NULL) m_pAdapterStat->setText(tr("Available"));
			}
			else
			{
				if (m_pAdapterStat != NULL) m_pAdapterStat->setText(tr("Available -- Cable unplugged"));
			}
		}
    }
    else if (pConn->flags & POSS_CONN_INT_UNKNOWN)
    {
      if (m_pAdapterStat != NULL) m_pAdapterStat->setText(tr("Invalid"));
    }
    else
    {
      if (m_pAdapterStat != NULL) m_pAdapterStat->setText(tr("Not Available"));
    }

    if ((pConn->flags & POSS_CONN_IS_WIRELESS) && (m_pSSIDStat != NULL))
    {
      if (pConn->flags & POSS_CONN_IS_HIDDEN)
      {
        m_pSSIDStat->setText(tr("%1 - Hidden").arg(pConn->ssid));
      }
      else if (pConn->flags & POSS_CONN_SSID_KNOWN)
      {
        m_pSSIDStat->setText(tr("%1 - Available").arg(pConn->ssid));
      }
      else
      {
        m_pSSIDStat->setText(tr("%1 - Unknown").arg(pConn->ssid));
      }
    }
    else
    {
      if (m_pSSIDStat != NULL) m_pSSIDStat->setText(tr("<Wired Connection>"));
      if (m_pSSIDStatLabel != NULL) m_pSSIDStatLabel->setText("");
    }
}

QString LoginGetInfo::get_password()
{
	if (dataFrameProfilesPassword == NULL)
	{
		return QString("");
	}
	else
	{
		return dataFrameProfilesPassword->text();
	}
}

QString LoginGetInfo::get_username()
{
	if (dataFrameProfilesUsername == NULL)
	{
		return QString("");
	}
	else
	{
		return dataFrameProfilesUsername->text();
	}
}

void LoginGetInfo::setEAPAuth(QString username, QString password, uint8_t flags)
{
	hideBtn = qFindChild<QPushButton*>(m_pStack, "showBtnUPW");

	if (hideBtn != NULL)
	{
		// If the button isn't on the form, then don't do anything, otherwise, do this stuff.
		Util::myConnect(hideBtn, SIGNAL(clicked()), this, SLOT(slotUnhidePwd()));
		m_bSignalConnected = true;
	}

	m_pSaveCreds = qFindChild<QCheckBox*>(m_pStack, "dataCheckboxSaveUsernamePassowrd");

	if (m_pSaveCreds != NULL)
	{
		// Make sure the box is unchecked to start with.
		m_pSaveCreds->setCheckState(Qt::Unchecked);
	}

	dataFrameProfilesUsername = qFindChild<QLineEdit*>(m_pStack, "dataFieldUsername");

	if (dataFrameProfilesUsername == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The 'dataFieldUsername' line edit box wasn't found in this form!  You won't be able to enter a username!"));
	}
	else
	{
		dataFrameProfilesUsername->setText(username);
	}

	dataFrameProfilesPassword = qFindChild<QLineEdit*>(m_pStack, "dataFieldPassword");

	if (dataFrameProfilesPassword == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"),  tr("The 'dataFieldPassword' line edit box wasn't found in this form!  You won't be able to enter a password!"));
	}
	else
	{
		dataFrameProfilesPassword->setEchoMode(QLineEdit::Password);
		dataFrameProfilesPassword->setText(password);
	}

	m_pEAPPwdLabel = qFindChild<QLabel*>(m_pStack, "labelPassword");

	if ((flags & POSS_CONN_NO_PWD) == POSS_CONN_NO_PWD)
	{
		dataFrameProfilesPassword->setEnabled(false);
		m_pSaveCreds->setEnabled(false);
		if (m_pEAPPwdLabel != NULL) m_pEAPPwdLabel->setEnabled(false);
	}
	else
	{
		dataFrameProfilesPassword->setEnabled(true);
		m_pSaveCreds->setEnabled(true);
		if (m_pEAPPwdLabel != NULL) m_pEAPPwdLabel->setEnabled(true);
	}
}

void LoginGetInfo::setPSKAuth(QString password)
{
	hideBtn = qFindChild<QPushButton*>(m_pStack, "pskShowBtn");

	if (hideBtn != NULL)
	{
		// If the button isn't on the form, then don't do anything, otherwise, do this stuff.
		Util::myConnect(hideBtn, SIGNAL(clicked()), this, SLOT(slotUnhidePwd()));
		m_bSignalConnected = true;
	}

	m_pSaveCreds = qFindChild<QCheckBox*>(m_pStack, "dataCheckboxSavePSK");

	dataFrameProfilesUsername = NULL;  // We don't use this one.

	dataFrameProfilesPassword = qFindChild<QLineEdit*>(m_pStack, "dataFieldPSK");

	if (dataFrameProfilesPassword == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The 'dataFieldPSK' line edit box wasn't found in this form!  You won't be able to enter a PSK!"));
	}
	else
	{
		dataFrameProfilesPassword->setEchoMode(QLineEdit::Password);
		dataFrameProfilesPassword->setText(password);
	}
}

void LoginGetInfo::slotUnhidePwd()
{
	if (dataFrameProfilesPassword->echoMode() == QLineEdit::Password)
	{
		// Unhide the password.
		dataFrameProfilesPassword->setEchoMode(QLineEdit::Normal);
		hideBtn->setText(tr("Hide"));
	}
	else
	{
		// Hide the password.
		dataFrameProfilesPassword->setEchoMode(QLineEdit::Password);
		hideBtn->setText(tr("Show"));
	}
}

bool LoginGetInfo::getCacheCredentialsFlag()
{
	if (m_pSaveCreds == NULL) return false;

	switch (m_pSaveCreds->checkState())
	{
	case Qt::Unchecked:
		return false;
		break;

	case Qt::PartiallyChecked:
	case Qt::Checked:
		return true;
		break;
	}

	return false;
}


