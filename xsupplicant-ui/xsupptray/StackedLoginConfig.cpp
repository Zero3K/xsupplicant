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

#include "StackedLoginConfig.h"
#include "LoginStatus.h"
#include "LoginStatusWireless.h"

//! Constructor
/*!
  \brief Make sure all data is initialized
  \return Nothing
*/
StackedLoginConfig::StackedLoginConfig(poss_conn_enum *pConns, QStackedWidget *widgets, QWidget *parent, Emitter *e):
  QWidget(parent), m_supplicant(this), m_pConns(pConns), m_message(this),
	  m_pWidgets(widgets), m_pEmitter(e)
{
	m_pStatusWidget = NULL;
	m_pLoginInfo = NULL;
}

//! Destructor
/*!
  \brief Make sure all data is freed
  \return Nothing
*/
StackedLoginConfig::~StackedLoginConfig(void)
{
	if (m_pStatusWidget != NULL)
	{
		delete m_pStatusWidget;
		m_pStatusWidget = NULL;
	}

	if (m_pLoginInfo != NULL)
	{
		delete m_pLoginInfo;
		m_pLoginInfo = NULL;
	}
}

/**
 * \brief Return the currently displayed widget in the stack.
 *
 * \retval statusE enumeration member.
 **/
int StackedLoginConfig::getCurrent()
{
	return m_pWidgets->currentIndex();
}

/////////////////////////////////////////////////
//! setCurrent()
//!  \brief This selects the correct layout from the stacked layout
//!  Passes correct information to the layout, if needed, and then handles
//!  the layout.
//!  \param[in] connection - the name of the connection
//!  \return Nothing
/////////////////////////////////////////////////
void StackedLoginConfig::setCurrent(statusE index, 
									bool fromConnect,
                                    QString &connectionName, 
                                    QString &deviceDescription, 
                                    QString &deviceName,
                                    bool bWireless, 
                                    poss_conn_enum *pConn)
{
  // Get the connection status

  // Since the following dialogs all share the same structure, 
  // it will be read in here and a pointer passed into the dialogs.
  // If they all share the same pointer, they will all share the same data
  // so when the data on one dialog is saved (refreshed), 
  // it will be saved (refreshed) for all of the dialogs.

  m_currentConnection = connectionName;
  m_deviceDescription = deviceDescription;
  m_deviceName = deviceName;
  m_bWireless = bWireless;
  
  m_pWidgets->setCurrentIndex(index);

  switch (index)
  {
    // If nothing else is selected, this is the default
    default:
    case LOGIN_GET_INFO:
		setLogin(pConn);
		break;

    case LOGIN_STATUS:
      {
        if (bWireless)
        {
			setWireless(pConn, fromConnect);
        }
        else
        {
			setWired(pConn, fromConnect);
        }
      }
      break;
  }
}


QString StackedLoginConfig::getUserName()
{
  if (m_pLoginInfo != NULL)
  {
	  return m_pLoginInfo->get_username();
  }

  return QString("");
}


QString StackedLoginConfig::getPassword()
{
  if (m_pLoginInfo != NULL)
  {
	  return m_pLoginInfo->get_password();
  }

  return QString("");
}


bool StackedLoginConfig::getCacheCredentialsFlag()
{
	if (m_pLoginInfo != NULL)
	{
		return m_pLoginInfo->getCacheCredentialsFlag();
	}

	return false;
}

QString &StackedLoginConfig::getDeviceName()
{
  return m_deviceName;
}

QString &StackedLoginConfig::getDeviceDescription()
{
  return m_deviceDescription;
}

bool StackedLoginConfig::getWireless()
{
  return m_bWireless;
}

void StackedLoginConfig::setWireless(poss_conn_enum *pConnEnum, bool fromConnect)
{
	QWidget *myWidget;

	if (m_pStatusWidget != NULL) 
	{
		delete m_pStatusWidget;
		m_pStatusWidget = NULL;
	}

	if (m_pLoginInfo != NULL)
	{
		delete m_pLoginInfo;
		m_pLoginInfo = NULL;
	}

	myWidget = qFindChild<QWidget*>(m_pWidgets, "statusPage");
	if (myWidget == NULL)
	{
		QMessageBox::critical(this, "Form Design Error", "There is no 'statusPage' defined in the widget stack!");
		return;
	}

	m_pStatusWidget = new LoginStatusWireless(fromConnect, getDeviceName(), pConnEnum, myWidget, this, m_pEmitter);
}

void StackedLoginConfig::setWired(poss_conn_enum *pConnEnum, bool fromConnect)
{
	QWidget *myWidget;

	if (m_pStatusWidget != NULL) 
	{
		delete m_pStatusWidget;
		m_pStatusWidget = NULL;
	}

	if (m_pLoginInfo != NULL)
	{
		delete m_pLoginInfo;
		m_pLoginInfo = NULL;
	}

	myWidget = qFindChild<QWidget*>(m_pWidgets, "statusPage");
	if (myWidget == NULL)
	{
		QMessageBox::critical(this, "Form Design Error", "There is no 'statusPage' defined in the widget stack!");
		return;
	}

	m_pStatusWidget = new LoginStatus(fromConnect, getDeviceName(), pConnEnum, myWidget, this, m_pEmitter);
}

void StackedLoginConfig::setLogin(poss_conn_enum *pConnEnum)
{
	QWidget *myWidget;

	if (m_pStatusWidget != NULL) 
	{
		delete m_pStatusWidget;
		m_pStatusWidget = NULL;
	}

	if (m_pLoginInfo != NULL)
	{
		delete m_pLoginInfo;
		m_pLoginInfo = NULL;
	}
	
	myWidget = qFindChild<QWidget*>(m_pWidgets, "loginPage");
	if (myWidget == NULL)
	{
		QMessageBox::critical(this, "Form Design Error", "There is no 'loginPage' defined in the widget stack!");
		return;
	}

	m_pLoginInfo = new LoginGetInfo(getDeviceName(), pConnEnum, myWidget, this, m_pEmitter);
}

// updateAll should be set to true when you want to update *ALL* information, which would
// include resetting the username and password fields!
void StackedLoginConfig::update(bool updateAll)
{
	if (m_pLoginInfo == NULL) return;

	m_pLoginInfo->updateWindow(updateAll);
}

void StackedLoginConfig::deviceRemoved(QString intName)
{
	if (intName == m_deviceDescription)
	{
		if (m_pWidgets->currentIndex() == LOGIN_STATUS)
		{
			m_pWidgets->setCurrentIndex(LOGIN_GET_INFO);
		}
	}
}


