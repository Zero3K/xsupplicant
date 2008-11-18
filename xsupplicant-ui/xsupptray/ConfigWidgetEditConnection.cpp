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
#include <QTreeWidgetItem>
#include "NavPanel.h"
#include "ConfigWidgetEditConnection.h"
#include "helpbrowser.h"
#include "Util.h"

ConfigWidgetEditConnection::ConfigWidgetEditConnection(QWidget *pRealWidget, Emitter *e, QString connName, XSupCalls *xsup, NavPanel *pPanel, unsigned char config_type, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pParent(parent), m_pSupplicant(xsup), m_originalConnName(connName), m_pEmitter(e), m_pNavPanel(pPanel)
{
	m_pTabs = NULL;
	m_pTabsWidget = NULL;

	m_pConnection = NULL;

	m_bChangedData = false;
	m_bNewConnection = false;
	m_bConnectionRenamed = false;

	m_config_type = config_type;
}

ConfigWidgetEditConnection::~ConfigWidgetEditConnection()
{
	if (m_pTabsWidget != NULL)
	{
		delete m_pTabsWidget;
		m_pTabsWidget = NULL;
	}
}

void ConfigWidgetEditConnection::detach()
{
	if (m_pConnNameEdit != NULL)
	{
		Util::myDisconnect(m_pConnNameEdit, SIGNAL(textChanged(const QString &)), this, SLOT(slotConnectionRenamed(const QString &)));
	}

	Util::myDisconnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotHelp()));
}

bool ConfigWidgetEditConnection::attach()
{
	m_pConnNameEdit = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldConnectionName");
	if (m_pConnNameEdit == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFrameTrustedServerName'."));
		return false;
	}

	m_pTabs = qFindChild<QTabWidget*>(m_pRealWidget, "widgetTabsConnections");
	if (m_pTabs == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QTabBar called 'widgetTabsConnections'."));
		return false;
	}

	m_pTabs->setCurrentIndex(0);  // Always start with tab 0.

	updateWindow();

	m_pTabsWidget = new ConfigConnectionTabs(m_pRealWidget, m_pEmitter, m_pSupplicant, m_pConnection, this);

	if ((m_pTabsWidget == NULL) || (m_pTabsWidget->attach() == false)) return false;

	Util::myConnect(m_pConnNameEdit, SIGNAL(textChanged(const QString &)), this, SLOT(slotConnectionRenamed(const QString &)));

	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotHelp()));

	Util::myConnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));

	if (m_bNewConnection)
	{
		emit signalSetSaveBtn(true);
	}
	else
	{
		emit signalSetSaveBtn(false);
	}

	return true;
}

bool ConfigWidgetEditConnection::newItem()
{
		// This is a new server configuration.
		m_bNewConnection = true;
		m_bChangedData = true;
		m_config_type = CONFIG_LOAD_USER;

		return true;
}

void ConfigWidgetEditConnection::updateWindow()
{
  QString temp;

	if (m_pConnection != NULL)
	{
		m_pSupplicant->freeConfigConnection(&m_pConnection);
		m_pConnection = NULL;
	}

	if (m_bNewConnection)
	{
	  temp = tr("New Connection");
		if (m_pSupplicant->createNewConnection(temp, &m_pConnection) != true)
		{
			QMessageBox::critical(this, tr("New Connection"), tr("There was an error attempting to create a new Connection."));
			m_pConnection = NULL;
			return;
		}

		m_pNavPanel->addItem(NavPanel::CONNECTIONS_ITEM, QString(m_pConnection->name));

		m_originalConnName = QString(m_pConnection->name);
		m_lastConnName = QString(m_pConnection->name);
	}
	else if (m_pSupplicant->getConfigConnection(m_config_type, m_originalConnName, &m_pConnection, true) == true)
	{
		m_lastConnName = m_originalConnName;
	}

	if (m_pConnection != NULL) m_pConnNameEdit->setText(QString(m_pConnection->name));
}


void ConfigWidgetEditConnection::slotDataChanged()
{
	m_bChangedData = true;
	emit signalSetSaveBtn(true);
}

bool ConfigWidgetEditConnection::save()
{
  QString temp;
  int retval = 0;
  config_connection *pConfig = NULL;
  char *temp_ptr = NULL;

	if (m_pConnNameEdit->text() == "")
	{
		QMessageBox::critical(m_pRealWidget, tr("Invalid Connection Name"), tr("You must specify a connection name before attempting to save."));
		return false;
	}

	if (m_pTabsWidget != NULL)
	{
		if (m_pTabsWidget->save() == false) return false;
	}

	if (m_bNewConnection)
	{
		temp_ptr = _strdup(m_pConnNameEdit->text().toAscii());
		retval = xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, temp_ptr, &pConfig);
		if (retval != REQUEST_SUCCESS) retval = xsupgui_request_get_connection_config(CONFIG_LOAD_USER, temp_ptr, &pConfig);

		free(temp_ptr);
		if ((retval == REQUEST_SUCCESS) && (pConfig != NULL))
		{
			xsupgui_request_free_connection_config(&pConfig);
			QMessageBox::critical(this, tr("Invalid Connection Name"), tr("A connection with this name already exists.  Please correct this and try again."));
			return false;
		}
	}

	if (m_pConnection->name != NULL)
	{
		free(m_pConnection->name);
		m_pConnection->name = NULL;
	}

	m_pConnection->name = _strdup(m_pConnNameEdit->text().toAscii());

	// If the server was renamed, then rename it first, then update the config, and write it.
	if ((m_bConnectionRenamed) && (QString(m_pConnection->name) != m_originalConnName))
	{
	  temp = m_pConnection->name;
		if (m_pSupplicant->renameConnection(m_config_type, m_originalConnName, temp) == false)
			return false;

		m_bConnectionRenamed = false;
	}

	if (m_pSupplicant->setConfigConnection(m_config_type, m_pConnection) == true)
	{
		if (m_pSupplicant->writeConfig(m_config_type) == true)
		{
			m_originalConnName = m_lastConnName;
			m_bChangedData = false;
			m_bNewConnection = false;
			emit signalSetSaveBtn(false);

			return true;
		}
	}

	return false;
}

bool ConfigWidgetEditConnection::dataChanged()
{
	return m_bChangedData;
}

void ConfigWidgetEditConnection::slotConnectionRenamed(const QString &newValue)
{
	if (m_bNewConnection == false)
	{
		m_bConnectionRenamed = true;
	}
	
	slotDataChanged();

	m_pNavPanel->renameItem(NavPanel::SELECTED_ITEM, m_lastConnName, newValue);
	m_lastConnName = newValue;
}

void ConfigWidgetEditConnection::discard()
{
	m_bChangedData = false;
	m_lastConnName = "";

	if (m_bNewConnection)
	{
		m_pNavPanel->removeItem(NavPanel::CONNECTIONS_ITEM, m_pConnNameEdit->text());
	}
	else
	{
		m_pNavPanel->renameItem(NavPanel::CONNECTIONS_ITEM, m_pConnNameEdit->text(), m_originalConnName);
	}
}

void ConfigWidgetEditConnection::getPageName(QString &name)
{
	name = m_pConnNameEdit->text();
}

void ConfigWidgetEditConnection::slotHelp()
{
	switch (m_pTabs->currentIndex())
	{
	case ADAPTER_TAB:
		HelpWindow::showPage("xsupphelp.html", "xsupconnections");
		break;

	case NETWORK_TAB:
		HelpWindow::showPage("xsupphelp.html", "xsupnetwork");
		break;

	case DNS_TAB:
		HelpWindow::showPage("xsupphelp.html", "xsupdns");
		break;

	default:
		HelpWindow::showPage("xsupphelp.html", "xsupconnections");
		break;
	}
}

/**
 * \brief Check to see if this connection is in use.  If it is, then display a warning to the user.
 **/
bool ConfigWidgetEditConnection::allowEdit()
{
	int state = 0;

	if (xsupgui_request_get_is_connection_in_use(m_pConnection->name, &state) == REQUEST_SUCCESS)
	{
		if (state == TRUE) 
		{
			QMessageBox::information(this, tr("Connection In Use"), tr("This connection is currently in use.  You will not be able to edit the connection settings until the connection has been terminated."));
			return false;
		}
	}

	return true;
}
