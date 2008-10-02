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
#include "ConfigWidgetEditTrustedServers.h"
#include "Util.h"
#include "helpbrowser.h"

ConfigWidgetEditTrustedServers::ConfigWidgetEditTrustedServers(QWidget *pRealWidget, QString serverName, XSupCalls *xsup, NavPanel *pPanel, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pParent(parent), m_pSupplicant(xsup), m_originalServername(serverName), m_pNavPanel(pPanel)
{
	m_pCNEdit = NULL;
	m_pValidateServer = NULL;
	m_pbuttonBrowse = NULL;
	m_pCertCNLabel = NULL;
	m_pCertDeptLabel = NULL;
	m_pCertCompanyLabel = NULL;
	m_pCertLocationLabel = NULL;
	m_pCertStateLabel = NULL;
	m_pCertOULabel = NULL;
	m_pCertDomainLabel = NULL;
	m_pCertPurposeLabel = NULL;

	m_pTrustedServer = NULL;

	m_pServerPicker = NULL;

	m_bChangedData = false;
	m_bNewServer = false;
	m_bServerRenamed = false;
}

ConfigWidgetEditTrustedServers::~ConfigWidgetEditTrustedServers()
{

}

void ConfigWidgetEditTrustedServers::detach()
{
	Util::myDisconnect(this, SIGNAL(signalAddItem(int, const QString &)), m_pParent, SIGNAL(signalAddItem(int, const QString &)));
	Util::myDisconnect(this, SIGNAL(signalRenameItem(int, const QString &, const QString &)), m_pParent, SIGNAL(signalRenameItem(int, const QString &, const QString &)));

	if (m_pCNEdit != NULL)
	{
		Util::myDisconnect(m_pCNEdit, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pServerNameEdit != NULL)
	{
		Util::myDisconnect(m_pServerNameEdit, SIGNAL(textChanged(const QString &)), this, SLOT(slotServerRenamed(const QString &)));
	}

	if (m_pValidateServer != NULL)
	{
		Util::myDisconnect(m_pValidateServer, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pbuttonBrowse != NULL)
	{
		Util::myDisconnect(m_pbuttonBrowse, SIGNAL(clicked()), this, SLOT(slotBrowse()));
	}

	Util::myDisconnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myDisconnect(m_pValidateServer, SIGNAL(stateChanged(int)), this, SLOT(slotValidateCheckbox(int)));

	Util::myDisconnect(this, SIGNAL(signalRemoveItem(int, const QString &)), m_pParent, SIGNAL(signalRemoveItem(int, const QString &)));

	Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));
}

bool ConfigWidgetEditTrustedServers::attach()
{
	m_pCNEdit = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldCommonNameEndsWith");
	if (m_pCNEdit == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFieldCommonNameEndsWith'."));
		return false;
	}

	m_pValidateServer = qFindChild<QCheckBox*>(m_pRealWidget, "dataCheckboxValidateCommonName");
	if (m_pValidateServer == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QCheckBox called 'dataCheckboxValidateCommonName'."));
		return false;
	}

	m_pbuttonBrowse = qFindChild<QPushButton*>(m_pRealWidget, "buttonTrustedServersBrowse");
	if (m_pbuttonBrowse == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QPushButton called 'buttonTrustedServersBrowse'."));
		return false;
	}

	m_pServerNameEdit = qFindChild<QLineEdit*>(m_pRealWidget, "dataFrameTrustedServerName");
	if (m_pServerNameEdit == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFrameTrustedServerName'."));
		return false;
	}

	m_pCertCNLabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldTrustedServersCertificateCN");

	m_pCertDeptLabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldTrustedServersDepartment");

	m_pCertCompanyLabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldTrustedServersCompany");

	m_pCertLocationLabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldTrustedServersLocation");

	m_pCertStateLabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldTrustedServersState");

	m_pCertOULabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldTrustedServersOU");

	m_pCertDomainLabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldTrustedServersDomain");

	m_pCertPurposeLabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldTrustedServersPurpose");

	// This needs to be connected before calling updateWindow()!
	Util::myConnect(this, SIGNAL(signalAddItem(int, const QString &)), m_pParent, SIGNAL(signalAddItem(int, const QString &)));

	updateWindow();

	if (m_pCNEdit != NULL)
	{
		Util::myConnect(m_pCNEdit, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pValidateServer != NULL)
	{
		Util::myConnect(m_pValidateServer, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pbuttonBrowse != NULL)
	{
		Util::myConnect(m_pbuttonBrowse, SIGNAL(clicked()), this, SLOT(slotBrowse()));
	}

	Util::myConnect(m_pServerNameEdit, SIGNAL(textChanged(const QString &)), this, SLOT(slotServerRenamed(const QString &)));

	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myConnect(this, SIGNAL(signalRenameItem(int, const QString &, const QString &)), m_pParent, SIGNAL(signalRenameItem(int, const QString &, const QString &)));

	Util::myConnect(this, SIGNAL(signalRemoveItem(int, const QString &)), m_pParent, SIGNAL(signalRemoveItem(int, const QString &)));

	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	if (m_bNewServer)
	{
		emit signalSetSaveBtn(true);
	}
	else
	{
		emit signalSetSaveBtn(false);
	}

	return true;
}

bool ConfigWidgetEditTrustedServers::allowEdit()
{
	int state;

	if (xsupgui_request_get_is_trusted_server_in_use(m_pTrustedServer->name, &state) == REQUEST_SUCCESS)
	{
		if (state == TRUE) 
		{
			QMessageBox::information(this, tr("Trusted Server In Use"), tr("This trusted server is in use by an active connection.  You will not be able to edit the configuration until that connection is terminated."));
			return false;
		}
	}

	return true;
}

bool ConfigWidgetEditTrustedServers::newItem()
{
		// This is a new server configuration.
		m_bNewServer = true;
		m_bChangedData = true;

		return true;
}

void ConfigWidgetEditTrustedServers::updateWindow()
{
  QString temp;

	if (m_pTrustedServer != NULL)
	{
		m_pSupplicant->freeConfigTrustedServer(&m_pTrustedServer);
		m_pTrustedServer = NULL;
	}

	if (m_bNewServer)
	{
	  temp = "New Server";
		if (m_pSupplicant->createNewTrustedServer(temp, &m_pTrustedServer) != true)
		{
			QMessageBox::critical(this, tr("New Trusted Server"), tr("There was an error attempting to create a new Trusted Server."));
			m_pTrustedServer = NULL;
			return;
		}

		m_pNavPanel->addItem(NavPanel::TRUSTED_SERVERS_ITEM, QString(m_pTrustedServer->name));

		m_originalServername = QString(m_pTrustedServer->name);
		m_lastServername = QString(m_pTrustedServer->name);

		m_pCNEdit->clear();
		m_pValidateServer->setCheckState(Qt::Unchecked);

		m_pCertCNLabel->clear();
		m_pCertCompanyLabel->clear();
		m_pCertOULabel->clear();
		m_pCertLocationLabel->clear();
		m_pCertStateLabel->clear();
		m_pCertDeptLabel->clear();
	}
	else if (m_pSupplicant->getConfigTrustedServer(m_originalServername, &m_pTrustedServer, true) == true)
	{
		m_lastServername = m_originalServername;

		if (m_pTrustedServer->common_name != NULL)
		{
			m_pCNEdit->setText(QString(m_pTrustedServer->common_name));
			m_pValidateServer->setCheckState(Qt::Checked);
			
		}
		else
		{
			m_pValidateServer->setCheckState(Qt::Unchecked);
		}

		updateCertData();
	}

	if (m_pValidateServer->checkState() == Qt::Unchecked)
	{
		m_pCNEdit->setEnabled(false);
	}
	else
	{
		m_pCNEdit->setEnabled(true);
	}

	if (m_pTrustedServer != NULL) m_pServerNameEdit->setText(QString(m_pTrustedServer->name));

	Util::myConnect(m_pValidateServer, SIGNAL(stateChanged(int)), this, SLOT(slotValidateCheckbox(int)));
}

void ConfigWidgetEditTrustedServers::updateCertData()
{
	cert_info *myCertInfo = NULL;
	QString temp, temp2;

	if (m_pTrustedServer->location != NULL)
	{
		temp = m_pTrustedServer->store_type;
		temp2 = m_pTrustedServer->location[0];
		if (m_pSupplicant->getCertInfo(temp, temp2, &myCertInfo, true) == true)
		{
			QFontMetrics pMet = fontMetrics();	

			m_pCertCNLabel->setText(pMet.elidedText(QString(myCertInfo->CN), Qt::ElideRight, 300));
			m_pCertCompanyLabel->setText(pMet.elidedText(QString(myCertInfo->C), Qt::ElideRight, 300));
			m_pCertOULabel->setText(pMet.elidedText(QString(myCertInfo->OU), Qt::ElideRight, 300));
			m_pCertLocationLabel->setText(pMet.elidedText(QString(myCertInfo->L), Qt::ElideRight, 300));
			m_pCertStateLabel->setText(pMet.elidedText(QString(myCertInfo->S), Qt::ElideRight, 300));
			m_pCertDeptLabel->setText(pMet.elidedText(QString(myCertInfo->O), Qt::ElideRight, 300));

			m_pSupplicant->freeCertInfo(&myCertInfo);
		}
		else
		{
			m_pCertCNLabel->setText("");
			m_pCertCompanyLabel->setText("");
			m_pCertOULabel->setText("");
			m_pCertLocationLabel->setText("");
			m_pCertStateLabel->setText("");
			m_pCertDeptLabel->setText("");
			m_pCNEdit->setText("");
			m_pValidateServer->setChecked(false);
		}
	}
}

void ConfigWidgetEditTrustedServers::slotValidateCheckbox(int newstate)
{
	m_pCNEdit->setEnabled(newstate);
}

void ConfigWidgetEditTrustedServers::slotDataChanged()
{
	m_bChangedData = true;
	emit signalSetSaveBtn(true);
}

bool ConfigWidgetEditTrustedServers::save()
{
  QString temp;
  char *temp_ptr = NULL;
  config_trusted_server *pConfig = NULL;
  int retval = 0;

	if (m_pServerNameEdit->text() == "")
	{
		QMessageBox::critical(this, tr("Trusted Server Name Error"), tr("You must specify a valid trusted server name before attempting to save."));
		return false;
	}

	if (m_bNewServer)
	{
		temp_ptr = _strdup(m_pServerNameEdit->text().toAscii());
		retval = xsupgui_request_get_trusted_server_config(temp_ptr, &pConfig);
		free(temp_ptr);
		if ((retval == REQUEST_SUCCESS) && (pConfig != NULL))
		{
			xsupgui_request_free_trusted_server_config(&pConfig);
			QMessageBox::critical(this, tr("Invalid Trusted Server Name"), tr("A trusted server with this name already exists.  Please correct this and try again."));
			return false;
		}
	}

	if (m_pCNEdit != NULL)
	{
		if (m_pTrustedServer->common_name != NULL) 
		{
			free(m_pTrustedServer->common_name);
			m_pTrustedServer->common_name = NULL;
		}

		if (m_pCNEdit->text() != "")
		{
			m_pTrustedServer->common_name = _strdup(m_pCNEdit->text().toAscii());
			m_pTrustedServer->exact_common_name = FALSE;
		}
	}

	if (m_pValidateServer != NULL)
	{
		if (m_pValidateServer->checkState() == Qt::Unchecked)
		{
			if (m_pTrustedServer->common_name != NULL)
			{
				free(m_pTrustedServer->common_name);
				m_pTrustedServer->common_name = NULL;
			}
		}
	}

	if (m_pTrustedServer->name != NULL)
	{
		free(m_pTrustedServer->name);
		m_pTrustedServer->name = NULL;
	}

	m_pTrustedServer->name = _strdup(m_pServerNameEdit->text().toAscii());

	// If the server was renamed, then rename it first, then update the config, and write it.
	if ((m_bServerRenamed) && (QString(m_pTrustedServer->name) != m_originalServername))
	{
	  temp = m_pTrustedServer->name;
		if (m_pSupplicant->renameTrustedServer(m_originalServername, temp) == false)
			return false;

		m_originalServername = m_pTrustedServer->name;
		m_bServerRenamed = false;
	}

	if (m_pSupplicant->setConfigTrustedServer(m_pTrustedServer) == true)
	{
		if (m_pSupplicant->writeConfig() == true)
		{
			m_bChangedData = false;
			m_bNewServer = false;
			emit signalSetSaveBtn(false);

			return true;
		}
	}

	return false;
}

bool ConfigWidgetEditTrustedServers::dataChanged()
{
	return m_bChangedData;
}

void ConfigWidgetEditTrustedServers::slotBrowse()
{
	if (m_pServerPicker != NULL)
	{
		delete m_pServerPicker;
		m_pServerPicker = NULL;
	}

	m_pServerPicker = new TrustedRootCertsDlg((*m_pSupplicant), this, m_pRealWidget->window());
	if ((m_pServerPicker != NULL) && (m_pServerPicker->attach() != false))
	{
		Util::myConnect(m_pServerPicker, SIGNAL(signalAccept()), this, SLOT(slotServerSelected()));
		Util::myConnect(m_pServerPicker, SIGNAL(signalCancel()), this, SLOT(slotServerCanceled()));
		m_pServerPicker->show();
	}
}

void ConfigWidgetEditTrustedServers::slotServerRenamed(const QString &newValue)
{
	if (m_bNewServer == false)
	{
		m_bServerRenamed = true;
	}
	
	slotDataChanged();

	m_pNavPanel->renameItem(NavPanel::SELECTED_ITEM, m_lastServername, newValue);
	m_lastServername = newValue;
}

void ConfigWidgetEditTrustedServers::slotServerCanceled()
{
	m_pServerPicker->deleteLater();  // Let the main event loop delete it, just in case there are events left in the queue.
	m_pServerPicker = NULL;
}

void ConfigWidgetEditTrustedServers::slotServerSelected()
{
	QString location;
	QString storetype;

	if (m_pServerPicker != NULL)
	{
		m_pServerPicker->getCurrentCertificate(storetype, location);
		
		if (location != "")
		{
			if (m_pTrustedServer->location == NULL)
			{
				m_pTrustedServer->location = (char**)malloc(1 * sizeof(char *));
				if (m_pTrustedServer->location != NULL)
					memset(m_pTrustedServer->location, 0x00, 1 * sizeof(char *));
				else
				{
					QMessageBox::critical(m_pRealWidget->window(), tr("Error"), tr("Failed to allocate memory to store trusted server data."));
					return; // just exit
				}	
			}
			else
			{
				if (m_pTrustedServer->location[0] != NULL)
				{
					free(m_pTrustedServer->location[0]);
					m_pTrustedServer->location[0] = NULL;
				}
			}

			m_pTrustedServer->location[0] = _strdup(location.toAscii());
			m_pTrustedServer->num_locations = 1;
			slotDataChanged();
		}
	}

	slotServerCanceled();  // Clean up the window.
	updateCertData();
}

void ConfigWidgetEditTrustedServers::getPageName(QString &name)
{
	name = m_pServerNameEdit->text();
}

void ConfigWidgetEditTrustedServers::discard()
{
	m_bChangedData = false;

	if (m_bNewServer)
	{
		m_pNavPanel->removeItem(NavPanel::TRUSTED_SERVERS_ITEM, m_pServerNameEdit->text());
	}
	else
	{
		m_pNavPanel->renameItem(NavPanel::TRUSTED_SERVERS_ITEM, m_pServerNameEdit->text(), m_originalServername);
	}
}

void ConfigWidgetEditTrustedServers::slotShowHelp()
{
	HelpWindow::showPage("xsupphelp.html", "xsuptrustedservers");
}

