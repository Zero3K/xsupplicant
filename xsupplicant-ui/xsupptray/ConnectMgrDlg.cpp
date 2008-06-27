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

#include "ConnectMgrDlg.h"
#include "FormLoader.h"
#include "Emitter.h"
#include "TrayApp.h"
#include "XSupWrapper.h"
#include "PreferredConnections.h"
#include "ConnectionWizard.h"
#include "ConnectionWizardData.h"
#include <QLabel>
#include <QList>

#include <algorithm>


// TODO:  disable wired options if no wired interface present
// TODO:  disable wireless options if no wireless interfaces present

ConnectMgrDlg::ConnectMgrDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *supplicant)
	: QWidget(parent),
	m_pParent(parent),
	m_pEmitter(e),
	m_pSupplicant(supplicant),
	m_pParentWindow(parentWindow)
{
	m_pConnections = NULL;
	m_pPrefDlg = NULL;
	m_pConnWizard = NULL;
}

ConnectMgrDlg::~ConnectMgrDlg()
{
	if (m_pAdvancedButton != NULL)
		Util::myDisconnect(m_pAdvancedButton, SIGNAL(clicked()), this, SLOT(showAdvancedConfig()));
		
	if (m_pCloseButton != NULL)
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
		
	if (m_pConnectionsTable != NULL)
		Util::myDisconnect(m_pConnectionsTable, SIGNAL(itemSelectionChanged()), this, SLOT(handleConnectionListSelectionChange()));
		
	if (m_pDeleteConnButton != NULL)
		Util::myDisconnect(m_pDeleteConnButton, SIGNAL(clicked()), this, SLOT(deleteSelectedConnection()));
		
	if (m_pEditConnButton != NULL)
		Util::myDisconnect(m_pEditConnButton, SIGNAL(clicked()), this, SLOT(editSelectedConnection()));			
		
	if (m_pNetworkPrioritiesButton != NULL)
		Util::myDisconnect(m_pNetworkPrioritiesButton, SIGNAL(clicked()), this, SLOT(showPriorityDialog()));		
		
	if (m_pNewConnButton != NULL)
		Util::myDisconnect(m_pNewConnButton, SIGNAL(clicked()), this, SLOT(createNewConnection()));	
		
	if (m_pWirelessAutoConnect != NULL)
		Util::myDisconnect(m_pWirelessAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(enableDisableWirelessAutoConnect(int)));
		
	if (m_pWiredAutoConnect != NULL)
		Util::myDisconnect(m_pWiredAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(enableDisableWiredAutoConnect(int)));
		
	if (m_pWiredConnections != NULL)
		Util::myDisconnect(m_pWiredConnections, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(setWiredAutoConnection(const QString &)));						

	Util::myDisconnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(updateConnectionLists()));

	if (m_pPrefDlg != NULL)
		delete m_pPrefDlg;
		
	this->cleanupConnectionWizard();
		
	if (m_pRealForm != NULL)
		delete m_pRealForm;
		
	if (m_pConnections != NULL)
		xsupgui_request_free_conn_enum(&m_pConnections);		
}

bool ConnectMgrDlg::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("ConnectionManagerWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
		
	Qt::WindowFlags flags;
	
	// set window flags so minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
			
	// cache off pointers to UI objects
	m_pHelpButton = qFindChild<QPushButton*>(m_pRealForm, "buttonHelp");
	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");
	m_pMainTab = qFindChild<QTabWidget*>(m_pRealForm, "mainTabControl");
	
	m_pNetworkPrioritiesButton = qFindChild<QPushButton*>(m_pRealForm, "buttonOptionsNetworkPriorities");
	m_pAdvancedButton = qFindChild<QPushButton*>(m_pRealForm, "buttonOptionsAdvancedConfig");
	m_pWiredConnections = qFindChild<QComboBox*>(m_pRealForm, "comboOptionsWirelessConnections");
	m_pWiredAutoConnect = qFindChild<QCheckBox*>(m_pRealForm, "checkboxWiredAutoConnect");
	m_pWirelessAutoConnect = qFindChild<QCheckBox*>(m_pRealForm, "checkboxWirelessAutoConnect");
	
	m_pDeleteConnButton = qFindChild<QPushButton*>(m_pRealForm, "buttonDeleteConnection");
	m_pEditConnButton = qFindChild<QPushButton*>(m_pRealForm, "buttonEditConnection");
	m_pNewConnButton = qFindChild<QPushButton*>(m_pRealForm,"buttonNewConnection");
	m_pConnectionsTable = qFindChild<QTableWidget*>(m_pRealForm, "dataTableConnectionProfiles");
			
	// populate strings
	if (m_pAdvancedButton != NULL)
		m_pAdvancedButton->setText(tr("Show Advanced Configuration"));
		
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
	
	if (m_pHelpButton != NULL)
		m_pHelpButton->setText(tr("Help"));	
		
	if (m_pNetworkPrioritiesButton != NULL)
		m_pNetworkPrioritiesButton->setText(tr("Set Network Priorities"));
	
	if (m_pWiredAutoConnect != NULL)
		m_pWiredAutoConnect->setText(tr("Automatically Establish Connection"));
		
	if (m_pWirelessAutoConnect != NULL)
		m_pWirelessAutoConnect->setText(tr("Automatically Establish Connection"));		
		
	if (m_pDeleteConnButton != NULL)
		m_pDeleteConnButton->setText(tr("Delete"));
		
	if (m_pEditConnButton != NULL)
		m_pEditConnButton->setText(tr("Edit"));
		
	if (m_pNewConnButton != NULL)
		m_pNewConnButton->setText(tr("New Connection"));
		
	if (m_pMainTab != NULL)
	{
		m_pMainTab->setTabText(0,tr("Connections"));
		m_pMainTab->setTabText(1,tr("Options"));	
	}
	
	if (m_pConnectionsTable != NULL)
	{
		m_pConnectionsTable->horizontalHeaderItem(0)->setText(tr("Name"));
		m_pConnectionsTable->horizontalHeaderItem(1)->setText(tr("Interface"));
	}
		
	QLabel *pWiredOptionsHeader;
	pWiredOptionsHeader = qFindChild<QLabel*>(m_pRealForm, "headerWiredOptions");
	if (pWiredOptionsHeader != NULL)
		pWiredOptionsHeader->setText(tr("Wired"));
		
	QLabel *pWirelessOptionsHeader;
	pWirelessOptionsHeader = qFindChild<QLabel*>(m_pRealForm, "headerWirelessOptions");
	if (pWirelessOptionsHeader != NULL)
		pWirelessOptionsHeader->setText(tr("Wireless"));
		
	QLabel *pAdvancedOptionsHeader;
	pAdvancedOptionsHeader = qFindChild<QLabel*>(m_pRealForm, "headerAdvancedOptions");
	if (pAdvancedOptionsHeader != NULL)
		pAdvancedOptionsHeader->setText(tr("Advanced"));
		
	QLabel *pConnectionsHeader;
	pConnectionsHeader = qFindChild<QLabel*>(m_pRealForm, "headerConnectionProfiles");
	if (pConnectionsHeader != NULL)
		pConnectionsHeader->setText(tr("Connection Profiles"));
		
	
	// set up event-handling
	if (m_pAdvancedButton != NULL)
		Util::myConnect(m_pAdvancedButton, SIGNAL(clicked()), this, SLOT(showAdvancedConfig()));
		
	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
		
	if (m_pConnectionsTable != NULL)
		Util::myConnect(m_pConnectionsTable, SIGNAL(itemSelectionChanged()), this, SLOT(handleConnectionListSelectionChange()));
		
	if (m_pDeleteConnButton != NULL)
		Util::myConnect(m_pDeleteConnButton, SIGNAL(clicked()), this, SLOT(deleteSelectedConnection()));
		
	if (m_pEditConnButton != NULL)
		Util::myConnect(m_pEditConnButton, SIGNAL(clicked()), this, SLOT(editSelectedConnection()));		
		
	if (m_pNetworkPrioritiesButton != NULL)
		Util::myConnect(m_pNetworkPrioritiesButton, SIGNAL(clicked()), this, SLOT(showPriorityDialog()));
		
	if (m_pNewConnButton != NULL)
		Util::myConnect(m_pNewConnButton, SIGNAL(clicked()), this, SLOT(createNewConnection()));
		
	if (m_pWirelessAutoConnect != NULL)
		Util::myConnect(m_pWirelessAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(enableDisableWirelessAutoConnect(int)));
		
	if (m_pWiredAutoConnect != NULL)
		Util::myConnect(m_pWiredAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(enableDisableWiredAutoConnect(int)));
		
	if (m_pWiredConnections != NULL)
		Util::myConnect(m_pWiredConnections, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(setWiredAutoConnection(const QString &)));			
		
	Util::myConnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(updateConnectionLists()));
	
	// other initializations
	if (m_pMainTab != NULL)
		m_pMainTab->setCurrentIndex(0);
		
	if (m_pConnectionsTable != NULL)
	{
		// disallow user from sizing columns
		m_pConnectionsTable->horizontalHeader()->setResizeMode(QHeaderView::Fixed);
		
		m_pConnectionsTable->horizontalHeader()->setResizeMode(0,QHeaderView::Stretch);
		m_pConnectionsTable->horizontalHeader()->resizeSection(1,100);
		m_pConnectionsTable->horizontalHeader()->resizeSection(2,100);
			
		// don't draw header any differently when row is selected
		m_pConnectionsTable->horizontalHeader()->setHighlightSections(false);
		
		m_pConnectionsTable->clearContents();
		
		m_pConnectionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);		
		
		this->populateConnectionsList();
		
		// enable/disable buttons dependent on selection
		handleConnectionListSelectionChange();
	}
		
	return true;	
}

bool ConnectMgrDlg::create(void)
{
	return this->initUI();
}

void ConnectMgrDlg::updateWirelessAutoConnectState(void)
{
	if (m_pWirelessAutoConnect != NULL)
	{
		int retVal;
		config_globals *pConfig;
		
		retVal = xsupgui_request_get_globals_config(&pConfig);
		if (retVal == REQUEST_SUCCESS && pConfig != NULL) {
			m_pWirelessAutoConnect->setChecked((pConfig->flags & CONFIG_GLOBALS_ASSOC_AUTO) == CONFIG_GLOBALS_ASSOC_AUTO);
			if (m_pNetworkPrioritiesButton != NULL)
				m_pNetworkPrioritiesButton->setEnabled((pConfig->flags & CONFIG_GLOBALS_ASSOC_AUTO) == CONFIG_GLOBALS_ASSOC_AUTO);			
		}
		else
		{
			// if we can't get data we need, make sure everything's enabled
			if (m_pNetworkPrioritiesButton != NULL)
				m_pNetworkPrioritiesButton->setEnabled(true);			
		}
			
		if (pConfig != NULL)
			xsupgui_request_free_config_globals(&pConfig);
	}
}

void ConnectMgrDlg::enableDisableWirelessAutoConnect(int newState)
{
	if (m_pWirelessAutoConnect != NULL)
	{
		int retVal;
		config_globals *pConfig;
		
		retVal = xsupgui_request_get_globals_config(&pConfig);
		if (retVal == REQUEST_SUCCESS && pConfig != NULL)	
		{
			if (newState == Qt::Checked)
			{
				pConfig->flags |= CONFIG_GLOBALS_ASSOC_AUTO;
				if (m_pNetworkPrioritiesButton != NULL)
					m_pNetworkPrioritiesButton->setEnabled(true);
			}
			else 
			{
				pConfig->flags &= ~CONFIG_GLOBALS_ASSOC_AUTO;
				if (m_pNetworkPrioritiesButton != NULL)
					m_pNetworkPrioritiesButton->setEnabled(false);
			}
				
			retVal = xsupgui_request_set_globals_config(pConfig);
			
			if (retVal == REQUEST_SUCCESS)
				XSupWrapper::writeConfig();
		}
		
		if (pConfig != NULL)
			xsupgui_request_free_config_globals(&pConfig);
	}
}

void ConnectMgrDlg::updateWiredAutoConnectState(void)
{
	// don't bother doing any work if the UI elements aren't present
	if (m_pWiredAutoConnect != NULL && m_pWiredConnections != NULL)
	{
		int_config_enum *pInterfaceList = NULL;
		int retVal;
		
		// jking !!! for now just assume there's only one wired adapter
		// The UI needs to be updated to handle the multi-adapter case.
		retVal = xsupgui_request_enum_ints_config(&pInterfaceList);
		if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
		{
			int i = 0;
			while (pInterfaceList[i].desc != NULL)
			{
				if (pInterfaceList[i].is_wireless == FALSE)
				{
					if (pInterfaceList[i].default_connection != NULL)
					{										
						// ensure connection is in list before checking option
						QString connName = pInterfaceList[i].default_connection;
						int index = m_pWiredConnections->findText(connName);
						if (index != -1)
						{
							// !!!! this causes event to be fired?!
							m_pWiredAutoConnect->setCheckState(Qt::Checked);
							this->enableDisableWiredAutoConnect(Qt::Checked);
							m_pWiredConnections->setCurrentIndex(index);
						}
						else
						{
							m_pWiredAutoConnect->setCheckState(Qt::Unchecked);
							enableDisableWiredAutoConnect(Qt::Unchecked);
						}
					}
					else
					{
						m_pWiredAutoConnect->setCheckState(Qt::Unchecked);
						this->enableDisableWiredAutoConnect(Qt::Unchecked);
					}
					break;
				}
				
				++i;
			}
			xsupgui_request_free_int_config_enum(&pInterfaceList);
			pInterfaceList = NULL;	
		}
	}
}


void ConnectMgrDlg::setWiredAutoConnection(const QString &connectionName)
{
	bool success = false;
	int_config_enum *pInterfaceList = NULL;
	int retVal;
		
	// jking !!! for now just assume there's only one wired adapter
	// The UI needs to be updated to handle the multi-adapter case.
	retVal = xsupgui_request_enum_ints_config(&pInterfaceList);
	if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
	{
		int i = 0;
		bool found = false;
		
		// find the first wired interface
		while (pInterfaceList[i].desc != NULL)
		{
			if (pInterfaceList[i].is_wireless == FALSE)
			{
				found = true;
				break;
			}
			++i;
		}
		
		// do nothing if no wired interfaces found
		if (found == true)
		{
			config_interfaces *pInterface;
			retVal = xsupgui_request_get_interface_config(pInterfaceList[i].desc, &pInterface);
			if (retVal == REQUEST_SUCCESS && pInterface != NULL)
			{
				if (!connectionName.isEmpty())
				{
					// save off new string
					char *oldPtr = pInterface->default_connection;
					pInterface->default_connection = _strdup(connectionName.toAscii().data());
					
					// free memory holding old string
					if (oldPtr != NULL)
						xsupgui_request_free_str(&oldPtr);					
				}
				else
				{
					// clear out old setting
					char *oldPtr = pInterface->default_connection;
					pInterface->default_connection = NULL;
					
					// free memory holding old string
					if (oldPtr != NULL)
						xsupgui_request_free_str(&oldPtr);
				}
				
				// save off new setting
				retVal = xsupgui_request_set_interface_config(pInterface);
				if (retVal == REQUEST_SUCCESS)
				{
					success = true;
					
					// write out configuration
					// no biggie if this fails
					XSupWrapper::writeConfig();
				}
								
				xsupgui_request_free_interface_config(&pInterface);
			}	
		}
				
		xsupgui_request_free_int_config_enum(&pInterfaceList);
		pInterfaceList = NULL;
	}
	//return success;
}

void ConnectMgrDlg::enableDisableWiredAutoConnect(int newState)
{
	if (m_pWiredAutoConnect != NULL && m_pWiredConnections != NULL)
	{
		if (newState == Qt::Checked)
		{
			setWiredAutoConnection(m_pWiredConnections->currentText());
			m_pWiredConnections->setEnabled(true);
		}
		else
		{
			this->setWiredAutoConnection(QString(""));
			m_pWiredConnections->setEnabled(false);
		}
	}
}

void ConnectMgrDlg::show(void)
{
	// every time we show this, refresh the connection list in case it changed
	this->refreshConnectionList();
	this->populateConnectionsList();
	this->populateWiredConnectionsCombo();
	this->updateWirelessAutoConnectState();
	this->updateWiredAutoConnectState();

	// always come up with first tab visible, regardless of state user left it in
	if (m_pMainTab != NULL)
		m_pMainTab->setCurrentIndex(0);
		
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

void ConnectMgrDlg::hide(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
}

void ConnectMgrDlg::showAdvancedConfig(void)
{
	m_pSupplicant->showAdvancedConfig();
	this->hide();
}

void ConnectMgrDlg::refreshConnectionList(void)
{	
	int retval = 0;
	conn_enum *pConn;
	
	retval = xsupgui_request_enum_connections(&pConn);
	if (retval == REQUEST_SUCCESS && pConn)
	{
		if (m_pConnections != NULL)
			xsupgui_request_free_conn_enum(&m_pConnections);

		// count connections
		m_nConnections = 0;
		while (pConn[m_nConnections].name != NULL)
			++m_nConnections;
			
		m_pConnections = pConn;
	}	
}

void ConnectMgrDlg::populateWiredConnectionsCombo(void)
{
	if (m_pWiredConnections != NULL)
	{
		// disconnect this slot while populate combo box
		// QT is silly and emits signals for index changed as it populates
		Util::myDisconnect(m_pWiredConnections, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(setWiredAutoConnection(const QString &)));						

		m_pWiredConnections->clear();
		
		// jking - !!! right now this assumes only one wired interface
		// We really need to filter this list by selected interface once
		// the UI supports it
		if (m_pConnections != NULL)
		{	
			// create sorted list of wired connections
			QVector<QString> wiredConnVector;
			
			for (int i=0; i<m_nConnections; i++)
			{
				if (m_pConnections[i].ssid == NULL || QString(m_pConnections[i].ssid).isEmpty())
					wiredConnVector.append(QString(m_pConnections[i].name));
			}
			
			// we now have vector of connections. Now sort them.
			std::sort(wiredConnVector.begin(), wiredConnVector.end());
			
			for (int i=0; i<wiredConnVector.size(); i++)
				m_pWiredConnections->addItem(wiredConnVector.at(i));
		}
		Util::myConnect(m_pWiredConnections, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(setWiredAutoConnection(const QString &)));			
	}
}

void ConnectMgrDlg::populateConnectionsList(void)
{
	if (m_pConnections != NULL)
	{
		// clear table before re-populating
		m_pConnectionsTable->clearContents();
		
		// make sure we have enough rows in the table
		m_pConnectionsTable->setRowCount(std::max<int>(this->m_minConnListRowCount, m_nConnections));
		m_pConnectionsTable->setSortingEnabled(false);
		
		for (int i=0; i<m_nConnections; i++)
		{
			// check if connection is volatile
			bool bVolatile = false;
			config_connection *pConfig;
			int retVal = xsupgui_request_get_connection_config(m_pConnections[i].name, &pConfig);
			if (retVal == REQUEST_SUCCESS && pConfig != NULL)
			{
				if ((pConfig->flags & CONFIG_VOLATILE_CONN) != 0)
					bVolatile = true;
				xsupgui_request_free_connection_config(&pConfig);	
			}		
			
			// don't include volatile connectiions in list
			if (bVolatile == false)
			{
				QTableWidgetItem *nameItem=NULL;
				nameItem = new QTableWidgetItem(m_pConnections[i].name, 0);
				if (nameItem != NULL)
					m_pConnectionsTable->setItem(i, 0, nameItem);
					
				QTableWidgetItem *adapterItem=NULL;
				QString adapterTypeStr;
				if (m_pConnections[i].ssid != NULL && m_pConnections[i].ssid[0] != '\0')
					adapterTypeStr = tr("Wireless");
				else
					adapterTypeStr = tr("Wired");
					
				adapterItem = new QTableWidgetItem(adapterTypeStr, 0);
				if (adapterItem != NULL)
					m_pConnectionsTable->setItem(i, 1, adapterItem);
			}	
		}
		m_pConnectionsTable->setSortingEnabled(true);
	}
}

void ConnectMgrDlg::handleConnectionListSelectionChange(void)
{
	QList<QTableWidgetItem*> selectedItems;
	
	selectedItems = m_pConnectionsTable->selectedItems();
	
	if (selectedItems.isEmpty() == false) 
	{
		QTableWidgetItem* selItem = selectedItems.at(0);
		if ((selItem->row() >= 0) && (selItem->row() < m_nConnections))
		{
			if (m_pDeleteConnButton != NULL)
				m_pDeleteConnButton->setEnabled(true);
			if (m_pEditConnButton != NULL)
				m_pEditConnButton->setEnabled(true);
		}
		else
		{
			if (m_pDeleteConnButton != NULL)
				m_pDeleteConnButton->setEnabled(false);
			if (m_pEditConnButton != NULL)
				m_pEditConnButton->setEnabled(false);	
		}
	}
	else
	{
		if (m_pDeleteConnButton != NULL)
			m_pDeleteConnButton->setEnabled(false);
		if (m_pEditConnButton != NULL)
			m_pEditConnButton->setEnabled(false);	
	}
}

void ConnectMgrDlg::deleteSelectedConnection(void)
{
	QList<QTableWidgetItem*> selectedItems;
	
	selectedItems = m_pConnectionsTable->selectedItems();
	
	if (selectedItems.isEmpty() == false) 
	{
		QTableWidgetItem* selItem = selectedItems.at(0);
		if ((selItem->row() >= 0) && (selItem->row() < m_nConnections))
		{
			QTableWidgetItem *nameItem = m_pConnectionsTable->item(selItem->row(), 0);
			QString connName = nameItem->text();
			config_connection *pConfig;
			bool canDelete = true;
			
			// first check if connection is in use
			// if so, don't allow deleting	
			bool success;
			success = XSupWrapper::getConfigConnection(connName,&pConfig);
			if (success == true && pConfig != NULL)
			{
				char *pDeviceName = NULL;
				int retVal;
					
				retVal = xsupgui_request_get_devname(pConfig->device, &pDeviceName);
				if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)
				{
					char *pConnName = NULL;
					retVal = xsupgui_request_get_conn_name_from_int(pDeviceName, &pConnName);
					if (retVal == REQUEST_SUCCESS && pConnName != NULL)
					{
						if (QString(pConnName) == connName)
						{
							QMessageBox::warning(m_pRealForm, tr("Connection In Use"), tr("The connection '%1' cannot be deleted because it is currently in use.  Please disconnect from the network before deleting the connection.").arg(connName));
							canDelete = false;
						}
					}
					if (pConnName != NULL)
						free(pConnName);
				}	
				
				if (pDeviceName != NULL)
					free(pDeviceName);
			}
			
			if (canDelete == true)
			{
				QString message;
			
				// check if is wired and if so is default connection
				if (XSupWrapper::isDefaultWiredConnection(connName))
					message = tr("The connection '%1' is set as the default connection for one of your wired adapters.  Are you sure you want to delete it?").arg(connName);
				else
					message = tr("Are you sure you want to delete the connection '%1'?").arg(connName);
				
				// check if wireless and is in preferred list?
				bool result = XSupWrapper::getConfigConnection(connName, &pConfig);
				if (result == true && pConfig != NULL)
				{
					if (pConfig->priority != DEFAULT_PRIORITY)
						message = tr("The connection '%1' is in your preferred connection list.  Are you sure you want to delete it?").arg(connName);
				}
				else
					pConfig = NULL;
				
				
				if (QMessageBox::question(m_pRealForm, tr("Delete Connection"), 
					message, 
					QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
				{
					bool success;
					config_profiles *pProfile;
					success = XSupWrapper::getConfigProfile(QString(pConfig->profile), &pProfile);
					
					success = XSupWrapper::deleteConnectionConfig(connName);
					if (success == false)
					{
						QMessageBox::critical(m_pRealForm,tr("Error Deleting Connection"), tr("An error occurred when attempting to delete the connection '%1'.  If the connection is in use, please disconnect and try again.").arg(connName));
					}
					else
					{	
						// delete profile and trusted server
						if (pProfile != NULL && XSupWrapper::isProfileInUse(QString(pProfile->name)) == false)
						{
							// if no other connections are using this profile, delete it
							config_trusted_server *pServer;
							XSupWrapper::getTrustedServerForProfile(QString(pProfile->name), &pServer);
							success = XSupWrapper::deleteProfileConfig(QString(pProfile->name));
							
							if (success == false)
							{
								QMessageBox::critical(m_pRealForm, tr("Error Deleting Profile"), tr("An error occurred while attempting to delete the profile '%1'").arg(pProfile->name));
							}
							else
							{
								// delete trusted server
								if (pServer != NULL && XSupWrapper::isTrustedServerInUse(QString(pServer->name)) == false)
									success = XSupWrapper::deleteServerConfig(QString(pServer->name));
								else if (pServer != NULL)
									QMessageBox::critical(m_pRealForm, tr("Error Deleting Trusted Server"), tr("The trused server '%1' cannot be deleted because it is being used by multiple profiles").arg(pServer->name));
							}
							if (pServer != NULL)
								XSupWrapper::freeConfigServer(&pServer);
						}
						else if (pProfile != NULL)
						{
							QMessageBox::critical(m_pRealForm, tr("Error Deleting Profile"), tr("The profile '%1' cannot be deleted because it is being used by multiple connection profiles").arg(pProfile->name));
						}
					
						// save off the config since it changed
						XSupWrapper::writeConfig();
						
						// tell everyone we changed the config
						m_pEmitter->sendConnConfigUpdate();
					}
					if (pProfile != NULL)
						XSupWrapper::freeConfigProfile(&pProfile);
				}
			}
			if (pConfig != NULL)
				XSupWrapper::freeConfigConnection(&pConfig);	
		}	
	}
}

void ConnectMgrDlg::showPriorityDialog()
{
	if (m_pPrefDlg == NULL)
	{
		m_pPrefDlg = new PreferredConnections(m_pConnections, XSupCalls(m_pSupplicant), this, m_pRealForm);
		if (m_pPrefDlg != NULL)
		{
			if (m_pPrefDlg->attach() == false)
				return;
		}

		Util::myConnect(m_pPrefDlg, SIGNAL(close()), this, SLOT(cleanupPriorityDialog()));
		m_pPrefDlg->show();
	}
	else
	{
		m_pPrefDlg->show();
	}
}

void ConnectMgrDlg::cleanupPriorityDialog(void)
{
	if (m_pPrefDlg != NULL)
	{
		Util::myDisconnect(m_pPrefDlg, SIGNAL(close()), this, SLOT(cleanupPriorityDialog()));

		delete m_pPrefDlg;
		m_pPrefDlg = NULL;
	}
}

bool ConnectMgrDlg::isVisible(void)
{
	if (m_pRealForm != NULL)
		return m_pRealForm->isVisible();
	else
		return false;
}

void ConnectMgrDlg::bringToFront(void)
{
	if (m_pRealForm != NULL)
	{
		m_pRealForm->raise();
		m_pRealForm->activateWindow();
	}
}

void ConnectMgrDlg::createNewConnection(void)
{
	if (m_pConnWizard == NULL)
	{
		// create the wizard if it doesn't already exist
		m_pConnWizard = new ConnectionWizard(this, m_pRealForm, m_pEmitter);
		if (m_pConnWizard != NULL)
		{
			if (m_pConnWizard->create() == true)
			{
				Util::myConnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
				Util::myConnect(m_pConnWizard, SIGNAL(finished(bool,const QString &)), this, SLOT(finishConnectionWizard(bool,const QString &)));			
				m_pConnWizard->init();
				m_pConnWizard->show();
			}
			else
			{
				QMessageBox::critical(m_pRealForm, tr("Error"),tr("An error occurred when attempting to launch the Connection Wizard"));
				delete m_pConnWizard;
				m_pConnWizard = NULL;
			}
		}
		else
			QMessageBox::critical(m_pRealForm, tr("Error"),tr("An error occurred when attempting to launch the Connection Wizard"));
	}
	else
	{
		m_pConnWizard->init();
		m_pConnWizard->show();
	}
}

void ConnectMgrDlg::finishConnectionWizard(bool success, const QString &)
{
	if (success == false)
		QMessageBox::critical(m_pRealForm,tr("Error saving connection data"), tr("An error occurred while saving the configuration data you provided."));
	this->cleanupConnectionWizard();
}

void ConnectMgrDlg::cleanupConnectionWizard(void)
{
	if (m_pConnWizard != NULL)
	{
		Util::myDisconnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
		Util::myDisconnect(m_pConnWizard, SIGNAL(finished(bool, const QString &)), this, SLOT(finishConnectionWizard(bool, const QString &)));				
		delete m_pConnWizard;
		m_pConnWizard = NULL;
	}
}

void ConnectMgrDlg::updateConnectionLists(void)
{
	// need to refresh the list of connections
	this->refreshConnectionList();
	this->populateConnectionsList();
	
	// connections changed.  Repopulate combo box
	this->populateWiredConnectionsCombo();
	
	// since the combo box items may have changed, make sure to re-select the right item
	this->updateWiredAutoConnectState();
}

void ConnectMgrDlg::editSelectedConnection(void)
{
	QList<QTableWidgetItem*> selectedItems;
	
	selectedItems = m_pConnectionsTable->selectedItems();
	
	if (selectedItems.isEmpty() == false) 
	{
		QTableWidgetItem* selItem = selectedItems.at(0);
		if ((selItem->row() >= 0) && (selItem->row() < m_nConnections))
		{
			bool success;
			config_connection *pConfig;
			QTableWidgetItem *nameItem = m_pConnectionsTable->item(selItem->row(), 0);
			QString connName = nameItem->text();
			
			success = XSupWrapper::getConfigConnection(connName,&pConfig);
			if (success == true && pConfig != NULL)
			{
				bool editable = true;
				char *pDeviceName = NULL;
				int retVal;
				
				// first check if connection is in use
				// if so, don't allow editing				
				retVal = xsupgui_request_get_devname(pConfig->device, &pDeviceName);
				if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)
				{
					char *pConnName = NULL;
					retVal = xsupgui_request_get_conn_name_from_int(pDeviceName, &pConnName);
					if (retVal == REQUEST_SUCCESS && pConnName != NULL)
					{
						if (QString(pConnName) == connName)
						{
							QMessageBox::warning(m_pRealForm, tr("Connection In Use"), tr("The connection '%1' cannot be edited because it is currently in use.  Please disconnect from the network before editing the connection.").arg(connName));
							editable = false;
						}
					}
					if (pConnName != NULL)
						free(pConnName);
				}	
				
				if (pDeviceName != NULL)
					free(pDeviceName);			
				
				if (editable == true)
				{
					config_profiles *pProfile = NULL;
					config_trusted_server *pServer = NULL;
					
					if (pConfig->profile != NULL)
						success = XSupWrapper::getConfigProfile(QString(pConfig->profile),&pProfile);
						
					if (success == true && pProfile != NULL)
						success = XSupWrapper::getTrustedServerForProfile(QString(pProfile->name),&pServer);
						
					ConnectionWizardData wizData;
					wizData.initFromSupplicantProfiles(pConfig,pProfile,pServer);
					
					if (pConfig != NULL)
						XSupWrapper::freeConfigConnection(&pConfig);
					if (pProfile != NULL)
						XSupWrapper::freeConfigProfile(&pProfile);
					if (pServer != NULL)
						XSupWrapper::freeConfigServer(&pServer);
					
					if (m_pConnWizard == NULL)
					{
						// create the wizard if it doesn't already exist
						m_pConnWizard = new ConnectionWizard(this, m_pRealForm, m_pEmitter);
						if (m_pConnWizard != NULL)
						{
							if (m_pConnWizard->create() == true)
							{
								Util::myConnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
								Util::myConnect(m_pConnWizard, SIGNAL(finished(bool,const QString &)), this, SLOT(finishConnectionWizard(bool,const QString &)));			
								m_pConnWizard->edit(wizData);
								m_pConnWizard->show();
							}
							// else show error?
						}
						// else show error?
					}
					else
					{
						m_pConnWizard->edit(wizData);
						m_pConnWizard->show();
					}	
				}			
			}
		}
	}
}