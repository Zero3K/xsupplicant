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
#include <QLabel>
#include <QList>

#include <algorithm>

ConnectMgrDlg::ConnectMgrDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *supplicant)
	: QWidget(parent),
	m_pParent(parent),
	m_pEmitter(e),
	m_pSupplicant(supplicant),
	m_pParentWindow(parentWindow)
{
	m_pConnections = NULL;
	m_pPrefDlg = NULL;
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
		
	if (m_pWiredAutoConnect != NULL)
		Util::myDisconnect(m_pWiredAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(wiredAutoConnectStateChanged(int)));		

	if (m_pPrefDlg != NULL)
		delete m_pPrefDlg;
		
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
		
	if (m_pWiredAutoConnect != NULL)
		Util::myConnect(m_pWiredAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(wiredAutoConnectStateChanged(int)));
		
	if (m_pNetworkPrioritiesButton != NULL)
		Util::myConnect(m_pNetworkPrioritiesButton, SIGNAL(clicked()), this, SLOT(showPriorityDialog()));
		
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
	
	// TODO: read state from config file rather than init here
	if (m_pWiredAutoConnect != NULL)
		this->wiredAutoConnectStateChanged(m_pWiredAutoConnect->checkState());
		
	return true;	
}

bool ConnectMgrDlg::create(void)
{
	return this->initUI();
}

void ConnectMgrDlg::show(void)
{
	// every time we show this, refresh the connection list in case it changed
	this->refreshConnectionList();
	this->populateConnectionsList();
	this->populateWiredConnectionsCombo();

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
	int i,retval = 0;
	conn_enum *pConn;
	retval = xsupgui_request_enum_connections(&pConn);
	if (retval == REQUEST_SUCCESS && pConn)
	{
		if (m_pConnections != NULL)
			xsupgui_request_free_conn_enum(&m_pConnections);

		// count connections
		m_nConnections = 0;
		i = 0;
		while (pConn[i].name != NULL)
		{
			++m_nConnections;
			++i;
		}
			
		m_pConnections = pConn;
	}	
}

void ConnectMgrDlg::populateWiredConnectionsCombo(void)
{
	if (m_pWiredConnections != NULL)
	{
		m_pWiredConnections->clear();
		m_pWiredConnections->addItem(tr("<None>"));	
		
		if (m_pConnections != NULL)
		{	
			// create sorted list of wired connections
			QVector<QString> wiredConnVector;
			
			int i;
			for (i=0; i<m_nConnections; i++)
			{
				if (m_pConnections[i].ssid == NULL)
					wiredConnVector.append(QString(m_pConnections[i].name));
			}
			
			// we now have vector of connections. Now sort them.
			std::sort(wiredConnVector.begin(), wiredConnVector.end());
			
			for (i=0; i<wiredConnVector.size(); i++)
				m_pWiredConnections->addItem(wiredConnVector.at(i));
		}
	}
}

void ConnectMgrDlg::populateConnectionsList(void)
{
	if (m_pConnections != NULL)
	{
		int i=0;
	
		// clear table before re-populating
		m_pConnectionsTable->clearContents();
		
		// make sure we have enough rows in the table
		m_pConnectionsTable->setRowCount(std::max<int>(this->m_minConnListRowCount, m_nConnections));
		m_pConnectionsTable->setSortingEnabled(false);
		
		for (i=0; i<m_nConnections; i++)
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
			
			if (QMessageBox::question(m_pRealForm, tr("Delete a Connection"), 
				tr("Are you sure you want to delete the connection '%1'?").arg(connName), 
				QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
			{
				bool success;
				success = XSupWrapper::deleteConnectionConfig(connName);
				if (success == false)
				{
					QMessageBox::critical(m_pRealForm,tr("Error Deleting Connection"), tr("An error occurred when attempting to delete the connection '%1'.  If the connection is in use, please disconnect and try again.").arg(connName));
				}
				else
				{
					// need to refresh the list of connections
					this->refreshConnectionList();
					this->populateConnectionsList();
					
					// save off the config since it changed
					XSupWrapper::writeConfig();
				}
			}		
		}	
	}
}

void ConnectMgrDlg::wiredAutoConnectStateChanged(int newState)
{
	if (m_pWiredConnections != NULL)
	{
		m_pWiredConnections->setEnabled(newState != Qt::Unchecked);
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
		// show it if it's here?
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