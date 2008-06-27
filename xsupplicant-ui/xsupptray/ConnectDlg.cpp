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

#include <QVector>
#include <algorithm>

#include "ConnectDlg.h"
#include "FormLoader.h"
#include "Emitter.h"
#include "TrayApp.h"
#include "SSIDListDlg.h"
#include "ConnectionWizard.h"
#include "ConnectionInfoDlg.h"
#include "XSupWrapper.h"

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

static const QString editConnString = QWidget::tr("Edit Connections...");
static const QString seperatorString = "-----";

ConnectDlg::ConnectDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *supplicant)
	: QWidget(parent), 
	m_pParent(parent),
	m_pParentWindow(parentWindow),
	m_pEmitter(e),
	m_pSupplicant(supplicant)
{
	m_pSSIDListDlg = NULL;
	m_pConnWizard = NULL;
	m_pConnInfo = NULL;
	m_days = 0;
}

ConnectDlg::~ConnectDlg()
{ 
	if (m_pCloseButton != NULL)
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
	
	if (m_pBrowseWirelessNetworksButton != NULL)
		Util::myDisconnect(m_pBrowseWirelessNetworksButton, SIGNAL(clicked()), this, SLOT(showSSIDList()));
		
	if (m_pWirelessAdapterList != NULL)
		Util::myConnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
				
	if (m_pWirelessConnectionList != NULL)
		Util::myDisconnect(m_pWirelessConnectionList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessConnection(int)));		
	
	if (m_pWiredAdapterList != NULL)
		Util::myConnect(m_pWiredAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredAdapter(int)));
				
	if (m_pWiredConnectionList != NULL)
		Util::myDisconnect(m_pWiredConnectionList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredConnection(int)));	
		
	if (m_pConnWizardButton != NULL)
		Util::myDisconnect(m_pConnWizardButton, SIGNAL(clicked()), this, SLOT(launchConnectionWizard()));

	if (m_pWiredConnectButton != NULL)
		Util::myDisconnect(m_pWiredConnectButton, SIGNAL(clicked()), this, SLOT(connectWiredConnection()));

	if (m_pWirelessConnectButton != NULL)
		Util::myDisconnect(m_pWirelessConnectButton, SIGNAL(clicked()), this, SLOT(connectWirelessConnection()));

	if (m_pWiredDisconnectButton != NULL)
		Util::myDisconnect(m_pWiredDisconnectButton, SIGNAL(clicked()), this, SLOT(disconnectWiredConnection()));

	if (m_pWirelessDisconnectButton != NULL)
		Util::myDisconnect(m_pWirelessDisconnectButton, SIGNAL(clicked()), this, SLOT(disconnectWirelessConnection()));

	if (m_pAdapterTabControl != NULL)
		Util::myConnect(m_pAdapterTabControl, SIGNAL(currentChanged(int)), this, SLOT(currentTabChanged(int)));
		
	if (m_pWirelessConnectionInfo != NULL)
		Util::myConnect(m_pWirelessConnectionInfo, SIGNAL(clicked()), this, SLOT(showWirelessConnectionInfo()));
		
	if (m_pWiredConnectionInfo != NULL)
		Util::myConnect(m_pWiredConnectionInfo, SIGNAL(clicked()), this, SLOT(showWiredConnectionInfo()));			

	Util::myDisconnect(&m_timer, SIGNAL(timeout()), this, SLOT(timerUpdate()));

	Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(interfaceInserted(char *)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceRemoved(char *)), this, SLOT(interfaceRemoved(char *)));		

	Util::myDisconnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(populateConnectionLists()));		
	Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
		this, SLOT(stateChange(const QString &, int, int, int, unsigned int)));
		
	if (m_pSSIDListDlg != NULL)
		delete m_pSSIDListDlg;
		
	if (m_pConnInfo != NULL)
		delete m_pConnInfo;
		
	this->cleanupConnectionWizard();
		
	if (m_pRealForm != NULL) 
		delete m_pRealForm;	
}

bool ConnectDlg::create(void)
{
	return initUI();
}

bool ConnectDlg::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("ConnectWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
	
	Qt::WindowFlags flags;
	
	// set window flags so minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
		
	// cache pointers to objects on our UI 
	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");
	m_pBrowseWirelessNetworksButton = qFindChild<QPushButton*>(m_pRealForm, "buttonBrowseWireless");
	m_pAdapterTabControl = qFindChild<QTabWidget*>(m_pRealForm, "adapterTypeTabControl");
	m_pWirelessAdapterList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWirelessAdapter");
	m_pWirelessConnectionList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWirelessConnection");
	m_pWiredAdapterList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWiredAdapter");
	m_pWiredConnectionList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWiredConnection");
	m_pWirelessConnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonWirelessConnect");
	m_pWiredConnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonWiredConnect");
	m_pConnWizardButton = qFindChild<QPushButton*>(m_pRealForm, "buttonNewConnection");
	m_pWirelessDisconnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonWirelessDisconnect");
	m_pWiredDisconnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonWiredDisconnect");
	m_pWirelessConnectionName = qFindChild<QLabel*>(m_pRealForm, "labelWirelessConnectionName");
	m_pWiredConnectionName = qFindChild<QLabel*>(m_pRealForm, "labelWiredConnectionName");
	m_pWirelessConnectionStatus = qFindChild<QLabel*>(m_pRealForm, "labelWirelessConnectionStatus");
	m_pWiredConnectionStatus = qFindChild<QLabel*>(m_pRealForm, "labelWiredConnectionStatus");
	m_pWirelessConnectionStack = qFindChild<QStackedWidget*>(m_pRealForm, "stackedWidgetWirelessConnection");
	m_pWiredConnectionStack = qFindChild<QStackedWidget*>(m_pRealForm, "stackedWidgetWiredConnection");
	m_pWiredConnectionInfo = qFindChild<QPushButton*>(m_pRealForm, "buttonWiredConnectionInfo");
	m_pWirelessConnectionInfo = qFindChild<QPushButton*>(m_pRealForm, "buttonWirelessConnectionInfo");

	// populate text
	m_pWirelessConnectionStatus->setText(tr("Idle"));
	m_pWiredConnectionStatus->setText(tr("Idle"));
	
	// wireless tab
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
		
	if (m_pConnWizardButton != NULL)
		m_pConnWizardButton->setText(tr("New Connection"));
	
	if (m_pBrowseWirelessNetworksButton != NULL)
		m_pBrowseWirelessNetworksButton->setText(tr("Browse Networks"));
	
	QLabel *pAdapterLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessAdapter");
	if (pAdapterLabel != NULL)
		pAdapterLabel->setText(tr("Adapter:"));
		
	QLabel *pStatusLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessStatus");
	if (pStatusLabel != NULL)
		pStatusLabel->setText(tr("Status:"));
		
	QLabel *pConnectionLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessConnectConnection");
	if (pConnectionLabel != NULL)
		pConnectionLabel->setText(tr("Connection:"));
		
	pConnectionLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredConnectedConnection");
	if (pConnectionLabel != NULL)
		pConnectionLabel->setText(tr("Connection:"));
			
	pAdapterLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredAdapter");
	if (pAdapterLabel != NULL)
		pAdapterLabel->setText(tr("Adapter:"));
		
	pStatusLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredStatus");
	if (pStatusLabel != NULL)
		pStatusLabel->setText(tr("Status:"));
		
	pConnectionLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredConnectConnection");
	if (pConnectionLabel != NULL)
		pConnectionLabel->setText(tr("Connection:"));
		
	pConnectionLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredConnectedConnection");
	if (pConnectionLabel != NULL)
		pConnectionLabel->setText(tr("Connection:"));
					
	if (m_pAdapterTabControl != NULL)
	{
		m_pAdapterTabControl->setTabText(0,tr("Wireless"));
		m_pAdapterTabControl->setTabText(1,tr("Wired"));
	}

	// set up event-handling
	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));

	if (m_pBrowseWirelessNetworksButton != NULL)
		Util::myConnect(m_pBrowseWirelessNetworksButton, SIGNAL(clicked()), this, SLOT(showSSIDList()));
		
	if (m_pWirelessAdapterList != NULL)
		Util::myConnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
		
	if (m_pWirelessConnectionList != NULL)
		Util::myConnect(m_pWirelessConnectionList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessConnection(int)));
		
	if (m_pWiredAdapterList != NULL)
		Util::myConnect(m_pWiredAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredAdapter(int)));
		
	if (m_pWiredConnectionList != NULL)
		Util::myConnect(m_pWiredConnectionList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredConnection(int)));
		
	if (m_pConnWizardButton != NULL)
		Util::myConnect(m_pConnWizardButton, SIGNAL(clicked()), this, SLOT(launchConnectionWizard()));

	if (m_pWiredConnectButton != NULL)
		Util::myConnect(m_pWiredConnectButton, SIGNAL(clicked()), this, SLOT(connectWiredConnection()));

	if (m_pWirelessConnectButton != NULL)
		Util::myConnect(m_pWirelessConnectButton, SIGNAL(clicked()), this, SLOT(connectWirelessConnection()));

	if (m_pWiredDisconnectButton != NULL)
		Util::myConnect(m_pWiredDisconnectButton, SIGNAL(clicked()), this, SLOT(disconnectWiredConnection()));

	if (m_pWirelessDisconnectButton != NULL)
		Util::myConnect(m_pWirelessDisconnectButton, SIGNAL(clicked()), this, SLOT(disconnectWirelessConnection()));

	if (m_pAdapterTabControl != NULL)
		Util::myConnect(m_pAdapterTabControl, SIGNAL(currentChanged(int)), this, SLOT(currentTabChanged(int)));
		
	if (m_pWirelessConnectionInfo != NULL)
		Util::myConnect(m_pWirelessConnectionInfo, SIGNAL(clicked()), this, SLOT(showWirelessConnectionInfo()));
		
	if (m_pWiredConnectionInfo != NULL)
		Util::myConnect(m_pWiredConnectionInfo, SIGNAL(clicked()), this, SLOT(showWiredConnectionInfo()));		

	Util::myConnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(populateConnectionLists()));		
	Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
		this, SLOT(stateChange(const QString &, int, int, int, unsigned int)));

	Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(interfaceInserted(char *)));
	Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceRemoved(char *)), this, SLOT(interfaceRemoved(char *)));		
	
	Util::myConnect(&m_timer, SIGNAL(timeout()), this, SLOT(timerUpdate()));
	
	// set initial state of UI - mainly setting the active tab
	if (m_pAdapterTabControl != NULL)
		m_pAdapterTabControl->setCurrentIndex(0);
	
	if (m_pWirelessAdapterList != NULL) 
	{
		this->populateWirelessAdapterList();
		this->selectWirelessAdapter(0);
	}
	
	if (m_pWiredAdapterList != NULL)
	{
		this->populateWiredAdapterList();
		this->selectWiredAdapter(0);
	}
				
	// jking - not sure this button should exist on this screen. hiding for now			
	if (m_pConnWizardButton != NULL)
		m_pConnWizardButton->hide();				

	// Initialize the timer that we will use to show the time in connected
	// state.
	m_timer.setInterval(1000);   // Fire every second.

	return true;
}

void ConnectDlg::show(void)
{
	// always start out on wireless tab
	if (m_pAdapterTabControl != NULL)
		m_pAdapterTabControl->setCurrentIndex(0);
	if (m_pWirelessAdapterList != NULL)
	{
		m_pWirelessAdapterList->setCurrentIndex(0);
		this->selectWirelessAdapter(0);	
	}
	
	if (m_pWiredAdapterList != NULL)
	{
		m_pWiredAdapterList->setCurrentIndex(0);
		this->selectWiredAdapter(0);	
	}	
	
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

void ConnectDlg::populateWirelessAdapterList(void)
{
	int_enum *pInterfaceList = NULL;
	int retVal;	
	
	if (m_pWirelessAdapterList != NULL)
	{
		// QT generates events while populating a combobox, so stop listening during this time
		Util::myDisconnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
			
		m_pWirelessAdapterList->clear();
		m_pWirelessAdapterList->setToolTip("");
		
		QVector<QString> adapters;
		adapters = XSupWrapper::getWirelessAdapters();
		for (int i=0; i<adapters.size();i++)
			m_pWirelessAdapterList->addItem(adapters.at(i));
			
		Util::myConnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
	}
}

void ConnectDlg::populateWiredAdapterList(void)
{	
	if (m_pWiredAdapterList != NULL)
	{
		int_enum *pInterfaceList = NULL;
		int retVal;	
	
		// QT generates events while populating a combobox, so stop listening during this time
		Util::myDisconnect(m_pWiredAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredAdapter(int)));
		
		m_pWiredAdapterList->clear();
		m_pWiredAdapterList->setToolTip("");
		
		QVector<QString> adapters;
		adapters = XSupWrapper::getWiredAdapters();
		for (int i=0; i<adapters.size();i++)
			m_pWiredAdapterList->addItem(adapters.at(i));	
		
		Util::myConnect(m_pWiredAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredAdapter(int)));
	}
}

void ConnectDlg::populateConnectionLists(void)
{
	this->populateWirelessConnectionList();
	this->populateWiredConnectionList();
}

void ConnectDlg::populateWirelessConnectionList(void)
{
	if (m_pWirelessConnectionList != NULL)
	{
		QString oldSelection = m_pWirelessConnectionList->itemText(m_pWirelessConnectionList->currentIndex());
		m_pWirelessConnectionList->clear();
		
		QVector<QString> *connVector;
		connVector = this->getConnectionListForAdapter(m_currentWirelessAdapter);
		if (connVector != NULL)
		{
			std::sort(connVector->begin(), connVector->end());
			for (int i=0; i<connVector->size(); i++)
				m_pWirelessConnectionList->addItem(connVector->at(i));
				
			delete connVector;
		}
		if (m_pWirelessConnectionList->count() == 0)
			m_pWirelessConnectionList->addItem(QString(""));
		m_pWirelessConnectionList->addItem(seperatorString);		
		m_pWirelessConnectionList->addItem(editConnString);
		
		// try to restore the previous selection
		int idx = m_pWirelessConnectionList->findText(oldSelection);
		if (idx == -1)
			idx = 0;
		
		m_lastWirelessConnectionIdx = idx;
		m_pWirelessConnectionList->setCurrentIndex(idx);
	}
}

void ConnectDlg::selectWirelessAdapter(int index)
{
	if (m_pWirelessAdapterList != NULL) {
		m_currentWirelessAdapter = m_pWirelessAdapterList->itemText(index);
		m_pWirelessAdapterList->setToolTip(m_currentWirelessAdapter);
		
		// if selected adapter is invalid, disable browse button
		if (m_pBrowseWirelessNetworksButton != NULL)
			m_pBrowseWirelessNetworksButton->setEnabled(!m_currentWirelessAdapter.isEmpty());
	}
	
	this->populateWirelessConnectionList();
	
	if (m_pWirelessConnectionList != NULL) {
		m_pWirelessConnectionList->setCurrentIndex(0);
		m_lastWirelessConnectionIdx = 0;
		this->selectWirelessConnection(0);
	}
	
	this->updateWirelessState();
}

void ConnectDlg::populateWiredConnectionList(void)
{
	if (m_pWiredConnectionList != NULL)
	{
		QString oldSelection = m_pWiredConnectionList->itemText(m_pWiredConnectionList->currentIndex());
		m_pWiredConnectionList->clear();
		
		QVector<QString> *connVector;
		connVector = this->getConnectionListForAdapter(m_currentWiredAdapter);
		if (connVector != NULL)
		{
			std::sort(connVector->begin(), connVector->end());
			for (int i=0; i<connVector->size(); i++)
				m_pWiredConnectionList->addItem(connVector->at(i));
				
			delete connVector;
		}
		if (m_pWiredConnectionList->count() == 0)
			m_pWiredConnectionList->addItem(QString(""));
		m_pWiredConnectionList->addItem(seperatorString);
		m_pWiredConnectionList->addItem(editConnString);

		// try to restore the previous selection
		int idx = m_pWiredConnectionList->findText(oldSelection);
		if (idx == -1)
			idx = 0;
			
		m_lastWiredConnectionIdx = idx;
		m_pWiredConnectionList->setCurrentIndex(idx);
	}
}

void ConnectDlg::selectWiredAdapter(int index)
{
	if (m_pWiredAdapterList != NULL) {
		m_currentWiredAdapter = m_pWiredAdapterList->itemText(index);
		m_pWiredAdapterList->setToolTip(m_currentWiredAdapter);
	}
	
	this->populateWiredConnectionList();
	if (m_pWiredConnectionList != NULL) {
		m_pWiredConnectionList->setCurrentIndex(0);
		m_lastWiredConnectionIdx = 0;		
		this->selectWiredConnection(0);
	}
	
	this->updateWiredState();
}

void ConnectDlg::showSSIDList()
{	
	if (m_pSSIDListDlg == NULL)
	{
		// jking - for now assume this was launched via the connect dialog
		m_pSSIDListDlg = new SSIDListDlg(this, m_pRealForm, m_pEmitter, m_pSupplicant);
		if (m_pSSIDListDlg == NULL || m_pSSIDListDlg->create() == false)
		{
			QMessageBox::critical(m_pRealForm, tr("Form Creation Error"), tr("The SSID List Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
			if (m_pSSIDListDlg != NULL)
			{
				delete m_pSSIDListDlg;
				m_pSSIDListDlg = NULL;
			}			
		}
		else
		{
			m_pSSIDListDlg->refreshList(m_currentWirelessAdapter);
			m_pSSIDListDlg->show();
		}
	}
	else
	{
		m_pSSIDListDlg->refreshList(m_currentWirelessAdapter);
		m_pSSIDListDlg->show();
	}

}

QVector<QString> *ConnectDlg::getConnectionListForAdapter(const QString &adapterDesc)
{
	if (adapterDesc.isEmpty())
		return NULL;
	
	QVector<QString> *retVector = new QVector<QString>();
	if (retVector != NULL)
	{
		conn_enum *pConn;
		int retVal = xsupgui_request_enum_connections(&pConn);
		if (retVal == REQUEST_SUCCESS && pConn != NULL)
		{
			int i = 0;
			while (pConn[i].name != NULL)
			{
				if (pConn[i].dev_desc == adapterDesc)
				{
					config_connection *pConfig;
					retVal = xsupgui_request_get_connection_config(pConn[i].name, &pConfig);
					if (retVal == REQUEST_SUCCESS && pConfig != NULL)
					{
						if ((pConfig->flags & CONFIG_VOLATILE_CONN) == 0)
							retVector->append(QString(pConn[i].name));
						xsupgui_request_free_connection_config(&pConfig);
						
					}
					else
						retVector->append(QString(pConn[i].name));
				}
				++i;
			}
		}
		
		xsupgui_request_free_conn_enum(&pConn);
	}
	
	return retVector;
}

void ConnectDlg::selectWirelessConnection(int connIdx)
{
	if (m_pWirelessConnectionList != NULL)
	{
		if (m_pWirelessConnectionList->itemText(connIdx) == editConnString)
		{
			// this is the "edit connections..." item.  Launch config
			m_pSupplicant->slotLaunchConfig();
			m_pWirelessConnectionList->setCurrentIndex(m_lastWirelessConnectionIdx);
		}
		else if (m_pWirelessConnectionList->itemText(connIdx) == seperatorString)
		{
			// not a valid selection. The "-----" item/separator
			m_pWirelessConnectionList->setCurrentIndex(m_lastWirelessConnectionIdx);
		}
		else
			m_lastWirelessConnectionIdx = connIdx;
			
		if (m_pWirelessConnectButton != NULL)
		{
			QString curConnName = m_pWirelessConnectionList->itemText(m_pWirelessConnectionList->currentIndex());
			m_pWirelessConnectButton->setEnabled(!curConnName.isEmpty());
		}			
	}
}

void ConnectDlg::selectWiredConnection(int connIdx)
{
	if (m_pWiredConnectionList != NULL)
	{
		if (m_pWiredConnectionList->itemText(connIdx) == editConnString)
		{
			// this is the "edit connections..." item.  Launch config
			m_pSupplicant->slotLaunchConfig();
			m_pWiredConnectionList->setCurrentIndex(m_lastWiredConnectionIdx);
		}
		else if (m_pWiredConnectionList->itemText(connIdx) == seperatorString)
		{
			// not a valid selection. The "-----" item/separator
			m_pWiredConnectionList->setCurrentIndex(m_lastWiredConnectionIdx);
		}
		else
			m_lastWiredConnectionIdx = connIdx;
			
		if (m_pWiredConnectButton != NULL)
		{
			QString curConnName = m_pWiredConnectionList->itemText(m_pWiredConnectionList->currentIndex());
			m_pWiredConnectButton->setEnabled(!curConnName.isEmpty());
		}
	}
}

void ConnectDlg::launchConnectionWizard(void)
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
				Util::myConnect(m_pConnWizard, SIGNAL(finished(bool)), this, SLOT(finishConnectionWizard(bool)));
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

void ConnectDlg::finishConnectionWizard(bool success)
{
	this->cleanupConnectionWizard();
}

void ConnectDlg::cleanupConnectionWizard(void)
{
	if (m_pConnWizard != NULL)
	{
		Util::myDisconnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
		Util::myDisconnect(m_pConnWizard, SIGNAL(finished(bool)), this, SLOT(finishConnectionWizard(bool)));
	
		delete m_pConnWizard;
		m_pConnWizard = NULL;
	}
}

/**
 * \brief Determine if the connection named \ref connectName is already active and
 *        in a connected or authenticated state.
 *
 * @param[in] interfaceDesc   The interface description we are looking at.
 * @param[in] connectionName   The description of the connection we want to check.
 * @param[in] isWireless   Is the interface wireless or not?
 *
 * \retval true if it is in use
 * \retval false if it isn't in use
 **/
bool ConnectDlg::isConnectionActive(QString interfaceDesc, QString connectionName, bool isWireless)
{
	char *pDeviceName = NULL;
	int retval = 0;
	bool isActive = false;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(interfaceDesc.toAscii().data(), &pDeviceName);
	if (retval == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		char *pName = NULL;
		
		// See if a connection is bound to the interface in question.
		retval = xsupgui_request_get_conn_name_from_int(pDeviceName, &pName);
		if (retval = REQUEST_SUCCESS && pName != NULL)
		{
			// If they match, then check the status of the connection to determine if the connection
			// is active.
			if (connectionName.compare(pName) == 0) 
			{
				int state = 0;
				
				if (isWireless == true)
				{
					if (xsupgui_request_get_physical_state(pDeviceName, &state) == REQUEST_SUCCESS)
					{
						if ((state != WIRELESS_INT_STOPPED) && (state != WIRELESS_INT_HELD))
							isActive = true;
					}
				}
				else
				{
					// It is wired, we only care if it is in 802.1X authenticated state or not.
					if (xsupgui_request_get_1x_state(pDeviceName, &state) == REQUEST_SUCCESS)
						isActive = (state != DISCONNECTED);
				}
			}
		}
		
		if (pName != NULL)
			free(pName);			
	}

	if (pDeviceName != NULL) 
		free(pDeviceName);

	return false;
}

/**
 * \brief Issue a request to the engine to establish a connection.
 *
 * @param[in] interfaceDesc   The interface description that we want to use with the
 *							  connection.
 * @param[in] connectionName   The connection name that we want the interface to attach to.
 *
 * \retval true if the connection attempt should succeed.
 * \retval false if the connection attempt failed.
 **/
bool ConnectDlg::connectToConnection(QString interfaceDesc, QString connectionName)
{
	char *pDeviceName = NULL;
	int retval = 0;
	bool success = false;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(interfaceDesc.toAscii().data(), &pDeviceName);
	if (retval == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		retval = xsupgui_request_set_connection(pDeviceName, connectionName.toAscii().data());
		if (retval == REQUEST_SUCCESS)
			success = true;
		else if (retval == IPC_ERROR_NEW_ERRORS_IN_QUEUE)
			XSupWrapper::getAndDisplayErrors();
	}

	if (pDeviceName != NULL)
		free(pDeviceName);
		
	return success;
}

void ConnectDlg::connectWirelessConnection(void)
{
	// If the connection is already the active one, then ignore it.
	if (!isConnectionActive(m_pWirelessAdapterList->currentText(), m_pWirelessConnectionList->currentText(), true))
	{
		if (!connectToConnection(m_pWirelessAdapterList->currentText(), m_pWirelessConnectionList->currentText()))
		{
			QMessageBox::critical(this, tr("Connection Error"), tr("Unable to establish a wireless connection."));
		}
		else
		{
			m_pWirelessConnectionName->setText(m_pWirelessConnectionList->currentText());
			m_pWirelessConnectionStack->setCurrentIndex(1);  // Set the disabled page.
		}
	}
}

void ConnectDlg::connectWiredConnection(void)
{
	// If the connection is already the active one, then ignore it.
	if (!isConnectionActive(m_pWiredAdapterList->currentText(), m_pWiredConnectionList->currentText(), false))
	{
		if (!connectToConnection(m_pWiredAdapterList->currentText(), m_pWiredConnectionList->currentText()))
		{
			QMessageBox::critical(this, tr("Connection Error"), tr("Unable to establish a wired connection."));
		}
		else
		{
			m_pWiredConnectionName->setText(m_pWiredConnectionList->currentText());
			m_pWiredConnectionStack->setCurrentIndex(1);   // Set the disabled page.
		}
	}
}

void ConnectDlg::disconnectWirelessConnection(void)
{
	bool success;
	
	success = XSupWrapper::disconnectAdapter(m_currentWirelessAdapter);
	if (success == true)
	{
		stopAndClearTimer();	
	}
	else
	{
		QMessageBox::critical(NULL, tr("Disconnect Wireless"),
			tr("An error occurred while disconnecting device '%1'.\n").arg(m_currentWirelessAdapter));	
	}
}

void ConnectDlg::disconnectWiredConnection(void)
{
	bool success;
	
	success = XSupWrapper::disconnectAdapter(m_currentWiredAdapter);
	if (success == true)
	{
		stopAndClearTimer();	
	}
	else
	{
		QMessageBox::critical(NULL, tr("Disconnect Wired"),
			tr("An error occurred while disconnecting device '%1'.\n").arg(m_currentWiredAdapter));		
	}	
}

void ConnectDlg::updateWirelessState(void)
{
	char *pDeviceName = NULL;
	int retVal = 0;

	// Using the device description - get the device name
	retVal = xsupgui_request_get_devname(m_currentWirelessAdapter.toAscii().data(), &pDeviceName);
	if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		int state = 0;
		Util::ConnectionStatus status = Util::status_idle;
		
		if (xsupgui_request_get_physical_state(pDeviceName, &state) == REQUEST_SUCCESS)
		{
			if (state != WIRELESS_ASSOCIATED)
			{
				status = Util::getConnectionStatusFromPhysicalState(state);
				if (m_pWirelessConnectionStatus != NULL)
					m_pWirelessConnectionStatus->setText(Util::getConnectionTextFromConnectionState(status));
				if (status == Util::status_connected)
					this->startConnectedTimer(QString(pDeviceName));
				else
					this->stopAndClearTimer();				
			}
			else
			{
				if (xsupgui_request_get_1x_state(pDeviceName, &state) == REQUEST_SUCCESS)
				{
					status = Util::getConnectionStatusFromDot1XState(state);
					if (m_pWirelessConnectionStatus != NULL)
						m_pWirelessConnectionStatus->setText(Util::getConnectionTextFromConnectionState(status));
					if (status == Util::status_connected)
						this->startConnectedTimer(QString(pDeviceName));
					else
						this->stopAndClearTimer();	
				}
			}
		}
		if (status == Util::status_idle)
		{
			if (m_pWirelessConnectionStack != NULL)
				m_pWirelessConnectionStack->setCurrentIndex(0);  // Change to the 'connect' page.
		}
		else
		{
			if (m_pWirelessConnectionStack != NULL)
				m_pWirelessConnectionStack->setCurrentIndex(1);  // Change to the 'connected' page.
			
			// get name of connection that's bound
			char *connName;
			retVal = xsupgui_request_get_conn_name_from_int(pDeviceName, &connName);
			if (retVal == REQUEST_SUCCESS && connName != NULL)
				m_pWirelessConnectionName->setText(connName);	
			else
				m_pWirelessConnectionName->setText(QString(""));
				
			if (connName != NULL)
				free(connName);				
		}
	}
	else
	{
		if (m_pWirelessConnectionStack != NULL)
			m_pWirelessConnectionStack->setCurrentIndex(0);  // Change to the 'connect' page.
	}
		
	if (pDeviceName != NULL) 
		free(pDeviceName);
}

void ConnectDlg::updateWiredState(void)
{
	char *pDeviceName = NULL;
	int retVal = 0;
	
	// Using the device description - get the device name
	retVal = xsupgui_request_get_devname(m_currentWiredAdapter.toAscii().data(), &pDeviceName);
	if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		int state = 0;
		Util::ConnectionStatus status = Util::status_idle;

		if (xsupgui_request_get_1x_state(pDeviceName, &state) == REQUEST_SUCCESS)
		{
			status = Util::getConnectionStatusFromDot1XState(state);
			if (m_pWiredConnectionStatus != NULL)
				m_pWiredConnectionStatus->setText(Util::getConnectionTextFromConnectionState(status));
			if (status == Util::status_connected)
				this->startConnectedTimer(QString(pDeviceName));
			else
				this->stopAndClearTimer();	
		}
		
		if (status == Util::status_idle)
		{
			if (m_pWiredConnectionStack != NULL)
				m_pWiredConnectionStack->setCurrentIndex(0);  // Change to the 'connect' page.
		}
		else
		{
			if (m_pWiredConnectionStack != NULL)
			m_pWiredConnectionStack->setCurrentIndex(1);  // Change to the 'connected' page.
			
			// get name of connection that's bound
			char *connName;
			retVal = xsupgui_request_get_conn_name_from_int(pDeviceName, &connName);
			if (retVal == REQUEST_SUCCESS && connName != NULL)
				m_pWirelessConnectionName->setText(connName);	
			else
				m_pWirelessConnectionName->setText(QString(""));
				
			if (connName != NULL)
				free(connName);				
		}		
	}
	else
	{
		if (m_pWiredConnectionStack != NULL)
			m_pWiredConnectionStack->setCurrentIndex(0);  // Change to the 'connect' page.		
	}

	if (pDeviceName != NULL) 
		free(pDeviceName);
}

void ConnectDlg::timerUpdate(void)
{
	if ((m_time.hour() == 23) && (m_time.minute() == 59) && (m_time.second() == 59))
	{
		// We are about to roll a day.
		m_days++;
		m_time.setHMS(0, 0, 0);
	}
	else
	{
		m_time = m_time.addSecs(1);
	}

	this->showTime();
}

void ConnectDlg::startConnectedTimer(QString adapterName)
{
	long int seconds = 0;
	int retval = 0;

	retval = xsupgui_request_get_seconds_authenticated(adapterName.toAscii().data(), &seconds);
	if (retval == REQUEST_SUCCESS)
	{
		long int tempTime = seconds;
		int hours = 0;
		int minutes = 0;
    
		// Get days, hours, minutes and seconds the hard way - for now
		m_days = (unsigned int)(tempTime / (60*60*24));
		tempTime = tempTime % (60*60*24);
		hours = (int) (tempTime / (60*60));
		tempTime = tempTime % (60*60);
		minutes = (int) tempTime / 60;
		seconds = tempTime % 60;

		m_time.setHMS(hours, minutes, seconds);

		this->showTime();

		m_timer.start(1000);
	}
}

void ConnectDlg::showTime()
{
	QString timeTxt = Util::getConnectionTextFromConnectionState(Util::status_connected);

	if (m_days > 0)
		timeTxt.append(QString("  (%1d, %2)").arg(m_days).arg(m_time.toString(Qt::TextDate)));
	else
		timeTxt.append(QString("  (%1)").arg(m_time.toString(Qt::TextDate)));

	if (m_pAdapterTabControl->currentIndex() == 0)
	{
		// We are showing wireless.
		m_pWirelessConnectionStatus->setText(timeTxt);
	}
	else
	{
		// We are showing wired.
		m_pWiredConnectionStatus->setText(timeTxt);
	}
}

void ConnectDlg::currentTabChanged(int tabidx)
{
	if (tabidx == 0)
	{
		// This is a wireless tab.
		this->updateWirelessState();
	}
	else
	{
		// This is a wired tab.
		this->updateWiredState();
	}
}

void ConnectDlg::stopAndClearTimer(void)
{
	m_timer.stop();
	m_time.setHMS(0, 0, 0);
}

void ConnectDlg::stateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid)
{
	// We only care if it is the adapter that is currently displayed.
	if (m_pAdapterTabControl != NULL)
	{
		QString currentAdapterDesc;
		bool wireless;
		
		if (m_pAdapterTabControl->currentIndex() == 0)
		{
			currentAdapterDesc = m_currentWirelessAdapter;
			wireless = true;
		}
		else
		{
			currentAdapterDesc = m_currentWiredAdapter;
			wireless = false;
		}
			
		// Using the device description - get the device name
		int retVal;
		char *pDeviceName;
		
		retVal = xsupgui_request_get_devname(currentAdapterDesc.toAscii().data(), &pDeviceName);
		if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)
		{
			if (intName == QString(pDeviceName))
			{
				if (wireless == true)
					this->updateWirelessState();
				else
					this->updateWiredState();
			}
		}
		
		if (pDeviceName != NULL)
			free(pDeviceName);
	}
}

void ConnectDlg::showWirelessConnectionInfo(void)
{
	if (m_pConnInfo == NULL)
	{
		m_pConnInfo= new ConnectionInfoDlg(this, m_pRealForm, m_pEmitter);
		if (m_pConnInfo != NULL && m_pConnInfo->create() != false)
		{
			m_pConnInfo->setAdapter(m_currentWirelessAdapter);
			m_pConnInfo->show();
		}
		else
			QMessageBox::critical(m_pRealForm, tr("Error"), tr("An error occurred when trying to launch the Connection Info dialog"));
	}
	else
	{
		m_pConnInfo->setAdapter(m_currentWirelessAdapter);
		m_pConnInfo->show();
	}
}

void ConnectDlg::showWiredConnectionInfo(void)
{
	if (m_pConnInfo == NULL)
	{
		m_pConnInfo= new ConnectionInfoDlg(this, m_pRealForm, m_pEmitter);
		if (m_pConnInfo != NULL && m_pConnInfo->create() != false)
		{
			m_pConnInfo->setAdapter(m_currentWiredAdapter);
			m_pConnInfo->show();
		}
		else
			QMessageBox::critical(m_pRealForm, tr("Error"), tr("An error occurred when trying to launch the Connection Info dialog"));
	}
	else
	{
		m_pConnInfo->setAdapter(m_currentWiredAdapter);
		m_pConnInfo->show();
	}
}

void ConnectDlg::interfaceInserted(char *intName)
{
	int_enum *liveInts = NULL;

	if (xsupgui_request_enum_live_ints(&liveInts) == REQUEST_SUCCESS)
	{
		int i = 0;
		while ((liveInts[i].desc != NULL) && (strcmp(liveInts[i].name, intName) != 0))
			i++;

		if (liveInts[i].desc != NULL)
		{
			if (liveInts[i].is_wireless == TRUE)
				m_pWirelessAdapterList->addItem(liveInts[i].desc);
			else
				m_pWiredAdapterList->addItem(liveInts[i].desc);
		}
				
		xsupgui_request_free_int_enum(&liveInts);
	}
}

// !!! TODO: what if was selected item?!?!?!
void ConnectDlg::interfaceRemoved(char *intDesc)
{
	int index = 0;

	index = m_pWirelessAdapterList->findText(intDesc, Qt::MatchExactly);
	if (index < 0)
	{
		// It wasn't a wireless interface, so look in wired.
		index = m_pWiredAdapterList->findText(intDesc, Qt::MatchExactly);
		if (index >= 0)
			m_pWiredAdapterList->removeItem(index);
	}
	else
	{
		m_pWirelessAdapterList->removeItem(index);
	}
}


