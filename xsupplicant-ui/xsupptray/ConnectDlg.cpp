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

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

static const char *editConnString = "Edit Connections...";
static const char *seperatorString = "-----";

ConnectDlg::ConnectDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *supplicant)
	: QWidget(parent), 
	m_pParent(parent),
	m_pParentWindow(parentWindow),
	m_pEmitter(e),
	m_pSupplicant(supplicant)
{
	m_pSSIDListDlg = NULL;
	m_pConnWizard = NULL;
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

	Util::myDisconnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(populateConnectionLists()));		
		
	if (m_pSSIDListDlg != NULL)
		delete m_pSSIDListDlg;
		
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

	// These don't do anything (yet) so disable them.
	m_pWiredConnectionInfo->setEnabled(false);
	m_pWirelessConnectionInfo->setEnabled(false);
	
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

	Util::myConnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(populateConnectionLists()));		
	//Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(handleInterfaceInserted(char *)));
	//Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceRemoved(char *)), this, SLOT(slotInterfaceRemoved(char *)));		
	
	// set initial state of UI - mainly setting the active tab
	if (m_pAdapterTabControl != NULL)
	{
		m_pAdapterTabControl->setCurrentIndex(0);
	}
	
	if (m_pWirelessAdapterList != NULL) 
	{
		populateWirelessAdapterList();
		selectWirelessAdapter(0);
	}
	
	if (m_pWiredAdapterList != NULL)
	{
		populateWiredAdapterList();
		selectWiredAdapter(0);
	}
				
	// jking - not sure this button should exist on this screen. hiding for now			
	if (m_pConnWizardButton != NULL)
		m_pConnWizardButton->hide();				
	return true;
}

void ConnectDlg::show(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

void ConnectDlg::populateWirelessAdapterList(void)
{
	int_enum *pInterfaceList = NULL;
	int retVal;	
	
	m_pWirelessAdapterList->clear();
	
	retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
	if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
	{
		int i = 0;
		while (pInterfaceList[i].desc != NULL)
		{
			if (pInterfaceList[i].is_wireless == TRUE)
			{
				m_pWirelessAdapterList->addItem(QString(pInterfaceList[i].desc));
			}
			
			++i;
		}
		xsupgui_request_free_int_enum(&pInterfaceList);
		pInterfaceList = NULL;
		
	}
	else
	{
		// bad things man
	}
}

void ConnectDlg::populateWiredAdapterList(void)
{
	int_enum *pInterfaceList = NULL;
	int retVal;	
	
	m_pWiredAdapterList->clear();
	
	retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
	if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
	{
		int i = 0;
		while (pInterfaceList[i].desc != NULL)
		{
			if (pInterfaceList[i].is_wireless == FALSE)
			{
				m_pWiredAdapterList->addItem(QString(pInterfaceList[i].desc));
			}
			
			++i;
		}
		xsupgui_request_free_int_enum(&pInterfaceList);
		pInterfaceList = NULL;
	}
	else
	{
		// bad things man
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
			int i;
			for (i=0; i<connVector->size(); i++)
				m_pWirelessConnectionList->addItem(connVector->at(i));
				
			delete connVector;
		}
		if (m_pWirelessConnectionList->count() == 0)
			m_pWirelessConnectionList->addItem(QString(""));
		m_pWirelessConnectionList->addItem(seperatorString);		
		m_pWirelessConnectionList->addItem(tr(editConnString));
		
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
	int retVal = 0;
	char *adapterName = NULL;
	char *connName = NULL;

	if (m_pWirelessAdapterList != NULL) {
		m_currentWirelessAdapter = m_pWirelessAdapterList->itemText(index);
		m_pWirelessAdapterList->setToolTip(m_currentWirelessAdapter);
		
		// if selected adapter is invalid, disable browse button
		if (m_pBrowseWirelessNetworksButton != NULL)
			m_pBrowseWirelessNetworksButton->setEnabled(!m_currentWirelessAdapter.isEmpty());
	}
	
	this->populateWirelessConnectionList();
	
	if (m_pWirelessConnectionList != NULL)
		m_pWirelessConnectionList->setCurrentIndex(0);
	m_lastWirelessConnectionIdx = 0;
	selectWirelessConnection(0);	
	
	// need to update status and all that jazz
	retVal = xsupgui_request_get_devname(m_pWirelessAdapterList->currentText().toAscii().data(), &adapterName);	

	if ((retVal == REQUEST_SUCCESS) && (adapterName != NULL))
	{
		// Now, see if we have a connection bound.
		retVal = xsupgui_request_get_conn_name_from_int(adapterName, &connName);
		if ((retVal == REQUEST_SUCCESS) && (connName != NULL))
		{
			m_pWirelessConnectionStack->setCurrentIndex(1);  // Change to the 'connected' page.
			m_pWirelessConnectionName->setText(connName);

			free(connName);

			// Update the current state field.
			updateWirelessState();
		}
		else
		{
			m_pWirelessConnectionStack->setCurrentIndex(0);   // Change to the 'disconnected' page.
			m_pWirelessConnectionStatus->setText(tr("Not Connected"));
		}
	}
	else 
	{
		m_pWirelessConnectionStack->setCurrentIndex(0);  // Change to the 'disconnected' page.
		m_pWirelessConnectionStatus->setText(tr("Not Connected"));
	}
	
	// make sure we free allocated memory
	if (adapterName != NULL)
		xsupgui_request_free_str(&adapterName);
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
			int i;
			for (i=0; i<connVector->size(); i++)
				m_pWiredConnectionList->addItem(connVector->at(i));
				
			delete connVector;
		}
		if (m_pWiredConnectionList->count() == 0)
			m_pWiredConnectionList->addItem(QString(""));
		m_pWiredConnectionList->addItem(seperatorString);
		m_pWiredConnectionList->addItem(tr(editConnString));

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
	char *adapterName = NULL;
	char *connName = NULL;
	int retVal = 0;

	if (m_pWiredAdapterList != NULL) {
		m_currentWiredAdapter = m_pWiredAdapterList->itemText(index);
		m_pWiredAdapterList->setToolTip(m_currentWiredAdapter);
	}
	
	this->populateWiredConnectionList();
	
	if (m_pWiredConnectionList != NULL)
		m_pWiredConnectionList->setCurrentIndex(0);
		
	m_lastWiredConnectionIdx = 0;	
	selectWiredConnection(0);

	// need to update status and all that jazz
	retVal = xsupgui_request_get_devname(m_pWiredAdapterList->currentText().toAscii().data(), &adapterName);	

	if ((retVal == REQUEST_SUCCESS) && (adapterName != NULL))
	{
		// Now, see if we have a connection bound.
		retVal = xsupgui_request_get_conn_name_from_int(adapterName, &connName);
		if ((retVal == REQUEST_SUCCESS) && (connName != NULL))
		{
			m_pWiredConnectionStack->setCurrentIndex(1);  // Change to the 'connected' page.
			m_pWiredConnectionName->setText(connName);

			free(connName);

			// Update the current state field.
			updateWiredState();
		}
		else
		{
			m_pWiredConnectionStack->setCurrentIndex(0);   // Change to the 'disconnected' page.
			m_pWiredConnectionStatus->setText(tr("Not Connected"));
		}
	}
	else 
	{
		m_pWiredConnectionStack->setCurrentIndex(0);  // Change to the 'disconnected' page.
		m_pWiredConnectionStatus->setText(tr("Not Connected"));
	}
	
	// make sure we free allocated memory
	if (adapterName != NULL)
		xsupgui_request_free_str(&adapterName);
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
		if (m_pWirelessConnectionList->itemText(connIdx) == tr(editConnString))
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
		if (m_pWiredConnectionList->itemText(connIdx) == tr(editConnString))
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
			// else show error?
		}
		// else show error?
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
	char *pName = NULL;
	int retval = 0;
	int state = 0;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(interfaceDesc.toAscii().data(), &pDeviceName);
	if ((retval != REQUEST_SUCCESS) || (pDeviceName == NULL))
	{
		// If we can't determine the interface name, then tell the caller the connection isn't
		// active.  (Because we really don't know any better.)
		return false;
	}

	// See if a connection is bound to the interface in question.
	retval = xsupgui_request_get_conn_name_from_int(pDeviceName, &pName);
	if (retval != REQUEST_SUCCESS)
	{
		// We don't know what is bound to the interface, so return false.
		if (pDeviceName != NULL) free(pDeviceName);
		return false;
	}

	// If they match, then check the status of the connection to determine if the connection
	// is active.
	if (connectionName.compare(pName) == 0) 
	{
		if (isWireless)
		{
			retval = xsupgui_request_get_physical_state(pDeviceName, &state);
			if (retval != REQUEST_SUCCESS)
			{
				// We don't know the physical state, so return false.  (After we clean up some memory.)
				if (pDeviceName != NULL) free(pDeviceName);
				if (pName != NULL) free(pName);
				return false;
			}

			if ((state != WIRELESS_INT_STOPPED) && (state != WIRELESS_INT_HELD))
			{
				// The connection appears to be active.
				if (pDeviceName != NULL) free(pDeviceName);
				if (pName != NULL) free(pName);
				return true;
			}
		}
		else
		{
			// It is wired, we only care if it is in 802.1X authenticated state or not.
			retval = xsupgui_request_get_1x_state(pDeviceName, &state);
			if (retval != REQUEST_SUCCESS)
			{
				// We don't know the 802.1X state, so return false.  (After we clean up some memory.)
				if (pDeviceName != NULL) free(pDeviceName);
				if (pName != NULL) free(pName);
				return false;
			}

			if (state != DISCONNECTED)
			{
				// The connection appears to be active.
				if (pDeviceName != NULL) free(pDeviceName);
				if (pName != NULL) free(pName);
				return true;
			}
		}
	}

	if (pDeviceName != NULL) free(pDeviceName);
	if (pName != NULL) free(pName);

	return false;
}

void ConnectDlg::getAndDisplayErrors()
{
  int i = 0;
  QString errors;
  error_messages *msgs = NULL;

  int retval = xsupgui_request_get_error_msgs(&msgs);
  if (retval == REQUEST_SUCCESS)
  {
    if (msgs && msgs[0].errmsgs)
    {
      // If we have at least one message, display it here
      while (msgs[i].errmsgs != NULL)
      {
        errors += QString ("- %1\n").arg(msgs[i].errmsgs);
        i++;
      }

      QMessageBox::critical(NULL, tr("XSupplicant Error Summary"),
		  tr("The following errors were returned from XSupplicant while attempting to connect:\n%1")
        .arg(errors));
    }
  }
  else
  {
    QMessageBox::critical(NULL, tr("Get Error Message error"),
      tr("An error occurred while checking for errors from the XSupplicant."));
  }

  xsupgui_request_free_error_msgs(&msgs);
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

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(interfaceDesc.toAscii().data(), &pDeviceName);
	if ((retval != REQUEST_SUCCESS) || (pDeviceName == NULL))
	{
		// If we can't determine the device name, then tell the caller the connection can't
		// be made.
		return false;
	}

	retval = xsupgui_request_set_connection(pDeviceName, connectionName.toAscii().data());
	if (retval == REQUEST_SUCCESS)
	{
		if (pDeviceName != NULL) free(pDeviceName);
		return true;
	}
	else
	{
		if (retval == IPC_ERROR_NEW_ERRORS_IN_QUEUE)
		{
			getAndDisplayErrors();
			if (pDeviceName != NULL) free(pDeviceName);
			return false;
		}
	}

	if (pDeviceName != NULL) free(pDeviceName);
	return false;
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
	char *pDeviceName = NULL;
	int retval = 0;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_pWirelessAdapterList->currentText().toAscii().data(), &pDeviceName);
	if ((retval != REQUEST_SUCCESS) || (pDeviceName == NULL))
	{
		// If we can't determine the device name, then tell the caller the connection can't
		// be made.
		return;
	}

	retval = xsupgui_request_set_disassociate(pDeviceName, 1);
	if (retval != REQUEST_SUCCESS)
	{
		QMessageBox::critical(NULL, tr("Disconnect Wireless"),
			tr("An error occurred while disassociating device '%1'.\n").arg(m_pWirelessAdapterList->currentText()));

		if (pDeviceName != NULL) free(pDeviceName);

		// We need to remain on the "connected" page, since we can't be sure
		// of the wireless status.
		return;
	}

	// Lock the connection in a disconnected state so that we don't change to something else.
	xsupgui_request_set_connection_lock(pDeviceName, TRUE);

	xsupgui_request_unbind_connection(pDeviceName);

	if (pDeviceName != NULL) free(pDeviceName);

	m_pWirelessConnectionStack->setCurrentIndex(0);   // Set the enabled page.
	m_pWirelessConnectionStatus->setText(tr("Not Connected"));
}

void ConnectDlg::disconnectWiredConnection(void)
{
	char *pDeviceName = NULL;
	int retval = 0;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_pWiredAdapterList->currentText().toAscii().data(), &pDeviceName);
	if ((retval != REQUEST_SUCCESS) || (pDeviceName == NULL))
	{
		// If we can't determine the device name, then tell the caller the connection can't
		// be made.
		return;
	}

	retval = xsupgui_request_logoff(pDeviceName);
	if (retval != REQUEST_SUCCESS)
	{
		QMessageBox::critical(NULL, tr("Disconnect Wired"),
			tr("An error occurred while logging off device '%1'.")
			.arg(m_pWiredAdapterList->currentText()));

		if (pDeviceName != NULL) free(pDeviceName);

		// We need to remain on the "connected" page, since we can't be sure
		// of the wired status.
		return;
	}

	xsupgui_request_unbind_connection(pDeviceName);

	if (pDeviceName != NULL) free(pDeviceName);

	m_pWiredConnectionStack->setCurrentIndex(0);   // Set the enabled page.
	m_pWiredConnectionStatus->setText(tr("Not Connected"));
}

void ConnectDlg::updateWirelessState(void)
{
	char *pDeviceName = NULL;
	int retval = 0;
	int state = 0;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_pWirelessAdapterList->currentText().toAscii().data(), &pDeviceName);
	if ((retval != REQUEST_SUCCESS) || (pDeviceName == NULL))
	{
		// If we can't determine the device name, then tell the caller the connection can't
		// be made.
		return;
	}

	retval = xsupgui_request_get_physical_state(pDeviceName, &state);
	if (retval == REQUEST_SUCCESS)
	{
		switch (state)
		{
		case WIRELESS_UNKNOWN_STATE:
		case WIRELESS_UNASSOCIATED:
		case WIRELESS_ACTIVE_SCAN:
		case WIRELESS_PORT_DOWN:
		case WIRELESS_INT_STOPPED:
		case WIRELESS_INT_HELD:
		case WIRELESS_INT_RESTART:
			m_pWirelessConnectionStatus->setText(tr("Idle"));
			break;

		case WIRELESS_ASSOCIATING:
		case WIRELESS_ASSOCIATION_TIMEOUT_S:
			m_pWirelessConnectionStatus->setText(tr("Connecting..."));
			break;

		case WIRELESS_NO_ENC_ASSOCIATION:
			m_pWirelessConnectionStatus->setText(tr("Connected"));
			break;

		case WIRELESS_ASSOCIATED:
			retval = xsupgui_request_get_1x_state(pDeviceName, &state);
			if (retval == REQUEST_SUCCESS)
			{
				switch (state)
				{
				case LOGOFF:
				case DISCONNECTED:
				case S_FORCE_UNAUTH:
					m_pWirelessConnectionStatus->setText(tr("Idle"));
					break;

				case CONNECTING:
				case ACQUIRED:
				case AUTHENTICATING:
				case RESTART:
					m_pWirelessConnectionStatus->setText(tr("Connecting..."));
					break;

				case HELD:
					m_pWirelessConnectionStatus->setText(tr("Authentication Failed"));
					break;

				case AUTHENTICATED:
				case S_FORCE_AUTH:
					m_pWirelessConnectionStatus->setText(tr("Connected"));
					break;

				default:
					m_pWirelessConnectionStatus->setText(tr("Unknown"));  // This should be impossible!
					break;
				}
			}
			break;

		default:
			m_pWirelessConnectionStatus->setText(tr("Unknown"));  // This should be impossible!
			break;
		}
	}

	if (pDeviceName != NULL) free(pDeviceName);
}

void ConnectDlg::updateWiredState(void)
{
	char *pDeviceName = NULL;
	int retval = 0;
	int state = 0;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_pWiredAdapterList->currentText().toAscii().data(), &pDeviceName);
	if ((retval != REQUEST_SUCCESS) || (pDeviceName == NULL))
	{
		// If we can't determine the device name, then tell the caller the connection can't
		// be made.
		return;
	}

	retval = xsupgui_request_get_1x_state(pDeviceName, &state);
	if (retval == REQUEST_SUCCESS)
	{
		switch (state)
		{
		case LOGOFF:
		case DISCONNECTED:
		case S_FORCE_UNAUTH:
			m_pWiredConnectionStatus->setText(tr("Idle"));
			break;

		case CONNECTING:
		case ACQUIRED:
		case AUTHENTICATING:
		case RESTART:
			m_pWiredConnectionStatus->setText(tr("Connecting..."));
			break;

		case HELD:
			m_pWiredConnectionStatus->setText(tr("Authentication Failed"));
			break;

		case AUTHENTICATED:
		case S_FORCE_AUTH:
			m_pWiredConnectionStatus->setText(tr("Connected"));
			break;

		default:
			m_pWiredConnectionStatus->setText(tr("Unknown"));  // This should be impossible!
			break;
		}
	}

	if (pDeviceName != NULL) free(pDeviceName);
}

