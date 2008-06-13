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

#include "ConnectDlg.h"
#include "FormLoader.h"
#include "Emitter.h"
#include "TrayApp.h"
#include "SSIDListDlg.h"
#include <QVector>
#include <algorithm>

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
		
	Util::myDisconnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(populateConnectionLists()));		
		
	if (m_pSSIDListDlg != NULL)
		delete m_pSSIDListDlg;
		
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
	
	// populate text
	
	// wireless tab
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
	
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
		
	Util::myConnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(populateConnectionLists()));		
	//Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(slotInterfaceInserted(char *)));
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
	if (m_pWirelessAdapterList != NULL)
		m_currentWirelessAdapter = m_pWirelessAdapterList->itemText(index);
	
	this->populateWirelessConnectionList();
	
	if (m_pWirelessConnectionList != NULL)
		m_pWirelessConnectionList->setCurrentIndex(0);
	m_lastWirelessConnectionIdx = 0;
	selectWirelessConnection(0);	
	
	// need to update status and all that jazz
	int retVal;
	char *adapterName = NULL;
	retVal = xsupgui_request_get_devname(this->m_currentWirelessAdapter.toAscii().data(), &adapterName);
	
	if (retVal == REQUEST_SUCCESS && adapterName != NULL)
	{
		int devState;
		retVal = xsupgui_request_get_physical_state(adapterName, &devState);
		if (retVal == REQUEST_SUCCESS)
		{
			
		}
		else
		{
			// show some kind of generic state ("Unknown" perhaps?)
		}
	}
	else 
	{
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
	if (m_pWiredAdapterList != NULL)
		m_currentWiredAdapter = m_pWiredAdapterList->itemText(index);
	
	this->populateWiredConnectionList();
	
	if (m_pWiredConnectionList != NULL)
		m_pWiredConnectionList->setCurrentIndex(0);
		
	m_lastWiredConnectionIdx = 0;	
	selectWiredConnection(0);

	// need to update status and all that jazz
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