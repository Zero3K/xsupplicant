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

#include "SSIDListDlg.h"
#include "FormLoader.h"
#include "Util.h"
#include "wirelessScanDlg.h"
#include "TrayApp.h"
#include "SSIDList.h"
#include "Emitter.h"
#include "XSupWrapper.h"
#include "ConnectionWizard.h"

extern "C"
{
#include "libxsupgui/xsupgui_request.h"
}

// TODO: there's a race condition between finish of wizard (For connecting to 802.1X networks) and the time we try to connect.
// If the user could try to connect to another network during this time (lock out UI, maybe? disable the connect button?)

// TODO: after connecting to network (assuming it succeeds), we should close the SSIDList window and go back to the "connect"
// window to show status.


SSIDListDlg::SSIDListDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *supplicant)
	: QWidget(parent), 
	m_pParent(parent),
	m_pParentWindow(parentWindow),
	m_pEmitter(e),
	m_pSupplicant(supplicant)
{
	m_pRescanDialog = NULL;
	m_pConnWizard = NULL;
}

SSIDListDlg::~SSIDListDlg()
{ 
	if (m_pCloseButton != NULL)
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
	
	if (m_pHelpButton != NULL)
		Util::myDisconnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotShowHelp()));
		
	if (m_pRefreshButton != NULL)
		Util::myDisconnect(m_pRefreshButton, SIGNAL(clicked()), this, SLOT(rescanNetworks()));
		
	if (m_pConnectButton != NULL)
		Util::myDisconnect(m_pConnectButton, SIGNAL(clicked()), this, SLOT(connectToSelectedNetwork()));
	
	if (m_pSSIDList != NULL)
	{
		Util::myDisconnect(m_pSSIDList, SIGNAL(ssidSelectionChange(const WirelessNetworkInfo &)), this, SLOT(handleSSIDListSelectionChange(const WirelessNetworkInfo &)));
		Util::myDisconnect(m_pSSIDList, SIGNAL(ssidDoubleClick(const WirelessNetworkInfo &)), this, SLOT(handleSSIDListDoubleClick(const WirelessNetworkInfo &)));
		delete m_pSSIDList;
	}
		
	if (m_pRealForm != NULL) 
		delete m_pRealForm;	
}

bool SSIDListDlg::initUI()
{
	// load form
	m_pRealForm = FormLoader::buildform("SSIDListWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
	
	Qt::WindowFlags flags;
	
	// set window flags so not minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
		
	// cache off pointers to widget's we'll reference in future
	m_pHelpButton = qFindChild<QPushButton*>(m_pRealForm, "buttonHelp");
	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");
	m_pRefreshButton = qFindChild<QPushButton*>(m_pRealForm, "buttonRefresh");
	m_pConnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonConnect");
	m_pHeaderLabel = qFindChild<QLabel*>(m_pRealForm, "headerAvailableNetworks");
	m_pSSIDTable = qFindChild<QTableWidget*>(m_pRealForm, "dataTableAvailableWirelessNetworks");	
	
	// dynamically populate text in dialog
	if (m_pHelpButton != NULL)
		m_pHelpButton->setText(tr("Help"));
	
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
		
	if (m_pRefreshButton != NULL)
		m_pRefreshButton->setText(tr("Refresh List"));
	
	if (m_pConnectButton != NULL)
		m_pConnectButton->setText(tr("Connect"));
		
	if (m_pHeaderLabel != NULL)
		m_pHeaderLabel->setText(tr("Available Wireless Networks"));
			
			
	// set up event handling
	if (m_pHelpButton != NULL)
	    Util::myConnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotShowHelp()));	
	
	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
	
	if (m_pRefreshButton != NULL)
		Util::myConnect(m_pRefreshButton, SIGNAL(clicked()), this, SLOT(rescanNetworks()));
		
	if (m_pConnectButton != NULL)
		Util::myConnect(m_pConnectButton, SIGNAL(clicked()), this, SLOT(connectToSelectedNetwork()));

	// assume existing rows in table is min we want displayed
	m_pSSIDList = new SSIDList(m_pRealForm, m_pSSIDTable, m_pSSIDTable->rowCount());
	if (m_pSSIDList == NULL)
	{
		// something bad happened
		return false;
	}
	
	// register for events
	Util::myConnect(m_pSSIDList, SIGNAL(ssidSelectionChange(const WirelessNetworkInfo &)), this, SLOT(handleSSIDListSelectionChange(const WirelessNetworkInfo &)));
	Util::myConnect(m_pSSIDList, SIGNAL(ssidDoubleClick(const WirelessNetworkInfo &)), this, SLOT(handleSSIDListDoubleClick(const WirelessNetworkInfo &)));
	
	handleSSIDListSelectionChange(WirelessNetworkInfo());
	
	return true;
}

bool SSIDListDlg::create(void)
{
	return this->initUI();
}

void SSIDListDlg::show(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

void SSIDListDlg::slotShowHelp(void)
{
	HelpWindow::showPage("xsupphelp.html", "xsuploginmain");
}

void SSIDListDlg::rescanNetworks(void)
{
	int retVal;
	char* adapterName = NULL;
	
	// if currently "connected", warn user we may drop their connection
	retVal = xsupgui_request_get_devname(this->m_curAdapter.toAscii().data(), &adapterName);
	if (retVal == REQUEST_SUCCESS && adapterName != NULL)
	{
		int pState;
		bool doScan = true;
		retVal = xsupgui_request_get_physical_state(adapterName, &pState);
		if (retVal != REQUEST_SUCCESS || pState == WIRELESS_ASSOCIATED)
		{
			if (QMessageBox::warning(m_pRealForm, tr("Warning"), tr("Refreshing the list of networks may cause your current connection to be dropped.  Do you wish to proceed?"),
									QMessageBox::Ok|QMessageBox::Cancel, QMessageBox::Ok) != QMessageBox::Ok)
			{
				doScan = false;
			}	
		}
		if (doScan == true)
		{
			// register for notification for when the scan is complete
			Util::myConnect(m_pEmitter, SIGNAL(signalScanCompleteMessage(const QString &)), this, SLOT(wirelessScanComplete(const QString &)));
			
			// request scan for available networks
			retVal = xsupgui_request_wireless_scan(adapterName,FALSE);
			if (retVal == REQUEST_SUCCESS)
			{
				if (m_pRescanDialog == NULL)
				{
					m_pRescanDialog = new WirelessScanDlg(this, m_pRealForm);
					if (m_pRescanDialog != NULL)
					{
						Util::myConnect(m_pRescanDialog,SIGNAL(scanCancelled()), this, SLOT(cancelScan()));
						m_pRescanDialog->show();
					}
				}
				else
				{
					Util::myConnect(m_pRescanDialog,SIGNAL(scanCancelled()), this, SLOT(cancelScan()));
					m_pRescanDialog->show();
				}
			}
		}
		xsupgui_request_free_str(&adapterName);
	}
}

void SSIDListDlg::refreshList(const QString &adapterName)
{
	m_curAdapter = adapterName;
	if (m_pSSIDList != NULL)
		m_pSSIDList->refreshList(adapterName);
}

void SSIDListDlg::wirelessScanComplete(const QString &deviceName)
{
	char* adapterName = NULL;
	int retVal;
	
	// if the device the scan is complete for is what we're waiting on, kill dialog and update list
	retVal = xsupgui_request_get_devdesc(deviceName.toAscii().data(), &adapterName);
	if (retVal == REQUEST_SUCCESS && adapterName == m_curAdapter)
	{
		// unregister for notification
		Util::myDisconnect(m_pEmitter, SIGNAL(signalScanCompleteMessage(const QString &)), this, SLOT(wirelessScanComplete(const QString &)));
		if (m_pRescanDialog != NULL)
			m_pRescanDialog->hide();
		if (m_pSSIDList != NULL)
			m_pSSIDList->refreshList(m_curAdapter);
	}
	xsupgui_request_free_str(&adapterName);
}

void SSIDListDlg::cancelScan(void)
{
	if (m_pRescanDialog != NULL)
		m_pRescanDialog->hide();
	Util::myDisconnect(m_pEmitter, SIGNAL(signalScanCompleteMessage(const QString &)), this, SLOT(wirelessScanComplete(const QString &)));
}

void SSIDListDlg::handleSSIDListSelectionChange(const WirelessNetworkInfo &network)
{
	if (m_pConnectButton != NULL)
		m_pConnectButton->setEnabled(!network.m_name.isEmpty());	
	
	m_selectedNetwork = network;
}

void SSIDListDlg::handleSSIDListDoubleClick(const WirelessNetworkInfo &network)
{
	this->connectToNetwork(network);
}

void SSIDListDlg::connectToSelectedNetwork(void)
{
	if (m_selectedNetwork.m_name.isEmpty() == false)
		this->connectToNetwork(m_selectedNetwork);
}

void SSIDListDlg::connectToNetwork(const WirelessNetworkInfo &netInfo)
{	
	// first, look for existing connection profile
	int retVal;
	bool found = false;
	conn_enum *pConn = NULL;
	
	retVal = xsupgui_request_enum_connections(&pConn);
	
	if (retVal == REQUEST_SUCCESS && pConn != NULL)
	{
		int i = 0;
		while (pConn[i].name != NULL)
		{
			if (QString(pConn[i].ssid) == netInfo.m_name && QString(pConn[i].dev_desc) == m_curAdapter)
			{
				// jking - !!! Right now we're just going with the first match. Ideally we should check
				// if there's more than one connection for this SSID. If so, prompt the user to tell us
				// which one to use.  This should be rare, so punt for now
				char *adapterName= NULL;
				
				found = true;
				retVal = xsupgui_request_get_devname(this->m_curAdapter.toAscii().data(), &adapterName);
				
				if (retVal == REQUEST_SUCCESS && adapterName != NULL)
					retVal = xsupgui_request_set_connection(adapterName, pConn[i].name);

				if (retVal != REQUEST_SUCCESS || adapterName == NULL)
				{
					QString message = tr("An error occurred while connecting to the network '%1'.").arg(netInfo.m_name);
					QMessageBox::critical(m_pRealForm,tr("Error Connecting to Network"),message);
				}
				xsupgui_request_free_str(&adapterName);
				break;
			} 
			i++;
		}
	}
	xsupgui_request_free_conn_enum(&pConn);
	
	// we need to create a connection, profile, etc
	if (found == false)
	{
		QString connName = netInfo.m_name;
		connName.append(tr("_Connection"));
		config_connection *pNewConn;
		if (XSupWrapper::createNewConnection(connName,&pNewConn) && pNewConn != NULL)
		{
			bool runWizard = false;
						
			pNewConn->priority = DEFAULT_PRIORITY;
			pNewConn->ssid = _strdup(netInfo.m_name.toAscii().data());
			
			// jking - note this is a temporary hack.  This is really a bitfield, not a
			// singular value.  For now, assuming values are mutually exclusive. The SSIDList class
			// enforces this assumption at the moment
			switch (netInfo.m_assoc_modes) {
				case WirelessNetworkInfo::SECURITY_NONE:
					pNewConn->association.association_type = ASSOC_OPEN;
					pNewConn->association.auth_type = AUTH_NONE;				
					break;
				case WirelessNetworkInfo::SECURITY_STATIC_WEP:
					pNewConn->association.association_type = ASSOC_OPEN;
					pNewConn->association.auth_type = AUTH_NONE;	
					pNewConn->association.txkey = 1;				
					break;
				case WirelessNetworkInfo::SECURITY_WPA2_PSK:
					pNewConn->association.association_type = ASSOC_WPA2;
					pNewConn->association.auth_type = AUTH_PSK;					
					break;
				case WirelessNetworkInfo::SECURITY_WPA_PSK:
					pNewConn->association.association_type = ASSOC_WPA;
					pNewConn->association.auth_type = AUTH_PSK;				
					break;					
				case WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE:
					pNewConn->association.association_type = ASSOC_WPA2;
					runWizard = true;
					break;
				case WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE:
					pNewConn->association.association_type = ASSOC_WPA;
					runWizard= true;
					break;
			}
			pNewConn->device = _strdup(m_curAdapter.toAscii().data());
			pNewConn->ip.type = CONFIG_IP_USE_DHCP;
			pNewConn->ip.renew_on_reauth = FALSE;
			
			if (runWizard == true)
			{
				// alert user we are launching the wizard
				QString msg = tr("The network '%1' requires some additional information to connect.  The XSupplicant will now launch the Connection Wizard to collect this information. Continue?").arg(netInfo.m_name);
				if (QMessageBox::information(m_pRealForm, tr(""), msg, QMessageBox::Ok | QMessageBox::Cancel) == QMessageBox::Ok)
				{
					if (m_pConnWizard == NULL)
					{
						m_pConnWizard = new ConnectionWizard(this, m_pRealForm, m_pEmitter);
						if (m_pConnWizard != NULL && m_pConnWizard->create() != false)
						{
							// register for cancelled and finished events
							Util::myConnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
							Util::myConnect(m_pConnWizard, SIGNAL(finished(bool, const QString &)), this, SLOT(finishConnectionWizard(bool, const QString &)));
							
							ConnectionWizardData wizData;
							bool success = wizData.initFromSupplicantProfiles(pNewConn,NULL,NULL);
							if (success == true) {
								m_pConnWizard->editDot1XInfo(wizData);
								m_pConnWizard->show();
								}
							else
								cleanupConnectionWizard();
						}
						else
						{
							QMessageBox::critical(m_pRealForm,tr("Error Launching Connection Wizard"), tr("A failure occurred when attempting to launch the Connection Wizard"));
							if (m_pConnWizard != NULL)
								delete m_pConnWizard;
						}
					}
					else
					{
						// already exists.  What to do?
					}
				}
			}
			else
			{
				// set this connection as volatile
				pNewConn->flags |= CONFIG_VOLATILE_CONN;
			
				retVal = xsupgui_request_set_connection_config(pNewConn);
				
				if (retVal == REQUEST_SUCCESS)
				{
					// save off the config since it changed
					if (XSupWrapper::writeConfig() == false)
					{
						// error. what to do here?  For now, fail silently as it's non-fatal
						// perhaps write to log?
					}
					char *adapterName = NULL;
					
					retVal = xsupgui_request_get_devname(this->m_curAdapter.toAscii().data(), &adapterName);
					if (retVal == REQUEST_SUCCESS && adapterName != NULL)			
						retVal = xsupgui_request_set_connection(adapterName, pNewConn->name);
						
					if (retVal != REQUEST_SUCCESS || adapterName == NULL)
					{
						QString message = tr("An error occurred while connecting to the network '%1'.").arg(netInfo.m_name);
						QMessageBox::critical(m_pRealForm,tr("Error Connecting to Network"),message);				
					}
					xsupgui_request_free_str(&adapterName);
				}
				else
				{
					// !!! jking - error, what to do here?
				}
			}
			XSupWrapper::freeConfigConnection(&pNewConn);
		}
	}
}

void SSIDListDlg::finishConnectionWizard(bool success, const QString &connName)
{
	if (success)
	{
		char *adapterName = NULL;
		int retVal;
		
		retVal = xsupgui_request_get_devname(this->m_curAdapter.toAscii().data(), &adapterName);
		if (retVal == REQUEST_SUCCESS && adapterName != NULL)			
			retVal = xsupgui_request_set_connection(adapterName, connName.toAscii().data());
			
		if (retVal != REQUEST_SUCCESS || adapterName == NULL)
		{
			config_connection *pConn = NULL;
			QString message;
			
			success = XSupWrapper::getConfigConnection(connName, &pConn);
			
			if (success == true && pConn != NULL && pConn->ssid != NULL && QString(pConn->ssid).isEmpty() == false)
				message = tr("An error occurred while connecting to the wireless network '%1'.").arg(QString(pConn->ssid));
			else
				message = tr("An error occurred while connecting to the network.");
			QMessageBox::critical(m_pRealForm,tr("Error Connecting to Network"),message);
			
			if (pConn != NULL)
				XSupWrapper::freeConfigConnection(&pConn);			
		}
		xsupgui_request_free_str(&adapterName);	
	}
	this->cleanupConnectionWizard();
}

void SSIDListDlg::cleanupConnectionWizard(void)
{
	if (m_pConnWizard != NULL)
	{
		Util::myDisconnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
		Util::myDisconnect(m_pConnWizard, SIGNAL(finished(bool, const QString &)), this, SLOT(finishConnectionWizard(bool, const QString &)));
	
		delete m_pConnWizard;
		m_pConnWizard = NULL;
	}
}