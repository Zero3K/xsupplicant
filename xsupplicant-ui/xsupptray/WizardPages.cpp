/**
 * The XSupplicant User Interface is Copyright 2007, 2008, 2009 Nortel Networks.
 * Nortel Networks provides the XSupplicant User Interface under dual license terms.
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
 *   Nortel Networks for an OEM Commercial License.
 **/
 
 #include "stdafx.h"
 
 #include "WizardPages.h"
 #include "FormLoader.h"
 #include "SSIDList.h"
 #include "XSupWrapper.h"
 
extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

 WizardPage::WizardPage(QWidget *parent, QWidget *parentWidget)
	: QWidget(parent)
{
	m_pParent = parent;
	m_pParentWidget = parentWidget;
}

WizardPageNetworkType::WizardPageNetworkType(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageNetworkType::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageNetworkType.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Please indicate the type of network you would like to connect to:"));
		
	m_pRadioButtonWired = qFindChild<QRadioButton*>(m_pRealForm, "radioWired");
	if (m_pRadioButtonWired != NULL)
		m_pRadioButtonWired->setText(tr("Wired"));
		
	m_pRadioButtonWireless = qFindChild<QRadioButton*>(m_pRealForm, "radioWireless");
	if (m_pRadioButtonWireless != NULL)
		m_pRadioButtonWireless->setText(tr("Wireless"));
		
	// other initializations
	if (m_pRadioButtonWired != NULL)
		m_pRadioButtonWired->setChecked(true);
		
	// get list of adapters. If no wireless or no wired, disable that option
	int_enum *pInterfaceList = NULL;
	int retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
	if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
	{
		m_numWiredAdapters = 0;
		m_numWirelessAdapters = 0;
		int i = 0;
		while (pInterfaceList[i].desc != NULL)
		{
			if (pInterfaceList[i].is_wireless == TRUE)
				++m_numWirelessAdapters;
			else
				++m_numWiredAdapters;
				
			++i;
		}		
		
		// if no adapters, don't want to disable both so do nothing
		if (m_numWiredAdapters != 0 || m_numWirelessAdapters != 0)
		{
			if (m_pRadioButtonWireless != NULL)
				m_pRadioButtonWireless->setDisabled(m_numWirelessAdapters == 0);
				
			if (m_pRadioButtonWired != NULL)
				m_pRadioButtonWired->setDisabled(m_numWiredAdapters == 0);
		}
				
	}
	if (pInterfaceList != NULL)
	{
		xsupgui_request_free_int_enum(&pInterfaceList);
		pInterfaceList = NULL;
	}
		
	return true;
}

void WizardPageNetworkType::init(const ConnectionWizardData &data)
{
	m_curData = data;

	// assume one of radio buttons isn't diabled
	if (m_curData.m_wireless == true)
	{
		if (m_pRadioButtonWireless != NULL)
		{
			if (m_pRadioButtonWireless->isEnabled() == true)
				m_pRadioButtonWireless->setChecked(true);
			else
			{
				// if no wireless adapters, connection must be wired
				m_curData.m_wireless = false;
				if (m_pRadioButtonWired != NULL)
				{
					// assume it's enabled. Should check, and error out if not
					m_pRadioButtonWired->setChecked(true);
				}
			}
		}
	}
	else
	{
		if (m_pRadioButtonWired != NULL)
		{
			if (m_pRadioButtonWired->isEnabled() == true)
				m_pRadioButtonWired->setChecked(true);
			else
			{
				// if no wireless adapters, connection must be wired
				m_curData.m_wireless = true;
				if (m_pRadioButtonWireless != NULL)
				{
					// assume it's enabled. Should check, and error out if not
					m_pRadioButtonWireless->setChecked(true);
				}
			}
		}
	}
}


const ConnectionWizardData &WizardPageNetworkType::wizardData(void)
{

	if (m_pRadioButtonWireless != NULL && m_pRadioButtonWireless->isChecked() == true)
		m_curData.m_wireless = true;
	else
		m_curData.m_wireless = false;
		
	return m_curData;
}

WizardPageWiredSecurity::WizardPageWiredSecurity(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageWiredSecurity::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageWiredSecurity.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("What type of network security (if any) is employed on the network to which you wish to connect?"));
		
	m_pRadioButtonDot1X = qFindChild<QRadioButton*>(m_pRealForm, "radioDot1X");
	if (m_pRadioButtonDot1X != NULL)
		m_pRadioButtonDot1X->setText(tr("802.1X (default)"));
		
	m_pRadioButtonNone = qFindChild<QRadioButton*>(m_pRealForm, "radioNone");
	if (m_pRadioButtonNone != NULL)
		m_pRadioButtonNone->setText(tr("None"));
		
	// other initializations
	if (m_pRadioButtonDot1X != NULL)
		m_pRadioButtonDot1X->setChecked(true);
		
	return true;
}

void WizardPageWiredSecurity::init(const ConnectionWizardData &data)
{
	m_curData = data;

	if (m_curData.m_wiredSecurity == true)
	{
		if (m_pRadioButtonDot1X != NULL)
			m_pRadioButtonDot1X->setChecked(true);
	}
	else
	{
		if (m_pRadioButtonNone != NULL)
			m_pRadioButtonNone->setChecked(true);
	}
}

const ConnectionWizardData& WizardPageWiredSecurity::wizardData(void)
{
	if (m_pRadioButtonDot1X != NULL && m_pRadioButtonDot1X->isChecked() == true)
		m_curData.m_wiredSecurity = true;
	else if (m_pRadioButtonNone != NULL && m_pRadioButtonNone->isChecked() == true)
		m_curData.m_wiredSecurity = false;
	
	return m_curData;
}

WizardPageIPOptions::WizardPageIPOptions(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageIPOptions::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageIPOptions.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("How would you like to obtain an IP address? <i>(If you are unsure, use the default setting)<i>"));
		
	m_pRadioButtonAuto = qFindChild<QRadioButton*>(m_pRealForm, "radioAuto");
	if (m_pRadioButtonAuto != NULL)
		m_pRadioButtonAuto->setText(tr("Obtain an IP Address Automatically (default)"));
		
	m_pRadioButtonStatic = qFindChild<QRadioButton*>(m_pRealForm, "radioStatic");
	if (m_pRadioButtonStatic != NULL)
		m_pRadioButtonStatic->setText(tr("Use Static IP Address Settings"));
		
	// other initializations
	if (m_pRadioButtonAuto != NULL)
		m_pRadioButtonAuto->setChecked(true);
		
	return true;
}

void WizardPageIPOptions::init(const ConnectionWizardData &data)
{
	m_curData = data;
	if (m_curData.m_staticIP == true)
	{
		if (m_pRadioButtonStatic != NULL)
			m_pRadioButtonStatic->setChecked(true);
	}
	else
	{
		if (m_pRadioButtonAuto != NULL)
			m_pRadioButtonAuto->setChecked(true);
	}
}

const ConnectionWizardData &WizardPageIPOptions::wizardData(void)
{
	if (m_pRadioButtonAuto != NULL && m_pRadioButtonAuto->isChecked())
		m_curData.m_staticIP = false;
	else if (m_pRadioButtonStatic != NULL && m_pRadioButtonStatic->isChecked())
		m_curData.m_staticIP = true;

	return m_curData;
}

WizardPageStaticIP::WizardPageStaticIP(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageStaticIP::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageStaticIP.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
		
	// cache off pointers to UI objects
	m_pIPAddress = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldIPAddress");
	m_pNetmask = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldNetmask");
	m_pGateway = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldGateway");
	m_pPrimaryDNS = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldPrimaryDNS");
	m_pSecondaryDNS = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldSecondaryDNS");
	
	// dynamically populate text
	QLabel *pLabel = qFindChild<QLabel*>(m_pRealForm, "headerStaticIP");
	if (pLabel != NULL)
		pLabel->setText(tr("Static IP Address Settings"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelIPAddress");
	if (pLabel != NULL)
		pLabel->setText(tr("IP Address:"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelNetMask");
	if (pLabel != NULL)
		pLabel->setText(tr("Netmask:"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelGateway");
	if (pLabel != NULL)
		pLabel->setText(tr("Gateway:"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "headerStaticDNS");
	if (pLabel != NULL)
		pLabel->setText(tr("Static DNS Settings"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelPrimaryDNS");
	if (pLabel != NULL)
		pLabel->setText(tr("Primary:"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelSecondaryDNS");
	if (pLabel != NULL)
		pLabel->setText(tr("Secondary:"));								
		
	// other initializations
	if (m_pIPAddress != NULL)
		m_pIPAddress->setValidator(new QRegExpValidator(QRegExp("^(?:(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pIPAddress));
	if (m_pNetmask != NULL)
		m_pNetmask->setValidator(new QRegExpValidator(QRegExp("^(?:(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pNetmask));
	if (m_pGateway != NULL)
		m_pGateway->setValidator(new QRegExpValidator(QRegExp("^(?:(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pGateway));
	if (m_pPrimaryDNS != NULL)
		m_pPrimaryDNS->setValidator(new QRegExpValidator(QRegExp("^(?:(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pPrimaryDNS));
	if (m_pSecondaryDNS != NULL)
		m_pSecondaryDNS->setValidator(new QRegExpValidator(QRegExp("^(?:(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}(?:[3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pSecondaryDNS));
		
	return true;
}

void WizardPageStaticIP::init(const ConnectionWizardData &data)
{
	m_curData = data;

	if (m_pIPAddress != NULL)
		m_pIPAddress->setText(m_curData.m_IPAddress);
		
	if (m_pNetmask != NULL)
		m_pNetmask->setText(m_curData.m_netmask);
		
	if (m_pGateway != NULL)
		m_pGateway->setText(m_curData.m_gateway);
		
	if (m_pPrimaryDNS != NULL)
		m_pPrimaryDNS->setText(m_curData.m_primaryDNS);
		
	if (m_pSecondaryDNS != NULL)
		m_pSecondaryDNS->setText(m_curData.m_secondaryDNS);
}

const ConnectionWizardData &WizardPageStaticIP::wizardData(void)
{
	if (m_pIPAddress != NULL)
		m_curData.m_IPAddress = m_pIPAddress->text();
		
	if (m_pNetmask != NULL)
		m_curData.m_netmask = m_pNetmask->text();
		
	if (m_pGateway != NULL)
		m_curData.m_gateway = m_pGateway->text();
		
	if (m_pPrimaryDNS != NULL)
		m_curData.m_primaryDNS = m_pPrimaryDNS->text();
		
	if (m_pSecondaryDNS != NULL)
		m_curData.m_secondaryDNS = m_pSecondaryDNS->text();	

	return m_curData;
}

bool WizardPageStaticIP::validate(void)
{
	// the QLineEdit validator does most of the work for us.
	// just query the text fields
	if (m_pIPAddress != NULL)
	{
		if ((m_pIPAddress->hasAcceptableInput() == false)
			|| (Util::isIPAddrValid(m_pIPAddress->text()) == false))
		{
			QMessageBox::warning(m_pRealForm, tr("Invalid IP Address"), tr("Please provide a valid IP Address"));
			return false;
		}
	}
	
	if (m_pNetmask != NULL)
	{
		if ((m_pNetmask->hasAcceptableInput() == false) 
			|| (Util::isNetmaskValid(m_pNetmask->text()) == false))
		{
			QMessageBox::warning(m_pRealForm, tr("Invalid Netmask"), tr("Please provide a valid Netmask"));
			return false;
		}	
	}
		
	if (m_pPrimaryDNS != NULL)
	{
		if ((m_pPrimaryDNS->hasAcceptableInput() == false) || (Util::isIPAddrValid(m_pPrimaryDNS->text()) == false))
		{
			QMessageBox::warning(m_pRealForm, tr("Invalid Primary DNS Server"), tr("Please provide a valid Primary DNS Server address"));
			return false;
		}			
	}	
	
	if (m_pSecondaryDNS != NULL)
	{
		if ((m_pSecondaryDNS->text() != "") && ((m_pSecondaryDNS->hasAcceptableInput() == false)
			|| (Util::isIPAddrValid(m_pSecondaryDNS->text()) == false)))
		{
			QMessageBox::warning(m_pRealForm, tr("Invalid Secondary DNS Server"), tr("Please provide a valid Secondary DNS Server address"));
			return false;
		}			
	}
	
	return true;
}

WizardPageFinished::WizardPageFinished(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageFinished::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageFinished.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache off pointers to objects	
	m_pConnectionName = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldConnectionName");
	m_pConnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonConnect");
		
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Your network connection is now configured.\n\nPlease enter a name for the connection profile and press \"Finish\" to close the wizard."));	

	QLabel *pConnNameLabel = qFindChild<QLabel*>(m_pRealForm, "labelConnectionName");
	if (pConnNameLabel != NULL)
		pConnNameLabel->setText(tr("Connection Name:"));
		
	if (m_pConnectButton != NULL)
		m_pConnectButton->setText(tr("Connect"));
		
	if (m_pConnectButton != NULL)
		m_pConnectButton->hide();
		
	return true;
}

void WizardPageFinished::init(const ConnectionWizardData &data)
{
	m_curData = data;
	
	if (m_pConnectionName != NULL)
	{
		m_pConnectionName->setText(m_curData.m_connectionName);
		m_pConnectionName->selectAll();
		m_pConnectionName->setFocus();
	}
}

bool WizardPageFinished::validate(void)
{
	if (m_pConnectionName != NULL)
	{
		if (m_pConnectionName->text().isEmpty())
		{
			QMessageBox::warning(m_pRealForm, tr("Invalid Connection Name"), tr("Please input a valid name for the connection."));
			return false;
		}
		
		if (m_curData.m_newConnection == true)
		{
			config_connection *pConfig = NULL;	
	  
			QString connName = m_pConnectionName->text();
			if ((XSupWrapper::getConfigConnection(CONFIG_LOAD_GLOBAL, connName, &pConfig) == true) ||
				(XSupWrapper::getConfigConnection(CONFIG_LOAD_USER, connName, &pConfig) == true))
			{
				XSupWrapper::freeConfigConnection(&pConfig);
				
				//show dialog
				QMessageBox::warning(m_pRealForm, tr("Duplicate Connection Name"), tr("A connection already exists with the name you have provided.  Please choose another name."));
				return false;
			}
		}
		
		return true;
	}
	
	return false;
}
const ConnectionWizardData &WizardPageFinished::wizardData(void)
{
	if (m_pConnectionName != NULL) {
		m_curData.m_connectionName = m_pConnectionName->text();
		m_curData.m_profileName = m_curData.m_connectionName;
		m_curData.m_profileName.append(QWidget::tr("_Profile"));
		
		m_curData.m_serverName = m_curData.m_connectionName;
		m_curData.m_serverName.append(QWidget::tr("_Server"));		
	}
	
	return m_curData;
}

WizardPageWirelessNetwork::WizardPageWirelessNetwork(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

WizardPageWirelessNetwork::~WizardPageWirelessNetwork()
{
	if (m_pRadioButtonVisible != NULL)
		Util::myDisconnect(m_pRadioButtonVisible, SIGNAL(clicked(bool)), this, SLOT(handleVisibleClicked(bool)));
	if (m_pSSIDList != NULL) 
	{
		Util::myDisconnect(m_pSSIDList, SIGNAL(ssidSelectionChange(const WirelessNetworkInfo &)), this, SLOT(handleSSIDSelection(const WirelessNetworkInfo &)));	
		delete m_pSSIDList;
	}
}

bool WizardPageWirelessNetwork::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageWirelessNetwork.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache pointers to UI objets
	m_pRadioButtonVisible = qFindChild<QRadioButton*>(m_pRealForm, "radioVisible");
	m_pRadioButtonOther = qFindChild<QRadioButton*>(m_pRealForm, "radioOther");
	m_pTableWidget = qFindChild<QTableWidget*>(m_pRealForm, "dataTableAvailableWirelessNetworks");
	
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Choose a wireless network from the list to connect to, or choose \"Other\" to enter network information manually."));
		
	if (m_pRadioButtonVisible != NULL)
		m_pRadioButtonVisible->setText(tr("Visible Network"));
		
	if (m_pRadioButtonOther != NULL)
		m_pRadioButtonOther->setText(tr("Other"));
				
	if (m_pTableWidget != NULL)
	{
		m_pSSIDList = new SSIDList(this, m_pTableWidget,m_pTableWidget->rowCount());
		if (m_pSSIDList == NULL)
		{
			// something bad happened
			return false;
		}
		else
		{
			m_pSSIDList->hideColumn(SSIDList::COL_802_11);
		}
	}

	// set up event handling
	if (m_pRadioButtonVisible != NULL)
		Util::myConnect(m_pRadioButtonVisible, SIGNAL(clicked(bool)), this, SLOT(handleVisibleClicked(bool)));	
	if (m_pSSIDList != NULL)
		Util::myConnect(m_pSSIDList, SIGNAL(ssidSelectionChange(const WirelessNetworkInfo &)), this, SLOT(handleSSIDSelection(const WirelessNetworkInfo &)));			
	
		
	return true;
}

void WizardPageWirelessNetwork::handleVisibleClicked(bool checked)
{
	if (checked == true && m_pTableWidget != NULL)
		m_pTableWidget->setFocus();
}

void WizardPageWirelessNetwork::handleSSIDSelection(const WirelessNetworkInfo &networkData)
{
	// if user selects network, check the "visible" radio button
	if (networkData.m_name.isEmpty() == false)
	{
		if (m_pRadioButtonVisible != NULL)
		{
			m_pRadioButtonVisible->setChecked(true);
			this->handleVisibleClicked(true);
		}
	}
	m_networkInfo = networkData;
}

void WizardPageWirelessNetwork::init(const ConnectionWizardData &data)
{
	m_curData = data;
	if (m_pSSIDList != NULL) {
		m_pSSIDList->refreshCompleteList();
		
		// ensure something's selected
		if (m_pTableWidget != NULL)
			m_pTableWidget->selectRow(0);
	}

	if (m_curData.m_networkName.isEmpty() == true)
	{
		// if nothing selected yet, just choose one
		if (m_pTableWidget != NULL)
			m_pTableWidget->selectRow(0);
		if (m_curData.m_otherNetwork == true)
		{
			if (m_pRadioButtonOther != NULL)
				m_pRadioButtonOther->setChecked(true);
		}
		else if (m_pRadioButtonVisible != NULL) 
		{
			m_pRadioButtonVisible->setChecked(true);
			this->handleVisibleClicked(true);
		}
	}
	else
	{
		// look if it's in list. If so, choose it.  Otherwise select "other"
		if (m_pSSIDList->selectNetwork(m_curData.m_networkName) == true)
		{
			if(m_pRadioButtonVisible != NULL)
			{
				m_pRadioButtonVisible->setChecked(true);
				this->handleVisibleClicked(true);
			}
		}
		else
		{
			if (m_pRadioButtonOther != NULL)
				m_pRadioButtonOther->setChecked(true);
		}
		
	}
}

const ConnectionWizardData &WizardPageWirelessNetwork::wizardData(void)
{
	// if "other" is checked, no data on this screen worth saving off
	if (m_pRadioButtonVisible != NULL && m_pRadioButtonVisible->isChecked() == true)
	{
		m_curData.m_networkName = m_networkInfo.m_name;
		m_curData.m_otherNetwork = false;
		if (!m_networkInfo.m_name.isEmpty())
		{
			// set association mode. This is really a bitfield, but for now
			// the SSIDList sets modes as mutually exclusive
			switch (m_networkInfo.m_assoc_modes) {
				case WirelessNetworkInfo::SECURITY_NONE:
					m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_none;			
					break;
				case WirelessNetworkInfo::SECURITY_STATIC_WEP:
					m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WEP;		
					break;
				case WirelessNetworkInfo::SECURITY_WPA2_PSK:
					m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WPA2_PSK;				
					break;
				case WirelessNetworkInfo::SECURITY_WPA_PSK:	
					m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_PSK;		
					break;					
				case WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE:
					m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WPA2_ENT;
					break;
				case WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE:
					m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_ENT;
					break;
			}
		}
	}
	else if (m_pRadioButtonOther != NULL && m_pRadioButtonOther->isChecked() == true)
		m_curData.m_otherNetwork = true;
	
	return m_curData;
}

bool WizardPageWirelessNetwork::validate(void)
{
	if (m_pRadioButtonOther != NULL && m_pRadioButtonOther->isChecked() == true)
		return true;
	else if (m_pRadioButtonVisible != NULL && m_pRadioButtonVisible->isChecked() == true)
	{
		if (!m_networkInfo.m_name.isEmpty())
			return true;
	}
	
	return false;
}

WizardPageWirelessInfo::WizardPageWirelessInfo(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

WizardPageWirelessInfo::~WizardPageWirelessInfo()
{
	if (m_pHiddenNetwork != NULL)
		Util::myDisconnect(m_pHiddenNetwork,SIGNAL(stateChanged(int)), this, SLOT(hiddenStateChanged(int)));
		
	if (m_pAssocMode != NULL)
		Util::myDisconnect(m_pAssocMode, SIGNAL(currentIndexChanged(int)), this, SLOT(assocModeChanged(int)));
}

bool WizardPageWirelessInfo::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageWirelessInfo.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache pointers to UI objets
	m_pNetworkName = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldNetworkName");
	m_pAssocMode = qFindChild<QComboBox*>(m_pRealForm, "comboBoxSecurity");
	m_pEncryption = qFindChild<QComboBox*>(m_pRealForm, "comboBoxEncryption");
	m_pHiddenNetwork = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxHidden");
	
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Please provide details about the wireless network you would like to connect to.  If you are unsure of this information, click \"Back\" and choose from the list of visible wireless networks."));
		
	if (m_pHiddenNetwork != NULL)
		m_pHiddenNetwork->setText(tr("Hidden Network"));
		
	QLabel *pLabel = qFindChild<QLabel *>(m_pRealForm, "labelName");
	if (pLabel != NULL)
		pLabel->setText(tr("Network Name:"));
		
	pLabel = qFindChild<QLabel *>(m_pRealForm, "labelSecurity");
	if (pLabel != NULL)
		pLabel->setText(tr("Network Security:"));
		
	m_pEncryptionLabel = qFindChild<QLabel *>(m_pRealForm, "labelEncryption");
	if (m_pEncryptionLabel != NULL)
		m_pEncryptionLabel->setText(tr("Encryption:"));	
		
	if (m_pAssocMode != NULL)
	{
		m_pAssocMode->clear();
		m_pAssocMode->addItem(tr("<None>"));
		m_pAssocMode->addItem(tr("WEP"));
		m_pAssocMode->addItem(tr("WPA-Personal"));
		m_pAssocMode->addItem(tr("WPA-Enterprise"));
		m_pAssocMode->addItem(tr("WPA2-Personal"));
		m_pAssocMode->addItem(tr("WPA2-Enterprise"));
	}			
		
	if (m_pEncryption != NULL)
	{
		m_pEncryption->clear();
		m_pEncryption->addItem(tr("TKIP"));
		m_pEncryption->addItem(tr("CCMP"));
		m_pEncryption->addItem(tr("WEP"));		
	}
		
	// set up event handling
	if (m_pHiddenNetwork != NULL)
		Util::myConnect(m_pHiddenNetwork,SIGNAL(stateChanged(int)), this, SLOT(hiddenStateChanged(int)));
		
	if (m_pAssocMode != NULL)
		Util::myConnect(m_pAssocMode, SIGNAL(currentIndexChanged(int)), this, SLOT(assocModeChanged(int)));
	
	// other initializations
	if (m_pHiddenNetwork != NULL) {
		m_pHiddenNetwork->setCheckState(Qt::Unchecked);
		this->hiddenStateChanged(Qt::Unchecked);	
	}
	
	if (m_pNetworkName != NULL)
		m_pNetworkName->setValidator(new QRegExpValidator(QRegExp("^[\\w|\\W]{1,32}$"), m_pNetworkName));
	return true;
}

void WizardPageWirelessInfo::init(const ConnectionWizardData &data)
{
	m_curData =  data;

	if (m_pNetworkName != NULL)
		m_pNetworkName->setText(m_curData.m_networkName);
		
	// update assoc mode first before updating UI based on hidden state
	if (m_pAssocMode != NULL)
	{
		switch (m_curData.m_wirelessAssocMode)
		{
			case ConnectionWizardData::assoc_none:
				m_pAssocMode->setCurrentIndex(0);
				break;
			case ConnectionWizardData::assoc_WEP:
				m_pAssocMode->setCurrentIndex(1);
				break;
			case ConnectionWizardData::assoc_WPA_PSK:
				m_pAssocMode->setCurrentIndex(2);
				break;
			case ConnectionWizardData::assoc_WPA_ENT:
				m_pAssocMode->setCurrentIndex(3);
				break;
			case ConnectionWizardData::assoc_WPA2_PSK:
				m_pAssocMode->setCurrentIndex(4);
				break;
			case ConnectionWizardData::assoc_WPA2_ENT:
				m_pAssocMode->setCurrentIndex(5);
				break;
		}
	}
	
	if (m_pEncryption != NULL)
	{
		switch (m_curData.m_wirelessEncryptMeth)
		{
			case ConnectionWizardData::encrypt_CCMP:
				m_pEncryption->setCurrentIndex(1);
				break;
			case ConnectionWizardData::encrypt_TKIP:
				m_pEncryption->setCurrentIndex(0);
				break;
			case ConnectionWizardData::encrypt_WEP:
				m_pEncryption->setCurrentIndex(2);
				break;
		}
	}
	
	if (m_pHiddenNetwork != NULL) {
		m_pHiddenNetwork->setChecked(m_curData.m_hiddenNetwork);
		this->hiddenStateChanged(m_curData.m_hiddenNetwork ? Qt::Checked : Qt::Unchecked);
	}	
}

const ConnectionWizardData &WizardPageWirelessInfo::wizardData(void)
{
	if (m_pNetworkName != NULL)
		m_curData.m_networkName = m_pNetworkName->text();
		
	if (m_pAssocMode != NULL)
	{
		int curIdx = m_pAssocMode->currentIndex();
		switch (curIdx)
		{
			case 0:
				m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_none;
				break;
			case 1:
				m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WEP;
				break;
			case 2:
				m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_PSK;
				break;
			case 3:
				m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_ENT;
				break;
			case 4:
				m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WPA2_PSK;
				break;
			case 5:
				m_curData.m_wirelessAssocMode = ConnectionWizardData::assoc_WPA2_ENT;
				break;																									
			default:
				// error
				break;
		}
	}
				
	if (m_pEncryption != NULL)
	{
		int curIdx = m_pEncryption->currentIndex();
		switch (curIdx)
		{
			case 0:
				m_curData.m_wirelessEncryptMeth = ConnectionWizardData::encrypt_TKIP;
				break;
			case 1:
				m_curData.m_wirelessEncryptMeth = ConnectionWizardData::encrypt_CCMP;
				break;
			case 2:
				m_curData.m_wirelessEncryptMeth = ConnectionWizardData::encrypt_WEP;
				break;
			default:
				// error
				break;
		}
	}
	
	if (m_pHiddenNetwork != NULL)
		m_curData.m_hiddenNetwork = m_pHiddenNetwork->isChecked();	

	return m_curData;
}

bool WizardPageWirelessInfo::validate(void)
{
	if (m_pNetworkName != NULL)
	{
		if (m_pNetworkName->hasAcceptableInput() == false)
		{
			QMessageBox::warning(m_pRealForm, tr("Invalid Network Name"), tr("The name you entered for the wireless network is invalid"));
			return false;
		}
	}
	
	return true;
}

void WizardPageWirelessInfo::assocModeChanged(int newIndex)
{
	if (m_pAssocMode != NULL && m_pHiddenNetwork != NULL)
	{
		// only care about changes if network is hidden
		if (m_pHiddenNetwork->isChecked() == true)
		{
			bool enable = true;
			
			// if "none" or "WEP", don't need encryption mode
			if (newIndex == 0 || newIndex == 1)
				enable = false;
				
		if (m_pEncryption != NULL)
			m_pEncryption->setEnabled(enable);
		if (m_pEncryptionLabel != NULL)
			m_pEncryptionLabel->setEnabled(enable);					
		} 
	}
}

void WizardPageWirelessInfo::hiddenStateChanged(int newState)
{
	bool enable = true;
	switch (newState) {
		case Qt::Unchecked:
			enable = false;
			break;
		case Qt::Checked:
			{
			// if WPA/WPA2-PSK/ENT, we need to know the encryption method to use
			if (m_pAssocMode != NULL && (m_pAssocMode->currentIndex() == 0 || m_pAssocMode->currentIndex() == 1))
				enable = false;
			else
				enable = true;				
			break;
			}
		default:
			break;
	}
	if (m_pEncryption != NULL)
		m_pEncryption->setEnabled(enable);
	if (m_pEncryptionLabel != NULL)
		m_pEncryptionLabel->setEnabled(enable);		
}

WizardPageDot1XProtocol::WizardPageDot1XProtocol(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageDot1XProtocol::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageDot1XProtocol.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache off pointers to objects	
	m_pProtocol = qFindChild<QComboBox*>(m_pRealForm, "comboBoxProtocol");
		
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Indicate the EAP protocol to use for 802.1X authentication:"));	

	QLabel *pProtocolLabel = qFindChild<QLabel*>(m_pRealForm, "labelProtocol");
	if (pProtocolLabel != NULL)
		pProtocolLabel->setText(tr("Protocol:"));
		
	if (m_pProtocol != NULL)
	{
		m_pProtocol->clear();
		m_pProtocol->addItem(tr("EAP-PEAP"));
		m_pProtocol->addItem(tr("EAP-TTLS"));
		m_pProtocol->addItem(tr("EAP-TLS"));
		m_pProtocol->addItem(tr("EAP-FAST"));
		m_pProtocol->addItem(tr("EAP-AKA"));
		m_pProtocol->addItem(tr("EAP-SIM"));
		m_pProtocol->addItem(tr("EAP-MD5"));
	}
		
	return true;
}

void WizardPageDot1XProtocol::init(const ConnectionWizardData &data)
{
	m_curData = data;

	if (m_pProtocol != NULL)
	{
		m_pProtocol->clear();
		m_pProtocol->addItem(tr("EAP-PEAP"));
		m_pProtocol->addItem(tr("EAP-TTLS"));
		m_pProtocol->addItem(tr("EAP-TLS"));
		m_pProtocol->addItem(tr("EAP-FAST"));
		m_pProtocol->addItem(tr("EAP-AKA"));
		m_pProtocol->addItem(tr("EAP-SIM"));

		// EAP-MD5 not allowed for wireless connections
		if (m_curData.m_wireless == false)
			m_pProtocol->addItem(tr("EAP-MD5"));

		switch (m_curData.m_eapProtocol)
		{
			case ConnectionWizardData::eap_peap:
				m_pProtocol->setCurrentIndex(0);
				break;
			case ConnectionWizardData::eap_ttls:
				m_pProtocol->setCurrentIndex(1);
				break;
			case ConnectionWizardData::eap_tls:
				m_pProtocol->setCurrentIndex(2);
				break;
			case ConnectionWizardData::eap_fast:
				m_pProtocol->setCurrentIndex(3);
				break;
			case ConnectionWizardData::eap_aka:
				m_pProtocol->setCurrentIndex(4);
				break;
			case ConnectionWizardData::eap_sim:
				m_pProtocol->setCurrentIndex(5);
				break;
			case ConnectionWizardData::eap_md5:
				m_pProtocol->setCurrentIndex(6);
				break;
			default:
				m_pProtocol->setCurrentIndex(0);
				break;
		}
	}
}

const ConnectionWizardData &WizardPageDot1XProtocol::wizardData(void)
{
	if (m_pProtocol != NULL)
	{
		switch (m_pProtocol->currentIndex())
		{
			case 0:
				// EAP-PEAP
				m_curData.m_eapProtocol = ConnectionWizardData::eap_peap;
				break;
			case 1:
				// EAP-TTLS
				m_curData.m_eapProtocol = ConnectionWizardData::eap_ttls;
				break;
			case 2:
				// EAP-TLS
				m_curData.m_eapProtocol = ConnectionWizardData::eap_tls;
				break;
			case 3:
				// EAP-FAST
				m_curData.m_eapProtocol = ConnectionWizardData::eap_fast;
				break;
			case 4:
				// EAP-AKA
				m_curData.m_eapProtocol = ConnectionWizardData::eap_aka;
				break;
			case 5:
				// EAP-SIM
				m_curData.m_eapProtocol = ConnectionWizardData::eap_sim;
				break;
			case 6:
				// EAP-MD5
				m_curData.m_eapProtocol = ConnectionWizardData::eap_md5;
				break;
			default:
				break;
		}
	}

	return m_curData;
}

WizardPageDot1XInnerProtocol::WizardPageDot1XInnerProtocol(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageDot1XInnerProtocol::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageDot1XInnerProtocol.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache off pointers to objects	
	m_pProtocol = qFindChild<QComboBox*>(m_pRealForm, "comboBoxProtocol");
	m_pOuterID = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldOuterID");
	m_pValidateCert = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxValidateCert");
		
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Enter your PEAP settings for 802.1X authentication below.  The Outer Identity will be sent unencrypted."));	

	QLabel *pProtocolLabel = qFindChild<QLabel*>(m_pRealForm, "labelProtocol");
	if (pProtocolLabel != NULL)
		pProtocolLabel->setText(tr("Tunnel Protocol:"));
		
	QLabel *pOuterIDLabel = qFindChild<QLabel*>(m_pRealForm, "labelOuterID");
	if (pOuterIDLabel != NULL)
		pOuterIDLabel->setText(tr("Outer Identity:"));
		
	QLabel *pOptionalLabel = qFindChild<QLabel*>(m_pRealForm, "labelOptional");
	if (pOptionalLabel != NULL)
		pOptionalLabel->setText(tr("(Optional)"));			
		
	if (m_pValidateCert != NULL)
		m_pValidateCert->setText(tr("Validate Server Certificate"));
		
	if (m_pProtocol != NULL)
		m_pProtocol->clear();
		
	return true;
}

void WizardPageDot1XInnerProtocol::init(const ConnectionWizardData &data)
{
	m_curData = data;
	
	m_pSessionResume = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxSessionResume");

	// populate this label dynamically because the text references the outer protocol used
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
	{
		if (m_curData.m_eapProtocol == ConnectionWizardData::eap_peap)
		{
			pMsgLabel->setText(tr("Enter your PEAP settings for 802.1X authentication below.  The Outer Identity will be sent unencrypted."));
			if (m_pSessionResume != NULL)
				m_pSessionResume->setText(tr("Use Fast Reconnect"));
		}
		else if (m_curData.m_eapProtocol == ConnectionWizardData::eap_ttls)
		{
			pMsgLabel->setText(tr("Enter your TTLS settings for 802.1X authentication below.  The Outer Identity will be sent unencrypted."));	
			if (m_pSessionResume != NULL)
				m_pSessionResume->setText(tr("Use Session Resumption"));
		}
	}
			
	if (m_pOuterID != NULL)
		m_pOuterID->setText(m_curData.m_outerIdentity);
		
	if (m_pValidateCert != NULL)
		m_pValidateCert->setChecked(m_curData.m_validateCert);

	if (m_pSessionResume != NULL)
		m_pSessionResume->setChecked(m_curData.m_useSessionResume);
	
	if (m_pProtocol != NULL)
	{
		m_pProtocol->clear();	
		if (m_curData.m_eapProtocol == ConnectionWizardData::eap_peap)
		{
			m_pProtocol->addItem("EAP-MSCHAPv2");
			m_pProtocol->addItem("EAP-GTC");
			
			if (m_curData.m_innerPEAPProtocol == ConnectionWizardData::inner_eap_mschapv2)
				m_pProtocol->setCurrentIndex(0);
			else if (m_curData.m_innerPEAPProtocol == ConnectionWizardData::inner_eap_gtc)
				m_pProtocol->setCurrentIndex(1);
			else
				; // error
		}
		else if (m_curData.m_eapProtocol == ConnectionWizardData::eap_ttls)
		{
			m_pProtocol->addItem("PAP");
			m_pProtocol->addItem("CHAP");
			m_pProtocol->addItem("MSCHAP");
			m_pProtocol->addItem("MSCHAPv2");
			m_pProtocol->addItem("EAP-MD5");
			
			if (m_curData.m_innerTTLSProtocol == ConnectionWizardData::inner_pap)
				m_pProtocol->setCurrentIndex(0);
			else if (m_curData.m_innerTTLSProtocol == ConnectionWizardData::inner_chap)
				m_pProtocol->setCurrentIndex(1);
			else if (m_curData.m_innerTTLSProtocol == ConnectionWizardData::inner_mschap)
				m_pProtocol->setCurrentIndex(2);
			else if (m_curData.m_innerTTLSProtocol == ConnectionWizardData::inner_mschapv2)
				m_pProtocol->setCurrentIndex(3);
			else if (m_curData.m_innerTTLSProtocol == ConnectionWizardData::inner_eap_md5)
				m_pProtocol->setCurrentIndex(4);															
			else
				; // error										
		}
	}
}

const ConnectionWizardData &WizardPageDot1XInnerProtocol::wizardData(void)
{
	if (m_pOuterID != NULL)
		m_curData.m_outerIdentity = m_pOuterID->text();
		
	if (m_pValidateCert != NULL)
		m_curData.m_validateCert = m_pValidateCert->isChecked();
		
	if (m_pSessionResume != NULL)
		m_curData.m_useSessionResume = m_pSessionResume->isChecked();

	if (m_pProtocol != NULL)
	{
		if (m_curData.m_eapProtocol == ConnectionWizardData::eap_peap)
		{
			if (m_pProtocol->currentIndex() == 0)
				m_curData.m_innerPEAPProtocol = ConnectionWizardData::inner_eap_mschapv2;
			else if (m_pProtocol->currentIndex() == 1)
				m_curData.m_innerPEAPProtocol = ConnectionWizardData::inner_eap_gtc;
			else
				; // error
		}
		else if (m_curData.m_eapProtocol == ConnectionWizardData::eap_ttls)
		{
			if (m_pProtocol->currentIndex() == 0)
				m_curData.m_innerTTLSProtocol = ConnectionWizardData::inner_pap;
			else if (m_pProtocol->currentIndex() == 1)
				m_curData.m_innerTTLSProtocol = ConnectionWizardData::inner_chap;
			else if (m_pProtocol->currentIndex() == 2)
				m_curData.m_innerTTLSProtocol = ConnectionWizardData::inner_mschap;
			else if (m_pProtocol->currentIndex() == 3)
				m_curData.m_innerTTLSProtocol = ConnectionWizardData::inner_mschapv2;
			else if (m_pProtocol->currentIndex() == 4)
				m_curData.m_innerTTLSProtocol = ConnectionWizardData::inner_eap_md5;																												
			else
				; // error										
		}
	}			
	
	return m_curData;
}

WizardPageFASTInnerProtocol::WizardPageFASTInnerProtocol(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
	m_pRealForm = NULL;
}

WizardPageFASTInnerProtocol::~WizardPageFASTInnerProtocol()
{
	if (m_pRealForm != NULL)
	{
		Util::myDisconnect(m_pAnonymousProvision, SIGNAL(toggled(bool)), this, SLOT(slotToggleRadioButton(bool)));
	}
}

bool WizardPageFASTInnerProtocol::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageFASTInnerProtocol.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache off pointers to objects	
	m_pProtocol = qFindChild<QComboBox*>(m_pRealForm, "comboBoxProtocol");
	m_pOuterID = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldOuterID");
	m_pValidateCert = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxValidateCert");
	m_pAnonymousProvision = qFindChild<QRadioButton*>(m_pRealForm, "unauthProv");
	if (m_pAnonymousProvision != NULL) m_pAnonymousProvision->setText(tr("Use anonymous provisioning"));

	m_pAuthenticatedProvision = qFindChild<QRadioButton*>(m_pRealForm, "authProv");
	if (m_pAuthenticatedProvision != NULL) m_pAuthenticatedProvision->setText(tr("Use authenticated provisioning"));
		
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Enter your FAST settings for 802.1X authentication below.  The Outer Identity will be sent unencrypted."));	

	QLabel *pProtocolLabel = qFindChild<QLabel*>(m_pRealForm, "labelProtocol");
	if (pProtocolLabel != NULL)
		pProtocolLabel->setText(tr("Tunnel Protocol:"));
		
	QLabel *pOuterIDLabel = qFindChild<QLabel*>(m_pRealForm, "labelOuterID");
	if (pOuterIDLabel != NULL)
		pOuterIDLabel->setText(tr("Outer Identity:"));
		
	QLabel *pOptionalLabel = qFindChild<QLabel*>(m_pRealForm, "labelOptional");
	if (pOptionalLabel != NULL)
		pOptionalLabel->setText(tr("(Optional)"));			
		
	if (m_pValidateCert != NULL)
		m_pValidateCert->setText(tr("Validate Server Certificate"));
		
	if (m_pProtocol != NULL)
		m_pProtocol->clear();
		
	Util::myConnect(m_pAnonymousProvision, SIGNAL(toggled(bool)), this, SLOT(slotToggleRadioButton(bool)));

	return true;
}

void WizardPageFASTInnerProtocol::slotToggleRadioButton(bool checked)
{
	if (checked == true)
	{
		m_pValidateCert->setEnabled(false);
	}
	else
	{
		m_pValidateCert->setEnabled(true);
	}
}

void WizardPageFASTInnerProtocol::init(const ConnectionWizardData &data)
{
	m_curData = data;
	
	// populate this label dynamically because the text references the outer protocol used
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
	{
		pMsgLabel->setText(tr("Enter your FAST settings for 802.1X authentication below.  The Outer Identity will be sent unencrypted."));
	}
			
	if (m_pOuterID != NULL)
		m_pOuterID->setText(m_curData.m_outerIdentity);

	if (m_curData.m_anonymousProvisioning)
		m_pAnonymousProvision->setChecked(true);
		
	if (m_pValidateCert != NULL)
		m_pValidateCert->setChecked(m_curData.m_validateCert);
	
	if (m_pProtocol != NULL)
	{
		m_pProtocol->clear();	
		m_pProtocol->addItem("EAP-MSCHAPv2");
		m_pProtocol->addItem("EAP-GTC");
			
		if (m_curData.m_innerFASTProtocol == ConnectionWizardData::inner_eap_mschapv2)
			m_pProtocol->setCurrentIndex(0);
		else if (m_curData.m_innerFASTProtocol == ConnectionWizardData::inner_eap_gtc)
			m_pProtocol->setCurrentIndex(1);
		else
			; // error
	}
}

const ConnectionWizardData &WizardPageFASTInnerProtocol::wizardData(void)
{
	if (m_pOuterID != NULL)
		m_curData.m_outerIdentity = m_pOuterID->text();
		
	if (m_pValidateCert != NULL)
		m_curData.m_validateCert = m_pValidateCert->isChecked();
		
	if (m_pProtocol != NULL)
	{
		if (m_pProtocol->currentIndex() == 0)
			m_curData.m_innerFASTProtocol = ConnectionWizardData::inner_eap_mschapv2;
		else if (m_pProtocol->currentIndex() == 1)
			m_curData.m_innerFASTProtocol = ConnectionWizardData::inner_eap_gtc;
		else
			; // error
	}

	if (m_pAnonymousProvision->isChecked() == true)
	{
		m_curData.m_anonymousProvisioning = true;
		m_curData.m_authenticatedProvisioning = false;
		m_curData.m_validateCert = false;
	}
	else
	{
		m_curData.m_anonymousProvisioning = false;
		m_curData.m_authenticatedProvisioning = true;
	}
	
	return m_curData;
}

WizardPageDot1XCert::WizardPageDot1XCert(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
	m_pCertArray = NULL;
}

WizardPageDot1XCert::~WizardPageDot1XCert()
{
	if (m_pCertArray != NULL)
		xsupgui_request_free_cert_enum(&m_pCertArray);
	if (m_pVerifyName != NULL)
		Util::myDisconnect(m_pVerifyName, SIGNAL(stateChanged(int)), this, SLOT(handleValidateChecked(int)));
	if (m_pCertTable != NULL) {
		Util::myDisconnect(m_pCertTable, SIGNAL(cellClicked(int,int)), this, SLOT(handleCertTableClick(int,int)));
	}
		
}

bool WizardPageDot1XCert::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageDot1XCert.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache off pointers to UI objects	
	m_pCertTable = qFindChild<QTableWidget*>(m_pRealForm, "tableCertList");
	m_pNameField = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldCommonName");
	m_pVerifyName = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxVerifyName");
		
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Choose a Trusted CA Certificate to validate against:"));	

	QLabel *pLabel = qFindChild<QLabel*>(m_pRealForm, "labelNameInstructions");
	if (pLabel != NULL)
		pLabel->setText(tr("Use \"*\" for prefix wildcarding and commas to separate multiple entries"));		
		
	if (m_pVerifyName != NULL)
		m_pVerifyName->setText(tr("Verify Server Common Name"));
		
	// set up event handling
	if (m_pVerifyName != NULL)
		Util::myConnect(m_pVerifyName, SIGNAL(stateChanged(int)), this, SLOT(handleValidateChecked(int)));
		
	if (m_pCertTable != NULL) {
		Util::myConnect(m_pCertTable, SIGNAL(cellClicked(int,int)), this, SLOT(handleCertTableClick(int,int)));
	}
		
	// other initializations
	if (m_pNameField != NULL)
	{
		// set validator. Allow "*.subdomain.subdomain.domain" or "subdomain.subdomain.domain", or comma separated list of same
		m_pNameField->setValidator(new QRegExpValidator(QRegExp("^(?:(?:(?:\\*)|(?:\\w{1,253}))(?:\\.\\w{1,253})+)(?:\\,(?:(?:(?:\\*)|(?:\\w{1,253}))(?:\\.\\w{1,253})+))*$"), m_pNameField));
	}
	
	if (m_pCertTable != NULL)
	{
		// min # of rows to show...assume form was properly set up
		int minRows = m_pCertTable->rowCount();
		
		// disallow user from sizing columns
		m_pCertTable->horizontalHeader()->setResizeMode(QHeaderView::Fixed);
		
		// network name
		m_pCertTable->horizontalHeaderItem(0)->setText(QString(""));
		m_pCertTable->horizontalHeader()->resizeSection(0,16);	
		
		// signal
		m_pCertTable->horizontalHeaderItem(1)->setText(tr("Trusted Certification Authority"));
		m_pCertTable->horizontalHeader()->setResizeMode(1,QHeaderView::Stretch);
		
		// don't draw header any differently when row is selected
		m_pCertTable->horizontalHeader()->setHighlightSections(false);
		m_pCertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
		
		// make sure we get all moue events
		m_pCertTable->setMouseTracking(true);
		
		m_pCertTable->verticalHeader()->hide();
		m_pCertTable->setRowCount(0);
		
		int retVal;
		int i=0;
		
		// turn off sorting while table is populated
		bool sortable = m_pCertTable->isSortingEnabled();
		m_pCertTable->setSortingEnabled(false);
		
		retVal = xsupgui_request_enum_root_ca_certs(&m_pCertArray);
		if (retVal == REQUEST_SUCCESS && m_pCertArray != NULL)
		{
			while (m_pCertArray[i].certname != NULL)
			{
				m_pCertTable->insertRow(i);
				m_pCertTable->setRowHeight(i,20);
				
				// use item type as index into original array
				QTableWidgetItem *item = new QTableWidgetItem(QString::fromUtf8(m_pCertArray[i].certname), i+1000);
				m_pCertTable->setItem(i,1,item);
				
				QCheckBox *pCheckBox = new QCheckBox();
				m_pCertTable->setCellWidget(i,0,pCheckBox);

				QTableWidgetItem *issuedToItem = new QTableWidgetItem(QString::fromUtf8(m_pCertArray[i].certname));
				m_pCertTable->setItem(i,2,issuedToItem);

				QDate d(m_pCertArray[i].year, m_pCertArray[i].month, m_pCertArray[i].day);
				QTableWidgetItem *dateItem = new QTableWidgetItem(d.toString("MM/dd/yyyy")); // need to change this for appropriate locales
				m_pCertTable->setItem(i,3,dateItem);

				++i;
			}
		}
		for (;i<minRows;i++)
		{
			m_pCertTable->insertRow(i);
			m_pCertTable->setRowHeight(i,20);
		}
		
		// restore sorting behavior and sort by name
		if (sortable == true)
		{
			m_pCertTable->setSortingEnabled(true);
			m_pCertTable->sortByColumn(1, Qt::AscendingOrder);
		}	
	}
		
	return true;
}

void WizardPageDot1XCert::init(const ConnectionWizardData &data)
{
	m_curData = data;
	
	if (m_pVerifyName != NULL) {
		m_pVerifyName->setChecked(m_curData.m_verifyCommonName);
		handleValidateChecked(m_curData.m_verifyCommonName ? Qt::Checked : Qt::Unchecked);
	}
		
	if (m_pNameField != NULL)
		m_pNameField->setText(m_curData.m_commonNames.join(QString(",")));
	
	// check those that are selected	
	if (m_pCertTable != NULL)
	{
		int nRows = m_pCertTable->rowCount();
		m_numCerts = 0;
		
		while (m_pCertArray[m_numCerts].certname != NULL)
			++m_numCerts;
			
		for (int i=0; i<nRows; i++)
		{
			QTableWidgetItem *item = m_pCertTable->item(i,1);
			if (item != NULL)
			{
				QWidget *widget = m_pCertTable->cellWidget(i,0); 
				if (widget != NULL)
				{
					int index = item->type() - 1000;
					
					if (m_pCertArray != NULL && index > 0 && index < m_numCerts && m_curData.m_serverCerts.contains(m_pCertArray[index].location))
					{
						((QCheckBox*)widget)->setChecked(true);
					}
					else
					{
						((QCheckBox*)widget)->setChecked(false);
					}
				}
			}
		}	
	}
}

void WizardPageDot1XCert::handleCertTableClick(int, int)
{
/*
	// if user clicks on name of server, toggle checkbox
	if (m_pCertTable != NULL && col == 1)
	{
		QWidget *widget = m_pCertTable->cellWidget(row,0);
		if (widget != NULL)
			((QCheckBox*)widget)->toggle();
	}
*/
}

void WizardPageDot1XCert::handleValidateChecked(int checkState)
{
	if (m_pNameField != NULL)
		m_pNameField->setDisabled(checkState == Qt::Unchecked);
}

bool WizardPageDot1XCert::validate(void)
{
	// check that at least one cert chosen
	if (m_pCertTable != NULL)
	{
		int nRows = m_pCertTable->rowCount();
		int nSelected = 0;
		
		for (int i=0;i<nRows;i++)
		{
			QWidget *item = m_pCertTable->cellWidget(i,0);
			if (item != NULL)
			{
				if (((QCheckBox *)item)->isChecked() == true)
					++nSelected;
			}
		}
		
		if (nSelected == 0)
		{
			QMessageBox::warning(m_pRealForm, tr("No Certificates Selected"),tr("Please select at least one certificate to use for validation."));
			return false;
		}
	}
	
	if (m_pNameField != NULL)
	{
		if (m_pVerifyName != NULL && m_pVerifyName->isChecked() == true)
		{
			if (m_pNameField->text() == "")
			{
				QMessageBox::warning(m_pRealForm, tr("Invalid Common Name String"), tr("You must enter a valid common name string if common name verification is enabled."));
				return false;
			}

			if (m_pNameField->hasAcceptableInput() == false)
			{
				QMessageBox::warning(m_pRealForm, tr("Invalid Common Name String"), tr("Please input a valid common name string.  Domain names must be of the form \"subdomain.domain\" or \"*.subdomain.domain\" if using wildcards."));
				return false;
			}
			else
			{
				// make sure none are longer than 255 chars
				QStringList dNames;
				dNames = m_pNameField->text().split(",");
				
				bool valid = true;
				for (int i=0; i<dNames.size(); i++)
				{
					if (dNames.at(i).length() > 255)
					{
						valid = false;
						break;
					}
				}
				if (valid == false)
				{
					QMessageBox::warning(m_pRealForm, tr("Invalid Common Name String"), tr("Please ensure each domain name you entered has 255 or fewer characters."));
					return false;
				}
			}
		}
	}
	return true;
}

const ConnectionWizardData &WizardPageDot1XCert::wizardData()
{
	if (m_pVerifyName != NULL)
		m_curData.m_verifyCommonName = m_pVerifyName->isChecked();	
	if (m_pNameField != NULL)
		m_curData.m_commonNames = m_pNameField->text().split(QString(","));	
		
	if (m_pCertTable != NULL)
	{
		// check for checked rows
		m_curData.m_serverCerts.clear();
		int nRows = m_pCertTable->rowCount();
		
		for (int i=0; i<nRows; i++)
		{
			QWidget *widget = m_pCertTable->cellWidget(i,0);
			if (widget != NULL && ((QCheckBox*)widget)->isChecked())
			{
				// if user selected item, add cert's location to list. 
				// (location is guaranteed to be unique)
				QTableWidgetItem *item = m_pCertTable->item(i,1);
				
				// TODO: range check index before indexing m_pCertArray
				if (item != NULL && m_pCertArray != NULL)
					m_curData.m_serverCerts.append(QString(m_pCertArray[item->type() - 1000].location));
			}
		}
	}
	return m_curData;
}


WizardPageSCReader::WizardPageSCReader(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageSCReader::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageSIMReader.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache off pointers to objects	
	m_pReader = qFindChild<QComboBox*>(m_pRealForm, "comboBoxReader");
		
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Select the smartcard reader to use:"));	

	QLabel *pReaderLabel = qFindChild<QLabel*>(m_pRealForm, "labelReader");
	if (pReaderLabel != NULL)
		pReaderLabel->setText(tr("Reader:"));
		
	if (m_pReader != NULL)
	{
		populateSIMReaders();
	}

	m_pAutoRealm = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxAutoRealm");
	if (m_pAutoRealm != NULL)
		m_pAutoRealm->setText(tr("Auto Generate Realm from IMSI"));
		
	return true;
}

void WizardPageSCReader::init(const ConnectionWizardData &data)
{
	int index = 0;

	m_curData = data;

	if (m_pReader != NULL)
	{
		index = m_pReader->findText(m_curData.m_SCreader);		
		if (index == -1)
		{
			if (m_curData.m_SCreader == "")
			{
				m_pReader->setCurrentIndex(0);
			}
			else
			{
				m_pReader->addItem(m_curData.m_SCreader);
				m_pReader->setCurrentIndex(m_pReader->findText(m_curData.m_SCreader));
			}
		}
		else
		{
			m_pReader->setCurrentIndex(index);
		}
	}

	if (m_pAutoRealm) m_pAutoRealm->setChecked(m_curData.m_autoRealm);

}

void WizardPageSCReader::populateSIMReaders()
{
	char **list = NULL;
	int retval = 0;
	int count = 0;

	m_pReader->clear();
	m_pReader->insertItem(0, tr("<None>"));

	retval = xsupgui_request_enum_smartcard_readers(&list);
	if (retval != REQUEST_SUCCESS) 
		return;

	while (list[count] != NULL)
	{
		m_pReader->insertItem(m_pReader->count()+1, list[count]);
		count++;
	}

	xsupgui_request_free_enum_smartcard_readers(&list);
}

bool WizardPageSCReader::validate(void)
{
	if (m_pReader->currentIndex() == 0) 
	{
		QMessageBox::warning(this, tr("Invalid Reader"), tr("Please select a valid smart card reader.  If none are listed, then you will be unable to use this EAP type."));
		return false;
	}

	if (m_pReader->currentText() == "") 
	{
		QMessageBox::warning(this, tr("Invalid Reader"), tr("Please select a valid smart card reader.  If none are listed, then you will be unable to use this EAP type."));
		return false;
	}

	return true;
}

const ConnectionWizardData &WizardPageSCReader::wizardData(void)
{
	if (m_pReader != NULL)
	{
		m_curData.m_SCreader = m_pReader->currentText();
	}

	if (m_pAutoRealm != NULL)
	{
		m_curData.m_autoRealm = m_pAutoRealm->isChecked();
	}

	return m_curData;
}

WizardPageDot1XUserCert::WizardPageDot1XUserCert(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
	m_pCertArray = NULL;
}

WizardPageDot1XUserCert::~WizardPageDot1XUserCert()
{
	if (m_pCertArray != NULL)
		xsupgui_request_free_cert_enum(&m_pCertArray);
	if (m_pCertTable != NULL) {
		Util::myDisconnect(m_pCertTable, SIGNAL(cellClicked(int,int)), this, SLOT(handleCertTableClick(int,int)));
	}
		
}

bool WizardPageDot1XUserCert::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageDot1XUserCert.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache off pointers to UI objects	
	m_pCertTable = qFindChild<QTableWidget*>(m_pRealForm, "tableCertList");
		
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Choose a user certificate to use :"));	
			
	if (m_pCertTable != NULL) {
		Util::myConnect(m_pCertTable, SIGNAL(cellClicked(int,int)), this, SLOT(handleCertTableClick(int,int)));
	}
			
	if (m_pCertTable != NULL)
	{
		// min # of rows to show...assume form was properly set up
		int minRows = m_pCertTable->rowCount();
		
		// disallow user from sizing columns
		m_pCertTable->horizontalHeader()->setResizeMode(QHeaderView::Fixed);
		
		// friendly name
		m_pCertTable->horizontalHeaderItem(0)->setText(tr("Name"));
		m_pCertTable->horizontalHeader()->setResizeMode(0,QHeaderView::Stretch);
		
		// issued to
		m_pCertTable->horizontalHeaderItem(1)->setText(tr("Issued To"));
		m_pCertTable->horizontalHeader()->setResizeMode(1,QHeaderView::Stretch);

		// expires
		m_pCertTable->horizontalHeaderItem(2)->setText(tr("Expires"));
		m_pCertTable->horizontalHeader()->setResizeMode(2,QHeaderView::Stretch);
		
		// don't draw header any differently when row is selected
		m_pCertTable->horizontalHeader()->setHighlightSections(false);
		m_pCertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
		
		// make sure we get all mouse events
		m_pCertTable->setMouseTracking(true);
		
		m_pCertTable->verticalHeader()->hide();
		m_pCertTable->setRowCount(0);
		
		int retVal;
		int i=0;
		
		// turn off sorting while table is populated
		bool sortable = m_pCertTable->isSortingEnabled();
		m_pCertTable->setSortingEnabled(false);
		
		retVal = xsupgui_request_enum_user_certs(&m_pCertArray);
		if (retVal == REQUEST_SUCCESS && m_pCertArray != NULL)
		{
			while (m_pCertArray[i].certname != NULL)
			{
				m_pCertTable->insertRow(i);
				m_pCertTable->setRowHeight(i,20);
				
				// use item type as index into original array
				QTableWidgetItem *item = new QTableWidgetItem(QString::fromUtf8(m_pCertArray[i].friendlyname), i+1000);
				m_pCertTable->setItem(i,0,item);
				
				QTableWidgetItem *issuedToItem = new QTableWidgetItem(QString::fromUtf8(m_pCertArray[i].certname));
				m_pCertTable->setItem(i,1,issuedToItem);

				QDate d(m_pCertArray[i].year, m_pCertArray[i].month, m_pCertArray[i].day);
				QTableWidgetItem *dateItem = new QTableWidgetItem(d.toString("MM/dd/yyyy")); // need to change this for appropriate locales
				m_pCertTable->setItem(i,2,dateItem);

				++i;
			}
		}
		for (;i<minRows;i++)
		{
			m_pCertTable->insertRow(i);
			m_pCertTable->setRowHeight(i,20);
		}
		
		// restore sorting behavior and sort by name
		if (sortable == true)
		{
			m_pCertTable->setSortingEnabled(true);
			m_pCertTable->sortByColumn(1, Qt::AscendingOrder);
		}	
	}
		
	return true;
}

void WizardPageDot1XUserCert::init(const ConnectionWizardData &data)
{
	m_curData = data;
		
	// highlight the selected cert
	if (m_pCertTable != NULL)
	{
		int nRows = m_pCertTable->rowCount();
		m_numCerts = 0;
		
		while (m_pCertArray[m_numCerts].certname != NULL)
			++m_numCerts;
			
		for (int i=0; i<nRows; i++)
		{
			QTableWidgetItem *item = m_pCertTable->item(i,0);
			if (item != NULL)
			{
				int index = item->type() - 1000;
					
				if (m_pCertArray != NULL && index >= 0 && index < m_numCerts && m_curData.m_userCert == QString(m_pCertArray[index].location))
				{
					m_pCertTable->setCurrentItem(item);
					break;	// No need to continue, only one can be selected.
				}
			}
		}	
	}
}

void WizardPageDot1XUserCert::handleCertTableClick(int, int)
{
/*
	// if user clicks on name of server, toggle checkbox
	if (m_pCertTable != NULL && col == 1)
	{
		QWidget *widget = m_pCertTable->cellWidget(row,0);
		if (widget != NULL)
			((QCheckBox*)widget)->toggle();
	}
*/
}

bool WizardPageDot1XUserCert::validate(void)
{
	// check that a cert is selected - We check for 3 items selected because
	// we are selecting by row, so all of the items in a single row get selected.
	if (m_pCertTable->selectedItems().count() != 3)
	{
		QMessageBox::warning(m_pRealForm, tr("No Certificate Selected"), tr("Please select a user certificate to use."));
		return false;
	}

	return true;
}

const ConnectionWizardData &WizardPageDot1XUserCert::wizardData()
{
	QTableWidgetItem *item = NULL;

	if (m_pCertTable->rowCount() > 0)
	{
		if (m_pCertTable->selectedItems().count() > 0)
		{
			item = m_pCertTable->selectedItems().at(0);	// There should only be one selected.
			if (item != NULL) m_curData.m_userCert = QString(m_pCertArray[item->type() - 1000].location);
		}
	}

	return m_curData;
}

WizardPageNetworkTypes::WizardPageNetworkTypes(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageNetworkTypes::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageSelectNetworkTypes.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Please indicate the types of network you would like to use machine authentication on:"));
		
	m_pCheckBoxWired = qFindChild<QCheckBox*>(m_pRealForm, "wiredCheckbox");
	if (m_pCheckBoxWired != NULL)
		m_pCheckBoxWired->setText(tr("Wired"));
		
	m_pCheckBoxWireless = qFindChild<QCheckBox*>(m_pRealForm, "wirelessCheckbox");
	if (m_pCheckBoxWireless != NULL)
		m_pCheckBoxWireless->setText(tr("Wireless"));
		
	// other initializations
	if (m_pCheckBoxWired != NULL)
		m_pCheckBoxWired->setChecked(true);

	if (m_pCheckBoxWireless != NULL)
		m_pCheckBoxWireless->setChecked(true);
				
	return true;
}

void WizardPageNetworkTypes::init(const ConnectionWizardData &data)
{
	m_curData = data;

	if (m_pCheckBoxWireless != NULL)
	{
		m_pCheckBoxWireless->setChecked(m_curData.m_wireless);
	}

	if (m_pCheckBoxWired != NULL)
	{
		m_pCheckBoxWired->setChecked(m_curData.m_wired);
	}
}


const ConnectionWizardData &WizardPageNetworkTypes::wizardData(void)
{

	if (m_pCheckBoxWireless != NULL && m_pCheckBoxWireless->isChecked() == true)
		m_curData.m_wireless = true;
	else
		m_curData.m_wireless = false;

	if (m_pCheckBoxWired != NULL && m_pCheckBoxWired->isChecked() == true)
		m_curData.m_wired = true;
	else
		m_curData.m_wired = false;
		
	return m_curData;
}

WizardPageMachineAuthFinished::WizardPageMachineAuthFinished(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageMachineAuthFinished::create(void)
{
	QLabel *pTemp = NULL;

	m_pRealForm = FormLoader::buildform("wizardPageMachineAuthDone.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// dynamically populate text
	m_pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "resultLabel");

	pTemp = qFindChild<QLabel*>(m_pRealForm, "finishLabel");
	if (pTemp != NULL) pTemp->setText(tr("Click Finish to save this configuration, or Back to go back and change options."));

	return true;
}

void WizardPageMachineAuthFinished::init(const ConnectionWizardData &data)
{
	m_curData = data;
	QString resultData = tr("Machine authentication has been successfully configured<br>with the following options :<br><ul>");

	if (m_curData.m_wireless)
		resultData += QString("<li>")+tr("Machine Authentication on Wireless")+QString("</li>");

	if (m_curData.m_wired)
		resultData += QString("<li>")+tr("Machine Authentication on Wired")+QString("</li>");

	if ((!m_curData.m_wired) && (!m_curData.m_wireless))
		resultData += QString("<li>")+tr("Machine Authentication is Disabled")+QString("</li>");

	resultData += QString("</ul>");

	m_pMsgLabel->setText(resultData);
}

bool WizardPageMachineAuthFinished::validate(void)
{
	return true;
}
const ConnectionWizardData &WizardPageMachineAuthFinished::wizardData(void)
{
	m_curData.m_connectionName = QString("Machine Authentication Connection");
	m_curData.m_profileName = QString("Machine Authentication Profile");
	m_curData.m_serverName = QString("Machine Authentication Trusted Server");
	m_curData.m_config_type = CONFIG_LOAD_GLOBAL;
	m_curData.m_machineAuth = true;
	m_curData.m_innerPEAPProtocol = ConnectionWizardData::inner_eap_mschapv2;

	return m_curData;
}

WizardPageAuthOptions::WizardPageAuthOptions(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageAuthOptions::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageSelectAuthOptions.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Please select any options you would like to enable for this configuration :"));
		
	m_pCheckBoxUseLogonCreds = qFindChild<QCheckBox*>(m_pRealForm, "useLogonCreds");
	if (m_pCheckBoxUseLogonCreds != NULL)
		m_pCheckBoxUseLogonCreds->setText(tr("Use logon credentials (if available)"));
				
	// other initializations
	if (m_pCheckBoxUseLogonCreds != NULL)
		m_pCheckBoxUseLogonCreds->setChecked(false);

	return true;
}

void WizardPageAuthOptions::init(const ConnectionWizardData &data)
{
	m_curData = data;

	if (m_pCheckBoxUseLogonCreds != NULL)
	{
		m_pCheckBoxUseLogonCreds->setChecked(m_curData.m_useLogonCreds);
	}
}

const ConnectionWizardData &WizardPageAuthOptions::wizardData(void)
{

	if (m_pCheckBoxUseLogonCreds != NULL && m_pCheckBoxUseLogonCreds->isChecked() == true)
		m_curData.m_useLogonCreds = true;
	else
		m_curData.m_useLogonCreds = false;

	return m_curData;
}

WizardPageCredentials::WizardPageCredentials(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageCredentials::create(void)
{
	QLabel *pMsgLabel = NULL;

	m_pRealForm = FormLoader::buildform("wizardPageCredentials.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// dynamically populate text
	pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("How would you like to obtain credentials? <i>(If you are unsure, use the default setting)<i>"));
		
	m_pRadioButtonPrompt = qFindChild<QRadioButton*>(m_pRealForm, "radioPromptForCreds");
	if (m_pRadioButtonPrompt != NULL)
		m_pRadioButtonPrompt->setText(tr("Prompt for credentials (default)"));
		
	m_pRadioButtonStore = qFindChild<QRadioButton*>(m_pRealForm, "radioStoredCreds");
	if (m_pRadioButtonStore != NULL)
		m_pRadioButtonStore->setText(tr("Store Credentials"));
		
	// other initializations
	if (m_pRadioButtonPrompt != NULL)
		m_pRadioButtonPrompt->setChecked(true);

	m_pUsernameLabel = qFindChild<QLabel*>(m_pRealForm, "labelUsername");
	if (m_pUsernameLabel != NULL)
		m_pUsernameLabel->setText(tr("Username : "));

	m_pPasswordLabel = qFindChild<QLabel*>(m_pRealForm, "labelPassword");
	if (m_pPasswordLabel != NULL)
		m_pPasswordLabel->setText(tr("Password : "));

	m_pUsernameEdit = qFindChild<QLineEdit*>(m_pRealForm, "usernameEdit");
	m_pPasswordEdit = qFindChild<QLineEdit*>(m_pRealForm, "passwordEdit");

	Util::myConnect(m_pRadioButtonPrompt, SIGNAL(toggled(bool)), this, SLOT(slotToggled(bool)));

	return true;
}

void WizardPageCredentials::init(const ConnectionWizardData &data)
{
	m_curData = data;
	if ((m_curData.m_username == "") && (m_curData.m_password == ""))
	{
		if (m_pRadioButtonPrompt != NULL)
			m_pRadioButtonPrompt->setChecked(true);

		if (m_pUsernameLabel != NULL)
			m_pUsernameLabel->setEnabled(false);

		if (m_pUsernameEdit != NULL)
			m_pUsernameEdit->setEnabled(false);

		if (m_pPasswordLabel != NULL)
			m_pPasswordLabel->setEnabled(false);

		if (m_pPasswordEdit != NULL)
			m_pPasswordEdit->setEnabled(false);
	}
	else
	{
		if (m_pRadioButtonStore != NULL)
			m_pRadioButtonStore->setChecked(true);

		if (m_pUsernameLabel != NULL)
			m_pUsernameLabel->setEnabled(true);

		if (m_pUsernameEdit != NULL)
			m_pUsernameEdit->setEnabled(true);

		if ((m_curData.m_eapProtocol != ConnectionWizardData::eap_tls) ||
			!((m_curData.m_eapProtocol == ConnectionWizardData::eap_peap) && (m_curData.m_innerPEAPProtocol == ConnectionWizardData::inner_eap_gtc)))
		{
			if (m_pPasswordLabel != NULL)
				m_pPasswordLabel->setEnabled(false);

			if (m_pPasswordEdit != NULL)
				m_pPasswordEdit->setEnabled(false);
		}
		else
		{
			if (m_pPasswordLabel != NULL)
				m_pPasswordLabel->setEnabled(true);

			if (m_pPasswordEdit != NULL)
				m_pPasswordEdit->setEnabled(true);
		}
	}
}

const ConnectionWizardData &WizardPageCredentials::wizardData(void)
{
	if ((m_pRadioButtonPrompt != NULL) && (m_pRadioButtonPrompt->isChecked()))
	{
		m_curData.m_username = "";
		m_curData.m_password = "";
	}
	else
	{
		m_curData.m_username = m_pUsernameEdit->text();
		m_curData.m_password = m_pPasswordEdit->text();
	}

	return m_curData;
}

bool WizardPageCredentials::validate(void)
{
	if ((m_pRadioButtonStore != NULL) && (m_pRadioButtonStore->isChecked()))
	{
		if ((m_curData.m_eapProtocol != ConnectionWizardData::eap_tls) ||
			!((m_curData.m_eapProtocol == ConnectionWizardData::eap_peap) && (m_curData.m_innerPEAPProtocol == ConnectionWizardData::inner_eap_gtc)))
		{
			// We need to make sure that we have values stored.
			if ((m_pUsernameEdit->text() == "") || (m_pPasswordEdit->text() == ""))
			{
				QMessageBox::critical(this, tr("Error"), tr("You need to provide a username and password, or select the 'Prompt for credentials' option."));
				return false;
			}
		}
		else
		{
			if (m_pUsernameEdit->text() == "")
			{
				QMessageBox::critical(this, tr("Error"), tr("You need to provide a username, or select the 'Prompt for credentials' option."));
				return false;
			}
		}
	}

	return true;
}

void WizardPageCredentials::slotToggled(bool checked)
{
	if (checked)
	{
		// Disable the username/password stuff
		if (m_pUsernameLabel != NULL)
			m_pUsernameLabel->setEnabled(false);

		if (m_pUsernameEdit != NULL)
			m_pUsernameEdit->setEnabled(false);

		if (m_pPasswordLabel != NULL)
			m_pPasswordLabel->setEnabled(false);

		if (m_pPasswordEdit != NULL)
			m_pPasswordEdit->setEnabled(false);
	}
	else
	{
		// Enable it
		if (m_pUsernameLabel != NULL)
			m_pUsernameLabel->setEnabled(true);

		if (m_pUsernameEdit != NULL)
			m_pUsernameEdit->setEnabled(true);

		if ((m_curData.m_eapProtocol != ConnectionWizardData::eap_tls) ||
			!((m_curData.m_eapProtocol == ConnectionWizardData::eap_peap) && (m_curData.m_innerPEAPProtocol == ConnectionWizardData::inner_eap_gtc)))
		{
			if (m_pPasswordLabel != NULL)
				m_pPasswordLabel->setEnabled(true);

			if (m_pPasswordEdit != NULL)
				m_pPasswordEdit->setEnabled(true);
		}
	}
}

WizardPageCredentials::~WizardPageCredentials()
{
	Util::myDisconnect(m_pRadioButtonPrompt, SIGNAL(toggled(bool)), this, SLOT(slotToggled(bool)));
}
