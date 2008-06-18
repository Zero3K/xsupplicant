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
 
 #include "WizardPages.h"
 #include "FormLoader.h"
 #include "SSIDList.h"
 
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
		xsupgui_request_free_int_enum(&pInterfaceList);
		pInterfaceList = NULL;
		
		// if no adapters, don't want to disable both so do nothing
		if (m_numWiredAdapters != 0 || m_numWirelessAdapters != 0)
		{
			if (m_pRadioButtonWireless != NULL)
				m_pRadioButtonWireless->setDisabled(m_numWirelessAdapters == 0);
				
			if (m_pRadioButtonWired != NULL)
				m_pRadioButtonWired->setDisabled(m_numWiredAdapters == 0);
		}
				
	}
		
	return true;
}

void WizardPageNetworkType::init(ConnectionWizardData *data)
{
	m_curData = data;
	if (m_curData != NULL)
	{
		// assume one of radio buttons isn't diabled
		if (m_curData->m_wireless == true)
		{
			if (m_pRadioButtonWireless != NULL)
			{
				if (m_pRadioButtonWireless->isEnabled() == true)
					m_pRadioButtonWireless->setChecked(true);
				else
				{
					// if no wireless adapters, connection must be wired
					m_curData->m_wireless = false;
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
					m_curData->m_wireless = true;
					if (m_pRadioButtonWireless != NULL)
					{
						// assume it's enabled. Should check, and error out if not
						m_pRadioButtonWireless->setChecked(true);
					}
				}
			}
		}
	}
}

ConnectionWizard::wizardPages WizardPageNetworkType::getNextPage(void)
{
	// jking - TODO: need to go to adapter selection page if more than one adapter!!!
	if (m_pRadioButtonWired != NULL && m_pRadioButtonWired->isChecked() == true)
		return ConnectionWizard::pageWiredSecurity;
	else if (m_pRadioButtonWireless != NULL && m_pRadioButtonWireless->isChecked() == true)
		return ConnectionWizard::pageWirelessNetwork;
	else
		return ConnectionWizard::pageNoPage;
}

ConnectionWizardData *WizardPageNetworkType::wizardData(void)
{
	if (m_curData != NULL)
	{
		if (m_pRadioButtonWireless != NULL && m_pRadioButtonWireless->isChecked() == true)
			m_curData->m_wireless = true;
		else
			m_curData->m_wireless = false;
			
		// assume one adapter and fill out connection data with first adapter of its kind
		int_enum *pInterfaceList = NULL;
		int retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
		if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
		{
			int i=0;
			while (pInterfaceList[i].desc != NULL)
			{
				if (pInterfaceList[i].is_wireless == TRUE && m_curData->m_wireless == true)
				{
					m_curData->m_adapterDesc = pInterfaceList[i].desc;
					break;
				}
				else if (pInterfaceList[i].is_wireless == FALSE && m_curData->m_wireless == false)
				{
					m_curData->m_adapterDesc = pInterfaceList[i].desc;
					break;				
				}
				++i;
			}
			xsupgui_request_free_int_enum(&pInterfaceList);
			pInterfaceList = NULL;				
		}
		else
		{
			// error. How do we alert user?
		}		
	}
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

void WizardPageWiredSecurity::init(ConnectionWizardData *data)
{
	m_curData = data;
	if (m_curData != NULL)
	{
		if (m_curData->m_wiredSecurity == true)
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
}

ConnectionWizardData* WizardPageWiredSecurity::wizardData(void)
{
	if (m_pRadioButtonDot1X != NULL && m_pRadioButtonDot1X->isChecked() == true)
	{
		if (m_curData != NULL)
			m_curData->m_wiredSecurity = true;
	}
	else if (m_pRadioButtonNone != NULL && m_pRadioButtonNone->isChecked() == true)
	{
		if (m_curData != NULL)
			m_curData->m_wiredSecurity = false;
	}
	
	return m_curData;
}

ConnectionWizard::wizardPages WizardPageWiredSecurity::getNextPage(void)
{
	if (m_pRadioButtonDot1X != NULL && m_pRadioButtonDot1X->isChecked() == true)
		return ConnectionWizard::pageDot1XProtocol;
	else if (m_pRadioButtonNone != NULL && m_pRadioButtonNone->isChecked() == true)
		return ConnectionWizard::pageIPOptions;
	else
		return ConnectionWizard::pageNoPage;
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

ConnectionWizard::wizardPages WizardPageIPOptions::getNextPage(void)
{
	if (m_pRadioButtonAuto != NULL && m_pRadioButtonAuto->isChecked() == true)
		return ConnectionWizard::pageFinishPage;
	else if (m_pRadioButtonStatic != NULL && m_pRadioButtonStatic->isChecked() == true)
		return ConnectionWizard::pageStaticIP;
	else
		return ConnectionWizard::pageNoPage;
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
		pMsgLabel->setText(tr("Your network connection is now configured.\n\nPlease enter a name for the connection profile and press \"Connect\" to connect to the network now, or \"Finish\" to close the wizard."));	

	QLabel *pConnNameLabel = qFindChild<QLabel*>(m_pRealForm, "labelConnectionName");
	if (pConnNameLabel != NULL)
		pConnNameLabel->setText(tr("Connection Name:"));
		
	if (m_pConnectButton != NULL)
		m_pConnectButton->setText(tr("Connect"));
		
	if (m_pConnectionName != NULL)
	{
		// TODO: populate default name
		m_pConnectionName->setText(tr("New Connection"));
		m_pConnectionName->selectAll();
		m_pConnectionName->setFocus();
	}
		
	return true;
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

void WizardPageWirelessNetwork::init(ConnectionWizardData *data)
{
	m_curData = data;
	if (m_pSSIDList != NULL) {
		m_pSSIDList->refreshList(m_curData->m_adapterDesc);
		
		// ensure something's selected
		if (m_pTableWidget != NULL)
			m_pTableWidget->selectRow(0);
	}
	if (m_curData != NULL)
	{
		if (m_curData->m_networkName.isEmpty() == true)
		{
			// if nothing selected yet, just choose one
			if (m_pTableWidget != NULL)
				m_pTableWidget->selectRow(0);
			if (m_pRadioButtonVisible != NULL) 
			{
				m_pRadioButtonVisible->setChecked(true);
				this->handleVisibleClicked(true);
			}
		}
		else
		{
			// look if it's in list. If so, choose it.  Otherwise select "other"
			if (m_pSSIDList->selectNetwork(m_curData->m_networkName) == true)
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
				{
					m_pRadioButtonOther->setChecked(true);
				}
			}
			
		}
	}
}

ConnectionWizardData *WizardPageWirelessNetwork::wizardData(void)
{
	if (m_curData != NULL)
	{
		m_curData->m_networkName = m_networkInfo.m_name;
		if (!m_networkInfo.m_name.isEmpty())
		{
			// set association mode. This is really a bitfield, but for now
			// the SSIDList sets modes as mutually exclusive
			switch (m_networkInfo.m_assoc_modes) {
				case WirelessNetworkInfo::SECURITY_NONE:
					m_curData->m_wirelessAssocMode = ConnectionWizardData::assoc_none;			
					break;
				case WirelessNetworkInfo::SECURITY_STATIC_WEP:
					m_curData->m_wirelessAssocMode = ConnectionWizardData::assoc_WEP;		
					break;
				case WirelessNetworkInfo::SECURITY_WPA2_PSK:
					m_curData->m_wirelessAssocMode = ConnectionWizardData::assoc_WPA2_PSK;				
					break;
				case WirelessNetworkInfo::SECURITY_WPA_PSK:	
					m_curData->m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_PSK;		
					break;					
				case WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE:
					m_curData->m_wirelessAssocMode = ConnectionWizardData::assoc_WPA2_ENT;
					break;
				case WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE:
					m_curData->m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_ENT;
					break;
			}
		}
	}
	
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

ConnectionWizard::wizardPages WizardPageWirelessNetwork::getNextPage(void)
{
	if (m_pRadioButtonVisible != NULL && m_pRadioButtonVisible->isChecked() == true)
		return ConnectionWizard::pageIPOptions;
	else if (m_pRadioButtonOther != NULL && m_pRadioButtonOther->isChecked() == true)
		return ConnectionWizard::pageWirelessInfo;
	else
		return ConnectionWizard::pageNoPage;
}

WizardPageWirelessInfo::WizardPageWirelessInfo(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
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
		m_pEncryption->addItem(tr("WEP"));
		m_pEncryption->addItem(tr("TKIP"));
		m_pEncryption->addItem(tr("AES"));
	}
		
	// set up event handling
	if (m_pHiddenNetwork != NULL)
		Util::myConnect(m_pHiddenNetwork,SIGNAL(stateChanged(int)), this, SLOT(hiddenStateChanged(int)));
	
	// other initializations
	if (m_pHiddenNetwork != NULL) {
		m_pHiddenNetwork->setCheckState(Qt::Unchecked);
		this->hiddenStateChanged(Qt::Unchecked);	
	}
		
	return true;
}
ConnectionWizard::wizardPages WizardPageWirelessInfo::getNextPage(void)
{
	if (m_pAssocMode != NULL)
	{
		// if WPA-Ent or WPA2-Ent, get 802.1X settings
		if (m_pAssocMode->currentIndex() == 3 || m_pAssocMode->currentIndex() == 5)
			return ConnectionWizard::pageDot1XProtocol;
		else
			return ConnectionWizard::pageIPOptions;
	}
	else
	{
		// bad stuff.  Need to do something better than this
		return ConnectionWizard::pageNoPage;
	}
}

void WizardPageWirelessInfo::hiddenStateChanged(int newState)
{
	switch (newState) {
		case Qt::Unchecked:
			if (m_pEncryption != NULL)
				m_pEncryption->setEnabled(false);
			if (m_pEncryptionLabel != NULL)
				m_pEncryptionLabel->setEnabled(false);	
			break;
		case Qt::Checked:
			if (m_pEncryption != NULL)
				m_pEncryption->setEnabled(true);
			if (m_pEncryptionLabel != NULL)
				m_pEncryptionLabel->setEnabled(true);					
			break;
		default:
			break;
	}
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
		m_pProtocol->addItem(tr("EAP-MD5"));
	}
		
	return true;
}

ConnectionWizard::wizardPages WizardPageDot1XProtocol::getNextPage(void)
{
	if (m_pProtocol != NULL)
	{
		// if EAP-MD5
		if (m_pProtocol->currentIndex() == 2)
			return ConnectionWizard::pageIPOptions;
		else
			return ConnectionWizard::pageDot1XInnerProtocol;
	}
	else
	{
		// bad. what to do?
		return ConnectionWizard::pageNoPage;
	}
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
	{
		// !!! need to populate based on outer protocol
		m_pProtocol->clear();
		m_pProtocol->addItem(tr("EAP-MSCHAPv2"));
		m_pProtocol->addItem(tr("EAP-GTC"));
	}
		
	return true;
}

ConnectionWizard::wizardPages WizardPageDot1XInnerProtocol::getNextPage(void)
{
	if (m_pValidateCert != NULL)
	{
		// if not set to validate server cert
		if (m_pValidateCert->checkState() == Qt::Unchecked)
			return ConnectionWizard::pageIPOptions;
		else
			return ConnectionWizard::pageDot1XCert;
	}
	else
	{
		// bad. what to do?
		return ConnectionWizard::pageNoPage;
	}
}

WizardPageDot1XCert::WizardPageDot1XCert(QWidget *parent, QWidget *parentWidget)
	:WizardPage(parent,parentWidget)
{
}

bool WizardPageDot1XCert::create(void)
{
	m_pRealForm = FormLoader::buildform("wizardPageDot1XCert.ui", m_pParentWidget);
	if (m_pRealForm == NULL)
		return false;
	
	// cache off pointers to objects	
	m_pCertTable = qFindChild<QTableWidget*>(m_pRealForm, "tableCertList");
	m_pNameField = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldCommonName");
	m_pVerifyName = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxVerifyName");
		
	// dynamically populate text
	QLabel *pMsgLabel = qFindChild<QLabel*>(m_pRealForm, "labelMessage");
	if (pMsgLabel != NULL)
		pMsgLabel->setText(tr("Choose a server certificate to validate against:"));	

	QLabel *pLabel = qFindChild<QLabel*>(m_pRealForm, "labelNameInstructions");
	if (pLabel != NULL)
		pLabel->setText(tr("Use \"*\" for prefix wildcarding.  For example: \"*.utah.edu\""));		
		
	if (m_pVerifyName != NULL)
		m_pVerifyName->setText(tr("Verify Common Name"));
		
	// other initializations
	if (m_pCertTable != NULL)
	{
		// disallow user from sizing columns
		m_pCertTable->horizontalHeader()->setResizeMode(QHeaderView::Fixed);
		
		// network name
		m_pCertTable->horizontalHeaderItem(0)->setText(tr(""));
		m_pCertTable->horizontalHeader()->resizeSection(0,16);	
		
		// signal
		m_pCertTable->horizontalHeaderItem(1)->setText(tr("Name"));
		m_pCertTable->horizontalHeader()->setResizeMode(1,QHeaderView::Stretch);
		
		// don't draw header any differently when row is selected
		m_pCertTable->horizontalHeader()->setHighlightSections(false);
		m_pCertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
		
		QCheckBox *pCheckBox;
		m_pCertTable->clearContents();
		m_pCertTable->verticalHeader()->hide();
		m_pCertTable->setRowCount(5);
		
		m_pCertTable->setRowHeight(0,20);
		pCheckBox = new QCheckBox();
		m_pCertTable->setCellWidget(0,0,pCheckBox);
		
		m_pCertTable->setRowHeight(1,20);
		pCheckBox = new QCheckBox();
		m_pCertTable->setCellWidget(1,0,pCheckBox);
				
		m_pCertTable->setRowHeight(2,20);
		pCheckBox = new QCheckBox();
		m_pCertTable->setCellWidget(2,0,pCheckBox);
				
		m_pCertTable->setRowHeight(3,20);
		pCheckBox = new QCheckBox();
		m_pCertTable->setCellWidget(3,0,pCheckBox);
				
		m_pCertTable->setRowHeight(4,20);
		pCheckBox = new QCheckBox();
		m_pCertTable->setCellWidget(4,0,pCheckBox);		
	}
		
	return true;
}