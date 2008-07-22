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

#include "ConnectionInfoDlg.h"
#include "FormLoader.h"
#include "Util.h"
#include "XSupWrapper.h"

ConnectionInfoDlg::ConnectionInfoDlg(QWidget *parent, QWidget *parentWindow, Emitter *e)
	:QWidget(parent), m_pParent(parent), m_pParentWindow(parentWindow), m_pEmitter(e)
{
	m_wirelessAdapter = false;
	m_days = 0;
}

ConnectionInfoDlg::~ConnectionInfoDlg()
{	
	if (m_pCloseButton != NULL)
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
		
	if (m_pDisconnectButton != NULL)
		Util::myDisconnect(m_pDisconnectButton, SIGNAL(clicked()), this, SLOT(disconnect()));
		
	if (m_pRenewIPButton != NULL)
		Util::myDisconnect(m_pRenewIPButton, SIGNAL(clicked()), this, SLOT(renewIP()));

	Util::myDisconnect(&m_timer, SIGNAL(timeout()), this, SLOT(timerUpdate()));
	
	Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
		this, SLOT(stateChange(const QString &, int, int, int, unsigned int)));	
		
	Util::myDisconnect(m_pEmitter, SIGNAL(signalIPAddressSet()), this, SLOT(updateIPAddress()));
	
	m_strengthTimer.stop();
	m_timer.stop();	

	if (m_pRealForm != NULL)
		delete m_pRealForm;
}

bool ConnectionInfoDlg::create(void)
{
	return this->initUI();
}

void ConnectionInfoDlg::show(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

bool ConnectionInfoDlg::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("ConnectionInfoWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
	
	Qt::WindowFlags flags;
	
	// set window flags so minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
		
	// cache off pointers to UI objects
	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");
	m_pDisconnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonDisconnect");
	m_pRenewIPButton = qFindChild<QPushButton*>(m_pRealForm, "buttonRenewIP");
	m_pAdapterNameLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldAdapter");
	m_pIPAddressLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldIPAddress");
	m_pStatusLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldStatus");
	m_pTimerLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldTimer");
	m_pSSIDLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldSSID");
	m_pSignalLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldSignalStrength");
	m_pSignalIcon = qFindChild<QLabel*>(m_pRealForm, "dataFieldSignalIcon");
	m_pSecurityLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldAssociationMode");
	m_pEncryptionLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldEncryption");
	
	// dynamically populate text
	
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
		
	if (m_pDisconnectButton != NULL)
		m_pDisconnectButton->setText(tr("Disconnect"));
		
	if (m_pRenewIPButton != NULL)
		m_pRenewIPButton->setText(tr("Renew IP"));
		
	QLabel *pLabel;
	pLabel = qFindChild<QLabel*>(m_pRealForm, "headerConnectionStatus");
	if (pLabel != NULL)
		pLabel->setText(tr("Connection Details"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelAdapter");
	if (pLabel != NULL)
		pLabel->setText(tr("Adapter:"));
			
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelIPAddress");
	if (pLabel != NULL)
		pLabel->setText(tr("IP Address:"));
	
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelStatus");
	if (pLabel != NULL)
		pLabel->setText(tr("Status:"));
			
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelTimer");
	if (pLabel != NULL)
		pLabel->setText(tr("Time Connected:"));
			
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelSSID");
	if (pLabel != NULL)
		pLabel->setText(tr("SSID:"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelSignalStrength");
	if (pLabel != NULL)
		pLabel->setText(tr("Signal Strength:"));
		
	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelAssociationMode");
	if (pLabel != NULL)
		pLabel->setText(tr("Security:"));

	pLabel = qFindChild<QLabel*>(m_pRealForm, "labelEncryption");
	if (pLabel != NULL)
		pLabel->setText(tr("Encryption:"));							
	
	// set up event handling
	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
		
	if (m_pDisconnectButton != NULL)
		Util::myConnect(m_pDisconnectButton, SIGNAL(clicked()), this, SLOT(disconnect()));
		
	if (m_pRenewIPButton != NULL)
		Util::myConnect(m_pRenewIPButton, SIGNAL(clicked()), this, SLOT(renewIP()));
		
	Util::myConnect(&m_timer, SIGNAL(timeout()), this, SLOT(timerUpdate()));
	
	Util::myConnect(&m_strengthTimer, SIGNAL(timeout()), this, SLOT(updateWirelessSignalStrength()));
		
	Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
		this, SLOT(stateChange(const QString &, int, int, int, unsigned int)));
		
	Util::myConnect(m_pEmitter, SIGNAL(signalIPAddressSet()), this, SLOT(updateIPAddress()));	
	
	// other initializations
	
	// load icons for signal strength
	QPixmap *p;
	
	p = FormLoader::loadicon("signal_0.png");
	if (p != NULL)
	{
		m_signalIcons[0] = *p;
		delete p;
	}
	
	p = FormLoader::loadicon("signal_1.png");
	if (p != NULL)
	{
		m_signalIcons[1] = *p;
		delete p;
	}

	p = FormLoader::loadicon("signal_2.png");
	if (p != NULL)
	{
		m_signalIcons[2] = *p;
		delete p;
	}
	
	p = FormLoader::loadicon("signal_3.png");
	if (p != NULL)
	{
		m_signalIcons[3] = *p;
		delete p;
	}
	
	p = FormLoader::loadicon("signal_4.png");
	if (p != NULL)
	{
		m_signalIcons[4] = *p;
		delete p;		
	}
	
	return true;
}

void ConnectionInfoDlg::disconnect(void)
{
	if (xsupgui_request_disconnect_connection(m_curAdapterName.toAscii().data()) != REQUEST_SUCCESS)
	{
		QMessageBox::critical(NULL, tr("Error Disconnecting"),
			tr("An error occurred while disconnecting device '%1'.\n").arg(m_curAdapter));			
	}
}

void ConnectionInfoDlg::renewIP(void)
{	
	xsupgui_request_dhcp_release_renew(m_curAdapterName.toAscii().data());
}

void ConnectionInfoDlg::setAdapter(const QString &adapterDesc)
{
	m_curAdapter = adapterDesc;
	m_strengthTimer.stop();
	
	if (m_curAdapter.isEmpty())
		this->clearUI();
	else
	{
		char *pDeviceName = NULL;
		int retVal;
		
		retVal = xsupgui_request_get_devname(m_curAdapter.toAscii().data(), &pDeviceName);
		if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)	
			m_curAdapterName = pDeviceName;
		else
			m_curAdapterName = "";
			
		if (pDeviceName != NULL)
			free(pDeviceName);
			
		config_interfaces *pInterface;
		retVal =xsupgui_request_get_interface_config(m_curAdapter.toAscii().data(),&pInterface);
		if (retVal == REQUEST_SUCCESS && pInterface != NULL)
		{
			if ((pInterface->flags & CONFIG_INTERFACE_IS_WIRELESS) == CONFIG_INTERFACE_IS_WIRELESS)
			{
				m_wirelessAdapter = true;
				if (m_pAdapterNameLabel != NULL)
				{
					QString adapterText;
					adapterText = Util::removePacketSchedulerFromName(m_curAdapter);
					m_pAdapterNameLabel->setText(adapterText);
				}
				this->updateWirelessState();
			}
			else
			{
				m_wirelessAdapter = false;
				if (m_pAdapterNameLabel != NULL)
				{
					QString adapterText;
					adapterText = Util::removePacketSchedulerFromName(m_curAdapter);
					m_pAdapterNameLabel->setText(adapterText);
				}
				this->updateWiredState();		
			}
			this->updateIPAddress();
		}
		else
		{
			this->clearUI();
		}
		
		if (pInterface != NULL)
			xsupgui_request_free_interface_config(&pInterface);
	}
}

void ConnectionInfoDlg::updateWirelessState(void)
{
	Util::ConnectionStatus status = Util::status_idle;
	if (m_curAdapterName.isEmpty() == false)
	{
		int state = 0;
		int retVal = 0;
		
		// get name of connection that's bound
		char *connName = NULL;
		config_connection *pConn = NULL;
		
		retVal = xsupgui_request_get_conn_name_from_int(m_curAdapterName.toAscii().data(), &connName);
		if (retVal == REQUEST_SUCCESS && connName != NULL)
		{
			// get connection info so we can look at it when deciding 
			bool success = XSupWrapper::getConfigConnection(QString(connName), &pConn);
			if (success == false && pConn != NULL)
			{
				XSupWrapper::freeConfigConnection(&pConn);
				pConn = NULL;
			}
		}
		else
		{
			if (connName != NULL)
				free(connName);
		}
		
		if (xsupgui_request_get_physical_state(m_curAdapterName.toAscii().data(), &state) == REQUEST_SUCCESS)
		{
			if (state != WIRELESS_ASSOCIATED || (pConn != NULL && pConn->association.association_type != AUTH_EAP))
			{
				status = Util::getConnectionStatusFromPhysicalState(state);
			}
			else
			{
				// only check with dot1X state machine if it's a dot1X connection
				if (xsupgui_request_get_1x_state(m_curAdapterName.toAscii().data(), &state) == REQUEST_SUCCESS)
					status = Util::getConnectionStatusFromDot1XState(state);	
			}
		}
		
		if (m_pStatusLabel != NULL)
			m_pStatusLabel->setText(Util::getConnectionTextFromConnectionState(status));
	
		if (status == Util::status_connected)
			this->startConnectedTimer();
		else
			this->stopAndClearTimer();
							
		if (status == Util::status_idle)
		{
			m_strengthTimer.stop();
			if (m_pSSIDLabel != NULL)
				m_pSSIDLabel->setText("");			
			if (m_pSignalIcon != NULL)
				m_pSignalIcon->clear();
			if (m_pSignalLabel != NULL)
				m_pSignalLabel->setText("");
			if (m_pIPAddressLabel != NULL)
				m_pIPAddressLabel->setText("");
			if (m_pSecurityLabel != NULL)
				m_pSecurityLabel->setText("");
			if (m_pEncryptionLabel != NULL)
				m_pEncryptionLabel->setText("");											
		}
		else
		{
			if (pConn != NULL)
			{
				if (m_pSSIDLabel != NULL)
					m_pSSIDLabel->setText(QString(pConn->ssid));
					
				if (m_pSecurityLabel != NULL)
				{
					int authType;
					
					retVal = xsupgui_request_get_association_type(m_curAdapterName.toAscii().data(), &authType);
					if (retVal == REQUEST_SUCCESS)
					{
						// either no security or WEP
						if (authType == ASSOC_TYPE_OPEN)
						{
							int keyType;
							retVal = xsupgui_request_get_pairwise_key_type(m_curAdapterName.toAscii().data(), &keyType);
							if (retVal == REQUEST_SUCCESS)
							{
								if (keyType == CIPHER_WEP40 || keyType == CIPHER_WEP104)
									m_pSecurityLabel->setText(tr("WEP"));
								else
									m_pSecurityLabel->setText(tr("None"));
							}
							else
								m_pSecurityLabel->setText(tr("<Unknown>"));
													
						}
						else if (authType == ASSOC_TYPE_WPA1)
						{
							// find out if PSK or not
							if (pConn->association.auth_type == AUTH_EAP)
								m_pSecurityLabel->setText(tr("WPA-Enterprise"));
							else
								m_pSecurityLabel->setText(tr("WPA-Personal"));
						}
						else if (authType == ASSOC_TYPE_WPA2)
						{
							// find out if PSK or not
							if (pConn->association.auth_type == AUTH_EAP)
								m_pSecurityLabel->setText(tr("WPA2-Enterprise"));
							else
								m_pSecurityLabel->setText(tr("WPA2-Personal"));
						}
					}
					else
						m_pSecurityLabel->setText(tr("<Unknown>"));
				}
				if (m_pEncryptionLabel != NULL)
				{
					int keyType;
					QString encryptionText;
					
					retVal = xsupgui_request_get_pairwise_key_type(m_curAdapterName.toAscii().data(), &keyType);
					if (retVal == REQUEST_SUCCESS)
					{
						switch (keyType)   // keyType contains the value for the encryption method we are using.
						{
							case CIPHER_NONE:
								encryptionText = tr("None");
								break;

							case CIPHER_WEP40:
								// TODO: check profile for key length
#ifdef WINDOWS
								encryptionText = tr("WEP");  // Windows doesn't let us tell between WEP40 & WEP104.
#else
								encryptionText = tr("WEP40");
#endif
								break;

							case CIPHER_TKIP:
								encryptionText = tr("TKIP");
								break;

							case CIPHER_CCMP:
								encryptionText = tr("CCMP");
								break;

							case CIPHER_WEP104:
								// TODO: check profile for key length
#ifdef WINDOWS
								encryptionText = tr("WEP");  // Windows doesn't let us tell between WEP40 & WEP104.
#else
								encryptionText = tr("WEP104");
#endif
								break;

							default:
								encryptionText = tr("<Unknown>");
								break;
						}
						m_pEncryptionLabel->setText(encryptionText);					
					}
					
					else
						m_pEncryptionLabel->setText(tr("<Unknown>"));
				}
			}
			else
			{
				if (m_pSecurityLabel != NULL)
					m_pSecurityLabel->setText(tr("<Unknown>"));
				if (m_pSSIDLabel != NULL)
					m_pSSIDLabel->setText("<Unknown>");
				if (m_pEncryptionLabel != NULL)
					m_pEncryptionLabel->setText(tr("<Unknown>"));
			}
			
			m_strengthTimer.start(3000);
			this->updateWirelessSignalStrength();
			this->updateIPAddress();
		}
		
		if (pConn != NULL)
		{
			XSupWrapper::freeConfigConnection(&pConn);
			pConn = NULL;
		}
		if (connName != NULL)
		{
			free(connName);
			connName = NULL;
		}
	}
	else
	{
		// if can't get data, just clear everything out
		if (m_pSSIDLabel != NULL)
			m_pSSIDLabel->setText("");			
		if (m_pSignalIcon != NULL)
			m_pSignalIcon->clear();
		if (m_pSignalLabel != NULL)
			m_pSignalLabel->setText("");
		if (m_pIPAddressLabel != NULL)
			m_pIPAddressLabel->setText("");
		if (m_pSecurityLabel != NULL)
			m_pSecurityLabel->setText("");
		if (m_pEncryptionLabel != NULL)
			m_pEncryptionLabel->setText("");							
	}
	
	if (m_pDisconnectButton != NULL)
		m_pDisconnectButton->setEnabled(status != Util::status_idle);
	if (m_pRenewIPButton != NULL)
		m_pRenewIPButton->setEnabled(status != Util::status_idle);
}

void ConnectionInfoDlg::updateWiredState(void)
{
	Util::ConnectionStatus status = Util::status_idle;
	
	if (m_curAdapterName.isEmpty() == false)
	{
		int retval = 0;
		int state = 0;
		
		retval = xsupgui_request_get_1x_state(m_curAdapterName.toAscii().data(), &state);
		if (retval == REQUEST_SUCCESS)
		{
			status = Util::getConnectionStatusFromDot1XState(state);
			if (m_pStatusLabel != NULL)
				m_pStatusLabel->setText(Util::getConnectionTextFromConnectionState(status));
			if (status == Util::status_connected)
				this->startConnectedTimer();
			else
				this->stopAndClearTimer();			
		}
	}
	
	if (m_pDisconnectButton != NULL)
		m_pDisconnectButton->setEnabled(status != Util::status_idle);
	if (m_pRenewIPButton != NULL)
		m_pRenewIPButton->setEnabled(status != Util::status_idle);
		
	// unused state fields	
	if (m_pSSIDLabel != NULL)
		m_pSSIDLabel->setText("");
	if (m_pSecurityLabel != NULL)
		m_pSecurityLabel->setText("");
	if (m_pEncryptionLabel != NULL)
		m_pEncryptionLabel->setText("");
	if (m_pSignalLabel != NULL)
		m_pSignalLabel->setText("");
	if (m_pSignalIcon != NULL)
		m_pSignalIcon->clear();						
}

void ConnectionInfoDlg::stopAndClearTimer(void)
{
	m_days = 0;
	m_timer.stop();
	m_time.setHMS(0, 0, 0);
	this->showTime();
}

void ConnectionInfoDlg::updateElapsedTime(void)
{
	long int seconds = 0;
	
	if (xsupgui_request_get_seconds_authenticated(m_curAdapterName.toAscii().data(), &seconds) == REQUEST_SUCCESS)
	{
		int hours = 0;
		int minutes = 0;
		long int tempTime = seconds;
    
		// Get days, hours, minutes and seconds the hard way - for now
		m_days = (unsigned int)(tempTime / (60*60*24));
		tempTime = tempTime % (60*60*24);
		hours = (int) (tempTime / (60*60));
		tempTime = tempTime % (60*60);
		minutes = (int) tempTime / 60;
		seconds = tempTime % 60;

		m_time.setHMS(hours, minutes, seconds);
	}
}

void ConnectionInfoDlg::startConnectedTimer(void)
{
	this->updateElapsedTime();
	this->showTime();
	m_timer.start(500);
}

void ConnectionInfoDlg::showTime(void)
{
	QString timeString;

	if (m_days > 0)
		timeString = QString("%1d, %2").arg(m_days).arg(m_time.toString(Qt::TextDate));
	else
		timeString = QString("%1").arg(m_time.toString(Qt::TextDate));

	if (m_pTimerLabel != NULL)
		m_pTimerLabel->setText(timeString);
}

void ConnectionInfoDlg::timerUpdate(void)
{
	this->updateElapsedTime();
	this->showTime();
}

void ConnectionInfoDlg::stateChange(const QString &intName, int , int, int , unsigned int)
{	
	// We only care if it is the adapter that is currently displayed.
	if (intName == m_curAdapterName)
	{
		if (m_wirelessAdapter == true)
			this->updateWirelessState();
		else
			this->updateWiredState();
	}
}
void ConnectionInfoDlg::clearUI(void)
{
	if (m_pAdapterNameLabel != NULL)
		m_pAdapterNameLabel->setText("");
	if (m_pIPAddressLabel != NULL)
		m_pIPAddressLabel->setText("");
	if (m_pStatusLabel != NULL)
		m_pStatusLabel->setText("");
	if (m_pTimerLabel != NULL)
		m_pTimerLabel->setText("");
	if (m_pSSIDLabel != NULL)
		m_pSSIDLabel->setText("");
	if (m_pSecurityLabel != NULL)
		m_pSecurityLabel->setText("");
	if (m_pEncryptionLabel != NULL)
		m_pEncryptionLabel->setText("");
	if (m_pSignalLabel != NULL)
		m_pSignalLabel->setText("");
	if (m_pSignalIcon != NULL)
		m_pSignalIcon->clear();									
}
void ConnectionInfoDlg::updateIPAddress(void)
{
	int retVal;
	QString ipText = "0.0.0.0";
	
	if (m_curAdapterName.isEmpty() == false)
	{
		ipinfo_type *pInfo;
		retVal = xsupgui_request_get_ip_info(m_curAdapterName.toAscii().data(), &pInfo);
		if (retVal == REQUEST_SUCCESS && pInfo != NULL)
			ipText = pInfo->ipaddr;
		if (pInfo != NULL)
			xsupgui_request_free_ip_info(&pInfo);			
	}

	if (m_pIPAddressLabel != NULL)
		m_pIPAddressLabel->setText(ipText);
}

void ConnectionInfoDlg::updateWirelessSignalStrength(void)
{
	int retval;
	int strength;
	
	retval = xsupgui_request_get_signal_strength_percent(m_curAdapterName.toAscii().data(), &strength);
	if (retval == REQUEST_SUCCESS)
	{
		if (m_pSignalLabel != NULL)
			m_pSignalLabel->setText(QString("%1%").arg(strength));
			
		if (m_pSignalIcon != NULL)
		{
			if (strength <= 11)
				m_pSignalIcon->setPixmap(m_signalIcons[0]);
			else if (strength <= 37)
				m_pSignalIcon->setPixmap(m_signalIcons[1]);
			else if (strength <= 62)
				m_pSignalIcon->setPixmap(m_signalIcons[2]);
			else if (strength <= 88)
				m_pSignalIcon->setPixmap(m_signalIcons[3]);
			else
				m_pSignalIcon->setPixmap(m_signalIcons[4]);	
		}		
	}
	else
	{
		if (m_pSignalLabel != NULL)
			m_pSignalLabel->setText(QString("0%"));
		if (m_pSignalIcon != NULL)
			m_pSignalIcon->setPixmap(m_signalIcons[0]);
	}
}