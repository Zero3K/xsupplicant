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
	m_pAdvancedConfig = qFindChild<QCheckBox*>(m_pRealForm, "checkBoxShowAdvanced");
	m_pAdapterNameLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldAdapter");
	m_pIPAddressLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldIPAddress");
	m_pStatusLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldStatus");
	m_pTimerLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldTimer");
	m_pSSIDLabel = qFindChild<QLabel*>(m_pRealForm, "dataFieldSSID");
	
	// dynamically populate text
	
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
		
	if (m_pDisconnectButton != NULL)
		m_pDisconnectButton->setText(tr("Disconnect"));
		
	if (m_pRenewIPButton != NULL)
		m_pRenewIPButton->setText(tr("Renew IP"));
		
	if (m_pAdvancedConfig != NULL)
		m_pAdvancedConfig->setText(tr("Show Advanced Details"));
		
	QLabel *pLabel;
	pLabel = qFindChild<QLabel*>(m_pRealForm, "headerConnectionStatus");
	if (pLabel != NULL)
		pLabel->setText(tr("Connection Status"));
		
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
	
	
	// set up event handling
	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
		
	if (m_pDisconnectButton != NULL)
		Util::myConnect(m_pDisconnectButton, SIGNAL(clicked()), this, SLOT(disconnect()));
		
	if (m_pRenewIPButton != NULL)
		Util::myConnect(m_pRenewIPButton, SIGNAL(clicked()), this, SLOT(renewIP()));
		
	Util::myConnect(&m_timer, SIGNAL(timeout()), this, SLOT(timerUpdate()));
		
	Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
		this, SLOT(stateChange(const QString &, int, int, int, unsigned int)));
		
	Util::myConnect(m_pEmitter, SIGNAL(signalIPAddressSet()), this, SLOT(updateIPAddress()));	
	
	// other initializations
	if (m_pAdvancedConfig != NULL)
		m_pAdvancedConfig->hide(); // not available ATM	
		
	// Initialize the timer that we will use to show the time in connected
	// state.
	m_timer.setInterval(1000);   // Fire every second.
	m_timer.start();				 // Don't run just yet.

	m_timer.stop();		
	
	return true;
}

void ConnectionInfoDlg::disconnect(void)
{
	if (XSupWrapper::disconnectAdapter(m_curAdapter) == false)
	{
		QMessageBox::critical(NULL, tr("Error Disconnecting"),
			tr("An error occurred while disconnecting device '%1'.\n").arg(m_curAdapter));			
	}
}

void ConnectionInfoDlg::renewIP(void)
{	
	char *pDeviceName = NULL;
	int retval = 0;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_curAdapter.toAscii().data(), &pDeviceName);
	if (retval == REQUEST_SUCCESS && pDeviceName == NULL)
		xsupgui_request_dhcp_release_renew(pDeviceName);
		
	if (pDeviceName != NULL)
		free(pDeviceName);
}

void ConnectionInfoDlg::setAdapter(const QString &adapterDesc)
{
	int retVal;
	
	m_curAdapter = adapterDesc;
	
	if (m_curAdapter.isEmpty())
		this->clearUI();
	else
	{
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
					m_pAdapterNameLabel->setText(m_curAdapter);
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
	char *pDeviceName = NULL;
	int retval = 0;
	int state = 0;
	Util::ConnectionStatus status = Util::status_idle;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_curAdapter.toAscii().data(), &pDeviceName);
	if (retval == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		retval = xsupgui_request_get_physical_state(pDeviceName, &state);
		if (retval == REQUEST_SUCCESS)
		{
			if (state != WIRELESS_ASSOCIATED)
			{
				status = Util::getConnectionStatusFromPhysicalState(state);
				if (m_pStatusLabel != NULL)
					m_pStatusLabel->setText(Util::getConnectionTextFromConnectionState(status));
				if (status == Util::status_connected)
					this->startConnectedTimer();
				else
					this->stopAndClearTimer();
				if (status != Util::status_idle)
					this->updateSSID();
				else
					if (m_pSSIDLabel != NULL)
						m_pSSIDLabel->setText("");
			}
			else
			{
				retval = xsupgui_request_get_1x_state(pDeviceName, &state);
				if (retval == REQUEST_SUCCESS)
				{
					status = Util::getConnectionStatusFromDot1XState(state);
					if (m_pStatusLabel != NULL)
						m_pStatusLabel->setText(Util::getConnectionTextFromConnectionState(status));
					if (status == Util::status_connected)
						this->startConnectedTimer();
					else
						this->stopAndClearTimer();	
					if (status != Util::status_idle)
						this->updateSSID();
					else
						if (m_pSSIDLabel != NULL)
							m_pSSIDLabel->setText("");							
				}
			}
		}
	}

	if (m_pDisconnectButton != NULL)
		m_pDisconnectButton->setEnabled(status != Util::status_idle);
	if (m_pRenewIPButton != NULL)
		m_pRenewIPButton->setEnabled(status != Util::status_idle);			
				
	if (pDeviceName != NULL)
		free(pDeviceName);
}

void ConnectionInfoDlg::updateWiredState(void)
{
	char *pDeviceName = NULL;
	int retval = 0;
	int state = 0;
	Util::ConnectionStatus status = Util::status_idle;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_curAdapter.toAscii().data(), &pDeviceName);
	if (retval == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		retval = xsupgui_request_get_1x_state(pDeviceName, &state);
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
		
	if (m_pSSIDLabel != NULL)
		m_pSSIDLabel->setText("");
		
	if (pDeviceName != NULL)
		free(pDeviceName);		
}

void ConnectionInfoDlg::stopAndClearTimer(void)
{
	m_days = 0;
	m_timer.stop();
	m_time.setHMS(0, 0, 0);
	this->showTime();
}

void ConnectionInfoDlg::startConnectedTimer(void)
{
	int retval = 0;
	long int seconds = 0;
	char *pDeviceName = NULL;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_curAdapter.toAscii().data(), &pDeviceName);
	if ((retval != REQUEST_SUCCESS) || (pDeviceName == NULL))
	{
		// If we can't determine the device name, then tell the caller the connection can't
		// be made.
		return;
	}
	
	retval = xsupgui_request_get_seconds_authenticated(pDeviceName, &seconds);
	if (retval == REQUEST_SUCCESS)
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

		this->showTime();

		m_timer.start(1000);
	}
	
	if (pDeviceName != NULL)
		free(pDeviceName);
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
void ConnectionInfoDlg::stateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid)
{
	char *pDeviceName = NULL;
	int retval = 0;

	// Using the device description - get the device name
	retval = xsupgui_request_get_devname(m_curAdapter.toAscii().data(), &pDeviceName);
	if ((retval != REQUEST_SUCCESS) || (pDeviceName == NULL))
		return;
	
	// We only care if it is the adapter that is currently displayed.
	if (intName == QString(pDeviceName))
	{
		if (sm == IPC_STATEMACHINE_8021X)
		{
			Util::ConnectionStatus status;
			status = Util::getConnectionStatusFromDot1XState(newstate);
			if (m_pStatusLabel != NULL)
				m_pStatusLabel->setText(Util::getConnectionTextFromConnectionState(status));
				
			if (status == Util::status_connected)
				this->startConnectedTimer();
			else
				this->stopAndClearTimer();
				
			if (m_wirelessAdapter == true && status != Util::status_idle)
			{
				this->updateSSID();
				this->updateIPAddress();
			}
			else
			{
				if (m_pSSIDLabel != NULL)
					m_pSSIDLabel->setText("");
				if (m_pIPAddressLabel != NULL)
					m_pIPAddressLabel->setText("");
			}
			if (m_pDisconnectButton != NULL)
				m_pDisconnectButton->setEnabled(status != Util::status_idle);
			if (m_pRenewIPButton != NULL)
				m_pRenewIPButton->setEnabled(status != Util::status_idle);									
		}

		if (sm == IPC_STATEMACHINE_PHYSICAL)
		{
			Util::ConnectionStatus status;
			status = Util::getConnectionStatusFromPhysicalState(newstate);
			
			if (m_pStatusLabel != NULL)
				m_pStatusLabel->setText(Util::getConnectionTextFromConnectionState(status));
				
			if (status == Util::status_connected)
				this->startConnectedTimer();
			else
				this->stopAndClearTimer();
				
			if (m_wirelessAdapter == true && status != Util::status_idle)
			{
				this->updateSSID();
				this->updateIPAddress();
			}
			else
			{
				if (m_pSSIDLabel != NULL)
					m_pSSIDLabel->setText("");
				if (m_pIPAddressLabel != NULL)
					m_pIPAddressLabel->setText("");
			}
			
			if (m_pDisconnectButton != NULL)
				m_pDisconnectButton->setEnabled(status != Util::status_idle);
			if (m_pRenewIPButton != NULL)
				m_pRenewIPButton->setEnabled(status != Util::status_idle);													
		}
	}
	if (pDeviceName != NULL)
		free(pDeviceName);
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
}
void ConnectionInfoDlg::updateIPAddress(void)
{
	int retVal;
	char *pDeviceName = NULL;
	QString ipText = "0.0.0.0";
	
	if (m_curAdapter.isEmpty())
		return;
		
	// Using the device description - get the device name
	retVal = xsupgui_request_get_devname(m_curAdapter.toAscii().data(), &pDeviceName);
	if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		ipinfo_type *pInfo;
		retVal = xsupgui_request_get_ip_info(pDeviceName, &pInfo);
		if (retVal == REQUEST_SUCCESS && pInfo != NULL)
			ipText = pInfo->ipaddr;
		if (pInfo != NULL)
			xsupgui_request_free_ip_info(&pInfo);			
	}

	if (m_pIPAddressLabel != NULL)
		m_pIPAddressLabel->setText(ipText);
	if (pDeviceName != NULL)
		free(pDeviceName);
}
void ConnectionInfoDlg::updateSSID(void)
{
	int retVal;
	QString ssidText = "";
	
	char *pDeviceName = NULL;

	// Using the device description - get the device name
	retVal = xsupgui_request_get_devname(m_curAdapter.toAscii().data(), &pDeviceName);
	if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		char *ssid = NULL;
		retVal = xsupgui_request_get_ssid(pDeviceName, &ssid);
		if (retVal == REQUEST_SUCCESS && ssid != NULL)
			ssidText = ssid;
		if (ssid != NULL)
			free(ssid);
	}

	if (m_pSSIDLabel != NULL)
		m_pSSIDLabel->setText(ssidText);
		
	if (pDeviceName != NULL)
		free(pDeviceName);

}