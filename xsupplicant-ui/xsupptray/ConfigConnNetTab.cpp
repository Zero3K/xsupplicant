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
#include "Util.h"
#include "ConfigConnNetTab.h"

ConfigConnNetTab::ConfigConnNetTab(QWidget *pRealWidget, XSupCalls *pSupplicant, config_connection *pConn, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pSupplicant(pSupplicant), m_pConn(pConn), m_pParent(parent)
{
	m_bConnected = false;
	m_bDataChanged = false;
}

ConfigConnNetTab::~ConfigConnNetTab()
{
	if (m_bConnected == true)
	{
		Util::myDisconnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

		Util::myDisconnect(m_pDHCPRadioBtn, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pRenewDHCPCheckbox, SIGNAL(stateChanged(int)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pIPAddrEdit, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pNetmaskEdit, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pGWEdit, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));

		Util::myDisconnect(m_pDHCPRadioBtn, SIGNAL(toggled(bool)), this, SLOT(slotDHCPtoggled(bool)));
	}
}

bool ConfigConnNetTab::attach()
{
	m_pDHCPRadioBtn = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioDHCP");
	if (m_pDHCPRadioBtn == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton named 'dataRadioDHCP'."));
		return false;
	}

	m_pStaticRadioBtn = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioStaticIP");
	if (m_pStaticRadioBtn == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton named 'dataRadioStaticIP'."));
		return false;
	}

	m_pRenewDHCPCheckbox = qFindChild<QCheckBox*>(m_pRealWidget, "dataCheckboxRenewSettings");
	if (m_pRenewDHCPCheckbox == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QCheckBox named 'dataCheckboxRenewSettings'."));
		return false;
	}

	m_pIPAddrEdit = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldStaticIPAddress");
	if (m_pIPAddrEdit == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit named 'dataFieldStaticIPAddress'."));
		return false;
	}

	m_pNetmaskEdit = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldStaticIPNetmask");
	if (m_pNetmaskEdit == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit named 'dataFieldStaticIPNetmask'."));
		return false;
	}

	m_pGWEdit = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldStaticIPGateway");
	if (m_pGWEdit == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit named 'dataFieldStaticIPGateway'."));
		return false;
	}

	m_pIPAddrEdit->setValidator(new QRegExpValidator(QRegExp("^(([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pIPAddrEdit));
	m_pNetmaskEdit->setValidator(new QRegExpValidator(QRegExp("^(([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pNetmaskEdit));
	m_pGWEdit->setValidator(new QRegExpValidator(QRegExp("^(([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pGWEdit));

	updateWindow();

	Util::myConnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));
	
	// This will cover both radio buttons.
	Util::myConnect(m_pDHCPRadioBtn, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
	Util::myConnect(m_pRenewDHCPCheckbox, SIGNAL(stateChanged(int)), this, SIGNAL(signalDataChanged()));
	Util::myConnect(m_pIPAddrEdit, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	Util::myConnect(m_pNetmaskEdit, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	Util::myConnect(m_pGWEdit, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));

	Util::myConnect(m_pDHCPRadioBtn, SIGNAL(toggled(bool)), this, SLOT(slotDHCPtoggled(bool)));

	m_bConnected = true;

	return true;
}

bool ConfigConnNetTab::save()
{
	if (m_pDHCPRadioBtn->isChecked() == true)
	{
		// Doing DHCP
		m_pConn->ip.type = CONFIG_IP_USE_DHCP;

		if (m_pRenewDHCPCheckbox->isChecked() == true)
		{
			m_pConn->ip.renew_on_reauth = TRUE;
		}
		else
		{
			m_pConn->ip.renew_on_reauth = FALSE;
		}

		if (m_pConn->ip.ipaddr != NULL)
		{
			free(m_pConn->ip.ipaddr);
			m_pConn->ip.ipaddr = NULL;
		}

		if (m_pConn->ip.netmask != NULL)
		{
			free(m_pConn->ip.netmask);
			m_pConn->ip.netmask = NULL;
		}

		if (m_pConn->ip.gateway != NULL)
		{
			free(m_pConn->ip.gateway);
			m_pConn->ip.gateway = NULL;
		}
	}
	else
	{
		// Doing static.
		m_pConn->ip.type = CONFIG_IP_USE_STATIC;

		if (m_pIPAddrEdit->text() == "")
		{
			QMessageBox::critical(this, tr("Configuration Error"), tr("Please enter a valid IP address in the space provided."));
			return false;
		}

		if (Util::isIPAddrValid(m_pIPAddrEdit->text()) == false) 
		{
			QMessageBox::critical(this, tr("Configuration Error"), tr("The IP address provided is a broadcast address.  Please provide a valid address."));
			return false;
		}

		if (m_pConn->ip.ipaddr != NULL)
		{
			free(m_pConn->ip.ipaddr);
			m_pConn->ip.ipaddr = NULL;
		}

		m_pConn->ip.ipaddr = _strdup(m_pIPAddrEdit->text().toAscii());

		if (m_pNetmaskEdit->text() == "")
		{
			QMessageBox::critical(this, tr("Configuration Error"), tr("Please enter a valid netmask in the space provided."));
			return false;
		}

		if (m_pConn->ip.netmask != NULL)
		{
			free(m_pConn->ip.netmask);
			m_pConn->ip.netmask = NULL;
		}

		if (Util::isNetmaskValid(m_pNetmaskEdit->text()) == false) 
		{
			QMessageBox::critical(this, tr("Configuration Error"), tr("The netmask provided is invalid."));
			return false;
		}
		
		if (Util::ipIsBroadcast(m_pIPAddrEdit->text(), m_pNetmaskEdit->text()) == true)
		{
			QMessageBox::critical(this, tr("Configuration Error"), tr("The IP address provided is a broadcast address.  Please provide a valid IP address."));
			return false;
		}

		m_pConn->ip.netmask = _strdup(m_pNetmaskEdit->text().toAscii());

		if (m_pGWEdit->text() != "")
		{
			if (Util::isGWinSubnet(m_pIPAddrEdit->text(), m_pNetmaskEdit->text(), m_pGWEdit->text()) == false)
			{
				QMessageBox::critical(this, tr("Configuration Error"), tr("The provided gateway is not a member of the same subnet as the IP address."));
				return false;
			}
		}

		if (m_pConn->ip.gateway != NULL)
		{
			free(m_pConn->ip.gateway);
			m_pConn->ip.gateway = NULL;
		}

		if (m_pGWEdit->text() != "") m_pConn->ip.gateway = _strdup(m_pGWEdit->text().toAscii());
	}

	return true;
}

void ConfigConnNetTab::slotDataChanged()
{
	m_bDataChanged = true;
}

void ConfigConnNetTab::slotDHCPtoggled(bool active)
{
	if (active)
	{
		// Use DHCP is selected.
		m_pRenewDHCPCheckbox->setEnabled(true);
		m_pIPAddrEdit->setEnabled(false);
		m_pNetmaskEdit->setEnabled(false);
		m_pGWEdit->setEnabled(false);
		emit signalChangeDHCP(true);
	}
	else
	{
		// Use static is selected.
		m_pRenewDHCPCheckbox->setEnabled(false);
		m_pIPAddrEdit->setEnabled(true);
		m_pNetmaskEdit->setEnabled(true);
		m_pGWEdit->setEnabled(true);
		emit signalChangeDHCP(false);
	}
}

void ConfigConnNetTab::updateWindow()
{
	if (m_pConn == NULL) return;

	if (m_pConn->ip.type == CONFIG_IP_USE_DHCP)
	{
		slotDHCPtoggled(true);
		m_pDHCPRadioBtn->setChecked(true);
		m_pStaticRadioBtn->setChecked(false);

		m_pIPAddrEdit->clear();
		m_pNetmaskEdit->clear();
		m_pGWEdit->clear();

		if (m_pConn->ip.renew_on_reauth == TRUE)
		{
			m_pRenewDHCPCheckbox->setChecked(true);
		}
		else
		{
			m_pRenewDHCPCheckbox->setChecked(false);
		}
	}
	else
	{
		slotDHCPtoggled(false);
		m_pDHCPRadioBtn->setChecked(false);
		m_pStaticRadioBtn->setChecked(true);

		m_pIPAddrEdit->setText(QString(m_pConn->ip.ipaddr));
		m_pNetmaskEdit->setText(QString(m_pConn->ip.netmask));
		m_pGWEdit->setText(QString(m_pConn->ip.gateway));
	}
}

