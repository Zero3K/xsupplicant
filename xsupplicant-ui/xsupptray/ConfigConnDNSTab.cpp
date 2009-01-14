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
#include "ConfigConnDNSTab.h"

ConfigConnDNSTab::ConfigConnDNSTab(QWidget *pRealWidget, XSupCalls *pSupplicant, config_connection *pConn, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pSupplicant(pSupplicant), m_pConn(pConn), m_pParent(parent)
{
	m_bConnected = false;
	m_bDataChanged = false;
}

ConfigConnDNSTab::~ConfigConnDNSTab()
{
	if (m_bConnected == true)
	{
		Util::myDisconnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

	}
}

bool ConfigConnDNSTab::attach()
{
	m_pDHCPAuto = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioAutoDNS");
	if (m_pDHCPAuto == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Couldn't find the QRadioButton called 'dataRadioAutoDNS'."));
		return false;
	}

	m_pDHCPStatic = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioStaticDNS");
	if (m_pDHCPStatic == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Couldn't find the QRadioButton called 'dataRadioStaticDNS'."));
		return false;
	}

	m_pPrimaryDNS = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldStaticDNSPrimary");
	if (m_pPrimaryDNS == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Couldn't find the QLineEdit called 'dataFieldStaticDNSPrimary'."));
		return false;
	}

	m_pPrimaryDNS->setValidator(new QRegExpValidator(QRegExp("^(([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pPrimaryDNS));

	m_pSecondaryDNS = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldStaticDNSSecondary");
	if (m_pSecondaryDNS == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Couldn't find the QLineEdit called 'dataFieldStaticDNSSecondary'."));
		return false;
	}

	m_pSecondaryDNS->setValidator(new QRegExpValidator(QRegExp("^(([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pSecondaryDNS));


	m_pSuffix = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldStaticDNSDomainSuffix");
	if (m_pSuffix == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Couldn't find the QLineEdit called 'dataFieldStaticDNSDomainSuffix'."));
		return false;
	}

	m_pPrimaryDNS->setValidator(new QRegExpValidator(QRegExp("^(([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pPrimaryDNS));
	m_pSecondaryDNS->setValidator(new QRegExpValidator(QRegExp("^(([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])\\.){3}([3-9]\\d?|[01]\\d{0,2}|2\\d?|2[0-4]\\d|25[0-5])$"), m_pSecondaryDNS));
	m_pSuffix->setValidator(new QRegExpValidator(QRegExp("^[\\w|\\.]{0,128}$"), m_pSuffix));

	updateWindow();

	Util::myConnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

	// This will cover both radio buttons.
	Util::myConnect(m_pDHCPAuto, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
	Util::myConnect(m_pDHCPAuto, SIGNAL(toggled(bool)), this, SLOT(slotDHCPToggled(bool)));

	Util::myConnect(m_pPrimaryDNS, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	Util::myConnect(m_pSecondaryDNS, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	Util::myConnect(m_pSuffix, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));

	return true;
}

void ConfigConnDNSTab::updateWindow()
{
	if (m_pConn == NULL) return;

	if (m_pConn->ip.type == CONFIG_IP_USE_STATIC)
	{
		m_pDHCPAuto->setChecked(false);
		m_pDHCPAuto->setEnabled(false);
		m_pDHCPStatic->setChecked(true);
		m_bDHCPSelected = false;
	}

	if ((m_pConn->ip.dns1 == NULL) && (m_pConn->ip.dns2 == NULL) && (m_pConn->ip.dns3 == NULL) &&
		(m_pConn->ip.search_domain == NULL) && (m_pConn->ip.type != CONFIG_IP_USE_STATIC))
	{
		// We are doing auto.
		m_pDHCPAuto->setChecked(true);
		m_pDHCPStatic->setChecked(false);
		m_pPrimaryDNS->clear();
		m_pPrimaryDNS->setEnabled(false);
		m_pSecondaryDNS->clear();
		m_pSecondaryDNS->setEnabled(false);
		m_pSuffix->clear();
		m_pSuffix->setEnabled(false);
		m_bDHCPSelected = true;
	}
	else
	{
		// We are doing static.
		m_pDHCPAuto->setChecked(false);

		if (m_pConn->ip.type == CONFIG_IP_USE_STATIC) m_pDHCPAuto->setEnabled(false);

		m_pDHCPStatic->setChecked(true);

		m_pPrimaryDNS->setEnabled(true);
		if (m_pConn->ip.dns1 != NULL)
		{
			m_pPrimaryDNS->setText(QString(m_pConn->ip.dns1));
		}
		else
		{
			m_pPrimaryDNS->clear();
		}

		m_pSecondaryDNS->setEnabled(true);
		if (m_pConn->ip.dns2 != NULL)
		{
			m_pSecondaryDNS->setText(QString(m_pConn->ip.dns2));
		}
		else
		{
			m_pSecondaryDNS->clear();
		}

		m_pSuffix->setEnabled(true);
		if (m_pConn->ip.search_domain != NULL)
		{
			m_pSuffix->setText(QString(m_pConn->ip.search_domain));
		}
		else
		{
			m_pSuffix->clear();
		}

		m_bDHCPSelected = false;
	}
}

bool ConfigConnDNSTab::save()
{
	if (m_pConn == NULL) return false;

	if (m_pDHCPAuto->isChecked() == true)
	{
		// We are doing auto.
		if (m_pConn->ip.dns1 != NULL)
		{
			free(m_pConn->ip.dns1);
			m_pConn->ip.dns1 = NULL;
		}

		if (m_pConn->ip.dns2 != NULL)
		{
			free(m_pConn->ip.dns2);
			m_pConn->ip.dns2 = NULL;
		}

		if (m_pConn->ip.search_domain != NULL)
		{
			free(m_pConn->ip.search_domain);
			m_pConn->ip.search_domain = NULL;
		}
	}
	else
	{
		// We are doing static.
		if (m_pConn->ip.dns1 != NULL)
		{
			free(m_pConn->ip.dns1);
			m_pConn->ip.dns1 = NULL;
		}

		if ((m_pPrimaryDNS->text() == "") && (m_pSecondaryDNS->text() == ""))
		{
			QMessageBox::critical(this, tr("DNS Setting Error"), tr("You must configure at least a primary DNS server when using static DNS settings."));
			return false;
		}

		if ((m_pPrimaryDNS->text() == "") && (m_pSecondaryDNS->text() != ""))
		{
			QMessageBox::critical(this, tr("DNS Setting Error"), tr("If you only have one DNS server to use, please configure it as the primary DNS server."));
			return false;
		}

		if (m_pPrimaryDNS->text() == m_pSecondaryDNS->text())
		{
			QMessageBox::critical(this, tr("DNS Setting Error"), tr("Your primary and secondary DNS servers can not be set to the same value.  Please correct this and try again."));
			return false;
		}

		if (m_pPrimaryDNS->text() != "")
		{
			if (Util::isIPAddrValid(m_pPrimaryDNS->text()) == false)  
			{
				QMessageBox::critical(this, tr("DNS Setting Error"), tr("The address provided for the primary DNS is a broadcast address.  Please enter a valid address."));
				return false;
			}

			if ((m_pPrimaryDNS->hasAcceptableInput() == false))
			{
				QMessageBox::critical(this, tr("DNS Setting Error"), tr("The address provided for the primary DNS server is incomplete, or invalid.  Please correct this and try again."));
				return false;
			}

			m_pConn->ip.dns1 = _strdup(m_pPrimaryDNS->text().toAscii());
		}

		if (m_pConn->ip.dns2 != NULL)
		{
			free(m_pConn->ip.dns2);
			m_pConn->ip.dns2 = NULL;
		}

		if (m_pSecondaryDNS->text() != "")
		{
			if (Util::isIPAddrValid(m_pSecondaryDNS->text()) == false)
			{
				QMessageBox::critical(this, tr("DNS Setting Error"), tr("The address provided for the secondary DNS is a broadcast address.  Please enter a valid address."));
				return false;
			}

			if ((m_pSecondaryDNS->hasAcceptableInput() == false))
			{
				QMessageBox::critical(this, tr("DNS Setting Error"), tr("The address provided for the secondary DNS server is incomplete, or invalid.  Please correct this and try again."));
				return false;
			}

			m_pConn->ip.dns2 = _strdup(m_pSecondaryDNS->text().toAscii());
		}

		if (m_pConn->ip.search_domain != NULL)
		{
			free(m_pConn->ip.search_domain);
			m_pConn->ip.search_domain = NULL;
		}

		if (m_pSuffix->text() != "")
		{
			m_pConn->ip.search_domain = _strdup(m_pSuffix->text().toAscii());
		}
	}
	return true;
}

void ConfigConnDNSTab::slotDataChanged()
{
	m_bDataChanged = true;
}

void ConfigConnDNSTab::slotDHCPToggled(bool active)
{
	if (active)
	{
		// Grey everything out.
		m_pPrimaryDNS->setEnabled(false);
		m_pSecondaryDNS->setEnabled(false);
		m_pSuffix->setEnabled(false);
	}
	else
	{
		// Make everything available.
		m_pPrimaryDNS->setEnabled(true);
		m_pSecondaryDNS->setEnabled(true);
		m_pSuffix->setEnabled(true);
	}
}

void ConfigConnDNSTab::slotDisableDHCP(bool setting)
{
	m_pDHCPAuto->setEnabled(setting);

	if (setting)
	{
		if (m_bDHCPSelected)
		{
			m_pDHCPAuto->setChecked(true);
			m_pDHCPStatic->setChecked(false);
		}
		else
		{
			m_pDHCPStatic->setChecked(true);
			m_pDHCPAuto->setChecked(false);
		}
	}
	else
	{
		m_pDHCPAuto->setChecked(false);
		m_pDHCPStatic->setChecked(true);
	}
}
