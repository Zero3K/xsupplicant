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

#include "ConfigConnectionTabs.h"
#include "ConfigConnAdapterTab.h"
#include "ConfigConnNetTab.h"
#include "ConfigConnDNSTab.h"

ConfigConnectionTabs::ConfigConnectionTabs(QWidget *pRealWidget, Emitter *e, XSupCalls *pSupplicant, config_connection *pConn, QWidget *parent):
	m_pConn(pConn), m_pParent(parent), m_pRealWidget(pRealWidget), m_pSupplicant(pSupplicant), m_pEmitter(e)
{
	m_bDataChanged = false;

	m_pAdapter = NULL;
	m_pNetwork = NULL;
	m_pDNS = NULL;
}

ConfigConnectionTabs::~ConfigConnectionTabs()
{
	Util::myDisconnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));
	Util::myDisconnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

	if ((m_pNetwork != NULL) && (m_pDNS != NULL))
	{
		Util::myDisconnect(m_pNetwork, SIGNAL(signalChangeDHCP(bool)), m_pDNS, SLOT(slotDisableDHCP(bool)));
	}

	if (m_pAdapter != NULL) 
	{
		delete m_pAdapter;
		m_pAdapter = NULL;
	}

	if (m_pNetwork != NULL)
	{
		delete m_pNetwork;
		m_pNetwork = NULL;
	}

	if (m_pDNS != NULL) 
	{
		delete m_pDNS;
		m_pDNS = NULL;
	}
}

bool ConfigConnectionTabs::save()
{
	if (m_pAdapter != NULL)
	{
		if (m_pAdapter->save() == false) return false;
	}

	if (m_pNetwork != NULL)
	{
		if (m_pNetwork->save() == false) return false;
	}

	if (m_pDNS != NULL)
	{
		if (m_pDNS->save() == false) return false;
	}

	return true;
}

bool ConfigConnectionTabs::attach()
{
	Util::myConnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));
	Util::myConnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

	m_pAdapter = new ConfigConnAdapterTab(m_pRealWidget, m_pEmitter, m_pSupplicant, m_pConn, this);
	if ((m_pAdapter == NULL) || (m_pAdapter->attach() == false)) return false;

	m_pNetwork = new ConfigConnNetTab(m_pRealWidget, m_pSupplicant, m_pConn, this);
	if ((m_pNetwork == NULL) || (m_pNetwork->attach() == false)) return false;

	m_pDNS = new ConfigConnDNSTab(m_pRealWidget, m_pSupplicant, m_pConn, this);
	if ((m_pDNS == NULL) || (m_pDNS->attach() == false)) return false;

	if ((m_pNetwork != NULL) && (m_pDNS != NULL))
	{
		Util::myConnect(m_pNetwork, SIGNAL(signalChangeDHCP(bool)), m_pDNS, SLOT(slotDisableDHCP(bool)));
	}

	return true;
}

bool ConfigConnectionTabs::dataChanged()
{
	return m_bDataChanged;
}

void ConfigConnectionTabs::discard()
{
	// Don't need to do anything here.
}

void ConfigConnectionTabs::slotDataChanged()
{
	m_bDataChanged = true;
}