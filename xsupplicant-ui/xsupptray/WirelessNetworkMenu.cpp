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

#include "WirelessNetworkMenu.h"
#include "TrayApp.h"
#include "SSIDList.h"
#include "FormLoader.h"
#include <algorithm>

WirelessNetworkMenu::WirelessNetworkMenu(const QString &adapterDesc, const QString &menuTitle, TrayApp *trayApp)
	:QWidget(trayApp), m_adapterDesc(adapterDesc), m_pTrayApp(trayApp)
{
	m_pMenu = new QMenu(menuTitle);
	if (m_pMenu != NULL)
		Util::myConnect(m_pMenu, SIGNAL(triggered(QAction *)), this, SLOT(handleMenuSelection(QAction *)));
		
	QPixmap *p;
	
	p = FormLoader::loadicon("lockedstate_bw.png");
	if (p != NULL)
	{
		m_lockIcon.addPixmap(*p);
		delete p;
	}				
}

WirelessNetworkMenu::~WirelessNetworkMenu()
{
	if (m_pMenu != NULL) {
		Util::myDisconnect(m_pMenu, SIGNAL(triggered(QAction *)), this, SLOT(handleMenuSelection(QAction *)));
		delete m_pMenu;
	}
}

QMenu *WirelessNetworkMenu::menu(void)
{
	return m_pMenu;
}

void WirelessNetworkMenu::populate(void)
{
	if (m_pMenu != NULL)
	{
		QList<WirelessNetworkInfo> networkList;
		
		// get list of available networks
		networkList = SSIDList::getNetworkInfo(m_adapterDesc);
		if (networkList.empty() == true)
		{
			QAction *act;
			act = m_pMenu->addAction(tr("No Networks Found"));
			if (act != NULL)
				act->setEnabled(false);
		}
		else
		{

			std::sort(networkList.begin(), networkList.end());
			for (int i=0; i<networkList.size(); i++)
			{
				if (networkList.at(i).m_assoc_modes == WirelessNetworkInfo::SECURITY_NONE)
					m_pMenu->addAction(networkList.at(i).m_name);
				else
				{
					m_pMenu->addAction(m_lockIcon,networkList.at(i).m_name);
				}
			}
		}
	}				
}


void WirelessNetworkMenu::handleMenuSelection(QAction *action)
{
	if (m_pTrayApp != NULL && action != NULL && action->text().isEmpty() == false)
		m_pTrayApp->connectToNetwork(action->text(), m_adapterDesc);
}