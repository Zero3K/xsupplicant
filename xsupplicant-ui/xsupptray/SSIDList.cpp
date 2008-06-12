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

#include "SSIDList.h"
#include "FormLoader.h"

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

WirelessNetworkInfo::WirelessNetworkInfo()
{
	m_name = "";
	m_signalStrength = 0;
	m_assoc_modes = 0;
	m_modes = 0;
}

WirelessNetworkInfo::~WirelessNetworkInfo()
{
}

SSIDList::SSIDList(QWidget *parent, QTableWidget *tableWidget, int minRowCount/* =0 */)
	: QWidget(parent),
	m_parent(parent),
	m_pTableWidget(tableWidget),
	m_minRowCount(minRowCount)
{
	m_curNetworks = NULL;
	this->initUI();
}

SSIDList::~SSIDList()
{
	if (m_pTableWidget != NULL)
	{
		Util::myDisconnect(m_pTableWidget, SIGNAL(itemSelectionChanged()), this, SLOT(handleSSIDTableSelectionChange()));
		Util::myDisconnect(m_pTableWidget, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(handleSSIDTableDoubleClick(int, int)));	
	}
	
	if (m_curNetworks != NULL)
		delete m_curNetworks;
}

void SSIDList::initUI(void)
{
	if (m_pTableWidget != NULL)
	{
		// disallow user from sizing columns
		m_pTableWidget->horizontalHeader()->setResizeMode(QHeaderView::Fixed);
		
		// network name
		m_pTableWidget->horizontalHeaderItem(SSIDList::COL_NAME)->setText(tr("Network Name"));
		m_pTableWidget->horizontalHeader()->setResizeMode(SSIDList::COL_NAME,QHeaderView::Stretch);
		
		// signal
		m_pTableWidget->horizontalHeaderItem(SSIDList::COL_SIGNAL)->setText(tr("Signal"));
		m_pTableWidget->horizontalHeader()->resizeSection(SSIDList::COL_SIGNAL,72);
		
		// security
		m_pTableWidget->horizontalHeaderItem(SSIDList::COL_SECURITY)->setText(tr("Security"));
		m_pTableWidget->horizontalHeader()->resizeSection(SSIDList::COL_SECURITY,100);
		
		// 802.11
		m_pTableWidget->horizontalHeaderItem(SSIDList::COL_802_11)->setText(tr("802.11"));
		m_pTableWidget->horizontalHeader()->resizeSection(SSIDList::COL_802_11,90);
		
		// don't draw header any differently when row is selected
		m_pTableWidget->horizontalHeader()->setHighlightSections(false);
		
		m_pTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
		
		m_pTableWidget->clearContents();
		
		Util::myConnect(m_pTableWidget, SIGNAL(itemSelectionChanged()), this, SLOT(handleSSIDTableSelectionChange()));
		Util::myConnect(m_pTableWidget, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(handleSSIDTableDoubleClick(int, int)));	
	}
}

void SSIDList::showColumn(SSIDListCol colIndex)
{
	if (m_pTableWidget != NULL)
		m_pTableWidget->setColumnHidden(colIndex, false);
}

void SSIDList::hideColumn(SSIDListCol colIndex)
{
	if (m_pTableWidget != NULL)
		m_pTableWidget->setColumnHidden(colIndex, true);
}

void SSIDList::refreshList(const QString &adapterName)
{
	// stash off name of adapter we're presenting networks for
	m_curWirelessAdapter = adapterName;
	
	this->getNetworkInfo(adapterName);
	
	// clear table before re-populating
	m_pTableWidget->clearContents();
	
	// make sure we have enough rows in the table
	int nNetworks=0;
	if (m_curNetworks != NULL)
		nNetworks = m_curNetworks->size();
	m_pTableWidget->setRowCount(std::max<int>(this->m_minRowCount, nNetworks));
	m_pTableWidget->setSortingEnabled(false);
	
	if (m_curNetworks != NULL)
	{
		QIcon iconSignal_0;
		QIcon iconSignal_1;
		QIcon iconSignal_2;
		QIcon iconSignal_3;
		QIcon iconSignal_4;
		
		QPixmap *p;
		
		p = FormLoader::loadicon("signal_0.png");
		if (p != NULL)
		{
			iconSignal_0.addPixmap(*p);
			delete p;
		}
		
		p = FormLoader::loadicon("signal_1.png");
		if (p != NULL)
		{
			iconSignal_1.addPixmap(*p);
			delete p;
		}

		p = FormLoader::loadicon("signal_2.png");
		if (p != NULL)
		{
			iconSignal_2.addPixmap(*p);
			delete p;
		}
		
		p = FormLoader::loadicon("signal_3.png");
		if (p != NULL)
		{
			iconSignal_3.addPixmap(*p);
			delete p;
		}
		
		p = FormLoader::loadicon("signal_4.png");
		if (p != NULL)
		{
			iconSignal_4.addPixmap(*p);
			delete p;		
		}
								
		for (int i=0; i<m_curNetworks->size(); i++)
		{
			QTableWidgetItem *nameItem=NULL;
			nameItem = new QTableWidgetItem(m_curNetworks->at(i).m_name, 1000+i);
			if (nameItem != NULL)
				m_pTableWidget->setItem(i, SSIDList::COL_NAME, nameItem);	
			
			int strength = m_curNetworks->at(i).m_signalStrength;
			QString signalText = "";
			signalText.setNum(strength);
			signalText.append(tr("%"));
			
			QTableWidgetItem *signalItem = NULL;
			signalItem = new QTableWidgetItem(signalText,1000+i);
			
			if (signalItem != NULL)
			{
				// !!! need to tweak these
				if (strength <= 11)
					signalItem->setIcon(iconSignal_0);
				else if (strength <= 37)
					signalItem->setIcon(iconSignal_1);
				else if (strength <= 62)
					signalItem->setIcon(iconSignal_2);
				else if (strength <= 88)
					signalItem->setIcon(iconSignal_3);
				else
					signalItem->setIcon(iconSignal_4);
				
				m_pTableWidget->setItem(i,SSIDList::COL_SIGNAL,signalItem);
			}
			
			QString securityText = "";
			switch (m_curNetworks->at(i).m_assoc_modes)
			{
				case WirelessNetworkInfo::SECURITY_NONE:
					securityText = tr("None");
					break;
				case WirelessNetworkInfo::SECURITY_STATIC_WEP:
					securityText = tr("WEP");
					break;
				case WirelessNetworkInfo::SECURITY_WPA_PSK:
					securityText = tr("WPA-Personal");
					break;
				case WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE:
					securityText = tr("WPA-Enterprise");
					break;
				case WirelessNetworkInfo::SECURITY_WPA2_PSK:
					securityText = tr("WPA2-Personal");
					break;
				case WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE:
					securityText = tr("WPA2-Enterprise");
					break;
				default:
					break;
			}	
			
			QTableWidgetItem *securityItem = NULL;
			securityItem = new QTableWidgetItem(securityText,1000+i);
			if (securityItem != NULL)
				m_pTableWidget->setItem(i,SSIDList::COL_SECURITY,securityItem);
		}
	}
	m_pTableWidget->setSortingEnabled(true);
	m_pTableWidget->sortItems(SSIDList::COL_SIGNAL, Qt::DescendingOrder);
}

void SSIDList::getNetworkInfo(QString adapterName)
{
	// temporary solution for now - get list of SSIDs for all wireless adapters
	if (m_curNetworks == NULL)
		m_curNetworks = new QVector<WirelessNetworkInfo>();
	else
		m_curNetworks->clear();
	
	if (m_curNetworks != NULL)
	{
		int_enum *pInterfaceList = NULL;
		int retVal;	
		
		retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
		if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
		{
			int i = 0;
			while (pInterfaceList[i].desc != NULL)
			{
				if (adapterName == pInterfaceList[i].desc)
				{
					ssid_info_enum *pSSIDList = NULL;
					retVal = xsupgui_request_enum_ssids(pInterfaceList[i].name,&pSSIDList);
					if (retVal == REQUEST_SUCCESS && pSSIDList != NULL)
					{
						int j = 0;
						while (pSSIDList[j].ssidname != NULL)
						{
							WirelessNetworkInfo networkInfo;
							networkInfo.m_name = pSSIDList[j].ssidname;
							networkInfo.m_signalStrength = int(pSSIDList[j].percentage);
							
							// jking -- hack for right now to assume only one association mode is
							// supported.  Do so by setting precedence (WPA2 before WPA1, 802.1X before PSK)
							// and go with highest precedence association mode
							unsigned char assoc_modes = pSSIDList[i].abil;
							if ((assoc_modes & ABILITY_ENC) != 0)
							{
								if ((assoc_modes & (ABILITY_WPA_IE | ABILITY_RSN_IE)) == 0)
									networkInfo.m_assoc_modes = WirelessNetworkInfo::SECURITY_STATIC_WEP;
								else if ((assoc_modes & ABILITY_RSN_DOT1X) != 0)
									networkInfo.m_assoc_modes = WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE;
								else if ((assoc_modes & ABILITY_WPA_DOT1X) != 0)
									networkInfo.m_assoc_modes = WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE;
								else if ((assoc_modes & ABILITY_RSN_PSK) != 0)
									networkInfo.m_assoc_modes = WirelessNetworkInfo::SECURITY_WPA2_PSK;
								else if ((assoc_modes & ABILITY_WPA_PSK) != 0)
									networkInfo.m_assoc_modes = WirelessNetworkInfo::SECURITY_WPA_PSK;									
							}
							else
								networkInfo.m_assoc_modes = WirelessNetworkInfo::SECURITY_NONE;
								
							m_curNetworks->append(networkInfo);
							++j;
						}
						xsupgui_request_free_ssid_enum(&pSSIDList);
						pSSIDList = NULL;
					}
					else
					{
						// problem or no SSIDs for this adapter
					}
				}
				
				++i;
			}
			xsupgui_request_free_int_enum(&pInterfaceList);
			pInterfaceList = NULL;
			
			for (i=0; i<m_curNetworks->size(); i++)
			{
				// get other details about network
			}
		}
		else
		{
			// bad things man
		}
	}
}

void SSIDList::handleSSIDTableSelectionChange(void)
{
	if (m_pTableWidget != NULL)
	{
		QList<QTableWidgetItem*> selectedItems;
		
		selectedItems = m_pTableWidget->selectedItems();
		
		if (selectedItems.isEmpty() == false)
		{
			int i;
			for (i=0; i<selectedItems.size(); i++)
			{
				if (selectedItems.at(i)->column() == SSIDList::COL_NAME)
				{
					emit ssidSelectionChange(m_curNetworks->at(selectedItems.at(i)->type() - 1000));
					break;
				}
			}
		}
		else
		{
			emit ssidSelectionChange(WirelessNetworkInfo());
		}
	}
}

void SSIDList::handleSSIDTableDoubleClick(int row, int)
{
	if (m_pTableWidget != NULL)
	{
		QTableWidgetItem* item = m_pTableWidget->item(row, SSIDList::COL_NAME);
		
		// check if they clicked in a row w/ a network listed
		if (item != NULL)
		{
			emit ssidDoubleClick(m_curNetworks->at(item->type() - 1000));
		}
	}
}

