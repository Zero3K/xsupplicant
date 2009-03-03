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

#include <QHeaderView>

#include "SSIDList.h"
#include "FormLoader.h"
#include "TableImageDelegate.h"
#include "WifiStandardImages.h"
#include "GraphSortItem.h"
#include "Util.h"

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

// so that we can use sort algorithm on container of WirelessNetworkInfo
bool operator< (const WirelessNetworkInfo &lhs, const WirelessNetworkInfo &rhs)
{ 
	return lhs.m_name < rhs.m_name; 
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
	this->initUI();
}

SSIDList::~SSIDList()
{
	if (m_pTableWidget != NULL)
	{
		Util::myDisconnect(m_pTableWidget, SIGNAL(itemSelectionChanged()), this, SLOT(handleSSIDTableSelectionChange()));
		Util::myDisconnect(m_pTableWidget, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(handleSSIDTableDoubleClick(int, int)));	
	}
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
		m_pTableWidget->horizontalHeader()->resizeSection(SSIDList::COL_802_11,80);
		
		// don't draw header any differently when row is selected
		m_pTableWidget->horizontalHeader()->setHighlightSections(false);
		
		// don't allow user to edit any of the cells
		m_pTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

		// Set our image delegate.
		m_pTableWidget->setItemDelegateForColumn(SSIDList::COL_802_11, new TableImageDelegate);
		
		// don't show header on left side of table
		m_pTableWidget->verticalHeader()->setVisible(false);
		
		m_pTableWidget->clearContents();
		
		Util::myConnect(m_pTableWidget, SIGNAL(itemSelectionChanged()), this, SLOT(handleSSIDTableSelectionChange()));
		Util::myConnect(m_pTableWidget, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(handleSSIDTableDoubleClick(int, int)));
		
		// load icons for signal strength
		QPixmap *p;
		
		p = FormLoader::loadicon("signal_0.png");
		if (p != NULL)
		{
			m_signalIcons[0].addPixmap(*p);
			delete p;
		}
		
		p = FormLoader::loadicon("signal_1.png");
		if (p != NULL)
		{
			m_signalIcons[1].addPixmap(*p);
			delete p;
		}

		p = FormLoader::loadicon("signal_2.png");
		if (p != NULL)
		{
			m_signalIcons[2].addPixmap(*p);
			delete p;
		}
		
		p = FormLoader::loadicon("signal_3.png");
		if (p != NULL)
		{
			m_signalIcons[3].addPixmap(*p);
			delete p;
		}
		
		p = FormLoader::loadicon("signal_4.png");
		if (p != NULL)
		{
			m_signalIcons[4].addPixmap(*p);
			delete p;		
		}			
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
	
	m_curNetworks = SSIDList::getNetworkInfo(adapterName);
	
	// name says it all.  make assoc mode only one value (best), rather than bitfield.
	// temporary until we have better UI solution
	this->tempAssocModeHack();	
	
	// clear table before re-populating
	m_pTableWidget->clearContents();
	
	// make sure we have enough rows in the table
	int nNetworks = m_curNetworks.size();
	m_pTableWidget->setRowCount(std::max<int>(this->m_minRowCount, nNetworks));
	m_pTableWidget->setSortingEnabled(false);
	
	if (!m_curNetworks.empty())
	{					
		for (int i=0; i<m_curNetworks.size(); i++)
		{
			QTableWidgetItem *nameItem=NULL;
			
			// use the custom item type to store index into our cached array of networks
			// so that we can index back into the array even after table's been sorted
			nameItem = new QTableWidgetItem(m_curNetworks.at(i).m_name, 1000+i);
			if (nameItem != NULL)
				m_pTableWidget->setItem(i, SSIDList::COL_NAME, nameItem);	
			
			int strength = m_curNetworks.at(i).m_signalStrength;
			QString signalText = "";
			signalText.setNum(strength);
			signalText.append(tr("%"));
			
			GraphSortItem *signalItem = NULL;
			signalItem = new GraphSortItem(strength);
			signalItem->setText(signalText);

			if (signalItem != NULL)
			{
				if (strength <= 11)
					signalItem->setIcon(m_signalIcons[0]);
				else if (strength <= 37)
					signalItem->setIcon(m_signalIcons[1]);
				else if (strength <= 62)
					signalItem->setIcon(m_signalIcons[2]);
				else if (strength <= 88)
					signalItem->setIcon(m_signalIcons[3]);
				else
					signalItem->setIcon(m_signalIcons[4]);
				
				m_pTableWidget->setItem(i,SSIDList::COL_SIGNAL,signalItem);
			}
			
			QString securityText = "";
			switch (m_curNetworks.at(i).m_assoc_modes)
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
			
			// if none of modes a,b,g,n supported, nothing to show here	
			if (m_curNetworks.at(i).m_modes != 0)
			{
				// build filename for icon image to load into table
				unsigned char modes = m_curNetworks.at(i).m_modes;

				GraphSortItem *standards = new GraphSortItem(modes);
				standards->setData(0, qVariantFromValue(WifiStandardImages(modes)));
				m_pTableWidget->setItem(i, SSIDList::COL_802_11, standards);
			}
		}
	}
	m_pTableWidget->setSortingEnabled(true);
	m_pTableWidget->sortItems(SSIDList::COL_SIGNAL, Qt::DescendingOrder);
}

void SSIDList::refreshCompleteList()
{
	m_curNetworks = SSIDList::getCompleteNetworkInfo();
	
	// name says it all.  make assoc mode only one value (best), rather than bitfield.
	// temporary until we have better UI solution
	this->tempAssocModeHack();	
	
	// clear table before re-populating
	m_pTableWidget->clearContents();
	
	// make sure we have enough rows in the table
	int nNetworks = m_curNetworks.size();
	m_pTableWidget->setRowCount(std::max<int>(this->m_minRowCount, nNetworks));
	m_pTableWidget->setSortingEnabled(false);
	
	if (!m_curNetworks.empty())
	{					
		for (int i=0; i<m_curNetworks.size(); i++)
		{
			QTableWidgetItem *nameItem=NULL;
			
			// use the custom item type to store index into our cached array of networks
			// so that we can index back into the array even after table's been sorted
			nameItem = new QTableWidgetItem(m_curNetworks.at(i).m_name, 1000+i);
			if (nameItem != NULL)
				m_pTableWidget->setItem(i, SSIDList::COL_NAME, nameItem);	
			
			int strength = m_curNetworks.at(i).m_signalStrength;
			QString signalText = "";
			signalText.setNum(strength);
			signalText.append(tr("%"));
			
			QTableWidgetItem *signalItem = NULL;
			signalItem = new QTableWidgetItem(signalText,1000+i);
			
			if (signalItem != NULL)
			{
				if (strength <= 11)
					signalItem->setIcon(m_signalIcons[0]);
				else if (strength <= 37)
					signalItem->setIcon(m_signalIcons[1]);
				else if (strength <= 62)
					signalItem->setIcon(m_signalIcons[2]);
				else if (strength <= 88)
					signalItem->setIcon(m_signalIcons[3]);
				else
					signalItem->setIcon(m_signalIcons[4]);
				
				m_pTableWidget->setItem(i,SSIDList::COL_SIGNAL,signalItem);
			}
			
			QString securityText = "";
			switch (m_curNetworks.at(i).m_assoc_modes)
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
			
			// if none of modes a,b,g,n supported, nothing to show here	
			if (m_curNetworks.at(i).m_modes != 0)
			{
				// build filename for icon image to load into table
				unsigned char modes = m_curNetworks.at(i).m_modes;
				
				QString labelFileName = "802_11_";
				if ((modes & WirelessNetworkInfo::WIRELESS_MODE_A) != 0)
					labelFileName.append("a");
				if ((modes & WirelessNetworkInfo::WIRELESS_MODE_B) != 0)
					labelFileName.append("b");
				if ((modes & WirelessNetworkInfo::WIRELESS_MODE_G) != 0)
					labelFileName.append("g");
				if ((modes & WirelessNetworkInfo::WIRELESS_MODE_N) != 0)
					labelFileName.append("n");	
				labelFileName.append(".png");

				QMap<QString, QPixmap>::const_iterator iter;
				
				// look for pixmap in cache first before loading from disk
				iter = m_pixmapMap.constFind(labelFileName);
				if (iter == m_pixmapMap.constEnd())
				{
					QPixmap *p;
					p = FormLoader::loadicon(labelFileName);
					if (p != NULL)
					{
						m_pixmapMap.insert(labelFileName, *p);
						iter = m_pixmapMap.constFind(labelFileName);
						delete p;
					}
				}

				// if image was successfully loaded or found in cache, use it in table
				if (iter != m_pixmapMap.constEnd())
				{
					QLabel *tmpLabel;
					tmpLabel = new QLabel();
					if (tmpLabel != NULL)
					{
						tmpLabel->setPixmap(*iter);
						tmpLabel->setAlignment(Qt::AlignCenter);
						m_pTableWidget->setCellWidget(i, SSIDList::COL_802_11, tmpLabel);
					}
				}																	
			}
		}
	}
	m_pTableWidget->setSortingEnabled(true);
	m_pTableWidget->sortItems(SSIDList::COL_SIGNAL, Qt::DescendingOrder);
}

QList<WirelessNetworkInfo> SSIDList::getNetworkInfo(QString adapterName)
{
	QList<WirelessNetworkInfo> networkList;
	
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
					QHash<QString, WirelessNetworkInfo> networkHashTable;
					while (pSSIDList[j].ssidname != NULL)
					{
						// if not empty ssid (this represents a non-broadcast SSID)
						if (QString(pSSIDList[j].ssidname).isEmpty() == false)
						{
							WirelessNetworkInfo networkInfo;
							networkInfo.m_name = pSSIDList[j].ssidname;
							networkInfo.m_signalStrength = int(pSSIDList[j].percentage);
							networkInfo.m_assoc_modes = 0;
							
							unsigned int abilities = pSSIDList[j].abil;
							if ((abilities & ABILITY_ENC) != 0)
							{
								if ((abilities & (ABILITY_WPA_IE | ABILITY_RSN_IE)) == 0)
									networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_STATIC_WEP;
								if ((abilities & ABILITY_RSN_DOT1X) != 0)
									networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE;
								if ((abilities & ABILITY_WPA_DOT1X) != 0)
									networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE;
								if ((abilities & ABILITY_RSN_PSK) != 0)
									networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_WPA2_PSK;
								if ((abilities & ABILITY_WPA_PSK) != 0)
									networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_WPA_PSK;									
							}
							else
								networkInfo.m_assoc_modes = WirelessNetworkInfo::SECURITY_NONE;
						
/*
							if ((abilities & ABILITY_DOT11_STD) != 0)
								; // no flags to pass on
								*/
							if ((abilities & ABILITY_DOT11_A) != 0)
								networkInfo.m_modes |= WirelessNetworkInfo::WIRELESS_MODE_A;
							if ((abilities & ABILITY_DOT11_B) != 0)
								networkInfo.m_modes |= WirelessNetworkInfo::WIRELESS_MODE_B;
							if ((abilities & ABILITY_DOT11_G) != 0)
								networkInfo.m_modes |= WirelessNetworkInfo::WIRELESS_MODE_G;
							if ((abilities & ABILITY_DOT11_N) != 0)
								networkInfo.m_modes |= WirelessNetworkInfo::WIRELESS_MODE_N;
								
							if (networkHashTable.contains(networkInfo.m_name))
							{
								// entry already exists for SSID.  Or in network capabiities
								WirelessNetworkInfo item;
								item = networkHashTable.value(networkInfo.m_name);
								item.m_assoc_modes |= networkInfo.m_assoc_modes;
								item.m_modes |= networkInfo.m_modes;
								item.m_signalStrength = std::max<int>(networkInfo.m_signalStrength, item.m_signalStrength);
								
								// replace item in table;
								networkHashTable[item.m_name] = item;
							}
							else
							{
								// else just insert new item into table
								networkHashTable[networkInfo.m_name] = networkInfo;
							}
						}
						++j;
					}
					networkList = networkHashTable.values();
				}
				else
				{
					// problem or no SSIDs for this adapter
				}
				
				if (pSSIDList != NULL)
					xsupgui_request_free_ssid_enum(&pSSIDList);
			}
			
			++i;
		}
	}
	else
	{
		// bad things man
	}
	
	if (pInterfaceList != NULL)
		xsupgui_request_free_int_enum(&pInterfaceList);
		
	return networkList;
}

QList<WirelessNetworkInfo> SSIDList::getCompleteNetworkInfo()
{
	QList<WirelessNetworkInfo> networkList;
	
	int_enum *pInterfaceList = NULL;
	QHash<QString, WirelessNetworkInfo> networkHashTable;
	int retVal;	
	
	retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
	if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
	{
		int i = 0;
		while (pInterfaceList[i].desc != NULL)
		{
			ssid_info_enum *pSSIDList = NULL;
			retVal = xsupgui_request_enum_ssids(pInterfaceList[i].name,&pSSIDList);
			if (retVal == REQUEST_SUCCESS && pSSIDList != NULL)
			{
				int j = 0;
				while (pSSIDList[j].ssidname != NULL)
				{
					// if not empty ssid (this represents a non-broadcast SSID)
					if (QString(pSSIDList[j].ssidname).isEmpty() == false)
					{
						WirelessNetworkInfo networkInfo;
						networkInfo.m_name = pSSIDList[j].ssidname;
						networkInfo.m_signalStrength = int(pSSIDList[j].percentage);
						networkInfo.m_assoc_modes = 0;
						
						unsigned int abilities = pSSIDList[j].abil;
						if ((abilities & ABILITY_ENC) != 0)
						{
							if ((abilities & (ABILITY_WPA_IE | ABILITY_RSN_IE)) == 0)
								networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_STATIC_WEP;
							if ((abilities & ABILITY_RSN_DOT1X) != 0)
								networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE;
							if ((abilities & ABILITY_WPA_DOT1X) != 0)
								networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE;
							if ((abilities & ABILITY_RSN_PSK) != 0)
								networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_WPA2_PSK;
							if ((abilities & ABILITY_WPA_PSK) != 0)
								networkInfo.m_assoc_modes |= WirelessNetworkInfo::SECURITY_WPA_PSK;									
						}
						else
							networkInfo.m_assoc_modes = WirelessNetworkInfo::SECURITY_NONE;
						
						if ((abilities & ABILITY_DOT11_A) != 0)
							networkInfo.m_modes |= WirelessNetworkInfo::WIRELESS_MODE_A;
						if ((abilities & ABILITY_DOT11_B) != 0)
							networkInfo.m_modes |= WirelessNetworkInfo::WIRELESS_MODE_B;
						if ((abilities & ABILITY_DOT11_G) != 0)
							networkInfo.m_modes |= WirelessNetworkInfo::WIRELESS_MODE_G;
						if ((abilities & ABILITY_DOT11_N) != 0)
							networkInfo.m_modes |= WirelessNetworkInfo::WIRELESS_MODE_N;
							
						if (networkHashTable.contains(networkInfo.m_name))
						{
							// entry already exists for SSID.  Or in network capabiities
							WirelessNetworkInfo item;
							item = networkHashTable.value(networkInfo.m_name);
							item.m_assoc_modes |= networkInfo.m_assoc_modes;
							item.m_modes |= networkInfo.m_modes;
							item.m_signalStrength = std::max<int>(networkInfo.m_signalStrength, item.m_signalStrength);
							
							// replace item in table;
							networkHashTable[item.m_name] = item;
						}
						else
						{
							// else just insert new item into table
							networkHashTable[networkInfo.m_name] = networkInfo;
						}
					}
					++j;
				}
				networkList = networkHashTable.values();
				
				if (pSSIDList != NULL)
					xsupgui_request_free_ssid_enum(&pSSIDList);
			}
			
			++i;
		}
	}
	else
	{
		// bad things man
	}
	
	if (pInterfaceList != NULL)
		xsupgui_request_free_int_enum(&pInterfaceList);
		
	return networkList;
}

void SSIDList::handleSSIDTableSelectionChange(void)
{
	if (m_pTableWidget != NULL)
	{
		QList<QTableWidgetItem*> selectedItems;
		
		selectedItems = m_pTableWidget->selectedItems();
		
		if (selectedItems.isEmpty() == false)
		{
			for (int i=0; i<selectedItems.size(); i++)
			{
				if (selectedItems.at(i)->column() == SSIDList::COL_NAME)
				{
					emit ssidSelectionChange(m_curNetworks.at(selectedItems.at(i)->type() - 1000));
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
			emit ssidDoubleClick(m_curNetworks.at(item->type() - 1000));
	}
}

bool SSIDList::selectNetwork(const QString &networkName)
{
	bool retVal = false;
	if (m_pTableWidget != NULL && !networkName.isEmpty())
	{
		// don't let user re-sort while we're doing this.  It'll mess us up
		bool sortable = m_pTableWidget->isSortingEnabled();
		if (sortable == true)
			m_pTableWidget->setSortingEnabled(false);
			
		for (int i=0; i<m_pTableWidget->rowCount(); i++)
		{
			QTableWidgetItem *item = m_pTableWidget->item(i,0);
			if (item != NULL && item->text() == networkName)
			{
				m_pTableWidget->selectRow(i);
				retVal = true;
				break;
			}
		}
	}
	
	return retVal;
}

// jking -- hack for right now to assume only one association mode is
// supported.  Do so by setting precedence (WPA2 before WPA1, 802.1X before PSK)
// and go with highest precedence association mode
void SSIDList::tempAssocModeHack(void)
{
	QList<WirelessNetworkInfo>::iterator iter;
	QList<WirelessNetworkInfo>::iterator end = m_curNetworks.end();
	
	for (iter=m_curNetworks.begin(); iter != end; iter++)
	{
		if ((iter->m_assoc_modes & WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE) != 0)
			iter->m_assoc_modes = WirelessNetworkInfo::SECURITY_WPA2_ENTERPRISE;
		else if ((iter->m_assoc_modes & WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE) != 0)
			iter->m_assoc_modes = WirelessNetworkInfo::SECURITY_WPA_ENTERPRISE;
		else if ((iter->m_assoc_modes & WirelessNetworkInfo::SECURITY_WPA2_PSK) != 0)
			iter->m_assoc_modes = WirelessNetworkInfo::SECURITY_WPA2_PSK;
		else if ((iter->m_assoc_modes & WirelessNetworkInfo::SECURITY_WPA_PSK) != 0)
			iter->m_assoc_modes = WirelessNetworkInfo::SECURITY_WPA_PSK;
	}
}
