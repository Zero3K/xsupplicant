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

#ifndef _SSIDLIST_H_
#define _SSIDLIST_H_

#include <QWidget>
#include <QTableWidget>
#include <QList>

		
class WirelessNetworkInfo
{
public:
	WirelessNetworkInfo();
	~WirelessNetworkInfo();
		
public:

	//values for auth modes bitfield
	static const unsigned char SECURITY_NONE			= 0x00;
	static const unsigned char SECURITY_STATIC_WEP		= 0x01;
	static const unsigned char SECURITY_WPA_PSK			= 0x02;
	static const unsigned char SECURITY_WPA_ENTERPRISE	= 0x04;
	static const unsigned char SECURITY_WPA2_PSK		= 0x08;
	static const unsigned char SECURITY_WPA2_ENTERPRISE	= 0x10;	
		
	// values for network mode bitfield
	static const unsigned char WIRELESS_MODE_A = 0x01;
	static const unsigned char WIRELESS_MODE_B = 0x02;
	static const unsigned char WIRELESS_MODE_G = 0x04;
	static const unsigned char WIRELESS_MODE_N = 0x08;
	
	QString m_name;
	int m_signalStrength;
	unsigned char m_assoc_modes;
	unsigned char m_modes;
};

// so that we can use sort algorithm on container of WirelessNetworkInfo
bool operator< (const WirelessNetworkInfo &lhs, const WirelessNetworkInfo &rhs);

class SSIDList : public QWidget
{
     Q_OBJECT

public:

	// enum representing columns in the SSIDList/table
	typedef enum {
		COL_NAME,
		COL_SIGNAL,
		COL_SECURITY,
		COL_802_11
		} SSIDListCol;
		
	SSIDList(QWidget *parent, QTableWidget *tableWidget, int minRowCount=0);
	~SSIDList();
	void refreshList(const QString &adapterName);
	void refreshCompleteList();
	void hideColumn(SSIDListCol colIndex);
	void showColumn(SSIDListCol colIndex);
	bool selectNetwork(const QString &networkName);
	static QList<WirelessNetworkInfo> getNetworkInfo(QString adapterName);
	static QList<WirelessNetworkInfo> getCompleteNetworkInfo();	

signals:
	void ssidSelectionChange(const WirelessNetworkInfo &);
	void ssidDoubleClick(const WirelessNetworkInfo &);
	
private:
	void initUI(void);
	void tempAssocModeHack(void);
	
private slots:
	void handleSSIDTableSelectionChange(void);
	void handleSSIDTableDoubleClick(int row, int col);
		
private:
	QWidget *m_parent;
	QTableWidget *m_pTableWidget;
	int m_minRowCount;
	QString m_curWirelessAdapter;
	QList<WirelessNetworkInfo> m_curNetworks;
	QIcon m_signalIcons[5];
	QMap<QString,QPixmap> m_pixmapMap;
};
#endif