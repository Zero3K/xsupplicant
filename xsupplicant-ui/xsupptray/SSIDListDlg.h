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

#ifndef _SSIDLISTDLG_H_
#define _SSIDLISTDLG_H_

#include <QPushButton>
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include "SSIDList.h"

class Emitter;
class WirelessScanDlg;
class TrayApp;
class ConnectionWizard;

class SSIDListDlg : public QWidget
{
	Q_OBJECT

public:
	SSIDListDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *supplicant);
	~SSIDListDlg();
	bool create(void);
	void show(void);
	void refreshList(const QString &adapterName);
	
private:
	typedef struct networkInfo {
		QString name;
		int signal;
		int security;
	};
	
private:
	bool initUI(void);
	void connectToNetwork(const WirelessNetworkInfo &);
	
private slots:
	void slotShowHelp(void);
	void rescanNetworks(void);
	void wirelessScanComplete(const QString&);
	void cancelScan(void);
	void handleSSIDListSelectionChange(const WirelessNetworkInfo &);
	void handleSSIDListDoubleClick(const WirelessNetworkInfo &);
	void connectToSelectedNetwork(void);
	void cleanupConnectionWizard(void);
	void finishConnectionWizard(bool, const QString &);

private:

	Emitter *m_pEmitter;
	QWidget *m_pRealForm;
	QWidget *m_pParent;
	QWidget *m_pParentWindow;
  
	// cached pointers to UI objects
	QPushButton *m_pCloseButton;
	QPushButton *m_pHelpButton; 
	QPushButton *m_pRefreshButton;
	QPushButton *m_pConnectButton;
	QLabel * m_pHeaderLabel;
	QTableWidget *m_pSSIDTable;
	
	ConnectionWizard *m_pConnWizard;
	WirelessScanDlg *m_pRescanDialog;
	SSIDList *m_pSSIDList;
	QString m_curAdapter;
	WirelessNetworkInfo m_selectedNetwork;
	TrayApp *m_pSupplicant;
};

#endif