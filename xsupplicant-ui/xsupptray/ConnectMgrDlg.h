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

#ifndef _CONNECTMGRDLG_H_
#define _CONNECTMGRDLG_H_


#include <QWidget>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QComboBox>
#include <QCheckBox>

extern "C"
{
#include "libxsupgui/xsupgui_request.h"
}

class TrayApp;
class Emitter;
class PreferredConnections;
class ConnectionWizard;

class ConnectMgrDlg : public QWidget
{
	Q_OBJECT

public:
	ConnectMgrDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *trayApp);
	~ConnectMgrDlg();
	bool create(void);
	void show(void);
	void hide(void);
	bool isVisible(void);
	void bringToFront(void);
	
private:
	bool initUI(void);
	void populateConnectionsList(void);
	void refreshConnectionList(void);
	void populateWiredConnectionsCombo(void);
	void updateWirelessAutoConnectState(void);
	void updateWiredAutoConnectState(void);
	void editConnection(int config_type, const QString &);
	bool buildMenuBar(void);
	
private slots:
	void showAdvancedConfig(void);
	void handleConnectionListSelectionChange(void);
	void deleteSelectedConnection(void);
	void showPriorityDialog(void);
	void cleanupPriorityDialog(void);
	void createNewConnection(void);
	void editSelectedConnection(void);
	void cleanupConnectionWizard(void);
	void finishConnectionWizard(bool, const QString &);
	void enableDisableWirelessAutoConnect(int);
	void enableDisableWiredAutoConnect(int);
	void setWiredAutoConnection(const QString &connectionName);
	void updateConnectionLists(void);
	void handleDoubleClick(int, int);
	void menuClose(void);
	void menuQuit(void);
	void menuCreateTicket(void);
	void menuViewLog(void);
	void menuHelp(void);
	void menuAbout(void);	
	
private:
	QWidget *m_pParent;
	QWidget *m_pRealForm;
	TrayApp *m_pTrayApp;
	Emitter *m_pEmitter;
	QWidget *m_pParentWindow;
	
	// top-level form objects
	QPushButton *m_pCloseButton;
	QPushButton *m_pHelpButton;
	QTabWidget *m_pMainTab;
		
	// options tab objects
	QPushButton *m_pAdvancedButton;
	QPushButton *m_pNetworkPrioritiesButton;
	QComboBox *m_pWiredConnections;
	QCheckBox *m_pWiredAutoConnect;
	QCheckBox *m_pWirelessAutoConnect;
	
	// connections tab objects
	QPushButton *m_pDeleteConnButton;
	QPushButton *m_pEditConnButton;
	QPushButton *m_pNewConnButton;
	QTableWidget *m_pConnectionsTable;
	
	PreferredConnections *m_pPrefDlg;
	ConnectionWizard *m_pConnWizard;
	
	static const int m_minConnListRowCount = 6;
	
	conn_enum *m_pConnections;
	int m_nConnections;
	
};

#endif