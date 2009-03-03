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

#ifndef _CONNECTMGRDLG_H_
#define _CONNECTMGRDLG_H_


#include <QWidget>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QComboBox>
#include <QCheckBox>
#include <QSpinBox>
#include "ViewLogDlg.h"

extern "C"
{
#include "libxsupgui/xsupgui_request.h"
}

class TrayApp;
class Emitter;
class PreferredConnections;
class ConnectionWizard;
class MachineAuthWizard;
class XSupCalls;

class ConnectMgrDlg : public QWidget
{
	Q_OBJECT

public:
	ConnectMgrDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *trayApp, XSupCalls *supplicant);
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
	void populateSettingsTabs();
	void setLoggingEnabled(bool);
	void tabStateUpdate();
	void gatherSettings();
	void setSaveEnabled(bool);
	
	 enum {
		 LOGGING_NORMAL,
		 LOGGING_VERBOSE,
		 LOGGING_DEBUG
	 };

	 enum {
		 DEBUG_NORMAL = BIT(0),
		 DEBUG_VERBOSE = BIT(25)
	 };

	#define DEBUG_ALL            0x7fffffff   // Enable ALL debug flags.

private slots:
	void handleConnectionListSelectionChange(void);
	void deleteSelectedConnection(void);
	void showPriorityDialog(void);
	void cleanupPriorityDialog(void);
	void createNewConnection(void);
	void editSelectedConnection(void);
	void cleanupConnectionWizard(void);
	void finishConnectionWizard(bool, const QString &, const QString &);
	void cleanupMachineAuthWizard(void);
	void finishMachineAuthWizard(bool, const QString &, const QString &);
	void enableDisableWirelessAutoConnect(int);
	void enableDisableWiredAutoConnect(int);
	void setWiredAutoConnection(const QString &connectionName);
	void clearWiredAutoConnection(const QString &connectionName);
	void updateConnectionLists(void);
	void handleDoubleClick(int, int);
	void menuClose(void);
	void menuQuit(void);
	void menuCreateTicket(void);
	void menuViewLog(void);
	void menuHelp(void);
	void menuAbout(void);	
	void menuMachineAuth(void);
	void configUpdate();
	void resetAdvTimers();
	void resetAdvSettings();
	void browseLogs();
	void viewLog();
	void cleanupuiWindowViewLogs();
	void enableSaveBtns();
	void updateCheckboxes();

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
	QPushButton *m_pNetworkPrioritiesButton;
	QComboBox *m_pWiredConnections;
	QCheckBox *m_pWiredAutoConnect;
	QCheckBox *m_pWirelessAutoConnect;
	
	// connections tab objects
	QPushButton *m_pDeleteConnButton;
	QPushButton *m_pEditConnButton;
	QPushButton *m_pNewConnButton;
	QTableWidget *m_pConnectionsTable;

	// Logging tab objects
	QCheckBox *m_pEnableLogging;
	QLineEdit *m_pLogPath;
	QPushButton *m_pBrowse;
	QComboBox *m_pLogLevel;
	QPushButton *m_pViewLog;
	QSpinBox *m_pLogsToKeep;
	QCheckBox *m_pRollBySize;
	QSpinBox *m_pSizeToRoll;
	QPushButton *m_pLoggingSave;

	// advanced settings tab objects
	QCheckBox *m_pCheckSupplicants;
	QCheckBox *m_pDisconnectAtLogoff;
	QCheckBox *m_pAllowMachineAuthContinue;
	QCheckBox *m_pForceMulticast;
	QSpinBox *m_pScanTimeout;
	QSpinBox *m_pAssocTimeout;
	QSpinBox *m_pPassiveInterval;
	QSpinBox *m_pPMKSACacheRefresh;
	QSpinBox *m_pPMKSACacheTimeout;
	QPushButton *m_pSettingsReset;
	QPushButton *m_pAdvSettingsSave;

	// advanced timers
	QSpinBox *m_pAuthPeriod;
	QSpinBox *m_pHeldPeriod;
	QSpinBox *m_pIdlePeriod;
	QSpinBox *m_pStaleKey;
	QSpinBox *m_pMaxStarts;
	QPushButton *m_pTimersReset;
	QPushButton *m_pAdvTimersSave;
	
	uiWindowViewLogs *m_pViewLogDialog;

	PreferredConnections *m_pPrefDlg;
	ConnectionWizard *m_pConnWizard;

	MachineAuthWizard *m_pMachineAuth;
	XSupCalls *m_psupplicant;
	
	int m_minConnListRowCount;
	
	conn_enum *m_pConnections;
	int m_nConnections;
	
};

#endif
