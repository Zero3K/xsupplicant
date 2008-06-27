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

#ifndef _CONNECTDLG_H_
#define _CONNECTDLG_H_

#include <QPushButton>
#include <QWidget>
#include <QLabel>
#include <QTabWidget>
#include <QComboBox>
#include <QStackedWidget>
#include <QTimer>
#include <QTime>

class TrayApp;
class Emitter;
class SSIDListDlg;
class ConnectionWizard;
class ConnectionInfoDlg;

class ConnectDlg : public QWidget
{
	Q_OBJECT
	
public: 
	ConnectDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *supplicant);
	~ConnectDlg();
	void show(void);
	bool create(void);
	
private:
	bool initUI(void);
	void populateWirelessAdapterList(void);
	void populateWiredAdapterList(void);
	void populateWirelessConnectionList(void);
	void populateWiredConnectionList(void);
	bool isConnectionActive(QString interfaceDesc, QString connectionName, bool isWireless);
	bool connectToConnection(QString interfaceDesc, QString connectionName);
	QVector<QString> *getConnectionListForAdapter(const QString &adapterDesc);
	void updateWirelessState(void);
	void updateWiredState(void);
	void startConnectedTimer(QString adapterName);
	void showTime(void);
	void stopAndClearTimer(void);
	
private slots:
	void showSSIDList(void);
	void selectWirelessAdapter(int);
	void selectWiredAdapter(int);
	void selectWirelessConnection(int);
	void selectWiredConnection(int);
	void populateConnectionLists(void);
	void launchConnectionWizard(void);
	void cleanupConnectionWizard(void);
	void finishConnectionWizard(bool);
	void connectWirelessConnection(void);
	void connectWiredConnection(void);
	void disconnectWirelessConnection(void);
	void disconnectWiredConnection(void);
	void timerUpdate(void);
	void currentTabChanged(int);
	void stateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid);
	void interfaceInserted(char *intName);
	void showWirelessConnectionInfo(void);
	void showWiredConnectionInfo(void);
	void interfaceRemoved(char *intDesc);
		
private:
	Emitter *m_pEmitter;
	QWidget *m_pRealForm;
	QWidget *m_pParent;
	QWidget *m_pParentWindow;
	
	QTabWidget	*m_pAdapterTabControl;
	QComboBox	*m_pWirelessAdapterList;
	QComboBox	*m_pWiredAdapterList;
	QComboBox	*m_pWirelessConnectionList;
	QComboBox	*m_pWiredConnectionList;
	QPushButton *m_pCloseButton;
	QPushButton *m_pBrowseWirelessNetworksButton;
	QPushButton *m_pWiredConnectButton;
	QPushButton *m_pWirelessConnectButton;
	QPushButton *m_pWiredDisconnectButton;
	QPushButton *m_pWirelessDisconnectButton;
	QPushButton *m_pWiredConnectionInfo;
	QPushButton *m_pWirelessConnectionInfo;
	QPushButton *m_pConnWizardButton;
	QLabel		*m_pWirelessConnectionName;
	QLabel		*m_pWiredConnectionName;
	QLabel		*m_pWirelessConnectionStatus;
	QLabel		*m_pWiredConnectionStatus;
	QStackedWidget *m_pWirelessConnectionStack;
	QStackedWidget *m_pWiredConnectionStack;


	TrayApp *m_pSupplicant;
	SSIDListDlg *m_pSSIDListDlg;
	ConnectionWizard *m_pConnWizard;
	ConnectionInfoDlg *m_pConnInfo;
	QString	m_currentWirelessAdapter;
	QString m_currentWiredAdapter;
	QTimer m_timer;
	QTime  m_time;
	int m_lastWirelessConnectionIdx;
	int m_lastWiredConnectionIdx;
	unsigned int m_days;
};
     
#endif
