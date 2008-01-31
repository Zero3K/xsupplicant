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

#ifndef _LOGINMAINDLG_H_
#define _LOGINMAINDLG_H_

#include <QStackedWidget>

#include "xsupcalls.h"
#include "LoggingConsole.h"
#include "messageclass.h"
#include "EventListenerThread.h"
#include "StackedLoginConfig.h"

//!\class LoginMainDlg 
/*!\brief LoginMainDlg class - the main login dialog
*/
 class LoginMainDlg : public QWidget
 {
     Q_OBJECT

public:
  LoginMainDlg(XSupCalls &sup, Emitter *e, QWidget *parent);
  ~LoginMainDlg();
  bool create();
  bool setInfo(bool bDisplay);
  void show();

private slots:
  void slotConnectionChangedEvent(int selection);
  void slotShowHelp();
  void slotNewScanData(const QString &);
  void slotBadPSK(const QString &);
  void slotAuthTimeout(const QString &);
  void slotStateChange(const QString &, int, int, int, unsigned int);

public slots:
  void slotConnectDisconnect();
  void slotSaveCreds(const QString &, int, int, int, unsigned int);
  void slotUpdateConnections();
  void slotUpdateProfiles();
  void slotInterfaceInserted(char *);
  void slotInterfaceRemoved(char *);
  void slotLinkUp(char *);
  void slotLinkDown(char *);

signals:
  void close();
  void signalChildUpdate();   // We got data that may mean the child needs to update itself.
  void signalShowConfig();    // Request that we show the configuration dialog.

 private: 
	 void setupWindow();
	 bool setupLoginStack();

  // GUI variables
  QWidget *m_pRealForm;
  QComboBox *m_pConnectionComboBox;
  StackedLoginConfig *m_pLoginStack;
  QStackedWidget *m_pStack;

  QLabel *m_pTitleImageLabel;
  QLabel *m_pNetworkLabel;

  Emitter *m_pEmitter;

  QPushButton *m_pConnectDisconnectButton;
  QPushButton *m_pCloseButton;
  QPushButton *m_pHelpButton;
  QPushButton *m_pConfigureButton;
  QPushButton *m_pShowLogButton;

  QGroupBox *m_pSSIDInfoBox;
  QLabel *m_pAdapterInfoLabel;
  QLabel *m_pSSIDInfoLabel;
  QLabel *m_pAdapterInfo;
  QLabel *m_pSSIDInfo;

  // Other variables
  bool m_bLogFileOpen;
  bool m_bConnecting;
  bool m_bCredsConnected;

  // Gui setup functions
  void layoutStackedDialogs();
  void setButtons(bool bShowInfo);
  void connectControls();
  bool networkConnect();
  bool networkDisconnect();
  bool isCurrentConnectionActive(poss_conn_enum &conn);


  // local variables
  XSupCalls &m_supplicant;
  QString m_deviceName;
  bool m_bWireless; // indicates whether the current connection is wireless
  int m_connsIndex;
  QString m_currentConnection;
  QString m_deviceDescription;
  QString m_connectionStatus;
  QString m_userName;
  QString m_password;

  QWidget *m_pParent;
  poss_conn_enum *m_pConns;
  int m_state;
  MessageClass m_message;

  bool enumPossibleConnections();
  QIcon m_wirelessIcon;
  QIcon m_wiredIcon;
  bool populateConnectionBox(bool bDisplayMessage);

 public:
  const QString getUserName();
  const QString &getConnection();
  const QString getPassword();
  bool getWirelessFlag();
  const QString &deviceName();
  const QString &deviceDescription();
  bool saveCredentials();
  const poss_conn_enum* getConnectionList() { return m_pConns;}
 };

#endif  // _LOGINMAINDLG_H_

