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

#ifndef _TRAYAPP_H_
#define _TRAYAPP_H_

#include <QSystemTrayIcon>
#include <QWidget>
#include "xsupcalls.h"
#include "MessageClass.h"
#include "LoginMainDlg.h"
#include "ConfigDlg.h"
#include "AboutDlg.h"
#include "interfacectrl.h"
#include "CreateTT.h"
#include "UICallbacks.h"
#include "CredentialsPopUp.h"

class TrayApp : public QWidget
{
    Q_OBJECT

  enum startOption
    {
      NONE,
      START_LOG,
      START_LOGIN,
      START_CONFIG,
      START_ABOUT
    };

	enum iconState
	{
		ENGINE_DISCONNECTED,
		ENGINE_CONNECTED,
		AUTHENTICATION_FAILED,
		AUTHENTICATION_IN_PROCESS,
		AUTHENTICATION_SUCCESS,
		AUTHENTICATION_NAC_NON_COMPLIANT
	};

public:
	QString m_pluginVersionString;

    TrayApp(QApplication &app);
    virtual ~TrayApp();
    MessageClass m_message;
    bool init(int argCount);
    void start();

private slots:
    void slotIconActivated(QSystemTrayIcon::ActivationReason reason);
    void slotLaunchConfig();
    void slotLaunchLogin();
    void slotViewLog();
    void slotAbout();
    void slotExit();
    void slotCreateTroubleticket();
    void slotConnectToSupplicant();
	void slotCleanupAbout();
	void slotHideLog();
	void slotCleanupLogin();
	void slotLaunchHelp(const QString &, const QString &);
	void slotCleanupConfig();
	void slotInterfaceInserted(char *);
	void slotInterfaceRemoved(char *);
	void slotWokeUp();
	void slotControlInterfaces();
	void slotControlInterfacesDone(bool);
	void slotCreateTroubleticketDone();
	void slotCreateTroubleticketError();
	void slotRequestUPW(QString connName);
	void slotCleanupUPW();
	void slotConnectionTimeout(QString devName);

signals:
	// Signals that can be rebroadcast from the root that other objects can subscribe to.
	void signalStrengthChanged(int);
	void signalStateChange(const QString &, int, int, int, unsigned int);
	void signalIPAddressSet();

public slots:
  void slotHelp();
  void slotSupError(const QString &error);
  void slotSupWarning(const QString &warning);
  void slotRestart();
	void slotStateChange(const QString &, int, int, int, unsigned int);

private:
    void createTrayActionsAndConnections();
    void createTrayIcon();
	void setTrayIconState(int curState);
	void setGlobalTrayIconState();
    void setEnabledMenuItems(bool bEnable);
    bool startEventListenerThread();
    bool postConnectActions();
    bool checkCommandLineParams(int argc);
	void loadPlugins();
	void unloadPlugins();
	void updateGlobalTrayIconState();
	void connectGlobalTrayIconSignals();
	void disconnectGlobalTrayIconSignals();
	void populateGlobalTrayData(QString, QString);
	void updateIntControlCheck();
	void disconnectTTSignals();

#ifdef WINDOWS
	void checkOtherSupplicants();
#endif

    QAction *m_pQuitAction;
    QAction *m_pConfigAction;
    QAction *m_pLoginAction;
    QAction *m_pAboutAction;
    QAction *m_pViewLogAction;
    QAction *m_pTroubleticketAction;
	QAction *m_p1XControl;
    QApplication &m_app;
    LoginMainDlg *m_pLoginDlg;
	ConfigDlg *m_pConfDlg;
    LogWindow *m_pLoggingCon;
    AboutWindow *m_pAboutWindow;
	Emitter *m_pEmitter;
    QTimer m_timer;
    bool m_bConnectFailed;

	QMultiHash<QString, QString> m_intStateHash;

    QSystemTrayIcon *m_pTrayIcon;
    QMenu *m_pTrayIconMenu;
    XSupCalls m_supplicant;
    EventListenerThread *m_pEventListenerThread; 
    bool m_bSupplicantConnected;
    bool m_bListenerStarted;
    startOption m_commandLineOption;

	InterfaceCtrl *m_pIntCtrl;
	CreateTT *m_pCreateTT;
	CredentialsPopUp *m_pCreds;

	UIPlugins *m_pPlugins;
	UICallbacks uiCallbacks;
};

#endif // _TRAYAPP_H_

