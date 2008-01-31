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

public:
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

private:
    void createTrayActionsAndConnections();
    void createTrayIcon();
    void setEnabledMenuItems(bool bEnable);
  	void setTrayIconConnected();
	void setTrayIconDisconnected();
    bool startEventListenerThread();
    bool postConnectActions();
    bool checkCommandLineParams(int argc);
	void loadPlugins();
	void unloadPlugins();

#ifdef WINDOWS
	void checkOtherSupplicants();
#endif

    QAction *m_pQuitAction;
    QAction *m_pConfigAction;
    QAction *m_pLoginAction;
    QAction *m_pAboutAction;
    QAction *m_pViewLogAction;
    QAction *m_pTroubleticketAction;
    QApplication &m_app;
    LoginMainDlg *m_pLoginDlg;
	ConfigDlg *m_pConfDlg;
    LoggingConsole *m_pLoggingCon;
    AboutDlg *m_pAboutDlg;
	Emitter *m_pEmitter;
    QTimer m_timer;
    bool m_bConnectFailed;

    QSystemTrayIcon *m_pTrayIcon;
    QMenu *m_pTrayIconMenu;
    XSupCalls m_supplicant;
    EventListenerThread *m_pEventListenerThread; 
    bool m_bSupplicantConnected;
    bool m_bListenerStarted;
    startOption m_commandLineOption;

	UIPlugins *m_pPlugins;
};

#endif // _TRAYAPP_H_

