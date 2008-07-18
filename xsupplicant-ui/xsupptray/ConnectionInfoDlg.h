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

#ifndef _CONNECTIONINFODLG_H_
#define _CONNECTIONINFODLG_H_

#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QTimer>
#include <QTime>
#include <QPixmap>

class Emitter;

class ConnectionInfoDlg : public QWidget
{
	Q_OBJECT

public:
	ConnectionInfoDlg(QWidget *parent, QWidget *parentWindow, Emitter *e);
	~ConnectionInfoDlg();
	bool create(void);
	void show(void);
	void setAdapter(const QString &adapterDesc);
	
private:
	bool initUI(void);
	void showTime(void);
	void startConnectedTimer(void);
	void stopAndClearTimer(void);
	void updateWirelessState(void);
	void updateWiredState(void);
	void clearUI(void);
	void updateElapsedTime(void);

private slots:
	void disconnect(void);
	void renewIP(void);
	void timerUpdate(void);
	void stateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid);
	void updateIPAddress(void);
	void updateWirelessSignalStrength(void);
	
private:
	QWidget *m_pParent;
	QWidget *m_pRealForm;
	Emitter *m_pEmitter;
	QWidget *m_pParentWindow;
	
	// top-level form objects
	QPushButton *m_pCloseButton;
	QPushButton *m_pDisconnectButton;
	QPushButton *m_pRenewIPButton;
	QLabel *m_pAdapterNameLabel;
	QLabel *m_pIPAddressLabel;
	QLabel *m_pStatusLabel;
	QLabel *m_pTimerLabel;
	QLabel *m_pSSIDLabel;
	QLabel *m_pSignalLabel;
	QLabel *m_pSignalIcon;
	QLabel *m_pSecurityLabel;
	QLabel *m_pEncryptionLabel;
	
	QString m_curAdapter; // description of current adapter
	QString m_curAdapterName;
	bool m_wirelessAdapter;
	QTimer m_timer;
	QTimer m_strengthTimer;
	QTime  m_time;
	unsigned int m_days;
	
	QPixmap m_signalIcons[5];
};

#endif