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

#ifndef _LOGINGETINFO_H_
#define _LOGINGETINFO_H_

#include <QWidget>
#include "xsupcalls.h"

class LoginGetInfo : public QWidget
{
    Q_OBJECT

public:
  typedef enum pages
  {
    LOGIN_NO_INFO_PAGE = 0,
	LOGIN_PSK_INFO_PAGE,
	LOGIN_CREDENTIALS_UPW_PAGE
  } pagesE;

	 LoginGetInfo(QString inDevName, poss_conn_enum *pConnEnum, QWidget *proxy, QWidget *parent, Emitter *e);
	~LoginGetInfo();

	void updateWindow(bool);

	QString get_username();
	QString get_password();
	bool getCacheCredentialsFlag();

private slots:
	void slotUnhidePwd();

private:
	Emitter *m_pEmitter;
	QWidget *m_pParent;
	QWidget *m_pStack;

	QGroupBox *m_pAdapterInfo;

	QStackedWidget *m_pWidgetStack;

	QCheckBox *m_pSaveCreds;

	QLabel *m_pAdapterStat;
	QLabel *m_pSSIDStatLabel;
	QLabel *m_pSSIDStat;

	QLineEdit *dataFrameProfilesUsername;
	QLineEdit *dataFrameProfilesPassword;

	QPushButton *hideBtn;

	bool m_bSignalConnected;

	XSupCalls m_supplicant;
	poss_conn_enum *pConn;

	void setAdapterInfo();
	void setEAPAuth(QString username, QString password);
	void setPSKAuth(QString password);
};

#endif  // _LOGINGETINFO_H_

