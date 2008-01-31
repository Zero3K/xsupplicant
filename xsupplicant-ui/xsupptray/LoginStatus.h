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

#ifndef _LOGINSTATUS_H_
#define _LOGINSTATUS_H_

#include <QWidget>
#include "xsupcalls.h"

class LoginStatus : public QWidget
{
    Q_OBJECT


public:
	 LoginStatus(bool fromConnect, QString inDevName, poss_conn_enum *pConnEnum, QWidget *proxy, QWidget *parent, Emitter *e);
	 LoginStatus();
	~LoginStatus();

	virtual void updateWindow(bool, bool);
	void clearWirelessItems();

public slots:
	void updateIPAddress();
    void updateTNCStatus(unsigned int, unsigned int, unsigned int, unsigned int);
	virtual void slotStateChange(const QString &, int, int, int, unsigned int);

protected:
	void setPixmapLabel(QLabel *label, QString &URLPath);
	void requestPostureState();

	  XSupCalls m_supplicant;
	  poss_conn_enum *pConn;
	  QWidget *myParent;
	  QWidget *myProxy;
	  QString devName;
	  uint32_t m_connID;

	  bool m_bDisplayError;

	  QLabel *m_pSignalImageLabel;
	  QLabel *m_pSignalTextLabel;

	  QLabel *m_pSecurityImageLabel;
	  QLabel *m_pSecurityTextLabel;

	  QLabel *m_pAssociationImageLabel;
	  QLabel *m_pAssociationTextLabel;

	  QLabel *m_pSSIDName;

	  QLabel *m_pStatusLabel;
	  Emitter *m_pEmitter;
  	  QTimer *m_pClockTimer;

      // TNC related objects:
      QLabel *m_pTNCStatusTextLabel;
      QLabel *m_pTNCStatusImageText;
	  QLabel *m_pTNCStatusImagePic;

	  bool getIPAddress();
	  bool getTime();
 	  void setTime(QTime &time);

	  virtual void updateState();

private:
	QLabel *m_pTimeBox;
    QLabel *m_pIpAddressTextBox;

	QTime m_time;

	long int m_timeauthed;

	bool sigsConnectHere;

private slots:
	void slotShowTime();
};

#endif  // _LOGINSTATUS_H_

