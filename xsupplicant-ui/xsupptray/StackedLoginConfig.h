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

#ifndef _STACKEDLOGINCONFIG_H_
#define _STACKEDLOGINCONFIG_H_

#include <QtGui>
#include "xsupcalls.h"
#include "Util.h"
#include "LoginGetInfo.h"


class StackedLoginConfig :
  public QWidget
{
  Q_OBJECT

public:

/////////////////////////////////////////////////
/// \enum StackedDialogsE
/// \brief This order must match the order of the stacked dialogs
///    see the function SupplicantMainDialog::layoutStackedDialogs()
///    to make sure that these match up to the order they are put onto the
///    stack.  There may be a better way of doing this in the future, but 
///    for now, this works.
/////////////////////////////////////////////////
  typedef enum status
  {
    LOGIN_GET_INFO = 0,
    LOGIN_STATUS
  }statusE;

  StackedLoginConfig(poss_conn_enum *pConns, QStackedWidget *widgets, QWidget *parent, Emitter *e);
  ~StackedLoginConfig();

  void setCurrent(statusE index, 
    bool fromConnect,
    QString &connectionName, 
    QString &deviceDescription, 
    QString &deviceName,
    bool bWireless, 
    poss_conn_enum *pConn);

  int getCurrent();

  QString getUserName();
  QString getPassword();
  QString &getDeviceName();
  QString &getDeviceDescription();
  bool getWireless();
  bool getCacheCredentialsFlag();
  void update(bool);
  void deviceRemoved(QString);

private:
  void setWireless(poss_conn_enum *pConnEnum, bool fromConnect);
  void setWired(poss_conn_enum *pConnEnum, bool fromConnect);
  void setLogin(poss_conn_enum *pConnEnum);

  QStackedWidget *m_pWidgets;

  XSupCalls m_supplicant;

  QWidget *m_pStatusWidget;
  LoginGetInfo *m_pLoginInfo;
  Emitter *m_pEmitter;

  poss_conn_enum *m_pConns; 
  QString m_deviceDescription;
  QString m_deviceName;
  QString m_currentConnection;
  bool m_bWireless;
  MessageClass m_message;
};

#endif  // _STACKEDLOGINCONFIG_H_

