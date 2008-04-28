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

#ifndef _LOGWINDOW_H_
#define _LOGWINDOW_H_

#include <stdafx.h>
#include <QtGui>
#include "MessageClass.h"
#include "Emitter.h"
#include "xsupcalls.h"
#include "PasswordDlg.h"

//!\class LogWindow
/*!\brief LogWindow is used to display the log messages from the xsupplicant
*/
class LogWindow :  public QWidget
{
  Q_OBJECT 
  signals:
    void signalSupplicantDownRestart();
	void close();

  public slots:
    void slotAddXSupplicantLogMessage(const QString &message);
    void slotAddUILogMessage(const QString &message);
    void slotClear();
    void slotStartLogMessage(const QString &message);
    void slotXSupplicantShutDown();
    void slotInterfaceInsertedMessage(char *interface);
    void slotRemediation(); // temporary
    void slotRequestPasswordMessage(const QString &m, const QString &q, const QString &s);
	void slotClearGTC();

private slots:
	void slotCopyToClipboard();
	void slotFinishPassword();

public:
  LogWindow(QWidget *parent = NULL, Emitter *e = NULL);
  bool isScanComplete();
  void addMessage(const QString &message);
  bool create();
  void hide();


private:
  QTextEdit *m_pLogEdit;
  QPushButton *m_pCloseButton;
  QPushButton *m_pClearButton;
  QPushButton *m_pUpdateButton;
  QPushButton *m_pCopyToClipboard;
  bool m_bUpdateCalled;
  XSupCalls m_supplicant;
  MessageClass m_message;
  QWidget *m_pRealForm;
  Emitter *m_pEmitter;
  PasswordDlg *m_pPassword;

public:
  virtual ~LogWindow(void);
  
  // Static functions to control only one occurrence of this dialog
  void showLog();
  XSupCalls &getSupplicant();
};

#endif  // _LOGWINDOW_H_

