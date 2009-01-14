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

#ifndef _MESSAGECLASS_H_
#define _MESSAGECLASS_H_

#include <QMessageBox>
#include "MessageDlg.h"

class QObject;
class QString;

void myMsgHandler(QtMsgType type , const char *msg);

typedef struct messages
{
  int messageNumber;
  QString text;
}MessageS;

//!\class MessageClass
/*!\brief The messaging class to be throughout.
*/
class MessageClass :
  public QObject
{
  Q_OBJECT
public:
  //MessageClass(bool bDisplayMessage = false, QWidget *pParent = NULL);
  MessageClass(QWidget *pParent);
public:
  virtual ~MessageClass(void);
  typedef enum 
  {
    QUESTION_TYPE,
    INFORMATION_TYPE,
    WARNING_TYPE,
    ERROR_TYPE
  }MESSAGE_TYPE;

  static MessageS m_xSupCalls[];

  void DisplayMessageModeless(QString &titleString, 
                                          QString &formattedString,
                                          QString &helpLocation);

  int DisplayMessage(MESSAGE_TYPE type, 
    QString &titleString, 
    QString &formattedString,  
    char *helpLocation = NULL);

  int DisplayMessage(MESSAGE_TYPE type, 
    QString &titleString,
    QString &formattedString, 
    int error, 
    char *api,
    char *helpLocation = NULL);

private:
  QString m_titleMessage;
  QString m_textMessage;
  char *m_pHelpFile;
  char *m_pHelpLocation;

  QWidget *m_pParent;
  MessageDlg msgDlg;
public:
  QString getMessageString(int errorNumber);

  private slots:
    void slotHelp();

};

#endif // _MESSAGECLASS_H_

