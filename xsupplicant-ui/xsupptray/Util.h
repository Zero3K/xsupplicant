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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <QtGui>

#ifdef WINDOWS
#define STRDUP _strdup
#else
#define STRDUP strdup
#define _strdup  strdup
#endif


//!\class Util
/*!\brief Util class - used to store procedures for functions that need to be used throughout.
*/
class Util : public QObject
{
//  Q_OBJECT

private:
  Util();
  ~Util();

public:
  static bool myConnect(const QObject *from, const char *signal, const QObject *to, const char *slot);
  static bool myDisconnect(const QObject *from, const char *signal, const QObject *to, const char *slot);
  static QPushButton *createButton(const QString &text, QObject *thisPtr, const char *slot, const QString &toolTip);
  static QLineEdit *createLineEdit(const QString &text, const QString &whatsThis);
  static QCheckBox *createCheckBox(const QString &text, const QString &whatsThis);
  static QRadioButton *createRadioButton(const QString &text, const QString &whatsThis);
  static QComboBox *createComboBox(const QString &whatsThis);
  static QLabel *createLabel(const QString &text, const QString &whatsThis);
  static QTextEdit *createTextEdit(const QString &text, const QString &whatsThis);
  static QListWidget *createListWidget(const QString &whatsThis);
  static QRadioButton *createRadioButton(const QString &text, QObject *thisPtr, const char *slot, const QString &toolTip);
  static QString removePacketSchedulerFromName(char *fullName);
  static QString removePacketSchedulerFromName(QString &fullName);

#ifdef WINDOWS
  static char *myNullStrdup(const char *p);
#else
  static char *myNullStrdup(const char *p);
#endif

  static void useBackslash(char *str);

  static void setWidgetWidth(QWidget *pWidget, char *text);
  static bool isValidIPAddress(QString &ipaddr);
  static void myFree(void **);
  static void myFree(char **);
  static QLabel *createPixmapLabel(QString &URLPath); // , int height, int width)
};

#endif   // _UTIL_H_

