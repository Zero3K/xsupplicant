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

#ifndef _FORMLOADER_H_
#define _FORMLOADER_H_

#include <QWidget>
#include <QtUiTools/QUiLoader>
#include <QFile>

class FormLoader : public QWidget
{
    Q_OBJECT 

public:
  FormLoader();
  virtual ~FormLoader();


#ifdef WINDOWS
  static QWidget *FormLoader::buildform(QString formname);
  static QPixmap *FormLoader::loadicon(QString iconname);
  static QString FormLoader::skinpath();
  static QString FormLoader::iconpath();
#else
  static QWidget *buildform(QString formname);
  static QPixmap *loadicon(QString iconname);
  static QString &iconpath();
  static QString &skinpath();
#endif
};

#endif // _FORMLOADER_H_

