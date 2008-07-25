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

#ifndef _HELPWINDOW_H_
#define _HELPWINDOW_H_

#include <QWidget>
#include <QTextBrowser>
#include <QPushButton>

// This help window is a singleton class/object.  It is not intended to be instantiated and instead simply
// use the static functions provided 
class HelpWindow: public QWidget
{
  Q_OBJECT

public:
	static void showPage(const QString &file, const QString &page);
	static HelpWindow *Instance(void);
  
protected:
	HelpWindow(void);
	HelpWindow(const HelpWindow &);
	
private:
	void setSource(const QString &path, const QString &file, const QString &page);
	bool create();
	void show();
	
private:
	static HelpWindow *m_pInstance;
	QWidget *m_pRealForm;
	QTextBrowser *m_pTextBrowser;
	QPushButton *m_pCloseButton;
};

#endif // _HELPWINDOW_H_
