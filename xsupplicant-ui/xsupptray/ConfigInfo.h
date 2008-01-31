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

#ifndef _CONFIGINFO_H_
#define _CONFIGINFO_H_

#include <QWidget>

#include "XSupCalls.h"
#include "ConfigStackedWidget.h"
#include "UIPlugins.h"

class ConfigInfo : public QWidget
 {
     Q_OBJECT

 public:
	 ConfigInfo(QWidget *proxy, conn_enum **ppConnEnum, profile_enum **ppProfEnum, trusted_servers_enum **ppTSEnum, Emitter *e, XSupCalls *sup, QWidget *parent, UIPlugins *pPlugins);
	 ~ConfigInfo();

	 bool attach();

 public slots:
	void slotSetSaveBtn(bool);
	void slotClose();

signals:
	 void signalItemClicked(int, const QString &);
	 void signalSaveClicked();
	 void signalHelpClicked();
	 void signalNewItem(int);
 	 void signalNavChangeItem(int, const QString &);
	 void signalNavChangeSelected(int, const QString &);
     void signalAddItem(int, const QString &);
     void signalRenameItem(int, const QString &, const QString &);
	 void signalParentClose();
 	 void signalRemoveItem(int, const QString &);
	 void signalItemDeleted(int);

 private:
	 QWidget *m_pRealWidget;

	 Emitter *m_pEmitter;

	 conn_enum **m_ppConnEnum;
	 profile_enum **m_ppProfileEnum;
	 trusted_servers_enum **m_ppTrustedServersEnum;

	 XSupCalls *m_pSupplicant;

	 QPushButton *m_pSaveButton;
	 QPushButton *m_pHelpButton;
	 QPushButton *m_pCloseButton;

	 bool m_bHaveClose;
	 bool m_bHaveHelp;

	 ConfigStackedWidget *m_pStackedWidget;

	 QWidget *m_pParent;

	 UIPlugins *m_pPlugins;
};

#endif  // _CONFIGINFO_H_

