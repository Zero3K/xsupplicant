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

#ifndef _CONFIGSTACKEDWIDGET_H_
#define _CONFIGSTACKEDWIDGET_H_

#include <QWidget>
#include <QStackedWidget>

#include "xsupcalls.h"
#include "ConfigWidgetBase.h"
#include "UIPlugins.h"
#include "NavPanel.h"

class ConfigStackedWidget : public QWidget
 {
     Q_OBJECT

 public:
	 ConfigStackedWidget(QStackedWidget *proxy, conn_enum **ppConnEnum, profile_enum **ppProfEnum, trusted_servers_enum **ppTSEnum, Emitter *e, XSupCalls *sup, NavPanel *pPanel, UIPlugins *pPlugins, QWidget *parent);
	 ~ConfigStackedWidget();

	 bool attach();
	 void close();

	 enum {
		 CONNECTIONS_LIST_WINDOW,
		 PROFILES_LIST_WINDOW,
		 TRUSTED_SERVERS_LIST_WINDOW,
		 GLOBALS_LIST_WINDOW,
		 ADVANCED_LIST_WINDOW,
		 CONNECTION_EDIT_WINDOW,
		 PROFILE_EDIT_WINDOW,
		 TRUSTED_SERVERS_EDIT_WINDOW,
		 GLOBALS_EDIT_WINDOW,
		 ADVANCED_SETTINGS_EDIT_WINDOW,
		 ADVANCED_INTERNALS_EDIT_WINDOW
	 };

signals:
	 void signalSetSaveBtn(bool);
	 void signalSaveClicked();
	 void signalHelpClicked();
     void signalAddItem(int, const QString &);
     void signalRenameItem(int, const QString &, const QString &);
	 void signalRemoveItem(int, const QString &);

 public slots:
	 void slotSetWidget(int, const QString &);
	 void slotNewItem(int);

 private slots:
	void slotSaveClicked();
	void slotDeletedItem(int);
	void slotConnectionStateChanged();

 private:
	 void doConnectionsPanels(QString toEdit, bool isNew);
	 void doProfilesPanels(QString toEdit, bool isNew);
	 void doGlobalsPanels(QString toEdit);
	 void doAdvancedPanels(QString toEdit);
	 void doTrustedServersPanels(QString toEdit, bool isNew);

	 void refreshConnectionsEnum();
	 void refreshProfilesEnum();
	 void refreshTrustedServersEnum();
	 void refreshData();

 	 void changeWidget(int, const QString &, bool);

	 QStackedWidget *m_pRealWidget;

 	 Emitter *m_pEmitter;
	 QWidget *m_pParent;

	 conn_enum **m_ppConnEnum;
	 profile_enum **m_ppProfileEnum;
	 trusted_servers_enum **m_ppTrustedServersEnum;

	 XSupCalls *m_pSupplicant;

	 ConfigWidgetBase *m_pActivePage;

	 int curPage;

	 bool m_bConnected;
	 bool m_bIsDeleted;

	 UIPlugins *m_pPlugins;
	 NavPanel *m_pNavPanel;
};

#endif  // _CONFIGSTACKEDWIDGET_H_

