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

#ifndef _NAVPANEL_H_
#define _NAVPANEL_H_

#include <QWidget>
#include <QTreeWidgetItem>

#include "xsupcalls.h"

class NavPanel : public QWidget
 {
     Q_OBJECT

 public:
		 enum {
			 CONNECTIONS_ITEM = 0,   
			 PROFILES_ITEM,
			 TRUSTED_SERVERS_ITEM,
			 GLOBALS_ITEM,
			 ADVANCED_ITEM,
			 SELECTED_ITEM
	 };

		 enum {
			 ADVANCED_SETTINGS_ITEM,
			 ADVANCED_INTERNAL_ITEM
		 };

  NavPanel(QWidget *proxy, conn_enum *pConnEnum, profile_enum *pProfEnum, trusted_servers_enum *pTSEnum, Emitter *e, XSupCalls *sup, QWidget *parent);
  ~NavPanel();

  bool attach();
  void changeSelectedItem(int, QString);
  void addItem(int itemType, const QString toAdd);
  void renameItem(int, QString, QString);
  void removeItem(int, QString);

signals:
  void signalItemClicked(int, const QString &);
  void signalNewItem(int);
  void signalItemDeleted(int);
  void navItemSelected(int, const QString &);

private slots:
  void slotItemClicked(QTreeWidgetItem *, int);
  void slotNewClicked();
  void slotDelItem();
  void slotDecideNavItemClicked(int, const QString &);
  void slotDelPressed();
  void slotItemChanged();

private:
	void populateTree();
	void populateConnections();
	void populateProfiles();
	void populateTrustedServers();
	void changeSelected(int, const QString &);

	void enableNavBtns();
	void disableNavBtns();

	void changeHighlight(QTreeWidgetItem *parent, QString item);

	void addItem(QTreeWidgetItem *parent, int itemType, QString child, QString icon);

	QTreeWidgetItem *getSelectedItem();

	QTreeWidgetItem *findTreeChild(QTreeWidgetItem *parent, QString name);

	QWidget *m_pRealWidget;
	QWidget *m_pParent;

	Emitter *m_pEmitter;

	QPushButton *m_pNewButton;
	QPushButton *m_pDeleteButton;

	QTreeWidget *m_pManagedItems;

	QTreeWidgetItem *m_pConnectionsItem;
	QTreeWidgetItem *m_pProfilesItem;
	QTreeWidgetItem *m_pTrustedServersItem;
	QTreeWidgetItem *m_pGlobalsItem;
	QTreeWidgetItem *m_pAdvancedItem;

	conn_enum *m_pConns;
	profile_enum *m_pProfs;
	trusted_servers_enum *m_pTrustedServers;

	XSupCalls *m_supplicant;
	QShortcut *myShortcut;

	bool m_bDontEmitChange;

	int activeType;
	QString activeName;
};

#endif  // _NAVPANEL_H_

