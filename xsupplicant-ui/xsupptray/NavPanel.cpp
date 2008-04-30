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

#include <QTreeWidgetItem>

#include "stdafx.h"
#include "NavPanel.h"
#include "FormLoader.h"
#include "Util.h"

NavPanel::NavPanel(QWidget *proxy, conn_enum *pConnEnum, profile_enum *pProfEnum, trusted_servers_enum *pTSEnum, Emitter *e, XSupCalls *sup, QWidget *parent) :
	m_pEmitter(e), m_pRealWidget(proxy), m_pParent(parent), m_pConns(pConnEnum), m_pProfs(pProfEnum),
		m_pTrustedServers(pTSEnum), m_supplicant(sup)
{
	m_pNewButton = NULL;
	m_pDeleteButton = NULL;
	m_pManagedItems = NULL;

	m_bDontEmitChange = false;

	activeType = -1;
	activeName = "";
}

NavPanel::~NavPanel()
{
	Util::myDisconnect(m_pManagedItems, SIGNAL(itemSelectionChanged()), this, SLOT(slotItemChanged()));
	Util::myDisconnect(this, SIGNAL(navItemSelected(int, const QString &)), m_pParent, SIGNAL(navItemSelected(int, const QString &)));
	Util::myDisconnect(m_pNewButton, SIGNAL(clicked()), this, SLOT(slotNewClicked()));
	Util::myDisconnect(m_pDeleteButton, SIGNAL(clicked()), this, SLOT(slotDelItem()));

	 Util::myDisconnect(myShortcut, SIGNAL(activated()), this, SLOT(slotDelPressed()));
	 delete myShortcut;
}

bool NavPanel::attach()
{
	 m_pNewButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonNew");

	 if (m_pNewButton == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("The QPushButton 'buttonNew' wasn't found in the form."));
		 return false;
	 }

	 m_pDeleteButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonDelete");

	 if (m_pDeleteButton == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("The QPushButton 'buttonDelete' wasn't found in the form."));
		 return false;
	 }

	 m_pManagedItems = qFindChild<QTreeWidget*>(m_pRealWidget, "widgetTreeItemsToManage");
	 
	 if (m_pManagedItems == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("The QTreeWidget 'widgetTreeItemsToManage' wasn't found in the form."));
		 return false;
	 }

	 Util::myConnect(m_pManagedItems, SIGNAL(itemSelectionChanged()), this, SLOT(slotItemChanged()));

	 myShortcut = new QShortcut(QKeySequence(Qt::Key_Delete), m_pManagedItems);
	 Util::myConnect(myShortcut, SIGNAL(activated()), this, SLOT(slotDelPressed()));

	 disableNavBtns();  // The tree widget starts with nothing connected, so disable the buttons to start with.

	 populateTree();

	 m_pManagedItems->setItemSelected(m_pManagedItems->invisibleRootItem()->child(0), true);
	 m_pManagedItems->setCurrentItem(m_pManagedItems->invisibleRootItem()->child(0));

	 return true;
}

void NavPanel::slotItemChanged()
{
	QList<QTreeWidgetItem *>myList;

	myList = m_pManagedItems->selectedItems();

	slotItemClicked(myList.first(), 0);
}

void NavPanel::slotDelPressed()
{
	// Only do something if the delete button is enabled.
	if (m_pDeleteButton->isEnabled() == true)
	{
		slotDelItem();
	}
}

void NavPanel::populateTree()
{
	populateConnections();
	populateProfiles();
	populateTrustedServers();

	m_pGlobalsItem = m_pManagedItems->invisibleRootItem()->child(GLOBALS_ITEM);
	m_pAdvancedItem = m_pManagedItems->invisibleRootItem()->child(ADVANCED_ITEM);

	// Set up the signal we will send to the parent when an item is selected.
	Util::myConnect(this, SIGNAL(navItemSelected(int, const QString &)), m_pParent, SIGNAL(navItemSelected(int, const QString &)));
	Util::myConnect(m_pNewButton, SIGNAL(clicked()), this, SLOT(slotNewClicked()));
	Util::myConnect(m_pDeleteButton, SIGNAL(clicked()), this, SLOT(slotDelItem()));
}

void NavPanel::populateConnections()
{
  // get the list of connections
  int m_connectionCount = 0;

  m_pConnectionsItem = m_pManagedItems->invisibleRootItem()->child(CONNECTIONS_ITEM);

  // Add them to the parent tree item
  if (m_pConns)
  {
    while (m_pConns[m_connectionCount].name != NULL)
    {
	  addItem(m_pConnectionsItem, CONNECTIONS_ITEM, m_pConns[m_connectionCount].name, "tree_connection.png");
	  m_connectionCount++;
    }
  }
}

void NavPanel::populateProfiles()
{
  // get the list of profiles
  int m_profileCount = 0;

  m_pProfilesItem = m_pManagedItems->invisibleRootItem()->child(PROFILES_ITEM);

  // Add them to the parent tree item
  if (m_pProfs)
  {
    while (m_pProfs[m_profileCount].name != NULL)
    {
	  addItem(m_pProfilesItem, PROFILES_ITEM, m_pProfs[m_profileCount].name, "tree_profile.png");
	  m_profileCount++;
    }
  }
}

void NavPanel::addItem(QTreeWidgetItem *parent, int itemType, QString child, QString icon)
{
	QTreeWidgetItem *subItem = NULL;
	QPixmap *p = NULL;

	subItem = new QTreeWidgetItem(parent, itemType);
	subItem->setText(0, child);

	p = FormLoader::loadicon(icon);
	subItem->setIcon(0, QIcon(*p));
	delete p;
}

void NavPanel::populateTrustedServers()
{
  // get the list of profiles
  int m_tsCount = 0;

  m_pTrustedServersItem = m_pManagedItems->invisibleRootItem()->child(TRUSTED_SERVERS_ITEM);

  // Add them to the parent tree item
  if (m_pTrustedServers)
  {
    while (m_pTrustedServers[m_tsCount].name != NULL)
    {
	  addItem(m_pTrustedServersItem, TRUSTED_SERVERS_ITEM, m_pTrustedServers[m_tsCount].name, "tree_trustedserver.png");
	  m_tsCount++;
    }
  }
}

void NavPanel::slotItemClicked(QTreeWidgetItem *selectedItem, int column)
{
	if (selectedItem == m_pConnectionsItem)  // The "Connections" top level item is selected.
	{
		enableNavBtns();
		m_pDeleteButton->setEnabled(false);

		if ((activeType != CONNECTIONS_ITEM) || ((activeType == CONNECTIONS_ITEM) && (activeName != ""))
			&& (m_bDontEmitChange == false))
		{
			emit signalItemClicked(CONNECTIONS_ITEM, QString(""));
		}

		// Otherwise, do nothing.
		activeType = CONNECTIONS_ITEM;
		activeName = "";
	}
	else if (selectedItem->parent() == m_pConnectionsItem)
	{
		enableNavBtns();

		if ((activeType != CONNECTIONS_ITEM) || ((activeType == CONNECTIONS_ITEM) && (activeName != selectedItem->text(column)) 
			&& (m_bDontEmitChange == false)))
		{
			emit signalItemClicked(CONNECTIONS_ITEM, selectedItem->text(column));
		}

		activeType = CONNECTIONS_ITEM;
		activeName = selectedItem->text(column);
	}
	else if (selectedItem == m_pProfilesItem)
	{
		enableNavBtns();
		m_pDeleteButton->setEnabled(false);

		if ((activeType != PROFILES_ITEM) || ((activeType == PROFILES_ITEM) && (activeName != ""))
			&& (m_bDontEmitChange == false))
		{
			emit signalItemClicked(PROFILES_ITEM, QString(""));
		}

		activeType = PROFILES_ITEM;
		activeName = "";
	}
	else if (selectedItem->parent() == m_pProfilesItem)
	{
		enableNavBtns();

		if ((activeType != PROFILES_ITEM) || ((activeType == PROFILES_ITEM) && (activeName != selectedItem->text(column)))
			&& (m_bDontEmitChange == false))
		{
			emit signalItemClicked(PROFILES_ITEM, selectedItem->text(column));
		}

		activeType = PROFILES_ITEM;
		activeName = selectedItem->text(column);
	}
	else if (selectedItem == m_pTrustedServersItem)
	{
		enableNavBtns();
		m_pDeleteButton->setEnabled(false);
		if ((activeType != TRUSTED_SERVERS_ITEM) || ((activeType == TRUSTED_SERVERS_ITEM) && (activeName != ""))
			&& (m_bDontEmitChange == false))
		{
			emit signalItemClicked(TRUSTED_SERVERS_ITEM, QString(""));
		}

		activeType = TRUSTED_SERVERS_ITEM;
		activeName = "";
	}
	else if (selectedItem->parent() == m_pTrustedServersItem)
	{
		enableNavBtns();
		if ((activeType != TRUSTED_SERVERS_ITEM) || ((activeType == TRUSTED_SERVERS_ITEM) && (activeName != selectedItem->text(column)))
			&& (m_bDontEmitChange == false))
		{
			emit signalItemClicked(TRUSTED_SERVERS_ITEM, selectedItem->text(column));
		}

		activeType = TRUSTED_SERVERS_ITEM;
		activeName = selectedItem->text(column);
	}
	else if (selectedItem == m_pGlobalsItem)
	{
		disableNavBtns();
		if ((activeType != GLOBALS_ITEM) || ((activeType == GLOBALS_ITEM) && (activeName != ""))
			&& (m_bDontEmitChange == false))
		{
			emit signalItemClicked(GLOBALS_ITEM, QString(""));
		}

		activeType = GLOBALS_ITEM;
		activeName = "";
	}
	else if (selectedItem->parent() == m_pGlobalsItem)
	{
		disableNavBtns();
		if ((activeType != GLOBALS_ITEM) || ((activeType == GLOBALS_ITEM) && (activeName != "Global_Logging"))
			&& (m_bDontEmitChange == false))
		{
			emit signalItemClicked(GLOBALS_ITEM, QString("Global_Logging"));
		}

		activeType = GLOBALS_ITEM;
		activeName = "Global_Logging";
	}
	else if (selectedItem == m_pAdvancedItem)
	{
		disableNavBtns();
		if ((activeType != ADVANCED_ITEM) || ((activeType == ADVANCED_ITEM) && (activeName != ""))
			&& (m_bDontEmitChange == false))
		{
			emit signalItemClicked(ADVANCED_ITEM, QString(""));
		}

		activeType = ADVANCED_ITEM;
		activeName = "";
	}
	else if (selectedItem->parent() == m_pAdvancedItem)
	{
		disableNavBtns();
		if (selectedItem->parent()->child(ADVANCED_SETTINGS_ITEM) == selectedItem)
		{
			if ((activeType != ADVANCED_ITEM) || ((activeType == ADVANCED_ITEM) && (activeName != "Advanced_Settings"))
			&& (m_bDontEmitChange == false))
			{
				emit signalItemClicked(ADVANCED_ITEM, QString("Advanced_Settings"));
			}

			activeType = ADVANCED_ITEM;
			activeName = "Advanced_Settings";
		}
		else
		{
			// There are currently only two selections, so this should be internals.
			if ((activeType != ADVANCED_ITEM) || ((activeType == ADVANCED_ITEM) && (activeName != "Advanced_Internals"))
			&& (m_bDontEmitChange == false))
			{
				emit signalItemClicked(ADVANCED_ITEM, QString("Advanced_Internals"));
			}

			activeType = ADVANCED_ITEM;
			activeName = "Advanced_Internals";
		}
	}
	else
	{
		disableNavBtns();
		QMessageBox::critical(this, tr("Bad Item Selected"), tr("An unknown item was selected from the navigation panel."));
	}
}

void NavPanel::slotNewClicked()
{
	QTreeWidgetItem *selectedItem;
	QList<QTreeWidgetItem *> itemList;

	itemList = m_pManagedItems->selectedItems();

	if (itemList.isEmpty() == true)
	{
		QMessageBox::information(this, tr("Nothing Selected"), tr("Please select an item before clicking new."));
		return;
	}

	selectedItem = itemList.first();
	
	if ((selectedItem == m_pConnectionsItem) || (selectedItem->parent() == m_pConnectionsItem))
	{
		emit signalNewItem(CONNECTIONS_ITEM);
		enableNavBtns();
	}
	else if ((selectedItem == m_pProfilesItem) || (selectedItem->parent() == m_pProfilesItem))
	{
		emit signalNewItem(PROFILES_ITEM);
		enableNavBtns();
	}
	else if ((selectedItem == m_pTrustedServersItem) || (selectedItem->parent() == m_pTrustedServersItem))
	{
		emit signalNewItem(TRUSTED_SERVERS_ITEM);
		enableNavBtns();
	}
	else
	{
		QMessageBox::critical(this, tr("New Item Error"), tr("Somehow, you managed to click new on an item that doesn't allow new things to be created!"));
	}

//	m_bDontEmitChange = false;
}

void NavPanel::enableNavBtns()
{
	m_pNewButton->setEnabled(true);
	m_pDeleteButton->setEnabled(true);
}

void NavPanel::disableNavBtns()
{
	m_pNewButton->setEnabled(false);
	m_pDeleteButton->setEnabled(false);
}

QTreeWidgetItem *NavPanel::getSelectedItem()
{
	QList<QTreeWidgetItem*> itemList;

	itemList = m_pManagedItems->selectedItems();

	if (itemList.isEmpty() == true) return NULL;

	return itemList.first();
}

void NavPanel::slotDelItem()
{
	QTreeWidgetItem *selectedItem;
	QTreeWidgetItem *toDelete;
	int toDeleteIdx;
	QString temp;

	selectedItem = getSelectedItem();
	
	if (selectedItem == m_pConnectionsItem) 
	{
		QMessageBox::critical(this, tr("Error"), tr("You cannot delete the root connections item."));
	}
	else if (selectedItem->parent() == m_pConnectionsItem)
	{
	  temp = selectedItem->text(0);
	  if (QMessageBox::question(this, tr("Delete a Connection"), 
		  tr("Are you sure you want to delete connection '%1'?").arg(temp), 
		  QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
	  {
		if (m_supplicant->deleteConnectionConfig(temp) == true)
		{
			emit signalItemDeleted(CONNECTIONS_ITEM);

			toDeleteIdx = m_pConnectionsItem->indexOfChild(selectedItem);
			toDelete = m_pConnectionsItem->takeChild(toDeleteIdx);

			delete toDelete;

			selectedItem = getSelectedItem();
			slotItemClicked(selectedItem, 0);

			m_pEmitter->sendConnConfigUpdate();
		}
	  }
	}
	else if (selectedItem == m_pProfilesItem) 
	{
		QMessageBox::critical(this, tr("Error"), tr("You cannot delete the root profile item."));
	}
	else if (selectedItem->parent() == m_pProfilesItem)
	{
	  temp = selectedItem->text(0);
	  if (QMessageBox::question(this, tr("Delete a Profile"), 
		  tr("Are you sure you want to delete profile '%1'?").arg(temp), 
		  QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
	  {
		if (m_supplicant->deleteProfileConfig(temp) == true)
		{
			emit signalItemDeleted(PROFILES_ITEM);

			toDeleteIdx = m_pProfilesItem->indexOfChild(selectedItem);
			toDelete = m_pProfilesItem->takeChild(toDeleteIdx);

			delete toDelete;

			selectedItem = getSelectedItem();
			slotItemClicked(selectedItem, 0);
		}
	  }
	}
	else if (selectedItem == m_pTrustedServersItem) 
	{
		QMessageBox::critical(this, tr("Error"), tr("You cannot delete the root trusted server item."));
	}
	else if (selectedItem->parent() == m_pTrustedServersItem)
	{
	  temp = selectedItem->text(0);
	  if (QMessageBox::question(this, tr("Delete a Trusted Server"), 
		  tr("Are you sure you want to delete trusted server '%1'?").arg(temp), 
		  QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
	  {
		if (m_supplicant->deleteTrustedServerConfig(temp) == true)
		{
			emit signalItemDeleted(TRUSTED_SERVERS_ITEM);

			toDeleteIdx = m_pTrustedServersItem->indexOfChild(selectedItem);
			toDelete = m_pTrustedServersItem->takeChild(toDeleteIdx);

			delete toDelete;

			selectedItem = getSelectedItem();
			slotItemClicked(selectedItem, 0);
		}
	  }
	}
	else
	{
		QMessageBox::critical(this, tr("Delete Item Error"), tr("Somehow, you managed to click delete on an item that doesn't allow new things to be deleted!"));
	}
}

void NavPanel::changeSelected(int index, const QString &itemName)
{
	switch (index)
	{
	case CONNECTIONS_ITEM:
		changeHighlight(m_pConnectionsItem, itemName);
		activeType = CONNECTIONS_ITEM;
		activeName = itemName;
		break;

	case PROFILES_ITEM:
		changeHighlight(m_pProfilesItem, itemName);
		activeType = PROFILES_ITEM;
		activeName = itemName;
		break;

	case TRUSTED_SERVERS_ITEM:
		changeHighlight(m_pTrustedServersItem, itemName);
		activeType = TRUSTED_SERVERS_ITEM;
		activeName = itemName;
		break;

	case GLOBALS_ITEM:
		if (itemName == "Global_Logging")
		{
			m_pManagedItems->setCurrentItem(m_pGlobalsItem->child(0));
			activeType = GLOBALS_ITEM;
			activeName = "Global_Logging";
		}
		else if (itemName == "")
		{
			activeType = GLOBALS_ITEM;
			activeName = "";
		}
		else
		{
			QMessageBox::critical(this, tr("Programming Error"), tr("There was a request to change the navigation panel to a non-existant item under Globals!"));
			activeType = GLOBALS_ITEM;
			activeName = itemName;
		}
		break;

	case ADVANCED_ITEM:
		if (itemName == "Advanced_Settings")
		{
			m_pManagedItems->setCurrentItem(m_pAdvancedItem->child(ADVANCED_SETTINGS_ITEM));
			activeType = ADVANCED_ITEM;
			activeName = "Advanced_Settings";
		}
		else if (itemName == "Advanced_Internals")
		{
			m_pManagedItems->setCurrentItem(m_pAdvancedItem->child(ADVANCED_INTERNAL_ITEM));
			activeType = ADVANCED_ITEM;
			activeName = "Advanced_Internals";
		}
		else if (itemName == "")
		{
			activeType = ADVANCED_ITEM;
			activeName = "";
		}
		else
		{
			QMessageBox::critical(this, tr("Programming Error"), tr("There was a request to change the navigation panel to a non-existant item under Advanced!"));
			activeType = ADVANCED_ITEM;
			activeName = itemName;
		}
		break;

	default:
		QMessageBox::critical(this, tr("Programming Error"), tr("There was a request to change the navigation panel to a non-existant item!"));
		break;
	}
}

QTreeWidgetItem *NavPanel::findTreeChild(QTreeWidgetItem *parent, QString name)
{
	int i;

	for (i = 0; i < parent->childCount(); i++)
	{
		if (parent->child(i)->text(0) == name) break;
	}

	if (i == parent->childCount()) return NULL;  // Didn't find it.

	return parent->child(i);
}

void NavPanel::changeHighlight(QTreeWidgetItem *parent, QString item)
{
	QTreeWidgetItem *selected;

	selected = findTreeChild(parent, item);

	if (selected != NULL) 
	{
		m_pManagedItems->setCurrentItem(selected);
		m_pManagedItems->setItemSelected(selected, true);
		
		selected->setSelected(true);
	}
}

void NavPanel::addItem(int itemType, const QString toAdd)
{
	m_bDontEmitChange = true;

	switch (itemType)
	{
	case CONNECTIONS_ITEM:
		if (m_pConnectionsItem != NULL)
			addItem(m_pConnectionsItem, CONNECTIONS_ITEM, toAdd, "tree_connections.png");
		changeSelected(itemType, toAdd);
		break;

	case PROFILES_ITEM:
		if (m_pProfilesItem != NULL)
			addItem(m_pProfilesItem, PROFILES_ITEM, toAdd, "tree_profiles.png");
		changeSelected(itemType, toAdd);
		break;

	case TRUSTED_SERVERS_ITEM:
		if (m_pTrustedServersItem != NULL)
			addItem(m_pTrustedServersItem, TRUSTED_SERVERS_ITEM, toAdd, "tree_trustedservers.png");
		changeSelected(itemType, toAdd);
		break;

	default:
		QMessageBox::critical(this, tr("Programming Error"), tr("There was a request to change the navigation panel to a non-existant item!"));
		break;
	}

	activeType = itemType;
	activeName = toAdd;

	m_bDontEmitChange = false;
}

void NavPanel::renameItem(int itemType, QString oldName, QString newName)
{
	QTreeWidgetItem *workingItem = NULL;

	switch (itemType)
	{
	case CONNECTIONS_ITEM:
		workingItem = findTreeChild(m_pConnectionsItem, oldName);
		break;

	case PROFILES_ITEM:
		workingItem = findTreeChild(m_pProfilesItem, oldName);
		break;

	case TRUSTED_SERVERS_ITEM:
		workingItem = findTreeChild(m_pTrustedServersItem, oldName);
		break;

	case GLOBALS_ITEM:
		QMessageBox::critical(this, tr("Programming Error"), tr("You cannot change the name of a Globals sub item!"));
		return;
		break;

	case ADVANCED_ITEM:
		QMessageBox::critical(this, tr("Programming Error"), tr("You cannot change the name of an Advanced sub item!"));
		return;
		break;

	case SELECTED_ITEM:
		workingItem = getSelectedItem();
		break;

	default:
		QMessageBox::critical(this, tr("Programming Error"), tr("There was a request to rename a non-existant item!"));
		return;
		break;
	}

	if (workingItem != NULL)
	{
		workingItem->setText(0, newName);
	}
}

void NavPanel::removeItem(int itemType, QString toRemove)
{
	QTreeWidgetItem *workingItem = NULL;
	QTreeWidgetItem *toDelete = NULL;
	QTreeWidgetItem *selectedItem = NULL;

	selectedItem = getSelectedItem();

	switch (itemType)
	{
	case CONNECTIONS_ITEM:
		workingItem = findTreeChild(m_pConnectionsItem, toRemove);

		if (workingItem == selectedItem) selectedItem = NULL;

		toDelete = m_pConnectionsItem->takeChild(m_pConnectionsItem->indexOfChild(workingItem));
		delete toDelete;
		break;

	case PROFILES_ITEM:
		workingItem = findTreeChild(m_pProfilesItem, toRemove);

		if (workingItem == selectedItem) selectedItem = NULL;

		toDelete = m_pProfilesItem->takeChild(m_pProfilesItem->indexOfChild(workingItem));
		delete toDelete;		
		break;

	case TRUSTED_SERVERS_ITEM:
		workingItem = findTreeChild(m_pTrustedServersItem, toRemove);

		if (workingItem == selectedItem) selectedItem = NULL;

		toDelete = m_pTrustedServersItem->takeChild(m_pTrustedServersItem->indexOfChild(workingItem));
		delete toDelete;		
		break;

	default:
		QMessageBox::critical(this, tr("Programming Error"), tr("There was a request to change the navigation panel to a non-existant item!"));
		break;
	}

	if (selectedItem != NULL) m_pManagedItems->setCurrentItem(selectedItem);
}

void NavPanel::slotDecideNavItemClicked(int type, const QString &name)
{
	if ((type != activeType) || ((type == activeType) && (name != activeName)))
	{
		emit navItemSelected(type, name);
		activeType = type;
		activeName = name;
	}
	// Otherwise, ignore it.
}

void NavPanel::changeSelectedItem(int type, QString name)
{
	m_bDontEmitChange = true;
	changeSelected(type, name);
	m_bDontEmitChange = false;
}



