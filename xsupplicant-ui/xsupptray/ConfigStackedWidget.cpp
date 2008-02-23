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

#include "stdafx.h"

#include "NavPanel.h"
#include "Util.h"
#include "ConfigStackedWidget.h"
#include "ConfigWidgetGlobalsTable.h"
#include "ConfigWidgetAdvancedTable.h"
#include "ConfigWidgetTrustedServersTable.h"
#include "ConfigWidgetProfilesTable.h"
#include "ConfigWidgetConnectionsTable.h"
#include "ConfigWidgetEditGlobalsLogging.h"
#include "ConfigWidgetEditAdvancedInternals.h"
#include "ConfigWidgetEditAdvancedSettings.h"
#include "ConfigWidgetEditTrustedServers.h"
#include "ConfigWidgetEditConnection.h"
#include "ConfigWidgetEditProfile.h"

ConfigStackedWidget::ConfigStackedWidget(QStackedWidget *proxy, conn_enum **ppConnEnum, profile_enum **ppProfEnum, trusted_servers_enum **ppTSEnum, Emitter *e, XSupCalls *sup, QWidget *parent, UIPlugins *pPlugins):
	m_pRealWidget(proxy), m_ppConnEnum(ppConnEnum), m_ppProfileEnum(ppProfEnum), m_ppTrustedServersEnum(ppTSEnum), m_pEmitter(e), m_pSupplicant(sup), m_pParent(parent), m_pPlugins(pPlugins)
{
	m_bConnected = false;
	m_bIsDeleted = false;
	curPage = NavPanel::CONNECTIONS_ITEM;
	m_pActivePage = NULL;
}

ConfigStackedWidget::~ConfigStackedWidget()
{
	if (m_bConnected)
	{
		Util::myDisconnect(m_pParent, SIGNAL(signalItemClicked(int, const QString &)), this, SLOT(slotSetWidget(int, const QString &)));
		Util::myDisconnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SLOT(slotSetSaveBtn(bool)));
		Util::myDisconnect(this, SIGNAL(signalNavChangeSelected(int, const QString &)), m_pParent, SIGNAL(signalNavChangeSelected(int, const QString &)));

		Util::myDisconnect(m_pParent, SIGNAL(signalSaveClicked()), this, SLOT(slotSaveClicked()));
		Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SIGNAL(signalHelpClicked()));
		Util::myDisconnect(m_pParent, SIGNAL(signalNewItem(int)), this, SLOT(slotNewItem(int)));

		Util::myDisconnect(this, SIGNAL(signalAddItem(int, const QString &)), m_pParent, SIGNAL(signalAddItem(int, const QString &)));
		Util::myDisconnect(this, SIGNAL(signalRenameItem(int, const QString &, const QString &)), m_pParent, SIGNAL(signalRenameItem(int, const QString &, const QString &)));
		Util::myDisconnect(this, SIGNAL(signalRemoveItem(int, const QString &)), m_pParent, SIGNAL(signalRemoveItem(int, const QString &)));
		Util::myDisconnect(this, SIGNAL(signalNavChangeItem(int, const QString &)), m_pParent, SIGNAL(signalNavChangeItem(int, const QString &)));

		Util::myDisconnect(m_pParent, SIGNAL(signalItemDeleted(int)), this, SLOT(slotDeletedItem(int)));
	}

	if (m_pActivePage != NULL)
	{
		delete m_pActivePage;
		m_pActivePage = NULL;
	}
}

bool ConfigStackedWidget::attach()
{
	slotSetWidget(NavPanel::CONNECTIONS_ITEM, "");

	Util::myConnect(m_pParent, SIGNAL(signalItemClicked(int, const QString &)), this, SLOT(slotSetWidget(int, const QString &)));
	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SLOT(slotSetSaveBtn(bool)));
	Util::myConnect(this, SIGNAL(signalNavChangeSelected(int, const QString &)), m_pParent, SIGNAL(signalNavChangeSelected(int, const QString &)));

	Util::myConnect(m_pParent, SIGNAL(signalSaveClicked()), this, SLOT(slotSaveClicked()));
	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SIGNAL(signalHelpClicked()));
	Util::myConnect(m_pParent, SIGNAL(signalNewItem(int)), this, SLOT(slotNewItem(int)));

	Util::myConnect(this, SIGNAL(signalAddItem(int, const QString &)), m_pParent, SIGNAL(signalAddItem(int, const QString &)));
	Util::myConnect(this, SIGNAL(signalRenameItem(int, const QString &, const QString &)), m_pParent, SIGNAL(signalRenameItem(int, const QString &, const QString &)));
	Util::myConnect(this, SIGNAL(signalRemoveItem(int, const QString &)), m_pParent, SIGNAL(signalRemoveItem(int, const QString &)));
	Util::myConnect(this, SIGNAL(signalNavChangeItem(int, const QString &)), m_pParent, SIGNAL(signalNavChangeItem(int, const QString &)));

	Util::myConnect(m_pParent, SIGNAL(signalItemDeleted(int)), this, SLOT(slotDeletedItem(int)));

	m_bConnected = true;

	return true;
}

void ConfigStackedWidget::slotNewItem(int itemType)
{
	changeWidget(itemType, "", true);  // Show the right page.  (And allow the user to save if needed.)
}

void ConfigStackedWidget::slotSetWidget(int stackIdx, const QString &editItem)
{
	changeWidget(stackIdx, editItem, false);
}

void ConfigStackedWidget::close()
{
	if (m_pActivePage->dataChanged())
	{
		switch (QMessageBox::question(this, tr("You have changed data"), tr("You have unsaved changes.  Would you like to save them?"),
				(QMessageBox::Save | QMessageBox::Discard), QMessageBox::Discard))  // Discard is the default.
		{
		case QMessageBox::Save:
			// Don't need to refresh data here because we are closing the window.
			if (m_pActivePage->save() == false)
			{
				QMessageBox::critical(this, tr("Error Saving"), tr("Your settings couldn't be saved."));
				m_pActivePage->discard();
			}
			break;

		default:
			// Don't need to refresh data here because we are closing the window.
			m_pActivePage->discard();
			break;
		}
	}
}

void ConfigStackedWidget::changeWidget(int stackIdx, const QString &editItem, bool isNew = false)
{
	QString name;

	if ((m_pActivePage != NULL) && (m_pActivePage->dataChanged() == true) 
		&& (m_bIsDeleted == false))
	{
		// Ask the user if we should save first.
		switch (QMessageBox::question(this, tr("You have changed data"), tr("You have unsaved changes.  Would you like to save them?"),
				(QMessageBox::Save | QMessageBox::Discard), QMessageBox::Discard))  // Discard is the default.
		{
		case QMessageBox::Save:
			if (m_pActivePage->save() == false)
			{
				QMessageBox::information(this, tr("Unable to save data"), tr("Your configuration changes couldn't be saved.  Please verify that all data is valid, and that the configuration file is not write protected, or in use by another program."));
				m_pActivePage->getPageName(name);
				emit signalNavChangeItem(curPage, name);
				return;
			}
			refreshData();
			break;

		default:
			refreshData();
			m_pActivePage->discard();
			break;
		}
	}
	else
	{
		if (m_bIsDeleted)
		{
			refreshData();

			m_bIsDeleted = false;  // Rest our trigger.
		}
	}
			
	switch (stackIdx)
	{
	case NavPanel::CONNECTIONS_ITEM:
		curPage = NavPanel::CONNECTIONS_ITEM;
		doConnectionsPanels(editItem, isNew);
		break;

	case NavPanel::ADVANCED_ITEM:
		curPage = NavPanel::ADVANCED_ITEM;
		doAdvancedPanels(editItem);
		break;

	case NavPanel::GLOBALS_ITEM:
		curPage = NavPanel::GLOBALS_ITEM;
		doGlobalsPanels(editItem);
		break;

	case NavPanel::PROFILES_ITEM:
		curPage = NavPanel::PROFILES_ITEM;
		doProfilesPanels(editItem, isNew);
		break;

	case NavPanel::TRUSTED_SERVERS_ITEM:
		curPage = NavPanel::TRUSTED_SERVERS_ITEM;
		doTrustedServersPanels(editItem, isNew);
		break;

	default:
		QMessageBox::critical(this, tr("Unknown Item Selected"), tr("You have selected an item from the navigation that is unknown."));
		break;
	}
}

void ConfigStackedWidget::doConnectionsPanels(QString toEdit, bool isNew)
{
	QWidget *pRealWidget = NULL;

	if ((toEdit == "") && (isNew == false))
	{
		// Display the Connections List.
		m_pRealWidget->setCurrentIndex(CONNECTIONS_LIST_WINDOW);

		// Then build the window.
		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealWidget = qFindChild<QWidget*>(m_pRealWidget, "widgetStackConnectionsTablePage");

		if (pRealWidget == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QWidget 'widgetStackConnectionsTablePage' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetConnectionsTable(pRealWidget, m_pSupplicant, (*m_ppConnEnum), this);

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The connection table page couldn't be created."));
			}
		}
	}
	else
	{
		// Display the "Edit a Connection" widget
		m_pRealWidget->setCurrentIndex(CONNECTION_EDIT_WINDOW);

		// Then build the window.
		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealWidget = qFindChild<QWidget*>(m_pRealWidget, "widgetStackConnectionsEditPage");

		if (pRealWidget == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QWidget 'widgetStackConnectionsEditPage' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetEditConnection(pRealWidget, m_pEmitter, toEdit, m_pSupplicant, this);

			if (isNew)
			{
				m_pActivePage->newItem();
			}

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The connections configuration page couldn't be created."));
			}
		}
	}
}

void ConfigStackedWidget::doProfilesPanels(QString toEdit, bool isNew)
{
	QTableWidget *pRealTable = NULL;
	QWidget *pRealWidget = NULL;

	if ((toEdit == "") && (isNew == false))
	{
		// Display the Profiles List.
		m_pRealWidget->setCurrentIndex(PROFILES_LIST_WINDOW);

		// Then build the window.
		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealTable = qFindChild<QTableWidget*>(m_pRealWidget, "dataTableProfiles");

		if (pRealTable == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QTableWidget 'dataTableProfiles' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetProfilesTable(pRealTable, (*m_ppProfileEnum), m_pSupplicant, this);

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The profile page couldn't be created."));
			}
		}
	}
	else
	{
		// Display the "Edit a Profile" widget.
		m_pRealWidget->setCurrentIndex(PROFILE_EDIT_WINDOW);

		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealWidget = qFindChild<QWidget*>(m_pRealWidget, "widgetStackProfilesEditPage");

		if (pRealWidget == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QWidget 'widgetStackProfilesEditPage' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetEditProfile(pRealWidget, toEdit, m_pSupplicant, this, m_pPlugins);

			if (isNew)
			{
				m_pActivePage->newItem();
			}

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The profile page couldn't be created."));
			}
		}
	}
}

void ConfigStackedWidget::doGlobalsPanels(QString toEdit)
{
	QTableWidget *pRealTable = NULL;
	QWidget *pRealWidget = NULL;

	if (toEdit == "")
	{
		//Display the Globals List
		m_pRealWidget->setCurrentIndex(GLOBALS_LIST_WINDOW);

		// Then build the window.
		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealTable = qFindChild<QTableWidget*>(m_pRealWidget, "dataTableGlobals");

		if (pRealTable == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QTableWidget 'dataTableGlobals' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetGlobalsTable(pRealTable, this);

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The globals table page couldn't be created."));
			}
		}
	}
	else
	{
		// Display the "Globals Edit" window.
		m_pRealWidget->setCurrentIndex(GLOBALS_EDIT_WINDOW);

		// Then build the window.
		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealWidget = qFindChild<QWidget*>(m_pRealWidget, "widgetStackLoggingEditPage");

		if (pRealWidget == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QWidget 'widgetStackLoggingEditPage' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetEditGlobalsLogging(pRealWidget, m_pSupplicant, this);

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The globals configuration page couldn't be created."));
			}
		}
	}
}

void ConfigStackedWidget::doAdvancedPanels(QString toEdit)
{
	QTableWidget *pRealTable = NULL;
	QWidget *pRealWidget = NULL;

	if (toEdit == "")
	{
		// Display the Advanced List
		m_pRealWidget->setCurrentIndex(ADVANCED_LIST_WINDOW);

		// Then build the window.
		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealTable = qFindChild<QTableWidget*>(m_pRealWidget, "advancedTable");

		if (pRealTable == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QTableWidget 'advancedTable' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetAdvancedTable(pRealTable, this);

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The advanced table page couldn't be created."));
			}
		}
	}
	else
	{
		if (toEdit == "Advanced_Settings")
		{
			// Display the Advanced Settings window.
			m_pRealWidget->setCurrentIndex(ADVANCED_SETTINGS_EDIT_WINDOW);

			// Then build the window.
			if (m_pActivePage != NULL)
			{
				m_pActivePage->detach();
				m_pActivePage->deleteLater();
				m_pActivePage = NULL;
			}

			pRealWidget = qFindChild<QWidget*>(m_pRealWidget, "widgetStackAdvancedSettingsEditPage");

			if (pRealWidget == NULL)
			{
				QMessageBox::critical(this, tr("Form Design Error"), tr("The QWidget 'widgetStackAdvancedSettingsEditPage' could not be found in this form!"));
			}
			else
			{
				m_pActivePage = new ConfigWidgetEditAdvancedSettings(pRealWidget, m_pSupplicant, this);

				if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
				{
					QMessageBox::critical(this, tr("Object Creation Error"), tr("The advanced settings configuration page couldn't be created."));
				}
			}
		}
		else if (toEdit == "Advanced_Internals")
		{
			// Display the Advanced Internals window.
			m_pRealWidget->setCurrentIndex(ADVANCED_INTERNALS_EDIT_WINDOW);

			// Then build the window.
			if (m_pActivePage != NULL)
			{
				m_pActivePage->detach();
				m_pActivePage->deleteLater();
				m_pActivePage = NULL;
			}

			pRealWidget = qFindChild<QWidget*>(m_pRealWidget, "widgetStackAdvancedInternalsEditPage");

			if (pRealWidget == NULL)
			{
				QMessageBox::critical(this, tr("Form Design Error"), tr("The QWidget 'widgetStackAdvancedInternalsEditPage' could not be found in this form!"));
			}
			else
			{
				m_pActivePage = new ConfigWidgetEditAdvancedInternals(pRealWidget, m_pSupplicant, this);

				if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
				{
					QMessageBox::critical(this, tr("Object Creation Error"), tr("The advanced internals configuration page couldn't be created."));
				}
			}
		}
		else
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("A signal was passed from a navigation window that instructed us to go to an known configuration widget."));
		}
	}
}

void ConfigStackedWidget::doTrustedServersPanels(QString toEdit, bool isNew)
{
	QTableWidget *pRealTable = NULL;
	QWidget *pRealWidget = NULL;

	if ((toEdit == "") && (isNew == false))
	{
		// Display the Trusted Servers Panel
		m_pRealWidget->setCurrentIndex(TRUSTED_SERVERS_LIST_WINDOW);

		// Then build the window.
		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealTable = qFindChild<QTableWidget*>(m_pRealWidget, "dataTableTrustedServers");

		if (pRealTable == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QTableWidget 'dataTableGlobals' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetTrustedServersTable(pRealTable, (*m_ppTrustedServersEnum), this);

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The trusted servers table page couldn't be created."));
			}
		}
	}
	else
	{
		// Display the "Edit a Trusted Server" panel.
		m_pRealWidget->setCurrentIndex(TRUSTED_SERVERS_EDIT_WINDOW);

		// Then build the window.
		if (m_pActivePage != NULL)
		{
			m_pActivePage->detach();
			m_pActivePage->deleteLater();
			m_pActivePage = NULL;
		}

		pRealWidget = qFindChild<QWidget*>(m_pRealWidget, "widgetStackTrustedServersEditPage");

		if (pRealWidget == NULL)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The QWidget 'widgetStackTrustedServersEditPage' could not be found in this form!"));
		}
		else
		{
			m_pActivePage = new ConfigWidgetEditTrustedServers(pRealWidget, toEdit, m_pSupplicant, this);

			if (isNew)
			{
				m_pActivePage->newItem();
			}

			if ((m_pActivePage == NULL) || (m_pActivePage->attach() == false))
			{
				QMessageBox::critical(this, tr("Object Creation Error"), tr("The trusted server configuration page couldn't be created."));
			}
		}

	}
}

void ConfigStackedWidget::refreshConnectionsEnum()
{
	if ((*m_ppConnEnum) != NULL)
	{
		m_pSupplicant->freeEnumConnections(m_ppConnEnum);
	}

	if (m_pSupplicant->enumAndSortConnections(m_ppConnEnum, true) == false)
	{
		m_ppConnEnum = NULL;
	}
}

void ConfigStackedWidget::refreshProfilesEnum()
{
	if ((m_ppProfileEnum != NULL) && ((*m_ppProfileEnum) != NULL))
	{
		m_pSupplicant->freeEnumProfile(m_ppProfileEnum);
	}

	if (m_pSupplicant->enumProfiles(m_ppProfileEnum, true) == false)
	{
		m_ppProfileEnum = NULL;
	}
}

void ConfigStackedWidget::refreshTrustedServersEnum()
{
	if ((*m_ppTrustedServersEnum) != NULL)
	{
		m_pSupplicant->freeEnumTrustedServer(m_ppTrustedServersEnum);
	}

	if (m_pSupplicant->enumTrustedServers(m_ppTrustedServersEnum, true) == false)
	{
		m_ppTrustedServersEnum = NULL;
	}
}

void ConfigStackedWidget::refreshData()
{
	switch (m_pRealWidget->currentIndex())
	{
	default:
	case CONNECTIONS_LIST_WINDOW:
	case PROFILES_LIST_WINDOW:
	case TRUSTED_SERVERS_LIST_WINDOW:
	case GLOBALS_LIST_WINDOW:
	case ADVANCED_LIST_WINDOW:
	case GLOBALS_EDIT_WINDOW:
	case ADVANCED_SETTINGS_EDIT_WINDOW:
	case ADVANCED_INTERNALS_EDIT_WINDOW:
		// Do nothing with these.
		break;

	case CONNECTION_EDIT_WINDOW:
		refreshConnectionsEnum();
		m_pEmitter->sendConnConfigUpdate();
		break;

	case PROFILE_EDIT_WINDOW:
		refreshProfilesEnum();
		m_pEmitter->sendProfConfigUpdate();
		break;

	case TRUSTED_SERVERS_EDIT_WINDOW:
		refreshTrustedServersEnum();
		break;
	}
}

void ConfigStackedWidget::slotSaveClicked()
{
	if (m_pActivePage != NULL)
	{
		m_pActivePage->save();

		refreshData();
	}
}

void ConfigStackedWidget::slotDeletedItem(int itemType)
{
	switch (itemType)
	{
	case NavPanel::CONNECTIONS_ITEM:
		refreshConnectionsEnum();
		m_bIsDeleted = true;
		break;

	case NavPanel::PROFILES_ITEM:
		refreshProfilesEnum();
		m_bIsDeleted = true;
		break;

	case NavPanel::TRUSTED_SERVERS_ITEM:
		refreshTrustedServersEnum();
		m_bIsDeleted = true;
		break;

	default:
		QMessageBox::critical(this, tr("Enumeration Refresh Error"), tr("The navigation panel claimed an unknown item type was deleted."));
		break;
	}
}