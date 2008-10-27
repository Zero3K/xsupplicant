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

#include <QWidget>

#include "stdafx.h"
#include "ConfigWidgetProfilesTable.h"
#include "Util.h"
#include "NavPanel.h"
#include "helpbrowser.h"

ConfigWidgetProfilesTable::ConfigWidgetProfilesTable(QTableWidget *pRealTable, profile_enum *pProfilesEnum, XSupCalls *xsup, QWidget *parent) :
	m_pRealTable(pRealTable), m_pParent(parent), m_pProfilesEnum(pProfilesEnum), m_pSupplicant(xsup)
{
	m_bConnected = false;

	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), parent, SIGNAL(signalSetSaveBtn(bool)));

	// Make sure the save button is disabled.
	emit signalSetSaveBtn(false);
}

ConfigWidgetProfilesTable::~ConfigWidgetProfilesTable()
{	
	if (m_pRealTable != NULL)
	{
		for (int i = m_pRealTable->rowCount(); i >= 0; i--)
		{
			m_pRealTable->removeRow(i);
		}
	}

	if (m_bConnected)
	{
		Util::myDisconnect(m_pRealTable, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(slotDoubleClicked(int, int)));
		Util::myDisconnect(this, SIGNAL(signalSetWidget(int, const QString &)), m_pParent, SLOT(slotSetWidget(int, const QString &)));
		Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));
	}
}

bool ConfigWidgetProfilesTable::attach()
{
	fillTable();

	m_pRealTable->resizeColumnsToContents();
	m_pRealTable->horizontalHeader()->setStretchLastSection(true);
	m_pRealTable->horizontalHeader()->setHighlightSections(false);   // Don't "push in" the header.
	m_pRealTable->verticalHeader()->setHighlightSections(false);     // Ditto for the vertical header.

	Util::myConnect(m_pRealTable, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(slotDoubleClicked(int, int)));
	Util::myConnect(this, SIGNAL(signalSetWidget(int, const QString &)), m_pParent, SLOT(slotSetWidget(int, const QString &)));
	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	m_bConnected = true;

	return true;
}

void ConfigWidgetProfilesTable::slotDoubleClicked(int row, int)
{
	QTableWidgetItem *myItem = NULL;

	// We only care about the row.
	myItem = m_pRealTable->item(row, 0);

	emit signalSetWidget(NavPanel::PROFILES_ITEM, myItem->text());
}

void ConfigWidgetProfilesTable::fillTable()
{
	int i = 0;
	config_profiles *myProfile = NULL;
	QString inner;
	QString outer;
	QTableWidgetItem *newItem = NULL;
	bool sorting = false;
	QString temp;

	m_pRealTable->setCursor(Qt::WaitCursor);   // This may take a second.

	sorting = m_pRealTable->isSortingEnabled();
	if (sorting)
	{
		// Turn off sorting while we populate the table.
		m_pRealTable->setSortingEnabled(false);
	}

	while (m_pProfilesEnum[i].name != NULL)
	{
		m_pRealTable->insertRow(i);
		newItem = new QTableWidgetItem(QString(m_pProfilesEnum[i].name), 0);
		m_pRealTable->setItem(i, 0, newItem);

	  temp = m_pProfilesEnum[i].name;
		if (m_pSupplicant->getConfigProfile(temp, &myProfile, true))
		{
			m_pSupplicant->getTunnelNames(myProfile->method, outer, inner);

			newItem = new QTableWidgetItem(outer, 0);
			m_pRealTable->setItem(i, 1, newItem);

			newItem = new QTableWidgetItem(inner, 0);
			m_pRealTable->setItem(i, 2, newItem);

			m_pSupplicant->freeConfigProfile(&myProfile);
		}

		i++;
	}

	m_pRealTable->setSortingEnabled(sorting);

	m_pRealTable->setCursor(Qt::ArrowCursor);  // okay, back to normal.
}

void ConfigWidgetProfilesTable::slotShowHelp()
{
	HelpWindow::showPage("xsupphelp.html", "xsupprofmain");
}
