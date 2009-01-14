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

#include <QWidget>

#include "stdafx.h"
#include "ConfigWidgetConnectionsTable.h"
#include "Util.h"
#include "FormLoader.h"
#include "NavPanel.h"
#include "PreferredConnections.h"
#include "helpbrowser.h"

ConfigWidgetConnectionsTable::ConfigWidgetConnectionsTable(QWidget *pRealWidget, XSupCalls *pSupplicant, conn_enum *pConnectionsEnum, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pParent(parent), m_pConnectionsEnum(pConnectionsEnum), m_pSupplicant(pSupplicant)
{
	m_bConnected = false;
	m_pPreferred = NULL;

	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), parent, SIGNAL(signalSetSaveBtn(bool)));

	// Make sure the save button is disabled.
	emit signalSetSaveBtn(false);
}

ConfigWidgetConnectionsTable::~ConfigWidgetConnectionsTable()
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
//		Util::myDisconnect(this, SIGNAL(signalNavChangeSelected(int, const QString &)), m_pParent, SIGNAL(signalNavChangeSelected(int, const QString &)));
		Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));
	}
}

void ConfigWidgetConnectionsTable::detach()
{
}

bool ConfigWidgetConnectionsTable::attach()
{
	m_pRealTable = qFindChild<QTableWidget*>(m_pRealWidget, "dataTableConnections");
	if (m_pRealTable == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to find the QTableWidget called 'dataTableConnections'."));
		return false;
	}

	m_pPriority = qFindChild<QPushButton*>(m_pRealWidget, "buttonPriority");
	if (m_pPriority == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to find the QPushButton called 'buttonPriority'."));
		return false;
	}

	updateWindow();

	Util::myConnect(m_pRealTable, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(slotDoubleClicked(int, int)));
	Util::myConnect(this, SIGNAL(signalSetWidget(int, const QString &)), m_pParent, SLOT(slotSetWidget(int, const QString &)));
	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	Util::myConnect(m_pPriority, SIGNAL(clicked()), this, SLOT(slotPriorityClicked()));

	m_bConnected = true;

	return true;
}

void ConfigWidgetConnectionsTable::updateWindow()
{
	int i = 0;
	int t = 0;
	QTableWidgetItem *newItem = NULL;
	QPixmap *p;
	QString myString;
	bool sorting = false;
	QLabel *myLabel = NULL;

	i = m_pRealTable->rowCount();
	for (t = 0; t < i; t++)
	{
		m_pRealTable->removeRow(0);
	}

	i = 0;

	m_pRealTable->setCursor(Qt::WaitCursor);   // This may take a second.
	
	m_pRealTable->horizontalHeader()->setHighlightSections(false);   // Don't "push in" the header.
	m_pRealTable->verticalHeader()->setHighlightSections(false);     // Ditto for the vertical header.
	        
	// don't allow user to re-size columns
	m_pRealTable->horizontalHeader()->setResizeMode(QHeaderView::Fixed);
	
	// let the first column take up as much space as possible
	m_pRealTable->horizontalHeader()->setResizeMode(0, QHeaderView::Stretch);
	m_pRealTable->horizontalHeaderItem(0)->setText(tr("Connection"));
	
	m_pRealTable->horizontalHeader()->resizeSection(1,70);
	m_pRealTable->horizontalHeaderItem(1)->setText(tr("Adapter"));
	
	m_pRealTable->horizontalHeader()->resizeSection(2,70);
	m_pRealTable->horizontalHeaderItem(2)->setText(tr("Priority"));
	
	m_pRealTable->horizontalHeader()->resizeSection(3,180);
	m_pRealTable->horizontalHeaderItem(3)->setText(tr("Secure"));

	if (m_pConnectionsEnum == NULL) return;

	sorting = m_pRealTable->isSortingEnabled();

	if (sorting)
	{
		// Turn off sorting while we populate the table.
		m_pRealTable->setSortingEnabled(false);
	}

	while (m_pConnectionsEnum[i].name != NULL)
	{
		m_pRealTable->insertRow(i);
		newItem = new QTableWidgetItem(QString(m_pConnectionsEnum[i].name), 0);
		m_pRealTable->setItem(i, 0, newItem);

		if (m_pConnectionsEnum[i].ssid != NULL)
		{
			// Wireless
			p = FormLoader::loadicon("wireless.png");

			myLabel = new QLabel();
			myLabel->setPixmap((*p));
			myLabel->setAlignment(Qt::AlignCenter);
			m_pRealTable->setCellWidget(i, 1, myLabel);
			delete p;
		}
		else
		{
			// Wired
			p = FormLoader::loadicon("wired.png");

			myLabel = new QLabel();
			myLabel->setPixmap((*p));
			myLabel->setAlignment(Qt::AlignCenter);
			m_pRealTable->setCellWidget(i, 1, myLabel);
			delete p;
		}

		if (m_pConnectionsEnum[i].priority == 0xff)
		{
			newItem = new QTableWidgetItem("Manual", 0);
			newItem->setTextAlignment(Qt::AlignCenter);
			m_pRealTable->setItem(i, 2, newItem);
		}
		else
		{
			newItem = new QTableWidgetItem(QString("%1").arg(m_pConnectionsEnum[i].priority));
			newItem->setTextAlignment(Qt::AlignCenter);
			m_pRealTable->setItem(i, 2, newItem);
		}

		if (m_pConnectionsEnum[i].encryption == CONNECTION_ENC_ENABLED)
		{
			p = FormLoader::loadicon("lockedstate.png");
		}
		else
		{
			p = FormLoader::loadicon("unlockedstate.png");
		}

		myString = "";

		if (m_pConnectionsEnum[i].ssid != NULL)
		{
			switch (m_pConnectionsEnum[i].assoc_type)
			{
			default:
			case ASSOC_TYPE_UNKNOWN:
				myString = myString + tr("Assoc : Unknown  ");
				break;

			case ASSOC_TYPE_OPEN:
				if  ((m_pConnectionsEnum[i].encryption == CONNECTION_ENC_ENABLED) && (m_pConnectionsEnum[i].auth_type != AUTH_EAP))
				{
					myString = myString + tr("Assoc : Static WEP  ");
				}
				else
				{
					myString = myString + tr("Assoc : Open  ");
				}
				break;

			case ASSOC_TYPE_SHARED:
				myString = myString + tr("Assoc : Shared Key  ");
				break;

			case ASSOC_TYPE_LEAP:
				myString = myString + tr("Assoc : Cisco's Network EAP  ");
				break;

			case ASSOC_TYPE_WPA1:
				myString = myString + tr("Assoc : WPA  ");
				break;

			case ASSOC_TYPE_WPA2:
				myString = myString + tr("Assoc : WPA2  ");
				break;
			}
		}

		switch (m_pConnectionsEnum[i].auth_type)
		{
		default:
		case AUTH_UNKNOWN:
			myString = myString + tr("Auth : Unknown ");
			break;

		case AUTH_NONE:
			myString = myString + tr("Auth : None ");
			break;

		case AUTH_PSK:
			myString = myString + tr("Auth : PSK");
			break;

		case AUTH_EAP:
			myString = myString + tr("Auth : EAP");
			break;
		}

		newItem = new QTableWidgetItem(QIcon((*p)), myString, 0);
		newItem->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
		m_pRealTable->setItem(i, 3, newItem);

		delete p;

		i++;
	}

	// Set sorting back to how it was.
	m_pRealTable->setSortingEnabled(sorting);

	m_pRealTable->setCursor(Qt::ArrowCursor);  // okay, back to normal.
}

void ConfigWidgetConnectionsTable::slotDoubleClicked(int row, int)
{
	QTableWidgetItem *myItem = NULL;

	// We only care about the row.
	myItem = m_pRealTable->item(row, 0);
	
	emit signalSetWidget(NavPanel::CONNECTIONS_ITEM, myItem->text());
}

void ConfigWidgetConnectionsTable::slotShowHelp()
{
	HelpWindow::showPage("xsupphelp.html", "xsupconnmain");
}

void ConfigWidgetConnectionsTable::slotPriorityCleanup()
{
	Util::myDisconnect(m_pPreferred, SIGNAL(close()), this, SLOT(slotPriorityCleanup()));

	delete m_pPreferred;
	m_pPreferred = NULL;

	updateWindow();
}

void ConfigWidgetConnectionsTable::slotPriorityClicked()
{
	if (m_pPreferred == NULL)
	{
		m_pPreferred = new PreferredConnections((*m_pSupplicant), this, m_pRealWidget->window());
		if (m_pPreferred != NULL)
		{
			if (m_pPreferred->attach() == false)
				return;
		}

		Util::myConnect(m_pPreferred, SIGNAL(close()), this, SLOT(slotPriorityCleanup()));

		m_pPreferred->show();
	}
}
