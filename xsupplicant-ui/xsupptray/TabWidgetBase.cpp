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

#include <QMessageBox>
#include "TabWidgetBase.h"

TabWidgetBase::TabWidgetBase()
{
}

TabWidgetBase::~TabWidgetBase()
{
}

bool TabWidgetBase::save()
{
	QMessageBox::critical(this, tr("Code Error"), tr("Either you didn't override the save member of the TabWidgetBase class, or you forgot to emit the signalDisableSaveBtn() signal!"));
	return false;
}

bool TabWidgetBase::attach()
{
	QMessageBox::critical(this, tr("Code Error"), tr("You didn't override the attach member of the TabWidgetBase class!"));
	return false;
}

bool TabWidgetBase::dataChanged()
{
	return false;
}

void TabWidgetBase::discard()
{
	QMessageBox::critical(this, tr("Code Error"), tr("You didn't override the discard member of the TabWidgetBase class!"));
}

void TabWidgetBase::pluginDataChanged()
{
	QMessageBox::critical(this, tr("Code Error"), tr("You didn't override the discard member of the TabWidgetBase class!"));
}

int TabWidgetBase::insertTab ( int index, QWidget * widget, const QString & label )
{
	if(m_pProfileTabs != NULL)
	{
		return m_pProfileTabs->insertTab(index, widget, label);
	}
	else
	{
		QMessageBox::critical(this, tr("Error"), tr("Attempted to insert a plugin tab into a NULL parent!"));
	}

	return -1;
}

void TabWidgetBase::removeTab(int index)
{
	if(m_pProfileTabs != NULL)
	{
		m_pProfileTabs->removeTab(index);
	}
	else
	{
		QMessageBox::critical(this, tr("Error"), tr("Attempted to remove a tab from a NULL parent!"));
	}
}


