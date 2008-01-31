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

#include "PluginWidget.h"
#include "UIPlugins.h"

PluginWidget::PluginWidget()
{
	m_pProfile = NULL;
	m_pParent  = NULL;
	pluginType = PLUGIN_TYPE_UNKNOWN;
	m_Version  = "";
}

PluginWidget::~PluginWidget()
{
}

bool PluginWidget::save()
{
	QMessageBox::critical(this, tr("Code Error"), tr("Either you didn't override the save member of the PluginWidget class, or you forgot to emit the signalDisableSaveBtn() signal!"));
	return false;
}

bool PluginWidget::dataChanged()
{
	return false;
}

void PluginWidget::discard()
{
	QMessageBox::critical(this, tr("Code Error"), tr("You didn't override the discard member of the PluginWidget class!"));
}

void PluginWidget::setProfile(config_profiles *pProfile)
{
	m_pProfile = pProfile;
}

void PluginWidget::setParent(QWidget *pParent)
{
	m_pParent = pParent;
}

void PluginWidget::pluginDataChanged()
{
	QMessageBox::critical(this, tr("Code Error"), tr("You didn't override the discard member of the PluginWidget class!"));
}

void PluginWidget::setEmitter(Emitter *pEmitter)
{
	m_pEmitter = pEmitter;
}

// This should be removed at some point in the future when we get something less hackish put in place.
void PluginWidget::setEngineVersionString(QString m_version)
{
	m_Version = m_version;
}

/*void PluginWidget::setSupplicant(XSupCalls *pSupplicant)
{
	m_pSupplicant = pSupplicant;
}*/
