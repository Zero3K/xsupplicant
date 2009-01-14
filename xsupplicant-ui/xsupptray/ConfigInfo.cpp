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

#include "stdafx.h"

#include "ConfigInfo.h"
#include "Util.h"
#include "UIPlugins.h"

ConfigInfo::ConfigInfo(QWidget *proxy, conn_enum **ppConnEnum, profile_enum **ppProfEnum, trusted_servers_enum **ppTSEnum, Emitter *e, XSupCalls *sup, NavPanel *pPanel, UIPlugins *pPlugins, QWidget *parent):
	m_pRealWidget(proxy), m_ppConnEnum(ppConnEnum), m_ppProfileEnum(ppProfEnum), m_ppTrustedServersEnum(ppTSEnum), m_pEmitter(e), m_pSupplicant(sup), m_pParent(parent), m_pPlugins(pPlugins), m_pNavPanel(pPanel)
{
	m_bHaveClose = false;
	m_bHaveHelp = false;

	m_pStackedWidget = NULL;
}

ConfigInfo::~ConfigInfo()
{
	 Util::myDisconnect(this, SIGNAL(signalParentClose()), m_pParent, SIGNAL(close()));
 	 Util::myDisconnect(m_pSaveButton, SIGNAL(clicked()), this, SIGNAL(signalSaveClicked()));

	if (m_bHaveClose)
	{
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), this, SLOT(slotClose()));
	}

	if (m_pHelpButton != NULL)
	{
		Util::myDisconnect(m_pHelpButton, SIGNAL(clicked()), this, SIGNAL(signalHelpClicked()));
	}

	if (m_pStackedWidget != NULL)
	{
		delete m_pStackedWidget;
		m_pStackedWidget = NULL;
	}
}

bool ConfigInfo::attach()
{
	QStackedWidget *m_pWidget;

	m_pWidget = qFindChild<QStackedWidget*>(m_pRealWidget, "widgetStackConfig");
	if (m_pWidget == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate a QStackedWidget named 'widgetStackConfig'."));
		return false;
	}

	 m_pSaveButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonSave");

	 if (m_pSaveButton == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("The configuration form doesn't have a 'buttonSave' defined."));
		 return false;
	 }

	 m_pHelpButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonHelp");
	 // Not worried if this button isn't there.

	 if (m_pHelpButton != NULL)
	 {
		 m_bHaveHelp = true;
		 Util::myConnect(m_pHelpButton, SIGNAL(clicked()), this, SIGNAL(signalHelpClicked()));
	 }

	 m_pCloseButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonClose");
	// Not worried if this button isn't there.

	 if (m_pCloseButton != NULL)
	 {
		m_bHaveClose = true;
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), this, SLOT(slotClose()));
	 }

	 Util::myConnect(this, SIGNAL(signalParentClose()), m_pParent, SIGNAL(close()));

	 Util::myConnect(m_pSaveButton, SIGNAL(clicked()), this, SIGNAL(signalSaveClicked()));

	 m_pSaveButton->setEnabled(false);  // We start with nothing that is saveable connected.

 	 m_pStackedWidget = new ConfigStackedWidget(m_pWidget, m_ppConnEnum, m_ppProfileEnum, m_ppTrustedServersEnum, m_pEmitter, m_pSupplicant, m_pNavPanel, m_pPlugins, this);
	 if ((m_pStackedWidget == NULL) || (m_pStackedWidget->attach() != true)) return false;

	 return true;
}

void ConfigInfo::slotClose()
{
	m_pStackedWidget->close();
	emit signalParentClose();
}

void ConfigInfo::slotSetSaveBtn(bool enabled)
{
	m_pSaveButton->setEnabled(enabled);
}

