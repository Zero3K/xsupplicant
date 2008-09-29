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
#include <QTreeWidgetItem>
#include "NavPanel.h"
#include "ConfigWidgetEditProfile.h"
#include "Util.h"

ConfigWidgetEditProfile::ConfigWidgetEditProfile(QWidget *pRealWidget, QString profName, XSupCalls *xsup, NavPanel *pPanel, UIPlugins *pPlugins, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pParent(parent), m_pSupplicant(xsup), m_originalProfName(profName), m_pPlugins(pPlugins), m_pNavPanel(pPanel)
{
	m_pTabsWidget = NULL;

	m_pProfile = NULL;

	m_bChangedData = false;
	m_bNewProfile = false;
	m_bProfileRenamed = false;
}

ConfigWidgetEditProfile::~ConfigWidgetEditProfile()
{
	if(m_pTabsWidget != NULL)
	{
		delete m_pTabsWidget;
		m_pTabsWidget = NULL;
	}
}

void ConfigWidgetEditProfile::detach()
{
	if (m_pProfNameEdit != NULL)
	{
		Util::myDisconnect(m_pProfNameEdit, SIGNAL(textChanged(const QString &)), this, SLOT(slotProfileRenamed(const QString &)));
	}

	Util::myDisconnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myDisconnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));

	Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	Util::myDisconnect(m_pEapType, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(slotChangeEAPType(const QString &)));

	// Make sure the tabs widget detaches itself before we delete it.
	// This helps clean up the plugins.
	// Qt connections should be handled this way in the future, too.
	if(m_pTabsWidget != NULL)
	{
		m_pTabsWidget->detach();
	}
}

bool ConfigWidgetEditProfile::attach()
{
	m_pProfNameEdit = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldProfileName");
	if (m_pProfNameEdit == NULL)
	{
		QMessageBox::critical(m_pRealWidget, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFieldProfileName'."));
		return false;
	}

	m_pEapType = qFindChild<QComboBox*>(m_pRealWidget, "dataComboEAPTypes");
	if (m_pEapType == NULL)
	{
		QMessageBox::critical(m_pRealWidget, tr("Form Design Error"), tr("Unable to locate the QComboBox called 'dataComboEAPTypes'."));
		return false;
	}

	updateWindow();

	m_pTabsWidget = new ConfigProfileTabs(m_pRealWidget, m_pSupplicant, m_pProfile, this, m_pPlugins);

	if ((m_pTabsWidget == NULL) || (m_pTabsWidget->attach() == false)) return false;

	Util::myConnect(m_pProfNameEdit, SIGNAL(textChanged(const QString &)), this, SLOT(slotProfileRenamed(const QString &)));

	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myConnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));

	// Connection signals for the EAP selection combo box.
	Util::myConnect(m_pEapType, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(slotChangeEAPType(const QString &)));

	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	if (m_bNewProfile)
	{
		emit signalSetSaveBtn(true);
	}
	else
	{
		emit signalSetSaveBtn(false);
	}

	return true;
}

void ConfigWidgetEditProfile::getPageName(QString &name)
{
	name = m_pProfNameEdit->text();
}

bool ConfigWidgetEditProfile::newItem()
{
		// This is a new server configuration.
		m_bNewProfile = true;
		m_bChangedData = true;

		return true;
}

void ConfigWidgetEditProfile::updateWindow()
{
	int index = 0;
	QString temp;

	if (m_pProfile != NULL)
	{
		m_pSupplicant->freeConfigProfile(&m_pProfile);
		m_pProfile = NULL;
	}

	if (m_bNewProfile)
	{
	  temp = "New Profile";
		if (m_pSupplicant->createNewProfile(temp, &m_pProfile) != true)
		{
			QMessageBox::critical(m_pRealWidget, tr("New Profile"), tr("There was an error attempting to create a new profile."));
			m_pProfile = NULL;
			return;
		}

		m_pNavPanel->addItem(NavPanel::PROFILES_ITEM, QString(m_pProfile->name));

		m_originalProfName = QString(m_pProfile->name);
		m_lastProfName = QString(m_pProfile->name);

		// Set PEAP as our default EAP type.
	    index = m_pEapType->findText("EAP-PEAP");
		m_pEapType->setCurrentIndex(index);
	}
	else if (m_pSupplicant->getConfigProfile(m_originalProfName, &m_pProfile, true) == true)
	{
		m_lastProfName = m_originalProfName;

		switch (m_pProfile->method->method_num)
		{
		case EAP_TYPE_MD5:
		    index = m_pEapType->findText("EAP-MD5");

			m_pEapType->setCurrentIndex(index);
			break;

		case EAP_TYPE_PEAP:
		    index = m_pEapType->findText("EAP-PEAP");

			m_pEapType->setCurrentIndex(index);
			break;

		case EAP_TYPE_TTLS:
		    index = m_pEapType->findText("EAP-TTLS");

			m_pEapType->setCurrentIndex(index);
			break;

		case EAP_TYPE_SIM:
			index = m_pEapType->findText("EAP-SIM");

			m_pEapType->setCurrentIndex(index);
			break;

		case EAP_TYPE_AKA:
			index = m_pEapType->findText("EAP-AKA");

			m_pEapType->setCurrentIndex(index);
			break;

		default:
			QMessageBox::critical(m_pRealWidget, tr("Unknown EAP Method"), tr("You selected an EAP method we know nothing about!"));
			break;
		}
	}

	if (m_pProfile != NULL) m_pProfNameEdit->setText(QString(m_pProfile->name));
}


void ConfigWidgetEditProfile::slotDataChanged()
{
	m_bChangedData = true;
	emit signalSetSaveBtn(true);
}

bool ConfigWidgetEditProfile::save()
{
	config_profiles *pNewProfile = NULL;
	QString temp;

	if (m_pProfNameEdit->text() == "")
	{
		QMessageBox::critical(m_pRealWidget, tr("Profile Name Error"), tr("You must specify a valid profile name before attempting to save."));
		return false;
	}

	temp = m_pProfNameEdit->text();
	if ((m_originalProfName != m_lastProfName) && (m_pSupplicant->getConfigProfile(temp, &pNewProfile, false) == true))
	{
		QMessageBox::critical(m_pRealWidget, tr("Profile Exists"), tr("The profile '%1' already exists in the configuration.  Please select a different name.").arg(m_pProfNameEdit->text()));
		return false;
	}

	if (m_pTabsWidget != NULL)
	{
		m_pTabsWidget->save();
	}

	m_pProfile->name = _strdup(m_pProfNameEdit->text().toAscii());

	// If the server was renamed, then rename it first, then update the config, and write it.
	if ((m_bProfileRenamed) && (QString(m_pProfile->name) != m_originalProfName))
	{
	  temp = m_pProfile->name;
		if (m_pSupplicant->renameProfile(m_originalProfName, temp) == false)
			return false;

		m_bProfileRenamed = false;  // We are done.
	}

	if (m_pSupplicant->setConfigProfile(m_pProfile) == true)
	{
		if (m_pSupplicant->writeConfig() == true)
		{
			m_originalProfName = m_lastProfName;
			m_bChangedData = false;
			m_bNewProfile = false;
			emit signalSetSaveBtn(false);

			return true;
		}
	}

	return false;
}

bool ConfigWidgetEditProfile::dataChanged()
{
	return m_bChangedData;
}

void ConfigWidgetEditProfile::slotProfileRenamed(const QString &newValue)
{
	if (m_bNewProfile == false)
	{
		m_bProfileRenamed = true;
	}
	
	slotDataChanged();

	m_pNavPanel->renameItem(NavPanel::SELECTED_ITEM, m_lastProfName, newValue);
	m_lastProfName = newValue;
}

void ConfigWidgetEditProfile::discard()
{
	m_bChangedData = false;
	m_lastProfName = "";

	if (m_bNewProfile)
	{
		m_pNavPanel->removeItem(NavPanel::PROFILES_ITEM, m_pProfNameEdit->text());
	}
	else
	{
		m_pNavPanel->renameItem(NavPanel::PROFILES_ITEM, m_pProfNameEdit->text(), m_originalProfName);
	}
}

void ConfigWidgetEditProfile::slotChangeEAPType(const QString &newEAPName)
{
	m_pTabsWidget->setPhase1EAPType(newEAPName);

	emit signalDataChanged();
}

void ConfigWidgetEditProfile::slotShowHelp()
{
	m_pTabsWidget->showHelp();
}
