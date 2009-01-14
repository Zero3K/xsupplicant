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

#ifdef WINDOWS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "stdafx.h"
#include "ConfigWidgetEditAdvancedSettings.h"
#include "Util.h"
#include "helpbrowser.h"

ConfigWidgetEditAdvancedSettings::ConfigWidgetEditAdvancedSettings(QWidget *pRealWidget, XSupCalls *xsup, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pParent(parent), m_pSupplicant(xsup)
{
	m_pAssocTimeout = NULL;
	m_pScanTimeout = NULL;
	m_pResetValues = NULL;
	m_pGlobals = NULL;
	m_pDisconnectOnLogoff = NULL;
	m_pPassiveScanInterval = NULL;
	m_pPMKSACacheTimeout = NULL;
	m_pPMKSACacheRefresh = NULL;

	m_bChangedData = false;
}

ConfigWidgetEditAdvancedSettings::~ConfigWidgetEditAdvancedSettings()
{
	if (m_pAssocTimeout != NULL)
	{
		Util::myDisconnect(m_pAssocTimeout, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pScanTimeout != NULL)
	{
		Util::myDisconnect(m_pScanTimeout, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pResetValues != NULL)
	{
		Util::myDisconnect(m_pResetValues, SIGNAL(clicked()), this, SLOT(slotResetValues()));
	}

	if (m_pDefaultWired != NULL)
	{
		Util::myDisconnect(m_pDefaultWired, SIGNAL(currentIndexChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pCheckOtherSupplicants != NULL)
	{
		Util::myDisconnect(m_pCheckOtherSupplicants, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pDisconnectOnLogoff != NULL)
	{
		Util::myDisconnect(m_pDisconnectOnLogoff, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pPassiveScanInterval != NULL)
	{
		Util::myDisconnect(m_pPassiveScanInterval, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pPMKSACacheTimeout != NULL)
	{
		Util::myDisconnect(m_pPMKSACacheTimeout, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pPMKSACacheRefresh != NULL)
	{
		Util::myDisconnect(m_pPMKSACacheRefresh, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pAllowMACont != NULL)
	{
		Util::myDisconnect(m_pAllowMACont, SIGNAL(clicked()), this, SLOT(slotDataChanged()));
	}

	Util::myDisconnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));
}

bool ConfigWidgetEditAdvancedSettings::attach()
{
	m_pScanTimeout = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldAdvancedSettingsScanTimeout");

	m_pAssocTimeout = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldAdvancedSettingsAssociationTimeout");

	m_pResetValues = qFindChild<QPushButton*>(m_pRealWidget, "buttonAdvancedSettingsReset");

	m_pDefaultWired = qFindChild<QComboBox*>(m_pRealWidget, "dataComboAdvancedSettingsWiredDefault");

	m_pPassiveScanInterval = qFindChild<QSpinBox*>(m_pRealWidget, "dataFieldAdvancedSettingsPassiveScanInterval");

	m_pPMKSACacheTimeout = qFindChild<QSpinBox*>(m_pRealWidget, "dataFieldAdvancedSettingsPMKSACacheTimeout");

	m_pPMKSACacheRefresh = qFindChild<QSpinBox*>(m_pRealWidget, "dataFieldAdvancedSettingsPMKSACacheRefresh");

	m_pCheckOtherSupplicants = qFindChild<QCheckBox*>(m_pRealWidget, "dataCheckboxAdvancedSettignsRunCheckOnStartup");

	m_pDisconnectOnLogoff = qFindChild<QCheckBox*>(m_pRealWidget, "logoffDisconnect");

	m_pWirelessOnly = qFindChild<QCheckBox*>(m_pRealWidget, "manageWireless");

	m_pAllowMACont = qFindChild<QCheckBox*>(m_pRealWidget, "checkBoxAllowMACont");

	updateWindow();

	if (m_pWirelessOnly != NULL)
	{
		Util::myConnect(m_pWirelessOnly, SIGNAL(clicked()), this, SLOT(slotDataChanged()));
	}

	if (m_pScanTimeout != NULL)
	{
		Util::myConnect(m_pScanTimeout, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

		m_pScanTimeout->setValidator(new QIntValidator(5, 32000, m_pScanTimeout));
	}

	if (m_pAssocTimeout != NULL)
	{
		Util::myConnect(m_pAssocTimeout, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

		m_pAssocTimeout->setValidator(new QIntValidator(5, 32000, m_pAssocTimeout));
	}

	if (m_pDefaultWired != NULL)
	{
		Util::myConnect(m_pDefaultWired, SIGNAL(currentIndexChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pResetValues != NULL)
	{
		Util::myConnect(m_pResetValues, SIGNAL(clicked()), this, SLOT(slotResetValues()));
	}

	if (m_pCheckOtherSupplicants != NULL)
	{
		Util::myConnect(m_pCheckOtherSupplicants, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pDisconnectOnLogoff != NULL)
	{
		Util::myConnect(m_pDisconnectOnLogoff, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pPassiveScanInterval != NULL)
	{
		Util::myConnect(m_pPassiveScanInterval, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pPMKSACacheTimeout != NULL)
	{
		Util::myConnect(m_pPMKSACacheTimeout, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pPMKSACacheRefresh != NULL)
	{
		Util::myConnect(m_pPMKSACacheRefresh, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pAllowMACont != NULL)
	{
		Util::myConnect(m_pAllowMACont, SIGNAL(clicked()), this, SLOT(slotDataChanged()));
	}

	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	emit signalSetSaveBtn(false);

	return true;
}

void ConfigWidgetEditAdvancedSettings::getPageName(QString &name)
{
	name = tr("Settings");
}

void ConfigWidgetEditAdvancedSettings::updateWindow()
{
	char tempStr[30];
	int tempVal = 0;

	if (m_pGlobals != NULL)
	{
		m_pSupplicant->freeConfigGlobals(&m_pGlobals);
		m_pGlobals = NULL;
	}

	m_pSupplicant->getConfigGlobals(&m_pGlobals, true);

	if (m_pGlobals->assoc_timeout == 0)
	{
		sprintf((char *)&tempStr, "%d", ASSOCIATION_TIMEOUT);         
	}
	else
	{
		sprintf((char *)&tempStr, "%d", m_pGlobals->assoc_timeout);
		
	}

	if (m_pAssocTimeout != NULL) m_pAssocTimeout->setText(QString(tempStr));

	if (m_pGlobals->active_timeout == 0)
	{
		sprintf((char *)&tempStr, "%d", RESCAN_TIMEOUT);
	}
	else
	{
		sprintf((char *)&tempStr, "%d", m_pGlobals->active_timeout);	
	}

	if (m_pScanTimeout != NULL) m_pScanTimeout->setText(QString(tempStr));

	if (m_pGlobals->passive_timeout == 0)
	{
		tempVal = PASSIVE_TIMEOUT;
	}
	else
	{
		tempVal = m_pGlobals->passive_timeout;
	}

	if (m_pPassiveScanInterval != NULL) m_pPassiveScanInterval->setValue(tempVal);

	if (m_pGlobals->pmksa_age_out == 0)
	{
		tempVal = PMKSA_DEFAULT_AGEOUT_TIME;
	}
	else
	{
		tempVal = m_pGlobals->pmksa_age_out;
	}

	if (m_pPMKSACacheTimeout != NULL) m_pPMKSACacheTimeout->setValue(tempVal);

	if (m_pGlobals->pmksa_cache_check == 0)
	{
		tempVal = PMKSA_CACHE_REFRESH;
	}
	else
	{
		tempVal = m_pGlobals->pmksa_cache_check;
	}

	if (m_pPMKSACacheRefresh != NULL) m_pPMKSACacheRefresh->setValue(tempVal);

	if (m_pCheckOtherSupplicants != NULL)
	{
		if ((m_pGlobals->flags & CONFIG_GLOBALS_DETECT_ON_STARTUP) == CONFIG_GLOBALS_DETECT_ON_STARTUP)
		{
			m_pCheckOtherSupplicants->setChecked(true);
		}
		else
		{
			m_pCheckOtherSupplicants->setChecked(false);
		}
	}

	if (m_pAllowMACont != NULL)
	{
		if ((m_pGlobals->flags & CONFIG_GLOBALS_ALLOW_MA_REMAIN) == CONFIG_GLOBALS_ALLOW_MA_REMAIN)
		{
			m_pAllowMACont->setChecked(true);
		}
		else
		{
			m_pAllowMACont->setChecked(false);
		}
	}

	if (m_pDisconnectOnLogoff != NULL)
	{
		if ((m_pGlobals->flags & CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF) == CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF)
		{
			m_pDisconnectOnLogoff->setChecked(true);
		}
		else
		{
			m_pDisconnectOnLogoff->setChecked(false);
		}
	}

	updateWiredList();
}

void ConfigWidgetEditAdvancedSettings::updateWiredList()
{
	int i = 0;
	conn_enum *m_pCons = NULL;
	QString m_netName;
	int_config_enum *m_pInts = NULL;

	if (m_pDefaultWired == NULL) return;

	while (m_pDefaultWired->itemText(1) != "")
	{
		m_pDefaultWired->removeItem(1);
	}

	// Build our list.
	if (m_pSupplicant->enumAndSortConnections(&m_pCons, true) == true)
	{
		while (m_pCons[i].name != NULL)
		{
			if (m_pCons[i].ssid == NULL)
			{
				// This should be a wired connection.
				m_netName = m_pCons[i].name;
				m_pDefaultWired->addItem(m_netName, 0); 
			}

			i++;
		}

		m_pSupplicant->freeEnumConnections(&m_pCons);
	}

	i = 0;

	// Then select the correct connection.
	if (m_pSupplicant->enumConfigInterfaces(&m_pInts, true) == true)
	{
		while ((m_pInts[i].desc != NULL) && (m_pInts[i].default_connection == NULL)) i++;

		if (m_pInts[i].default_connection != NULL)
		{
			// We have a default connection set up.  So highlight it.
			m_pDefaultWired->setCurrentIndex(m_pDefaultWired->findText(QString(m_pInts[i].default_connection)));
		}

		m_pSupplicant->freeEnumStaticInt(&m_pInts);
	}
}

void ConfigWidgetEditAdvancedSettings::slotResetValues()
{
	char tempStr[30];

	if (m_pAssocTimeout != NULL)
	{
		sprintf((char *)&tempStr, "%d", ASSOCIATION_TIMEOUT);         
		m_pAssocTimeout->setText(QString(tempStr));
	}

	if (m_pScanTimeout != NULL)
	{
		sprintf((char *)&tempStr, "%d", RESCAN_TIMEOUT);
		m_pScanTimeout->setText(QString(tempStr));
	}

	if (m_pPassiveScanInterval != NULL)
	{
		m_pPassiveScanInterval->setValue(PASSIVE_TIMEOUT);
	}

	if (m_pAllowMACont != NULL)
	{
		m_pAllowMACont->setChecked(false);
	}

	if (m_pPMKSACacheTimeout != NULL)
	{
		m_pPMKSACacheTimeout->setValue(PMKSA_DEFAULT_AGEOUT_TIME);
	}

	if (m_pPMKSACacheRefresh != NULL)
	{
		m_pPMKSACacheRefresh->setValue(PMKSA_CACHE_REFRESH);
	}

	if (m_pCheckOtherSupplicants != NULL)
	{
		m_pCheckOtherSupplicants->setChecked(true);
	}

	if (m_pDisconnectOnLogoff != NULL)
	{
		m_pDisconnectOnLogoff->setChecked(true);
	}

	if (m_pDefaultWired != NULL)
	{
		m_pDefaultWired->setCurrentIndex(0);
	}
}

void ConfigWidgetEditAdvancedSettings::slotDataChanged()
{
	m_bChangedData = true;
	emit signalSetSaveBtn(true);
}

bool ConfigWidgetEditAdvancedSettings::clearWiredConnectionDefaults()
{
	int i = 0;
	int_config_enum *m_pInts = NULL;
	config_interfaces *m_pConfigInt = NULL;
	QString m_intDesc;
	bool retval = true;

	// Then select the correct connection.
	if (m_pSupplicant->enumConfigInterfaces(&m_pInts, true) == true)
	{
		while ((m_pInts[i].desc != NULL) && (m_pInts[i].default_connection == NULL)) i++;

		if (m_pInts[i].default_connection != NULL)
		{
			// We have a default connection set up.  So clear it out.
			m_intDesc = m_pInts[i].desc;
			if (m_pSupplicant->getConfigInterface(m_intDesc, &m_pConfigInt, true) == true)
			{
				if (m_pConfigInt->default_connection != NULL) 
				{
					free(m_pConfigInt->default_connection);
					m_pConfigInt->default_connection = NULL;
				}

				if (m_pSupplicant->setConfigInterface(m_pConfigInt) == false)
				{
					retval = false;
				}

				m_pSupplicant->freeConfigInterface(&m_pConfigInt);
			}
			else
			{
				retval = false;
			}
		}

		m_pSupplicant->freeEnumStaticInt(&m_pInts);
	}

	return retval;
}

bool ConfigWidgetEditAdvancedSettings::saveWiredConnectionDefault()
{
	config_connection *m_pConn = NULL;
	config_profiles *m_pProf = NULL;
	config_interfaces *m_pInt = NULL;
	QString m_connName;
	QString m_intDesc;
	QString m_profName;
	QString username;
	QString password;
	bool retval = false;

	m_connName = m_pDefaultWired->currentText();
	if (m_connName == tr("<None>"))
	{
		return clearWiredConnectionDefaults();
	}
	else
	{
		if (m_pSupplicant->getConfigConnection(CONFIG_LOAD_GLOBAL, m_connName, &m_pConn, true) == true)
		{
			// We got the connection information, now make sure it isn't a wireless connection.
			if (m_pConn->ssid == NULL)
			{
				if (m_pInt->default_connection != NULL)
				{
					free(m_pInt->default_connection);
					m_pInt->default_connection = NULL;
				}

				// Now, verify that the connection is complete enough to connect automatically.
				// XXX - This will need to be expanded when we expand default connections to work on wireless
				// interfaces.
				if (m_pConn->profile == NULL)
				{
					QMessageBox::information(this, tr("Connection Configuration Problem"), tr("This connection doesn't "
						"have a profile bound to it.  You won't be able to automatically connect!"));
				}
				else
				{
					m_profName = m_pConn->profile;
					if (m_pSupplicant->getConfigProfile(CONFIG_LOAD_GLOBAL, m_profName, &m_pProf, false) == true)
					{
						m_pSupplicant->getUserAndPasswordFromProfile(m_pProf, username, password);		

						if (((username == "") && (m_pProf->identity == NULL)) || (password == ""))
						{
							QMessageBox::information(this, tr("Username/Password Problem"), tr("The username and/or "
								"password is not set for profile %1.  Automatic connection is not possible unless they "
								"are saved in your configuration!").arg(m_pConn->profile));
							m_pDefaultWired->setCurrentIndex(0);
							return false;
						}
					}
					else
					{
						QMessageBox::information(this, tr("Connection Configuration Problem"), tr("This profile this "
							"connection uses doesn't seem to exist.  Please check your configuration."));
					}
				}

				if ((m_connName != "") && (m_connName != tr("<None>")))
				{
					m_pInt->default_connection = _strdup(m_connName.toAscii());
				}

				if (m_pSupplicant->setConfigInterface(m_pInt) == true)
				{
					retval = true;
				}
			}

		}
	}

	if (m_pInt != NULL)
	{
		m_pSupplicant->freeConfigInterface(&m_pInt);
	}

	if (m_pConn != NULL)
	{
		m_pSupplicant->freeConfigConnection(&m_pConn);
	}

	return retval;
}

bool ConfigWidgetEditAdvancedSettings::save()
{
	if (m_pWirelessOnly != NULL)
	{
		if (m_pWirelessOnly->isChecked())
		{
			m_pGlobals->flags |= CONFIG_GLOBALS_WIRELESS_ONLY;
		}
		else
		{
			m_pGlobals->flags &= (~CONFIG_GLOBALS_WIRELESS_ONLY);
		}
	}

	if (m_pAllowMACont != NULL)
	{
		if (m_pAllowMACont->isChecked())
		{
			m_pGlobals->flags |= CONFIG_GLOBALS_ALLOW_MA_REMAIN;
		}
		else
		{
			m_pGlobals->flags &= (~CONFIG_GLOBALS_ALLOW_MA_REMAIN);
		}
	}

	if (m_pAssocTimeout != NULL)
	{
		m_pGlobals->assoc_timeout = atoi(m_pAssocTimeout->text().toAscii());
	}

	if (m_pScanTimeout != NULL)
	{
		m_pGlobals->active_timeout = atoi(m_pScanTimeout->text().toAscii());
	}

	if (m_pPassiveScanInterval != NULL)
	{
		m_pGlobals->passive_timeout = m_pPassiveScanInterval->value();
	}

	if (m_pPMKSACacheTimeout != NULL)
	{
		m_pGlobals->pmksa_age_out = m_pPMKSACacheTimeout->value();
	}

	if (m_pPMKSACacheRefresh != NULL)
	{
		m_pGlobals->pmksa_cache_check = m_pPMKSACacheRefresh->value();
	}

	if (m_pCheckOtherSupplicants != NULL)
	{
		if (m_pCheckOtherSupplicants->isChecked())
		{
			m_pGlobals->flags |= CONFIG_GLOBALS_DETECT_ON_STARTUP;
		}
		else
		{
			m_pGlobals->flags &= (~CONFIG_GLOBALS_DETECT_ON_STARTUP);
		}
	}

	if (m_pDisconnectOnLogoff != NULL)
	{
		if (m_pDisconnectOnLogoff->isChecked())
		{
			m_pGlobals->flags |= CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF;
		}
		else
		{
			m_pGlobals->flags &= (~CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF);
		}
	}

	if (saveWiredConnectionDefault() == false) return false;

	if (m_pSupplicant->setConfigGlobals(m_pGlobals) == true)
	{
		if (m_pSupplicant->writeConfig(CONFIG_LOAD_GLOBAL) == true)
		{
			m_bChangedData = false;
			emit signalSetSaveBtn(false);

			return true;
		}
	}

	return false;
}

bool ConfigWidgetEditAdvancedSettings::dataChanged()
{
	return m_bChangedData;
}

void ConfigWidgetEditAdvancedSettings::slotShowHelp()
{
	HelpWindow::showPage("xsupphelp.html", "xsupsettings");
}

void ConfigWidgetEditAdvancedSettings::discard()
{
	// Do nothing.
}
