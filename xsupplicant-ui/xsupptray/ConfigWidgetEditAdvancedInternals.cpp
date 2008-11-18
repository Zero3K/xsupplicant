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

#ifdef WINDOWS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "stdafx.h"
#include "Util.h"
#include "ConfigWidgetEditAdvancedInternals.h"
#include "helpbrowser.h"


ConfigWidgetEditAdvancedInternals::ConfigWidgetEditAdvancedInternals(QWidget *pRealWidget, XSupCalls *xsup, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pParent(parent), m_pSupplicant(xsup)
{
	m_pAuthPeriod = NULL;
	m_pHeldPeriod = NULL;
	m_pIdlePeriod = NULL;
	m_pStaleWepTimeout = NULL;
	m_pMaximumStarts = NULL;
	m_pResetValues = NULL;
	m_pGlobals = NULL;

	m_bChangedData = false;
}

ConfigWidgetEditAdvancedInternals::~ConfigWidgetEditAdvancedInternals()
{
	if (m_pAuthPeriod != NULL)
	{
		Util::myDisconnect(m_pAuthPeriod, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pHeldPeriod != NULL)
	{
		Util::myDisconnect(m_pHeldPeriod, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pIdlePeriod != NULL)
	{
		Util::myDisconnect(m_pIdlePeriod, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pStaleWepTimeout != NULL)
	{
		Util::myDisconnect(m_pStaleWepTimeout, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pMaximumStarts != NULL)
	{
		Util::myDisconnect(m_pMaximumStarts, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));
	}

	if (m_pResetValues != NULL)
	{
		Util::myDisconnect(m_pResetValues, SIGNAL(clicked()), this, SLOT(slotResetValues()));
	}

	Util::myDisconnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));
}

void ConfigWidgetEditAdvancedInternals::getPageName(QString &name)
{
	name = tr("Internals");
}

bool ConfigWidgetEditAdvancedInternals::attach()
{
	m_pAuthPeriod = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldAdvancedInternalsAuthPeriod");

	m_pHeldPeriod = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldAdvancedInternalsHeldPeriod");

	m_pIdlePeriod = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldAdvancedInternalsIdlePeriod");

	m_pStaleWepTimeout = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldAdvancedInternalsStaleWEPKeyTimeout");

	m_pMaximumStarts = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldAdvancedInternalsMaximumStarts");

	m_pResetValues = qFindChild<QPushButton*>(m_pRealWidget, "buttonAdvancedInternalsReset");

	updateWindow();

	if (m_pAuthPeriod != NULL)
	{
		Util::myConnect(m_pAuthPeriod, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

		m_pAuthPeriod->setValidator(new QIntValidator(5, 32000, m_pAuthPeriod));
	}

	if (m_pHeldPeriod != NULL)
	{
		Util::myConnect(m_pHeldPeriod, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

		m_pHeldPeriod->setValidator(new QIntValidator(5, 32000, m_pHeldPeriod));
	}

	if (m_pIdlePeriod != NULL)
	{
		Util::myConnect(m_pIdlePeriod, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

		m_pIdlePeriod->setValidator(new QIntValidator(5, 250, m_pIdlePeriod));
	}

	if (m_pStaleWepTimeout != NULL)
	{
		Util::myConnect(m_pStaleWepTimeout, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

		m_pStaleWepTimeout->setValidator(new QIntValidator(5, 32000, m_pStaleWepTimeout));
	}

	if (m_pMaximumStarts != NULL)
	{
		Util::myConnect(m_pMaximumStarts, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

		m_pMaximumStarts->setValidator(new QIntValidator(1, 32000, m_pMaximumStarts));
	}

	if (m_pResetValues != NULL)
	{
		Util::myConnect(m_pResetValues, SIGNAL(clicked()), this, SLOT(slotResetValues()));
	}

	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));

	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	emit signalSetSaveBtn(false);

	return true;
}

void ConfigWidgetEditAdvancedInternals::updateWindow()
{
	char tempStr[30];

	if (m_pGlobals != NULL)
	{
		m_pSupplicant->freeConfigGlobals(&m_pGlobals);
		m_pGlobals = NULL;
	}

	m_pSupplicant->getConfigGlobals(&m_pGlobals, true);

	if (m_pGlobals->auth_period == 0)
	{
		sprintf((char *)&tempStr, "%d", AUTHENTICATION_TIMEOUT);         
	}
	else
	{
		sprintf((char *)&tempStr, "%d", m_pGlobals->auth_period);
		
	}

	if (m_pAuthPeriod != NULL) m_pAuthPeriod->setText(QString(tempStr));

	if (m_pGlobals->held_period == 0)
	{
		sprintf((char *)&tempStr, "%d", HELD_STATE_TIMEOUT);
	}
	else
	{
		sprintf((char *)&tempStr, "%d", m_pGlobals->held_period);	
	}

	if (m_pHeldPeriod != NULL) m_pHeldPeriod->setText(QString(tempStr));

	if (m_pGlobals->idleWhile_timeout == 0)
	{
		sprintf((char *)&tempStr, "%d", IDLE_WHILE_TIMER);
	}
	else
	{
		sprintf((char *)&tempStr, "%d", m_pGlobals->idleWhile_timeout);
	}

	if (m_pIdlePeriod != NULL) m_pIdlePeriod->setText(QString(tempStr));

	if (m_pGlobals->stale_key_timeout == 0)
	{
		sprintf((char *)&tempStr, "%d", STALE_KEY_WARN_TIMEOUT);
	}
	else
	{
		sprintf((char *)&tempStr, "%d", m_pGlobals->stale_key_timeout);
	}

	if (m_pStaleWepTimeout != NULL) m_pStaleWepTimeout->setText(QString(tempStr));

	if (m_pGlobals->max_starts == 0)
	{
		sprintf((char *)&tempStr, "%d", MAX_STARTS);
	}
	else
	{
		sprintf((char *)&tempStr, "%d", m_pGlobals->max_starts);
	}

	if (m_pMaximumStarts != NULL) m_pMaximumStarts->setText(QString(tempStr));
}

void ConfigWidgetEditAdvancedInternals::slotResetValues()
{
	char tempStr[30];

	if (m_pAuthPeriod != NULL)
	{
		sprintf((char *)&tempStr, "%d", AUTHENTICATION_TIMEOUT);         
		m_pAuthPeriod->setText(QString(tempStr));
	}

	if (m_pHeldPeriod != NULL)
	{
		sprintf((char *)&tempStr, "%d", HELD_STATE_TIMEOUT);
		m_pHeldPeriod->setText(QString(tempStr));
	}

	if (m_pIdlePeriod != NULL)
	{
		sprintf((char *)&tempStr, "%d", IDLE_WHILE_TIMER);
		m_pIdlePeriod->setText(QString(tempStr));
	}

	if (m_pStaleWepTimeout != NULL)
	{
		sprintf((char *)&tempStr, "%d", STALE_KEY_WARN_TIMEOUT);
		m_pStaleWepTimeout->setText(QString(tempStr));
	}

	if (m_pMaximumStarts != NULL)
	{
		sprintf((char *)&tempStr, "%d", MAX_STARTS);
		m_pMaximumStarts->setText(QString(tempStr));
	}
}

void ConfigWidgetEditAdvancedInternals::slotDataChanged()
{
	m_bChangedData = true;
	emit signalSetSaveBtn(true);
}

bool ConfigWidgetEditAdvancedInternals::save()
{

	if (m_pAuthPeriod != NULL)
	{
		m_pGlobals->auth_period = atoi(m_pAuthPeriod->text().toAscii());
	}

	if (m_pHeldPeriod != NULL)
	{
		m_pGlobals->held_period = atoi(m_pHeldPeriod->text().toAscii());
	}

	if (m_pIdlePeriod != NULL)
	{
		m_pGlobals->idleWhile_timeout = atoi(m_pIdlePeriod->text().toAscii());
	}

	if (m_pStaleWepTimeout != NULL)
	{
		m_pGlobals->stale_key_timeout = atoi(m_pStaleWepTimeout->text().toAscii());
	}

	if (m_pMaximumStarts != NULL)
	{
		m_pGlobals->max_starts = atoi(m_pMaximumStarts->text().toAscii());
	}

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

bool ConfigWidgetEditAdvancedInternals::dataChanged()
{
	return m_bChangedData;
}

void ConfigWidgetEditAdvancedInternals::slotShowHelp()
{
	HelpWindow::showPage("xsupphelp.html", "xsupinternals");
}

void ConfigWidgetEditAdvancedInternals::discard()
{
	// Do nothing.
}
