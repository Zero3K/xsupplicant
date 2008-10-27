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

#include "ConfigWidgetEditGlobalsLogging.h"
#include "FormLoader.h"
#include "ViewLogDlg.h"
#include "Util.h"
#include "helpbrowser.h"

#ifdef WINDOWS
#include <shlobj.h>
#endif

ConfigWidgetEditGlobalsLogging::ConfigWidgetEditGlobalsLogging(QWidget *pRealWidget, XSupCalls *xsup, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pParent(parent), m_pSupplicant(xsup)
{
	m_bSettingsChanged = false;
	m_pGlobals = NULL;
	m_pViewLogDialog = NULL;
}

ConfigWidgetEditGlobalsLogging::~ConfigWidgetEditGlobalsLogging()
{
	if (m_pFriendlyWarnings != NULL)
	{
		Util::myDisconnect(m_pFriendlyWarnings, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	}

	if (m_pViewLogButton != NULL)
	{
		Util::myDisconnect(m_pViewLogButton, SIGNAL(clicked()), this, SLOT(viewLogButtonClicked()));
	}

	Util::myDisconnect(m_pRollBySize, SIGNAL(stateChanged(int)), this, SLOT(slotRollLogsClicked(int)));
	Util::myDisconnect(m_pLogsToKeep, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	Util::myDisconnect(m_pRollAtSize, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));

	Util::myDisconnect(m_pEnableLogging, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	Util::myDisconnect(m_pEnableLogging, SIGNAL(stateChanged(int)), this, SLOT(loggingStateChanged(int)));
	Util::myDisconnect(m_pLogLevel, SIGNAL(currentIndexChanged(int)), this, SLOT(slotDataChanged()));
	Util::myDisconnect(m_pLogDirectory, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

	Util::myDisconnect(m_pBrowseButton, SIGNAL(clicked()), this, SLOT(browseButtonClicked()));

	Util::myDisconnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));
	Util::myDisconnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	m_pSupplicant->freeConfigGlobals(&m_pGlobals);
}

void ConfigWidgetEditGlobalsLogging::discard()
{
	// Do nothing.
}

bool ConfigWidgetEditGlobalsLogging::attach()
{
	 m_pBrowseButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonLoggingBrowse");

	 m_pViewLogButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonLoggingViewLog");

	 m_pEnableLogging = qFindChild<QCheckBox*>(m_pRealWidget, "dataCheckboxEnableLoggingToFile");
	 if (m_pEnableLogging == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("The QCheckBox called 'dataCheckboxEnableLoggingToFile' is missing from the form design!"));
		 return false;
	 }

	m_pFriendlyWarnings = qFindChild<QCheckBox*>(m_pRealWidget, "dataCheckboxIncludeFriendlyWarnings");

	m_pLogDirectory = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldLoggingLogDirectory");
	if (m_pLogDirectory == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QLineEdit called 'dataFieldLoggingLogDirectory' is missing from the form design!"));
		return false;
	}

	m_pLogLevel = qFindChild<QComboBox*>(m_pRealWidget, "dataComboLoggingLogLevel");
	if (m_pLogLevel == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QComboBox called 'dataComboLoggingLogLevel' is missing from the form design!"));
		return false;
	}

	m_pLogsToKeep = qFindChild<QSpinBox*>(m_pRealWidget, "dataFieldNumberOfLogs");
	if (m_pLogsToKeep == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QSpinBox called 'dataFieldNumberOfLogs' is missing from the form design!"));
		return false;
	}

	m_pLogsToKeep->setMaximum(255);
	m_pLogsToKeep->setMinimum(1);

	m_pRollAtSize = qFindChild<QSpinBox*>(m_pRealWidget, "dataFieldLogSizeToRoll");
	if (m_pRollAtSize == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QSpinBox called 'dataFieldLogSizeToRoll' is missing from the form design!"));
		return false;
	}

	m_pRollAtSize->setMinimum(1);

	m_pRollBySize = qFindChild<QCheckBox*>(m_pRealWidget, "dataCheckboxRollLogs");
	if (m_pRollBySize == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QCheckBox called 'dataCheckboxRollLogs' is missing from the form design!"));
		return false;
	}

	updateWindow();

	// We have established connections to everything, so hook up some slots and signals.
	if (m_pFriendlyWarnings != NULL)
	{
		Util::myConnect(m_pFriendlyWarnings, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	}

	Util::myConnect(m_pLogsToKeep, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	Util::myConnect(m_pRollAtSize, SIGNAL(valueChanged(int)), this, SLOT(slotDataChanged()));
	Util::myConnect(m_pRollBySize, SIGNAL(stateChanged(int)), this, SLOT(slotRollLogsClicked(int)));

	Util::myConnect(m_pEnableLogging, SIGNAL(stateChanged(int)), this, SLOT(slotDataChanged()));
	Util::myConnect(m_pEnableLogging, SIGNAL(stateChanged(int)), this, SLOT(loggingStateChanged(int)));
	Util::myConnect(m_pLogLevel, SIGNAL(currentIndexChanged(int)), this, SLOT(slotDataChanged()));
	Util::myConnect(m_pLogDirectory, SIGNAL(textChanged(const QString &)), this, SLOT(slotDataChanged()));

	Util::myConnect(m_pBrowseButton, SIGNAL(clicked()), this, SLOT(browseButtonClicked()));

	Util::myConnect(this, SIGNAL(signalSetSaveBtn(bool)), m_pParent, SIGNAL(signalSetSaveBtn(bool)));
	Util::myConnect(m_pParent, SIGNAL(signalHelpClicked()), this, SLOT(slotShowHelp()));

	if (m_pViewLogButton != NULL)
	{
		Util::myConnect(m_pViewLogButton, SIGNAL(clicked()), this, SLOT(viewLogButtonClicked()));
	}

	emit signalSetSaveBtn(false);

	return true;
}

bool ConfigWidgetEditGlobalsLogging::save()
{
	if (m_pEnableLogging->checkState() == Qt::Unchecked)
	{
		// Clear out the path, and log level.
		if (m_pGlobals->logpath != NULL) free(m_pGlobals->logpath);
		m_pGlobals->logpath = NULL;

		m_pGlobals->loglevel = 0;
		m_pGlobals->logtype = LOGGING_NONE;
	}
	else
	{
		if (m_pGlobals->logpath != NULL) free(m_pGlobals->logpath);
		m_pGlobals->logpath = NULL;

		m_pGlobals->logtype = LOGGING_FILE;
		m_pGlobals->logpath = _strdup(m_pLogDirectory->text().toAscii());

		switch (m_pLogLevel->currentIndex())
		{
		case LOGGING_NORMAL:
			m_pGlobals->loglevel = DEBUG_NORMAL;
			break;

		case LOGGING_VERBOSE:
			m_pGlobals->loglevel = (DEBUG_VERBOSE | DEBUG_NORMAL);
			break;

		case LOGGING_DEBUG:
			m_pGlobals->loglevel = DEBUG_ALL;
			break;

		default:
			QMessageBox::critical(this, tr("Form design error"), tr("You have selected a log level setting that is not understood.  Your form design may be incorrect.  Defaulting to NORMAL logging."));
			m_pGlobals->loglevel = DEBUG_NORMAL;
			break;
		}
	}

	if (m_pFriendlyWarnings->checkState() == Qt::Checked)
	{
		m_pGlobals->flags &= (~CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS);
	}
	else
	{
		m_pGlobals->flags |= CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS;
	}

	if (m_pRollBySize->isChecked())
	{
		m_pGlobals->flags |= CONFIG_GLOBALS_ROLL_LOGS;
	}
	else
	{
		m_pGlobals->flags &= (~CONFIG_GLOBALS_ROLL_LOGS);
	}

	m_pGlobals->logs_to_keep = m_pLogsToKeep->value();

	m_pGlobals->size_to_roll = m_pRollAtSize->value();

	if (m_pSupplicant->setConfigGlobals(m_pGlobals) == true)
	{
		if (m_pSupplicant->writeConfig() == true)
		{
			m_bSettingsChanged = false;
			emit signalSetSaveBtn(false);

			return true;
		}
	}
	
	return false;
}

void ConfigWidgetEditGlobalsLogging::slotDataChanged()
{
	m_bSettingsChanged = true;
	emit signalSetSaveBtn(true);
}

void ConfigWidgetEditGlobalsLogging::setEnabled(bool isEnabled)
{
	if (m_pBrowseButton != NULL) m_pBrowseButton->setEnabled(isEnabled);
	if (m_pViewLogButton != NULL) m_pViewLogButton->setEnabled(isEnabled);
	if (m_pLogDirectory != NULL) m_pLogDirectory->setEnabled(isEnabled);
	if (m_pLogLevel != NULL) m_pLogLevel->setEnabled(isEnabled);
	if (m_pLogsToKeep != NULL) m_pLogsToKeep->setEnabled(isEnabled);
	if (m_pRollAtSize != NULL) m_pRollAtSize->setEnabled(isEnabled);
	if (m_pRollBySize != NULL) m_pRollBySize->setEnabled(isEnabled);
}

void ConfigWidgetEditGlobalsLogging::updateWindow()
{
	if (m_pGlobals != NULL)
	{
		m_pSupplicant->freeConfigGlobals(&m_pGlobals);
		m_pGlobals = NULL;
	}

	if (m_pSupplicant->getConfigGlobals(&m_pGlobals, true) == false) return;  // Nothing to do.

	// Now, set up the data.
	if (m_pGlobals->logtype == LOGGING_FILE)
	{
		// Enable everything.
		setEnabled(true);

		m_pLogDirectory->setText(QString(m_pGlobals->logpath));
		m_pEnableLogging->setCheckState(Qt::Checked);
	}
	else
	{
		// Disable everything.
		setEnabled(false);
		m_pEnableLogging->setCheckState(Qt::Unchecked);
	}

	// Set values on everything else, even if logging isn't enabled.
	if (m_pFriendlyWarnings != NULL)
	{
		if (m_pGlobals->flags & CONFIG_GLOBALS_NO_FRIENDLY_WARNINGS)
		{
			// Uncheck the check box.
			m_pFriendlyWarnings->setCheckState(Qt::Unchecked);
		}
		else
		{
			// Check the check box.
			m_pFriendlyWarnings->setCheckState(Qt::Checked);
		}
	}

	if (m_pLogLevel != NULL)
	{
		if ((m_pGlobals->loglevel & DEBUG_ALL) == DEBUG_ALL)
		{
			m_pLogLevel->setCurrentIndex(LOGGING_DEBUG);
		}
		else if ((m_pGlobals->loglevel & DEBUG_VERBOSE) == DEBUG_VERBOSE)
		{
			m_pLogLevel->setCurrentIndex(LOGGING_VERBOSE);
		}
		else
		{
			m_pLogLevel->setCurrentIndex(LOGGING_NORMAL);
		}
	}

	if (m_pLogsToKeep != NULL)
	{
		m_pLogsToKeep->setValue(m_pGlobals->logs_to_keep);
	}

	if (m_pRollAtSize != NULL)
	{
		m_pRollAtSize->setValue(m_pGlobals->size_to_roll);
	}

	if (m_pRollBySize != NULL)
	{
		if ((m_pGlobals->logtype == LOGGING_FILE) && (m_pGlobals->flags & CONFIG_GLOBALS_ROLL_LOGS) == CONFIG_GLOBALS_ROLL_LOGS)
		{
			m_pRollBySize->setChecked(true);
			m_pRollAtSize->setEnabled(true);
		}
		else
		{
			m_pRollBySize->setChecked(false);
			m_pRollAtSize->setEnabled(false);
		}
	}
}

void ConfigWidgetEditGlobalsLogging::getPageName(QString &name)
{
	name = tr("Logging");
}

void ConfigWidgetEditGlobalsLogging::loggingStateChanged(int newstate)
{
#ifdef WINDOWS
  TCHAR szMyPath[MAX_PATH];
  char *newPath = NULL;
#endif

	if (newstate == Qt::Unchecked)
	{
		setEnabled(false);
	}
	else if (newstate == Qt::Checked)
	{
		setEnabled(true);
		if (m_pLogDirectory->text() == "")
		{
#ifdef WINDOWS
		  if (FAILED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szMyPath)))
		  {
			  m_pLogDirectory->setText(".");
		  }
		  else
		  {
			  newPath = (char *)malloc(MAX_PATH);
			  sprintf(newPath, "%ws", szMyPath);
			  m_pLogDirectory->setText(newPath);
			  free(newPath);
		  }
#else
			m_pLogDirectory->setText("/var/log/");
#endif
		}
	}
	else
	{
		QMessageBox::critical(this, tr("Invalid Checkbox State"), tr("The checkbox was put in to a state we don't understand."));
	}
}

void ConfigWidgetEditGlobalsLogging::browseButtonClicked()
{
  QString logDir = m_pLogDirectory->text();
  QString directory = QFileDialog::getExistingDirectory(m_pRealWidget,
                             tr("Select Logging Folder"), logDir);
  if (!directory.isEmpty()) 
  {
#ifdef WINDOWS
	  directory.replace("/", "\\");   // Replace the / with a \ on Windows.
#endif
    m_pLogDirectory->setText(directory);
  }
}

void ConfigWidgetEditGlobalsLogging::viewLogButtonClicked()
{
  QString temp;

	if (m_pViewLogDialog != NULL)
	{
		cleanupuiWindowViewLogs();   // Close out the old one.
	}

	temp = m_pLogDirectory->text();
	m_pViewLogDialog = new uiWindowViewLogs(temp);
	
	if ((m_pViewLogDialog == NULL) || (m_pViewLogDialog->attach() == false))
	{
		QMessageBox::critical(this, tr("Form Error"), tr("Unable to load the form 'ViewLogWindow.ui'."));
		delete m_pViewLogDialog;
		m_pViewLogDialog = NULL;

		return;
	}

	m_pViewLogDialog->show();

	Util::myConnect(m_pViewLogDialog, SIGNAL(close()), this, SLOT(cleanupuiWindowViewLogs()));
}

void ConfigWidgetEditGlobalsLogging::cleanupuiWindowViewLogs()
{
	if (m_pViewLogDialog != NULL)
	{
		Util::myDisconnect(m_pViewLogDialog, SIGNAL(close()), this, SLOT(cleanupuiWindowViewLogs()));
		delete m_pViewLogDialog;
		m_pViewLogDialog = NULL;
	}
}

bool ConfigWidgetEditGlobalsLogging::dataChanged()
{
	return m_bSettingsChanged;
}

void ConfigWidgetEditGlobalsLogging::slotShowHelp()
{
	HelpWindow::showPage("xsupphelp.html", "xsuplogging");
}

void ConfigWidgetEditGlobalsLogging::slotRollLogsClicked(int newstate)
{
	slotDataChanged();
	
	if (newstate == Qt::Unchecked)
	{
		m_pRollAtSize->setEnabled(false);
	}
	else
	{
		m_pRollAtSize->setEnabled(true);
	}
}

