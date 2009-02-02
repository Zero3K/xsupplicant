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

#include "ConnectMgrDlg.h"
#include "FormLoader.h"
#include "Emitter.h"
#include "TrayApp.h"
#include "XSupWrapper.h"
#include "PreferredConnections.h"
#include "ConnectionWizard.h"
#include "ConnectionWizardData.h"
#include "MachineAuthWizard.h"
#include <QLabel>
#include <QList>

#include <algorithm>


// TODO:  disable wired options if no wired interface present
// TODO:  disable wireless options if no wireless interfaces present

ConnectMgrDlg::ConnectMgrDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *trayApp)
	: QWidget(parent),
	m_pParent(parent),
	m_pEmitter(e),
	m_pTrayApp(trayApp),
	m_pParentWindow(parentWindow)
{
	m_pConnections = NULL;
	m_pPrefDlg = NULL;
	m_pConnWizard = NULL;
	m_pMachineAuth = NULL;
	m_pViewLogDialog = NULL;
}

ConnectMgrDlg::~ConnectMgrDlg()
{
	if (m_pAdvancedButton != NULL)
		Util::myDisconnect(m_pAdvancedButton, SIGNAL(clicked()), this, SLOT(showAdvancedConfig()));
		
	if (m_pCloseButton != NULL)
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
		
	if (m_pConnectionsTable != NULL) {
		Util::myDisconnect(m_pConnectionsTable, SIGNAL(itemSelectionChanged()), this, SLOT(handleConnectionListSelectionChange()));
		Util::myDisconnect(m_pConnectionsTable, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(handleDoubleClick(int, int)));
	}
		
	if (m_pDeleteConnButton != NULL)
		Util::myDisconnect(m_pDeleteConnButton, SIGNAL(clicked()), this, SLOT(deleteSelectedConnection()));
		
	if (m_pEditConnButton != NULL)
		Util::myDisconnect(m_pEditConnButton, SIGNAL(clicked()), this, SLOT(editSelectedConnection()));			
		
	if (m_pNetworkPrioritiesButton != NULL)
		Util::myDisconnect(m_pNetworkPrioritiesButton, SIGNAL(clicked()), this, SLOT(showPriorityDialog()));		
		
	if (m_pNewConnButton != NULL)
		Util::myDisconnect(m_pNewConnButton, SIGNAL(clicked()), this, SLOT(createNewConnection()));	
		
	if (m_pWirelessAutoConnect != NULL)
		Util::myDisconnect(m_pWirelessAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(enableDisableWirelessAutoConnect(int)));
		
	if (m_pWiredAutoConnect != NULL)
		Util::myDisconnect(m_pWiredAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(enableDisableWiredAutoConnect(int)));
		
	if (m_pWiredConnections != NULL)
		Util::myDisconnect(m_pWiredConnections, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(setWiredAutoConnection(const QString &)));						
		
	if (m_pEnableLogging != NULL)
		Util::myDisconnect(m_pEnableLogging, SIGNAL(stateChanged(int)), this, SLOT(updateCheckboxes()));

	if (m_pLogPath != NULL)
		Util::myDisconnect(m_pLogPath, SIGNAL(textChanged(const QString &)), this, SLOT(enableSaveBtns()));

	if (m_pBrowse != NULL)
		Util::myDisconnect(m_pBrowse, SIGNAL(clicked()), this, SLOT(browseLogs()));

	if (m_pLogLevel != NULL)
		Util::myDisconnect(m_pLogLevel, SIGNAL(currentIndexChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pViewLog != NULL)
		Util::myDisconnect(m_pViewLog, SIGNAL(clicked()), this, SLOT(viewLog()));

	if (m_pLogsToKeep != NULL)
		Util::myDisconnect(m_pLogsToKeep, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pRollBySize != NULL)
		Util::myDisconnect(m_pRollBySize, SIGNAL(stateChanged(int)), this, SLOT(updateCheckboxes()));

	if (m_pSizeToRoll != NULL)
		Util::myDisconnect(m_pSizeToRoll, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pLoggingSave != NULL)
		Util::myDisconnect(m_pLoggingSave, SIGNAL(clicked()), this, SLOT(configUpdate()));

	// advanced settings tab objects
	if (m_pCheckSupplicants != NULL)
		Util::myDisconnect(m_pCheckSupplicants, SIGNAL(stateChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pDisconnectAtLogoff != NULL)
		Util::myDisconnect(m_pDisconnectAtLogoff, SIGNAL(stateChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pAllowMachineAuthContinue != NULL)
		Util::myDisconnect(m_pAllowMachineAuthContinue, SIGNAL(stateChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pScanTimeout != NULL)
		Util::myDisconnect(m_pScanTimeout, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pAssocTimeout != NULL)
		Util::myDisconnect(m_pAssocTimeout, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pPassiveInterval != NULL)
		Util::myDisconnect(m_pPassiveInterval, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pPMKSACacheRefresh != NULL)
		Util::myDisconnect(m_pPMKSACacheRefresh, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pPMKSACacheTimeout != NULL)
		Util::myDisconnect(m_pPMKSACacheTimeout, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pSettingsReset != NULL)
		Util::myDisconnect(m_pSettingsReset, SIGNAL(clicked()), this, SLOT(resetAdvSettings()));

	if (m_pAdvSettingsSave != NULL)
		Util::myDisconnect(m_pAdvSettingsSave, SIGNAL(clicked()), this, SLOT(configUpdate()));

	// advanced timers
	if (m_pAuthPeriod != NULL)
		Util::myDisconnect(m_pAuthPeriod, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pHeldPeriod != NULL)
		Util::myDisconnect(m_pHeldPeriod, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pIdlePeriod != NULL)
		Util::myDisconnect(m_pIdlePeriod, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pStaleKey != NULL)
		Util::myDisconnect(m_pStaleKey, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pMaxStarts != NULL)
		Util::myDisconnect(m_pMaxStarts, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pTimersReset != NULL)
		Util::myDisconnect(m_pTimersReset, SIGNAL(clicked()), this, SLOT(resetAdvTimers()));

	if (m_pAdvTimersSave != NULL)
		Util::myDisconnect(m_pAdvTimersSave, SIGNAL(clicked()), this, SLOT(configUpdate()));

	Util::myDisconnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(updateConnectionLists()));

	this->cleanupPriorityDialog();
	this->cleanupConnectionWizard();
		
	if (m_pRealForm != NULL)
		delete m_pRealForm;
		
	if (m_pConnections != NULL)
		xsupgui_request_free_conn_enum(&m_pConnections);		
}

bool ConnectMgrDlg::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("ConnectionManagerWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
		
	Qt::WindowFlags flags;
	
	// set window flags so minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMaximizeButtonHint;
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
			
	// cache off pointers to UI objects
	m_pHelpButton = qFindChild<QPushButton*>(m_pRealForm, "buttonHelp");
	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");
	m_pMainTab = qFindChild<QTabWidget*>(m_pRealForm, "mainTabControl");
	
	m_pNetworkPrioritiesButton = qFindChild<QPushButton*>(m_pRealForm, "buttonOptionsNetworkPriorities");
	m_pAdvancedButton = qFindChild<QPushButton*>(m_pRealForm, "buttonOptionsAdvancedConfig");
	m_pWiredConnections = qFindChild<QComboBox*>(m_pRealForm, "comboOptionsWirelessConnections");
	m_pWiredAutoConnect = qFindChild<QCheckBox*>(m_pRealForm, "checkboxWiredAutoConnect");
	m_pWirelessAutoConnect = qFindChild<QCheckBox*>(m_pRealForm, "checkboxWirelessAutoConnect");
	
	m_pDeleteConnButton = qFindChild<QPushButton*>(m_pRealForm, "buttonDeleteConnection");
	m_pEditConnButton = qFindChild<QPushButton*>(m_pRealForm, "buttonEditConnection");
	m_pNewConnButton = qFindChild<QPushButton*>(m_pRealForm,"buttonNewConnection");
	m_pConnectionsTable = qFindChild<QTableWidget*>(m_pRealForm, "dataTableConnectionProfiles");

	m_pEnableLogging = qFindChild<QCheckBox*>(m_pRealForm, "enableLogging");
	m_pLogPath = qFindChild<QLineEdit*>(m_pRealForm, "logDirectory");
	m_pBrowse = qFindChild<QPushButton*>(m_pRealForm, "browseButton");
	m_pLogLevel = qFindChild<QComboBox*>(m_pRealForm, "logLevel");
	m_pViewLog = qFindChild<QPushButton*>(m_pRealForm, "viewLogButton");
	m_pLogsToKeep = qFindChild<QSpinBox*>(m_pRealForm, "numLogsToKeep");
	m_pRollBySize = qFindChild<QCheckBox*>(m_pRealForm, "rollBySizeBox");
	m_pSizeToRoll = qFindChild<QSpinBox*>(m_pRealForm, "sizeToRollBox");
	m_pLoggingSave = qFindChild<QPushButton*>(m_pRealForm, "loggingSave");

	// advanced settings tab objects
	m_pCheckSupplicants = qFindChild<QCheckBox*>(m_pRealForm, "runOtherSuppCheck");
	m_pDisconnectAtLogoff = qFindChild<QCheckBox*>(m_pRealForm, "disconnectOnLogoff");
	m_pAllowMachineAuthContinue = qFindChild<QCheckBox*>(m_pRealForm, "allowMachineAuthRemain");
	m_pScanTimeout = qFindChild<QSpinBox*>(m_pRealForm, "scanTimeout");
	m_pAssocTimeout = qFindChild<QSpinBox*>(m_pRealForm, "assocTimeout");
	m_pPassiveInterval = qFindChild<QSpinBox*>(m_pRealForm, "passiveScanInterval");
	m_pPMKSACacheRefresh = qFindChild<QSpinBox*>(m_pRealForm, "pmksaRefresh");
	m_pPMKSACacheTimeout = qFindChild<QSpinBox*>(m_pRealForm, "pmksaTimeout");
	m_pSettingsReset = qFindChild<QPushButton*>(m_pRealForm, "resetButton");
	m_pAdvSettingsSave = qFindChild<QPushButton*>(m_pRealForm, "advSaveBtn");

	// advanced timers
	m_pAuthPeriod = qFindChild<QSpinBox*>(m_pRealForm, "authPeriodBox");
	m_pHeldPeriod = qFindChild<QSpinBox*>(m_pRealForm, "heldPeriodBox");
	m_pIdlePeriod = qFindChild<QSpinBox*>(m_pRealForm, "idlePeriodBox");
	m_pStaleKey = qFindChild<QSpinBox*>(m_pRealForm, "staleWepTimeout");
	m_pMaxStarts = qFindChild<QSpinBox*>(m_pRealForm, "maxStartsBox");
	m_pTimersReset = qFindChild<QPushButton*>(m_pRealForm, "resetBtn");
	m_pAdvTimersSave = qFindChild<QPushButton*>(m_pRealForm, "advTimerSave");

	// populate strings
	if (m_pAdvancedButton != NULL)
		m_pAdvancedButton->setText(tr("Show Advanced Configuration"));
		
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
	
	if (m_pHelpButton != NULL)
		m_pHelpButton->setText(tr("Help"));	
		
	if (m_pNetworkPrioritiesButton != NULL)
		m_pNetworkPrioritiesButton->setText(tr("Set Network Priorities"));
	
	if (m_pWiredAutoConnect != NULL)
		m_pWiredAutoConnect->setText(tr("Automatically Establish Connection"));
		
	if (m_pWirelessAutoConnect != NULL)
		m_pWirelessAutoConnect->setText(tr("Automatically Establish Connection"));		
		
	if (m_pDeleteConnButton != NULL)
		m_pDeleteConnButton->setText(tr("Delete"));
		
	if (m_pEditConnButton != NULL)
		m_pEditConnButton->setText(tr("Edit"));
		
	if (m_pNewConnButton != NULL)
		m_pNewConnButton->setText(tr("New Connection"));
		
	if (m_pMainTab != NULL)
	{
		m_pMainTab->setTabText(0,tr("Connections"));
		m_pMainTab->setTabText(1,tr("Options"));	
	}
	
	if (m_pConnectionsTable != NULL)
	{
		m_pConnectionsTable->horizontalHeaderItem(0)->setText(tr("Name"));
		m_pConnectionsTable->horizontalHeaderItem(1)->setText(tr("Interface"));
	}
		
	QLabel *pWiredOptionsHeader;
	pWiredOptionsHeader = qFindChild<QLabel*>(m_pRealForm, "headerWiredOptions");
	if (pWiredOptionsHeader != NULL)
		pWiredOptionsHeader->setText(tr("Wired"));
		
	QLabel *pWirelessOptionsHeader;
	pWirelessOptionsHeader = qFindChild<QLabel*>(m_pRealForm, "headerWirelessOptions");
	if (pWirelessOptionsHeader != NULL)
		pWirelessOptionsHeader->setText(tr("Wireless"));
		
	QLabel *pAdvancedOptionsHeader;
	pAdvancedOptionsHeader = qFindChild<QLabel*>(m_pRealForm, "headerAdvancedOptions");
	if (pAdvancedOptionsHeader != NULL)
		pAdvancedOptionsHeader->setText(tr("Advanced"));
		
	QLabel *pConnectionsHeader;
	pConnectionsHeader = qFindChild<QLabel*>(m_pRealForm, "headerConnectionProfiles");
	if (pConnectionsHeader != NULL)
		pConnectionsHeader->setText(tr("Connection Profiles"));
		
	// populate settings before activating events so that we don't generate a bunch of extra
	// IPC chatter.
	populateSettingsTabs();
	
	// set up event-handling
	if (m_pAdvancedButton != NULL)
		Util::myConnect(m_pAdvancedButton, SIGNAL(clicked()), this, SLOT(showAdvancedConfig()));
		
	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
		
	if (m_pConnectionsTable != NULL) {
		Util::myConnect(m_pConnectionsTable, SIGNAL(itemSelectionChanged()), this, SLOT(handleConnectionListSelectionChange()));
		Util::myConnect(m_pConnectionsTable, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(handleDoubleClick(int, int)));
	}	
		
	if (m_pDeleteConnButton != NULL)
		Util::myConnect(m_pDeleteConnButton, SIGNAL(clicked()), this, SLOT(deleteSelectedConnection()));
		
	if (m_pEditConnButton != NULL)
		Util::myConnect(m_pEditConnButton, SIGNAL(clicked()), this, SLOT(editSelectedConnection()));		
		
	if (m_pNetworkPrioritiesButton != NULL)
		Util::myConnect(m_pNetworkPrioritiesButton, SIGNAL(clicked()), this, SLOT(showPriorityDialog()));
		
	if (m_pNewConnButton != NULL)
		Util::myConnect(m_pNewConnButton, SIGNAL(clicked()), this, SLOT(createNewConnection()));
		
	if (m_pWirelessAutoConnect != NULL)
		Util::myConnect(m_pWirelessAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(enableDisableWirelessAutoConnect(int)));
		
	if (m_pWiredAutoConnect != NULL)
		Util::myConnect(m_pWiredAutoConnect, SIGNAL(stateChanged(int)), this, SLOT(enableDisableWiredAutoConnect(int)));
		
	if (m_pWiredConnections != NULL)
		Util::myConnect(m_pWiredConnections, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(setWiredAutoConnection(const QString &)));			
		
	if (m_pEnableLogging != NULL)
		Util::myConnect(m_pEnableLogging, SIGNAL(stateChanged(int)), this, SLOT(updateCheckboxes()));

	if (m_pLogPath != NULL)
		Util::myConnect(m_pLogPath, SIGNAL(textChanged(const QString &)), this, SLOT(enableSaveBtns()));

	if (m_pBrowse != NULL)
		Util::myConnect(m_pBrowse, SIGNAL(clicked()), this, SLOT(browseLogs()));

	if (m_pLogLevel != NULL)
		Util::myConnect(m_pLogLevel, SIGNAL(currentIndexChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pViewLog != NULL)
		Util::myConnect(m_pViewLog, SIGNAL(clicked()), this, SLOT(viewLog()));

	if (m_pLogsToKeep != NULL)
		Util::myConnect(m_pLogsToKeep, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pRollBySize != NULL)
		Util::myConnect(m_pRollBySize, SIGNAL(stateChanged(int)), this, SLOT(updateCheckboxes()));

	if (m_pSizeToRoll != NULL)
		Util::myConnect(m_pSizeToRoll, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pLoggingSave != NULL)
		Util::myConnect(m_pLoggingSave, SIGNAL(clicked()), this, SLOT(configUpdate()));

	// advanced settings tab objects
	if (m_pCheckSupplicants != NULL)
		Util::myConnect(m_pCheckSupplicants, SIGNAL(stateChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pDisconnectAtLogoff != NULL)
		Util::myConnect(m_pDisconnectAtLogoff, SIGNAL(stateChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pAllowMachineAuthContinue != NULL)
		Util::myConnect(m_pAllowMachineAuthContinue, SIGNAL(stateChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pScanTimeout != NULL)
		Util::myConnect(m_pScanTimeout, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pAssocTimeout != NULL)
		Util::myConnect(m_pAssocTimeout, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pPassiveInterval != NULL)
		Util::myConnect(m_pPassiveInterval, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pPMKSACacheRefresh != NULL)
		Util::myConnect(m_pPMKSACacheRefresh, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pPMKSACacheTimeout != NULL)
		Util::myConnect(m_pPMKSACacheTimeout, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pSettingsReset != NULL)
		Util::myConnect(m_pSettingsReset, SIGNAL(clicked()), this, SLOT(resetAdvSettings()));

	if (m_pAdvSettingsSave != NULL)
		Util::myConnect(m_pAdvSettingsSave, SIGNAL(clicked()), this, SLOT(configUpdate()));

	// advanced timers
	if (m_pAuthPeriod != NULL)
		Util::myConnect(m_pAuthPeriod, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pHeldPeriod != NULL)
		Util::myConnect(m_pHeldPeriod, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pIdlePeriod != NULL)
		Util::myConnect(m_pIdlePeriod, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pStaleKey != NULL)
		Util::myConnect(m_pStaleKey, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pMaxStarts != NULL)
		Util::myConnect(m_pMaxStarts, SIGNAL(valueChanged(int)), this, SLOT(enableSaveBtns()));

	if (m_pTimersReset != NULL)
		Util::myConnect(m_pTimersReset, SIGNAL(clicked()), this, SLOT(resetAdvTimers()));

	if (m_pAdvTimersSave != NULL)
		Util::myConnect(m_pAdvTimersSave, SIGNAL(clicked()), this, SLOT(configUpdate()));

	Util::myConnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(updateConnectionLists()));
	
	// other initializations
	if (m_pMainTab != NULL)
		m_pMainTab->setCurrentIndex(0);
		
	if (m_pConnectionsTable != NULL)
	{
		// disallow user from sizing columns
		m_pConnectionsTable->horizontalHeader()->setResizeMode(QHeaderView::Fixed);
		
		m_pConnectionsTable->horizontalHeader()->setResizeMode(0,QHeaderView::Stretch);
		m_pConnectionsTable->horizontalHeader()->resizeSection(1,100);
		m_pConnectionsTable->horizontalHeader()->resizeSection(2,100);
			
		// don't draw header any differently when row is selected
		m_pConnectionsTable->horizontalHeader()->setHighlightSections(false);
		
		m_pConnectionsTable->clearContents();
		
		m_pConnectionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);		
		
		this->populateConnectionsList();

		m_pConnectionsTable->sortItems(0);   // Start out by sorting on column 0.
		
		// enable/disable buttons dependent on selection
		handleConnectionListSelectionChange();
	}
		
	return this->buildMenuBar();	
}

bool ConnectMgrDlg::buildMenuBar(void)
{
	int admin = 0;

	// set up menu bar
	QMenuBar *pMenuBar = qFindChild<QMenuBar*>(m_pRealForm, "menubar");
	if (pMenuBar != NULL)
	{
		// assume that the 
		pMenuBar->clear();
		
		// build File menu
		QMenu *pFileMenu = new QMenu(tr("&File"));
		if (pFileMenu != NULL)
		{
			QAction *pAction = new QAction(NULL);
			if (pAction != NULL)
			{
				pAction->setText(tr("&Close"));
				pAction->setFont(pMenuBar->font());
				pAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_W));
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuClose()));
				pFileMenu->addAction(pAction);
			}
			
			pFileMenu->addSeparator();
			
			pAction = new QAction(NULL);
			if (pAction != NULL)
			{
				pAction->setText(tr("&Quit"));
				pAction->setFont(pMenuBar->font());
				pAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuQuit()));
				pFileMenu->addAction(pAction);
			}			
			pMenuBar->addMenu(pFileMenu);
		}
		
		// build tools menu
		QMenu *pToolsMenu = new QMenu(tr("&Tools"));
		if (pToolsMenu != NULL)
		{
			QAction *pAction = new QAction(NULL);
			if (pAction != NULL)
			{
				pAction->setText(tr("&View Log"));
				pAction->setFont(pMenuBar->font());
				pAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_L));
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuViewLog()));
				pToolsMenu->addAction(pAction);
			}
			
			pAction = new QAction(NULL);
			if (pAction != NULL)
			{
				pAction->setText(tr("&Create Troubleticket"));
				pAction->setFont(pMenuBar->font());
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuCreateTicket()));
				pToolsMenu->addAction(pAction);
			}

			pToolsMenu->addSeparator();

			// We only want to show the machine authentication menu if the user at the console is
			// an administrative user.
			if (xsupgui_request_get_are_administrator(&admin) == REQUEST_SUCCESS)
			{
				if (admin == TRUE)
				{
					pAction = new QAction(NULL);
					if (pAction != NULL)
					{
						pAction->setText(tr("&Machine Authentication..."));
						pAction->setFont(pMenuBar->font());
						Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuMachineAuth()));
						pToolsMenu->addAction(pAction);
					}
				}
			}

			pMenuBar->addMenu(pToolsMenu);
		}
		
		// build Help menu
		QMenu *pHelpMenu = new QMenu(tr("&Help"));
		if (pHelpMenu != NULL)
		{
			QAction *pAction = new QAction(NULL);
			if (pAction != NULL)
			{
				pAction->setText(tr("Help Contents"));
				pAction->setFont(pMenuBar->font());
				pAction->setShortcut(QKeySequence(Qt::Key_F1));
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuHelp()));
				pHelpMenu->addAction(pAction);
			}
			
			pHelpMenu->addSeparator();
			
			pAction = new QAction(NULL);
			if (pAction != NULL)
			{
				pAction->setText(tr("About XSupplicant"));
				pAction->setFont(pMenuBar->font());
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuAbout()));
				pHelpMenu->addAction(pAction);
			}			
			pMenuBar->addMenu(pHelpMenu);
		}		
	}
	
	return true;
}

bool ConnectMgrDlg::create(void)
{
	return this->initUI();
}

void ConnectMgrDlg::updateWirelessAutoConnectState(void)
{
	if (m_pWirelessAutoConnect != NULL)
	{
		int retVal;
		config_globals *pConfig;
		
		retVal = xsupgui_request_get_globals_config(&pConfig);
		if (retVal == REQUEST_SUCCESS && pConfig != NULL) {
			m_pWirelessAutoConnect->setChecked((pConfig->flags & CONFIG_GLOBALS_ASSOC_AUTO) == CONFIG_GLOBALS_ASSOC_AUTO);
			if (m_pNetworkPrioritiesButton != NULL)
				m_pNetworkPrioritiesButton->setEnabled((pConfig->flags & CONFIG_GLOBALS_ASSOC_AUTO) == CONFIG_GLOBALS_ASSOC_AUTO);			
		}
		else
		{
			// if we can't get data we need, make sure everything's enabled
			if (m_pNetworkPrioritiesButton != NULL)
				m_pNetworkPrioritiesButton->setEnabled(true);			
		}
			
		if (pConfig != NULL)
			xsupgui_request_free_config_globals(&pConfig);
	}
}

void ConnectMgrDlg::enableDisableWirelessAutoConnect(int newState)
{
	if (m_pWirelessAutoConnect != NULL)
	{
		int retVal;
		config_globals *pConfig;
		
		retVal = xsupgui_request_get_globals_config(&pConfig);
		if (retVal == REQUEST_SUCCESS && pConfig != NULL)	
		{
			if (newState == Qt::Checked)
			{
				pConfig->flags |= CONFIG_GLOBALS_ASSOC_AUTO;
				if (m_pNetworkPrioritiesButton != NULL)
					m_pNetworkPrioritiesButton->setEnabled(true);
			}
			else 
			{
				pConfig->flags &= ~CONFIG_GLOBALS_ASSOC_AUTO;
				if (m_pNetworkPrioritiesButton != NULL)
					m_pNetworkPrioritiesButton->setEnabled(false);
			}
				
			retVal = xsupgui_request_set_globals_config(pConfig);
			
			if (retVal == REQUEST_SUCCESS)
				XSupWrapper::writeConfig(CONFIG_LOAD_GLOBAL);
		}
		
		if (pConfig != NULL)
			xsupgui_request_free_config_globals(&pConfig);
	}
}

void ConnectMgrDlg::updateWiredAutoConnectState(void)
{
	int x, i;
	conn_enum *connEnum = NULL;
	bool found = false;

	// don't bother doing any work if the UI elements aren't present
	if (m_pWiredAutoConnect != NULL && m_pWiredConnections != NULL)
	{
		for (x = CONFIG_LOAD_GLOBAL; x <= CONFIG_LOAD_USER; x++)
		{
			if (xsupgui_request_enum_connections(x, &connEnum) == REQUEST_SUCCESS)
			{
				for (i = 0; connEnum[i].name != NULL; i++)
				{
					if (((connEnum[i].ssid == NULL) || (strlen(connEnum[i].ssid) == 0)) && (connEnum[i].priority == 1))
					{
						// We found our wired default network.
						QString connName = connEnum[i].name;
						int index = m_pWiredConnections->findText(connName);
						if (index != -1)
						{
							// !!!! this causes event to be fired?!
							m_pWiredAutoConnect->setCheckState(Qt::Checked);
							this->enableDisableWiredAutoConnect(Qt::Checked);
							m_pWiredConnections->setCurrentIndex(index);
							found = true;
							break;
						}
						else
						{
							m_pWiredAutoConnect->setCheckState(Qt::Unchecked);
							enableDisableWiredAutoConnect(Qt::Unchecked);
							found = true;
							break;
						}
					}
				}
			}

			xsupgui_request_free_conn_enum(&connEnum);
		}

		if (!found)
		{
			m_pWiredAutoConnect->setCheckState(Qt::Unchecked);
			this->enableDisableWiredAutoConnect(Qt::Unchecked);
		}
	}
}

void ConnectMgrDlg::setWiredAutoConnection(const QString &connectionName)
{
	conn_enum *connEnum = NULL;
	config_connection *myConn = NULL;
	int are_admin = 0;
	int x, i;
	bool alreadySet = false;

	if (connectionName.isEmpty())
		return;							// Nothing to do.

	if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, connectionName.toAscii().data(), &myConn) == REQUEST_SUCCESS)
	{
		// The current default is a machine defined default, so we need to verify that the user at the console
		// is allowed to change it.
		if (xsupgui_request_get_are_administrator(&are_admin) != REQUEST_SUCCESS)
		{
			QMessageBox::critical(this, tr("Error"), tr("Unable to determine if you have permissions to edit this setting."));
			xsupgui_request_free_connection_config(&myConn);
			return;
		}

		if (are_admin == FALSE)
		{
			QMessageBox::critical(this, tr("Error"), tr("The default wired connection is defined in the system configuration.  You must be an administrator to change it."));
			xsupgui_request_free_connection_config(&myConn);
			return;
		}
	}

	xsupgui_request_free_connection_config(&myConn);

	for (x = CONFIG_LOAD_GLOBAL; x <= CONFIG_LOAD_USER; x++)
	{
		if (xsupgui_request_enum_connections(x, &connEnum) == REQUEST_SUCCESS)
		{
			for (i = 0; connEnum[i].name != NULL; i++)
			{
				if (((connEnum[i].ssid == NULL) || (strlen(connEnum[i].ssid) == 0)) && (connEnum[i].priority != DEFAULT_PRIORITY))
				{
					if (xsupgui_request_get_connection_config(x, connEnum[i].name, &myConn) != REQUEST_SUCCESS)
					{
						QMessageBox::critical(this, tr("Error"), tr("Unable to reset the priority settings on connection %1.  The wired default behavior may not be what is expected.").arg(connEnum[i].name));
					}
					else
					{
						myConn->priority = DEFAULT_PRIORITY;
						if (xsupgui_request_set_connection_config(x, myConn) != REQUEST_SUCCESS)
						{
							QMessageBox::critical(this, tr("Error"), tr("Unable to reset the priority settings on connection %1.  The wired default behavior may not be what is expected.").arg(connEnum[i].name));
						}

						xsupgui_request_free_connection_config(&myConn);
					}
				}

				// If we have already set the value, don't set it again.  Technically it should be impossible to
				// end up in a situation where we have conflicting names in the configuration, but this bool will
				// save us processing time and act as a guard to make sure that in the event we do have two with
				// the same name that only the first one gets set.  (In this case we also would give preference
				// to global config if we had a name conflict between the two.)
				if ((!alreadySet) && ((connEnum[i].ssid == NULL) || (strlen(connEnum[i].ssid) == 0)) && (connectionName == QString(connEnum[i].name)))
				{
					if (xsupgui_request_get_connection_config(x, connEnum[i].name, &myConn) != REQUEST_SUCCESS)
					{
						QMessageBox::critical(this, tr("Error"), tr("Unable to set the priority settings on connection %1.  The wired default behavior may not be what is expected.").arg(connEnum[i].name));
					}
					else
					{
						myConn->priority = 1;
						if (xsupgui_request_set_connection_config(x, myConn) != REQUEST_SUCCESS)
						{
							QMessageBox::critical(this, tr("Error"), tr("Unable to set the priority settings on connection %1.  The wired default behavior may not be what is expected.").arg(connEnum[i].name));
						}

						xsupgui_request_free_connection_config(&myConn);
					}
				}
			}
		}

		xsupgui_request_free_conn_enum(&connEnum);
		XSupWrapper::writeConfig(x);
	}
}

void ConnectMgrDlg::enableDisableWiredAutoConnect(int newState)
{
	if (m_pWiredAutoConnect != NULL && m_pWiredConnections != NULL)
	{
		if (newState == Qt::Checked)
		{
			setWiredAutoConnection(m_pWiredConnections->currentText());
			m_pWiredConnections->setEnabled(true);
		}
		else
		{
			this->setWiredAutoConnection(QString(""));
			m_pWiredConnections->setEnabled(false);
		}
	}
}

void ConnectMgrDlg::show(void)
{
	// every time we show this, refresh the connection list in case it changed
	this->refreshConnectionList();
	this->populateConnectionsList();
	this->populateWiredConnectionsCombo();
	this->updateWirelessAutoConnectState();
	this->updateWiredAutoConnectState();

	// always come up with first tab visible, regardless of state user left it in
	if (m_pMainTab != NULL)
		m_pMainTab->setCurrentIndex(0);
		
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

void ConnectMgrDlg::hide(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
}

void ConnectMgrDlg::refreshConnectionList(void)
{	
	int retval = 0;
	conn_enum *pConn;
	
	retval = xsupgui_request_enum_connections((CONFIG_LOAD_GLOBAL | CONFIG_LOAD_USER), &pConn);
	if (retval == REQUEST_SUCCESS && pConn)
	{
		if (m_pConnections != NULL)
			xsupgui_request_free_conn_enum(&m_pConnections);

		// count connections
		m_nConnections = 0;
		while (pConn[m_nConnections].name != NULL)
			++m_nConnections;
			
		m_pConnections = pConn;
	}	
}

void ConnectMgrDlg::populateWiredConnectionsCombo(void)
{
	if (m_pWiredConnections != NULL)
	{
		// disconnect this slot while populate combo box
		// QT is silly and emits signals for index changed as it populates
		Util::myDisconnect(m_pWiredConnections, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(setWiredAutoConnection(const QString &)));						

		m_pWiredConnections->clear();
		
		// jking - !!! right now this assumes only one wired interface
		// We really need to filter this list by selected interface once
		// the UI supports it
		if (m_pConnections != NULL)
		{	
			// create sorted list of wired connections
			QVector<QString> wiredConnVector;
			
			for (int i=0; i<m_nConnections; i++)
			{
				if (m_pConnections[i].ssid == NULL || QString(m_pConnections[i].ssid).isEmpty())
					wiredConnVector.append(QString(m_pConnections[i].name));
			}
			
			// we now have vector of connections. Now sort them.
			std::sort(wiredConnVector.begin(), wiredConnVector.end());
			
			for (int i=0; i<wiredConnVector.size(); i++)
				m_pWiredConnections->addItem(wiredConnVector.at(i));
		}
		Util::myConnect(m_pWiredConnections, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(setWiredAutoConnection(const QString &)));			
	}
}

void ConnectMgrDlg::populateConnectionsList(void)
{
	if (m_pConnections != NULL && m_pConnectionsTable != NULL)
	{
		// clear table before re-populating
		m_pConnectionsTable->clearContents();
		
		// make sure we have enough rows in the table
		m_pConnectionsTable->setRowCount(std::max<int>(this->m_minConnListRowCount, m_nConnections));
		m_pConnectionsTable->setSortingEnabled(false);
		
		for (int i=0; i<m_nConnections; i++)
		{
			// check if connection is volatile
			bool bVolatile = false;
			config_connection *pConfig;
			int retVal = xsupgui_request_get_connection_config(m_pConnections[i].config_type, m_pConnections[i].name, &pConfig);
			if (retVal == REQUEST_SUCCESS && pConfig != NULL)
			{
				if ((pConfig->flags & CONFIG_VOLATILE_CONN) != 0)
					bVolatile = true;
			}
			
			if (pConfig != NULL)
				xsupgui_request_free_connection_config(&pConfig);
			
			// don't include volatile connectiions in list
			if (bVolatile == false)
			{
				QTableWidgetItem *nameItem=NULL;
				nameItem = new QTableWidgetItem(m_pConnections[i].name, QTableWidgetItem::UserType+m_pConnections[i].config_type);
				if (nameItem != NULL)
					m_pConnectionsTable->setItem(i, 0, nameItem);
					
				QTableWidgetItem *adapterItem=NULL;
				QString adapterTypeStr;
				if (m_pConnections[i].ssid != NULL && m_pConnections[i].ssid[0] != '\0')
					adapterTypeStr = tr("Wireless");
				else
					adapterTypeStr = tr("Wired");
					
				adapterItem = new QTableWidgetItem(adapterTypeStr, 0);
				if (adapterItem != NULL)
					m_pConnectionsTable->setItem(i, 1, adapterItem);
			}	
		}
		m_pConnectionsTable->setSortingEnabled(true);
	}
}

void ConnectMgrDlg::handleConnectionListSelectionChange(void)
{
	QList<QTableWidgetItem*> selectedItems;
	
	selectedItems = m_pConnectionsTable->selectedItems();
	
	if (selectedItems.isEmpty() == false) 
	{
		QTableWidgetItem* selItem = selectedItems.at(0);
		if ((selItem->row() >= 0) && (selItem->row() < m_nConnections))
		{
			if (m_pDeleteConnButton != NULL)
				m_pDeleteConnButton->setEnabled(true);
			if (m_pEditConnButton != NULL)
				m_pEditConnButton->setEnabled(true);
		}
		else
		{
			if (m_pDeleteConnButton != NULL)
				m_pDeleteConnButton->setEnabled(false);
			if (m_pEditConnButton != NULL)
				m_pEditConnButton->setEnabled(false);	
		}
	}
	else
	{
		if (m_pDeleteConnButton != NULL)
			m_pDeleteConnButton->setEnabled(false);
		if (m_pEditConnButton != NULL)
			m_pEditConnButton->setEnabled(false);	
	}
}

void ConnectMgrDlg::deleteSelectedConnection(void)
{
	int inuse = 0;

	QList<QTableWidgetItem*> selectedItems;
	
	selectedItems = m_pConnectionsTable->selectedItems();
	
	if (selectedItems.isEmpty() == false) 
	{
		QTableWidgetItem* selItem = selectedItems.at(0);
		if ((selItem->row() >= 0) && (selItem->row() < m_nConnections))
		{
			QTableWidgetItem *nameItem = m_pConnectionsTable->item(selItem->row(), 0);
			QString connName = nameItem->text();
			config_connection *pConfig;
			bool canDelete = true;
			unsigned char my_config_type = (nameItem->type() - QTableWidgetItem::UserType);
			
			// first check if connection is in use
			// if so, don't allow deleting	

			if (xsupgui_request_get_is_connection_in_use(connName.toAscii().data(), &inuse) == REQUEST_SUCCESS)
			{
				if (inuse == 0) 
				{
					canDelete = true;
				}
				else
				{
					QMessageBox::warning(m_pRealForm, tr("Connection In Use"), tr("The connection '%1' cannot be deleted because it is currently in use.  Please disconnect from the network before deleting the connection.").arg(connName));
					canDelete = false;
				}
			}
			
			if (canDelete == true)
			{
				QString message;
			
				// check if is wired and if so is default connection
				if (XSupWrapper::isDefaultWiredConnection(connName))
					message = tr("The connection '%1' is set as the default connection for one of your wired adapters.  Are you sure you want to delete it?").arg(connName);
				else
					message = tr("Are you sure you want to delete the connection '%1'?").arg(connName);
				
				// check if wireless and is in preferred list?
				bool result = XSupWrapper::getConfigConnection(my_config_type, connName, &pConfig);
				if (result == true && pConfig != NULL)
				{
					if (pConfig->priority != DEFAULT_PRIORITY)
						message = tr("The connection '%1' is in your preferred connection list.  Are you sure you want to delete it?").arg(connName);
				}
				else
					pConfig = NULL;
				
				
				if (QMessageBox::question(m_pRealForm, tr("Delete Connection"), 
					message, 
					QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
				{
					bool success;
					config_profiles *pProfile;
					unsigned char profile_type = CONFIG_LOAD_USER;
					unsigned char ts_type;

					success = XSupWrapper::getConfigProfile(CONFIG_LOAD_USER, QString(pConfig->profile), &pProfile);
					if (success == false) 
					{
						success = XSupWrapper::getConfigProfile(CONFIG_LOAD_GLOBAL, QString(pConfig->profile), &pProfile);
						profile_type = CONFIG_LOAD_GLOBAL;
					}
					
					success = XSupWrapper::deleteConnectionConfig(my_config_type, connName);
					if (success == false)
					{
						QMessageBox::critical(m_pRealForm,tr("Error Deleting Connection"), tr("An error occurred when attempting to delete the connection '%1'.  If the connection is in use, please disconnect and try again.").arg(connName));
					}
					else
					{	
						// delete profile and trusted server
						if (pProfile != NULL && XSupWrapper::isProfileInUse(QString(pProfile->name)) == false)
						{
							// if no other connections are using this profile, delete it
							config_trusted_server *pServer;
							XSupWrapper::getTrustedServerForProfile(profile_type, QString(pProfile->name), &pServer, &ts_type);
							success = XSupWrapper::deleteProfileConfig(profile_type, QString(pProfile->name));
							
							if (success == false)
							{
								QMessageBox::critical(m_pRealForm, tr("Error Deleting Profile"), tr("An error occurred while attempting to delete the profile '%1'").arg(pProfile->name));
							}
							else
							{
								// delete trusted server
								if (pServer != NULL && XSupWrapper::isTrustedServerInUse(QString(pServer->name)) == false)
									success = XSupWrapper::deleteServerConfig(ts_type, QString(pServer->name));
								else if (pServer != NULL)
									QMessageBox::critical(m_pRealForm, tr("Error Deleting Trusted Server"), tr("The trused server '%1' cannot be deleted because it is being used by multiple profiles").arg(pServer->name));
							}
							if (pServer != NULL)
								XSupWrapper::freeConfigServer(&pServer);
						}
						else if (pProfile != NULL)
						{
							QMessageBox::critical(m_pRealForm, tr("Error Deleting Profile"), tr("The profile '%1' cannot be deleted because it is being used by multiple connection profiles").arg(pProfile->name));
						}
					
						// save off the config since it changed
						XSupWrapper::writeConfig(CONFIG_LOAD_GLOBAL);
						XSupWrapper::writeConfig(CONFIG_LOAD_USER);
						
						// tell everyone we changed the config
						m_pEmitter->sendConnConfigUpdate();
					}
					if (pProfile != NULL)
						XSupWrapper::freeConfigProfile(&pProfile);
				}
			}
			if (pConfig != NULL)
				XSupWrapper::freeConfigConnection(&pConfig);	
		}	
	}
}

void ConnectMgrDlg::showPriorityDialog()
{
	if (m_pPrefDlg != NULL)
	{
		cleanupPriorityDialog();
	}

	if (m_pPrefDlg == NULL)
	{
		m_pPrefDlg = new PreferredConnections(XSupCalls(m_pTrayApp), this, m_pRealForm);
		if (m_pPrefDlg != NULL)
		{
			if (m_pPrefDlg->attach() == false)
			{
				this->cleanupPriorityDialog();
				return;
			}
		}

		Util::myConnect(m_pPrefDlg, SIGNAL(close()), this, SLOT(cleanupPriorityDialog()));
		m_pPrefDlg->show();
	}
}

void ConnectMgrDlg::cleanupPriorityDialog(void)
{
	if (m_pPrefDlg != NULL)
	{
		Util::myDisconnect(m_pPrefDlg, SIGNAL(close()), this, SLOT(cleanupPriorityDialog()));

		delete m_pPrefDlg;
		m_pPrefDlg = NULL;
	}
}

bool ConnectMgrDlg::isVisible(void)
{
	if (m_pRealForm != NULL)
		return m_pRealForm->isVisible();
	else
		return false;
}

void ConnectMgrDlg::bringToFront(void)
{
	if (m_pRealForm != NULL)
	{
		m_pRealForm->raise();
		m_pRealForm->activateWindow();
	}
}

void ConnectMgrDlg::handleDoubleClick(int row, int)
{
	if (m_pConnectionsTable != NULL)
	{
		QTableWidgetItem* item = m_pConnectionsTable->item(row, 0);
		if (item != NULL)
		{
			QString connName;
			int config_type = (item->type() - QTableWidgetItem::UserType);		
			connName = item->text();
	
			m_pRealForm->setCursor(Qt::WaitCursor);
			this->editConnection(config_type, connName);
			m_pRealForm->setCursor(Qt::ArrowCursor);
		}
	}
}

void ConnectMgrDlg::createNewConnection(void)
{
	if (m_pConnWizard == NULL)
	{
		// create the wizard if it doesn't already exist
		m_pConnWizard = new ConnectionWizard(QString(""), this, m_pRealForm, m_pEmitter);
		if (m_pConnWizard != NULL)
		{
			m_pRealForm->setCursor(Qt::WaitCursor);
			if (m_pConnWizard->create() == true)
			{
				Util::myConnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
				Util::myConnect(m_pConnWizard, SIGNAL(finished(bool, const QString &, const QString &)), this, SLOT(finishConnectionWizard(bool, const QString &, const QString &)));			
				m_pConnWizard->init();
				m_pRealForm->setCursor(Qt::ArrowCursor);
				m_pConnWizard->show();
			}
			else
			{
				m_pRealForm->setCursor(Qt::ArrowCursor);
				QMessageBox::critical(m_pRealForm, tr("Error"),tr("An error occurred when attempting to launch the Connection Wizard"));
				delete m_pConnWizard;
				m_pConnWizard = NULL;
			}
		}
		else
			QMessageBox::critical(m_pRealForm, tr("Error"),tr("An error occurred when attempting to launch the Connection Wizard"));
	}
	else
	{
		m_pRealForm->setCursor(Qt::WaitCursor);
		m_pConnWizard->init();
		m_pRealForm->setCursor(Qt::ArrowCursor);
		m_pConnWizard->show();
	}
}

void ConnectMgrDlg::finishConnectionWizard(bool success, const QString &, const QString &)
{
	if (success == false)
		QMessageBox::critical(m_pRealForm,tr("Error saving connection data"), tr("An error occurred while saving the configuration data you provided."));
	this->cleanupConnectionWizard();
}

void ConnectMgrDlg::cleanupConnectionWizard(void)
{
	if (m_pConnWizard != NULL)
	{
		Util::myDisconnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
		Util::myDisconnect(m_pConnWizard, SIGNAL(finished(bool, const QString &, const QString &)), this, SLOT(finishConnectionWizard(bool, const QString &, const QString &)));				
		delete m_pConnWizard;
		m_pConnWizard = NULL;
	}
}

void ConnectMgrDlg::finishMachineAuthWizard(bool success, const QString &, const QString &)
{
	if (success == false)
		QMessageBox::critical(m_pRealForm, tr("Error saving machine authentication data"), tr("An error occurred while saving the machine authentication data you provided."));
	this->cleanupMachineAuthWizard();
}

void ConnectMgrDlg::cleanupMachineAuthWizard(void)
{
	if (m_pMachineAuth != NULL)
	{
		Util::myDisconnect(m_pMachineAuth, SIGNAL(cancelled()), this, SLOT(cleanupMachineAuthWizard()));
		Util::myDisconnect(m_pMachineAuth, SIGNAL(finished(bool, const QString &, const QString &)), this, SLOT(finishMachineAuthWizard(bool, const QString &, const QString &)));
		delete m_pMachineAuth;
		m_pMachineAuth = NULL;
	}
}

void ConnectMgrDlg::updateConnectionLists(void)
{
	// need to refresh the list of connections
	this->refreshConnectionList();
	this->populateConnectionsList();
	
	// connections changed.  Repopulate combo box
	this->populateWiredConnectionsCombo();
	
	// since the combo box items may have changed, make sure to re-select the right item
	this->updateWiredAutoConnectState();
}

void ConnectMgrDlg::editConnection(int config_type, const QString &connName)
{	
	bool success;
	int inuse;
	config_connection *pConfig;
	struct config_eap_peap *peapconfig = NULL;
	
	success = XSupWrapper::getConfigConnection(config_type, connName,&pConfig);
	if (success == true && pConfig != NULL)
	{
		bool editable = true;
		
		// first check if connection is in use
		// if so, don't allow editing	
		if (xsupgui_request_get_is_connection_in_use(connName.toAscii().data(), &inuse) == REQUEST_SUCCESS)
		{
			if (inuse == 0) 
			{
				editable = true;
			}
			else
			{
				QMessageBox::warning(m_pRealForm, tr("Connection In Use"), tr("The connection '%1' cannot be edited because it is currently in use.  Please disconnect from the network before editing the connection.").arg(connName));
				editable = false;
			}
		}
				
		if (editable == true)
		{
			config_profiles *pProfile = NULL;
			config_trusted_server *pServer = NULL;
			unsigned char profile_type = CONFIG_LOAD_USER;
			unsigned char ts_type = 0;
			
			if (pConfig->profile != NULL)
			{
				success = XSupWrapper::getConfigProfile(profile_type, QString(pConfig->profile),&pProfile);
				if (success == false)
				{
					profile_type = CONFIG_LOAD_GLOBAL;
					success = XSupWrapper::getConfigProfile(profile_type, QString(pConfig->profile), &pProfile);
				}
			}
				
			if (success == true && pProfile != NULL)
				success = XSupWrapper::getTrustedServerForProfile(profile_type, QString(pProfile->name),&pServer, &ts_type);
				
			ConnectionWizardData wizData;
			wizData.initFromSupplicantProfiles(config_type, pConfig,pProfile,pServer);

			// See if this is a machine auth configuration.
			if (pProfile->method->method_num == EAP_TYPE_PEAP)
			{
				peapconfig = (struct config_eap_peap *)pProfile->method->method_data;

				if (TEST_FLAG(peapconfig->flags, FLAGS_PEAP_MACHINE_AUTH))
				{
					// Clean up the memory used here.
					if (pConfig != NULL)
						XSupWrapper::freeConfigConnection(&pConfig);
					if (pProfile != NULL)
						XSupWrapper::freeConfigProfile(&pProfile);
					if (pServer != NULL)
						XSupWrapper::freeConfigServer(&pServer);

					// Let our machine auth handler take care of things.
					menuMachineAuth();
					return;
				}
			}
			
			if (pConfig != NULL)
				XSupWrapper::freeConfigConnection(&pConfig);
			if (pProfile != NULL)
				XSupWrapper::freeConfigProfile(&pProfile);
			if (pServer != NULL)
				XSupWrapper::freeConfigServer(&pServer);
			
			if (m_pConnWizard == NULL)
			{
				// create the wizard if it doesn't already exist
				m_pConnWizard = new ConnectionWizard(QString(""), this, m_pRealForm, m_pEmitter);
				if (m_pConnWizard != NULL)
				{
					if (m_pConnWizard->create() == true)
					{
						Util::myConnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
						Util::myConnect(m_pConnWizard, SIGNAL(finished(bool, const QString &, const QString &)), this, SLOT(finishConnectionWizard(bool, const QString &, const QString &)));			
						m_pConnWizard->edit(wizData);
						m_pConnWizard->show();
					}
					// else show error?
				}
				// else show error?
			}
			else
			{
				m_pConnWizard->edit(wizData);
				m_pConnWizard->show();
			}	
		}			
	}
}

void ConnectMgrDlg::editSelectedConnection(void)
{
	if (m_pConnectionsTable != NULL)
	{
		QList<QTableWidgetItem*> selectedItems;
		
		selectedItems = m_pConnectionsTable->selectedItems();
		
		if (selectedItems.isEmpty() == false) 
		{
			QTableWidgetItem* selItem = selectedItems.at(0);
			if ((selItem->row() >= 0) && (selItem->row() < m_nConnections))
			{
				QTableWidgetItem *nameItem = m_pConnectionsTable->item(selItem->row(), 0);
				QString connName = nameItem->text();
				int config_type = (nameItem->type() - QTableWidgetItem::UserType);
				
				this->editConnection(config_type, connName);
			}
		}
	}
}

/**
 * \brief The user wants to configure machine authentication.
 **/
void ConnectMgrDlg::menuMachineAuth(void)
{
	ConnectionWizardData wizData;
	struct config_connection *pConn = NULL;
	struct config_profiles *pProf = NULL;
	struct config_trusted_server *pServer = NULL;
	struct config_globals *pGlobals = NULL;

	if (m_pMachineAuth != NULL)
	{
		m_pMachineAuth->show();
		return;
	}

	m_pMachineAuth = new MachineAuthWizard(QString(""), this, m_pRealForm, m_pEmitter);
	if (m_pMachineAuth != NULL)
	{
		m_pRealForm->setCursor(Qt::WaitCursor);

		if (m_pMachineAuth->create() == true)
		{
			Util::myConnect(m_pMachineAuth, SIGNAL(cancelled()), this, SLOT(cleanupMachineAuthWizard()));
			Util::myConnect(m_pMachineAuth, SIGNAL(finished(bool, const QString &, const QString &)), this, SLOT(finishMachineAuthWizard(bool, const QString &, const QString &)));			
			m_pMachineAuth->init();

			if (xsupgui_request_get_connection_config(CONFIG_LOAD_GLOBAL, "Machine Authentication Connection", &pConn) == REQUEST_SUCCESS)
			{
				xsupgui_request_get_profile_config(CONFIG_LOAD_GLOBAL, "Machine Authentication Profile", &pProf);
				xsupgui_request_get_trusted_server_config(CONFIG_LOAD_GLOBAL, "Machine Authentication Trusted Server", &pServer);

				if (wizData.initFromSupplicantProfiles(CONFIG_LOAD_GLOBAL, pConn, pProf, pServer) == true)
				{
					// Get the settings for wired/wireless.
					if (xsupgui_request_get_globals_config(&pGlobals) == REQUEST_SUCCESS)
					{
						if (pGlobals->wiredMachineAuthConnection != NULL) 
							wizData.m_wired = true;
						else
							wizData.m_wired = false;

						if (pGlobals->wirelessMachineAuthConnection != NULL)
							wizData.m_wireless = true;
						else
							wizData.m_wireless = false;

						xsupgui_request_free_config_globals(&pGlobals);
					}

					// Clean up our used memory
					xsupgui_request_free_connection_config(&pConn);
					xsupgui_request_free_profile_config(&pProf);
					xsupgui_request_free_trusted_server_config(&pServer);	

					m_pMachineAuth->edit(wizData);
				}
				else
				{
					// Clean up our used memory
					xsupgui_request_free_connection_config(&pConn);
					xsupgui_request_free_profile_config(&pProf);
					xsupgui_request_free_trusted_server_config(&pServer);	

					QMessageBox::critical(this, tr("Machine Authentication Configuration Error"), tr("There was an error gathering existing machine authentication data to edit."));
					return;
				}
			}

			m_pRealForm->setCursor(Qt::ArrowCursor);
			m_pMachineAuth->show();
		}
		else
		{
			m_pRealForm->setCursor(Qt::ArrowCursor);
			QMessageBox::critical(m_pRealForm, tr("Error"), tr("An error occurred when attempting to launch the Connection Wizard"));
			delete m_pMachineAuth;
			m_pMachineAuth = NULL;
		}
	}
}

void ConnectMgrDlg::menuViewLog(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotViewLog();
}

void ConnectMgrDlg::menuAbout(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotAbout();
}

void ConnectMgrDlg::menuQuit(void)
{
	// !!! TODO: warn about any open connections?!
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotExit();
}

void ConnectMgrDlg::menuClose(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
}

void ConnectMgrDlg::menuCreateTicket(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotCreateTroubleticket();
}

void ConnectMgrDlg::menuHelp(void)
{
	HelpWindow::showPage("xsupphelp.html", "xsupconnections");
}

void ConnectMgrDlg::configUpdate()
{
	config_globals *globals = NULL;

	tabStateUpdate();
	setSaveEnabled(false);

	globals = (config_globals *)malloc(sizeof(config_globals));
	if (globals == NULL)
	{
		QMessageBox::critical(this, tr("Error"), tr("Unable to allocate memory needed to store configuration globals."));
		return;
	}

	memset(globals, 0x00, sizeof(config_globals));
	xsupconfig_defaults_set_globals(globals);

	// Save logging tab data
	if (m_pEnableLogging->checkState() == Qt::Unchecked)
	{
		// Clear out the path, and log level.
		if (globals->logpath != NULL) free(globals->logpath);
		globals->logpath = NULL;

		globals->loglevel = 0;
		globals->logtype = LOGGING_NONE;
	}
	else
	{
		if (globals->logpath != NULL) free(globals->logpath);
		globals->logpath = NULL;

		globals->logtype = LOGGING_FILE;
		globals->logpath = _strdup(m_pLogPath->text().toAscii());

		switch (m_pLogLevel->currentIndex())
		{
		case LOGGING_NORMAL:
			globals->loglevel = DEBUG_NORMAL;
			break;

		case LOGGING_VERBOSE:
			globals->loglevel = (DEBUG_VERBOSE | DEBUG_NORMAL);
			break;

		case LOGGING_DEBUG:
			globals->loglevel = DEBUG_ALL;
			break;

		default:
			QMessageBox::critical(this, tr("Form design error"), tr("You have selected a log level setting that is not understood.  Your form design may be incorrect.  Defaulting to NORMAL logging."));
			globals->loglevel = DEBUG_NORMAL;
			break;
		}
	}

	globals->flags |= CONFIG_GLOBALS_FRIENDLY_WARNINGS;

	if (m_pRollBySize->isChecked())
	{
		globals->flags |= CONFIG_GLOBALS_ROLL_LOGS;
	}
	else
	{
		globals->flags &= (~CONFIG_GLOBALS_ROLL_LOGS);
	}

	globals->logs_to_keep = m_pLogsToKeep->value();

	globals->size_to_roll = m_pSizeToRoll->value();

	// save Advanced Settings tab data
	if (m_pAllowMachineAuthContinue != NULL)
	{
		if (m_pAllowMachineAuthContinue->isChecked())
		{
			globals->flags |= CONFIG_GLOBALS_ALLOW_MA_REMAIN;
		}
		else
		{
			globals->flags &= (~CONFIG_GLOBALS_ALLOW_MA_REMAIN);
		}
	}

	if (m_pAssocTimeout != NULL)
	{
		globals->assoc_timeout = atoi(m_pAssocTimeout->text().toAscii());
	}

	if (m_pScanTimeout != NULL)
	{
		globals->active_timeout = atoi(m_pScanTimeout->text().toAscii());
	}

	if (m_pPassiveInterval != NULL)
	{
		globals->passive_timeout = m_pPassiveInterval->value();
	}

	if (m_pPMKSACacheTimeout != NULL)
	{
		globals->pmksa_age_out = m_pPMKSACacheTimeout->value();
	}

	if (m_pPMKSACacheRefresh != NULL)
	{
		globals->pmksa_cache_check = m_pPMKSACacheRefresh->value();
	}

	if (m_pCheckSupplicants != NULL)
	{
		if (m_pCheckSupplicants->isChecked())
		{
			globals->flags |= CONFIG_GLOBALS_DETECT_ON_STARTUP;
		}
		else
		{
			globals->flags &= (~CONFIG_GLOBALS_DETECT_ON_STARTUP);
		}
	}

	if (m_pDisconnectAtLogoff != NULL)
	{
		if (m_pDisconnectAtLogoff->isChecked())
		{
			globals->flags |= CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF;
		}
		else
		{
			globals->flags &= (~CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF);
		}
	}

	// save Advanced Timers settings
	if (m_pAuthPeriod != NULL)
	{
		globals->auth_period = atoi(m_pAuthPeriod->text().toAscii());
	}

	if (m_pHeldPeriod != NULL)
	{
		globals->held_period = atoi(m_pHeldPeriod->text().toAscii());
	}

	if (m_pIdlePeriod != NULL)
	{
		globals->idleWhile_timeout = atoi(m_pIdlePeriod->text().toAscii());
	}

	if (m_pStaleKey != NULL)
	{
		globals->stale_key_timeout = atoi(m_pStaleKey->text().toAscii());
	}

	if (m_pMaxStarts != NULL)
	{
		globals->max_starts = atoi(m_pMaxStarts->text().toAscii());
	}

	if (xsupgui_request_set_globals_config(globals) != REQUEST_SUCCESS)
	{
		QMessageBox::critical(this, tr("Cannot Save"), tr("Unable to save your configuration data."));
		xsupgui_request_free_config_globals(&globals);
		return;
	}

	if (xsupgui_request_write_config(CONFIG_LOAD_GLOBAL, NULL) != REQUEST_SUCCESS)
	{
		QMessageBox::critical(this, tr("Cannot Save"), tr("Unable to save your configuration data."));
		xsupgui_request_free_config_globals(&globals);
		return;
	}

	xsupgui_request_free_config_globals(&globals);
}

void ConnectMgrDlg::updateCheckboxes()
{
	tabStateUpdate();
	setSaveEnabled(true);
}

void ConnectMgrDlg::tabStateUpdate()
{
	if (m_pEnableLogging->isChecked())
		setLoggingEnabled(true);
	else
		setLoggingEnabled(false);
}

void ConnectMgrDlg::resetAdvTimers()
{
	m_pAuthPeriod->setValue(32);
	m_pHeldPeriod->setValue(60);
	m_pIdlePeriod->setValue(32);
	m_pStaleKey->setValue(600);
	m_pMaxStarts->setValue(3);

	enableSaveBtns();
}

void ConnectMgrDlg::resetAdvSettings()
{
	m_pCheckSupplicants->setChecked(true);
	m_pDisconnectAtLogoff->setChecked(true);
	m_pAllowMachineAuthContinue->setChecked(false);
	m_pScanTimeout->setValue(30);
	m_pAssocTimeout->setValue(60);
	m_pPassiveInterval->setValue(30);
	m_pPMKSACacheRefresh->setValue(10);
	m_pPMKSACacheTimeout->setValue(300);

	enableSaveBtns();
}

void ConnectMgrDlg::browseLogs()
{
  QString logDir = m_pLogPath->text();
  QString directory = QFileDialog::getExistingDirectory(m_pRealForm,
                             tr("Select Logging Folder"), logDir);
  if (!directory.isEmpty()) 
  {
#ifdef WINDOWS
	  directory.replace("/", "\\");   // Replace the / with a \ on Windows.
#endif
    m_pLogPath->setText(directory);
  }
}

void ConnectMgrDlg::viewLog()
{
  QString temp;

	if (m_pViewLogDialog != NULL)
	{
		cleanupuiWindowViewLogs();   // Close out the old one.
	}

	temp = m_pLogPath->text();
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

void ConnectMgrDlg::cleanupuiWindowViewLogs()
{
	if (m_pViewLogDialog != NULL)
	{
		Util::myDisconnect(m_pViewLogDialog, SIGNAL(close()), this, SLOT(cleanupuiWindowViewLogs()));
		delete m_pViewLogDialog;
		m_pViewLogDialog = NULL;
	}
}

void ConnectMgrDlg::populateSettingsTabs()
{
	config_globals *myglobals = NULL;
	int areadmin = 0;

	if ((xsupgui_request_get_are_administrator(&areadmin) != REQUEST_SUCCESS) || (areadmin != TRUE))
	{
		// Disable the logging, advsettings, and adv timers tabs.
		// remove them in reverse order as the indicies shift when a tab is removed.
		m_pMainTab->removeTab(4);
		m_pMainTab->removeTab(3);
		m_pMainTab->removeTab(2);

		return;
	}

	if (xsupgui_request_get_globals_config(&myglobals) != REQUEST_SUCCESS) 
	{
		QMessageBox::critical(this, tr("Request Failed"), tr("Unable to get global configuration settings."));
		return;
	}

	// Logging tab objects
	if (myglobals->logtype == LOGGING_FILE) 
	{
		m_pEnableLogging->setChecked(true);
		setLoggingEnabled(true);
	}
	else
	{
		m_pEnableLogging->setChecked(false);
		setLoggingEnabled(false);
	}

	m_pLogPath->setText(myglobals->logpath);

	if ((myglobals->loglevel & DEBUG_ALL) == DEBUG_ALL)
	{
		m_pLogLevel->setCurrentIndex(LOGGING_DEBUG);
	}
	else if ((myglobals->loglevel & DEBUG_VERBOSE) == DEBUG_VERBOSE)
	{
		m_pLogLevel->setCurrentIndex(LOGGING_VERBOSE);
	}
	else
	{
		m_pLogLevel->setCurrentIndex(LOGGING_NORMAL);
	}

	m_pLogsToKeep->setValue(myglobals->logs_to_keep);

	if ((myglobals->logtype == LOGGING_FILE) && (myglobals->flags & CONFIG_GLOBALS_ROLL_LOGS) == CONFIG_GLOBALS_ROLL_LOGS)
	{
		m_pRollBySize->setChecked(true);
		m_pSizeToRoll->setEnabled(true);
	}
	else
	{
		m_pRollBySize->setChecked(false);
		m_pSizeToRoll->setEnabled(false);
	}

	m_pSizeToRoll->setValue(myglobals->size_to_roll);

	// advanced settings
	if ((myglobals->flags & CONFIG_GLOBALS_DETECT_ON_STARTUP) == CONFIG_GLOBALS_DETECT_ON_STARTUP)
	{
		m_pCheckSupplicants->setChecked(true);
	}
	else
	{
		m_pCheckSupplicants->setChecked(false);
	}

	if ((myglobals->flags & CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF) == CONFIG_GLOBALS_DISCONNECT_AT_LOGOFF)
	{
		m_pDisconnectAtLogoff->setChecked(true);
	}
	else
	{
		m_pDisconnectAtLogoff->setChecked(false);
	}

	if ((myglobals->flags & CONFIG_GLOBALS_ALLOW_MA_REMAIN) == CONFIG_GLOBALS_ALLOW_MA_REMAIN)
	{
		m_pAllowMachineAuthContinue->setChecked(true);
	}
	else
	{
		m_pAllowMachineAuthContinue->setChecked(false);
	}

	m_pScanTimeout->setValue(myglobals->active_timeout);
	m_pAssocTimeout->setValue(myglobals->assoc_timeout);
	m_pPassiveInterval->setValue(myglobals->passive_timeout);

	if (myglobals->pmksa_cache_check == 0)
		m_pPMKSACacheRefresh->setValue(PMKSA_CACHE_REFRESH);
	else
		m_pPMKSACacheRefresh->setValue(myglobals->pmksa_cache_check);

	if (myglobals->pmksa_age_out == 0)
		m_pPMKSACacheTimeout->setValue(PMKSA_DEFAULT_AGEOUT_TIME);
	else
		m_pPMKSACacheTimeout->setValue(myglobals->pmksa_age_out);

	// advanced timers
	if (myglobals->auth_period == 0)
		m_pAuthPeriod->setValue(AUTHENTICATION_TIMEOUT);
	else
		m_pAuthPeriod->setValue(myglobals->auth_period);

	if (myglobals->held_period == 0)
		m_pHeldPeriod->setValue(HELD_STATE_TIMEOUT);
	else
		m_pHeldPeriod->setValue(myglobals->held_period);

	if (myglobals->idleWhile_timeout == 0)
		m_pIdlePeriod->setValue(IDLE_WHILE_TIMER);
	else
		m_pIdlePeriod->setValue(myglobals->idleWhile_timeout);

	if (myglobals->stale_key_timeout == 0)
		m_pStaleKey->setValue(STALE_KEY_WARN_TIMEOUT);
	else
		m_pStaleKey->setValue(myglobals->stale_key_timeout);

	if (myglobals->max_starts == 0)
		m_pMaxStarts->setValue(MAX_STARTS);
	else
		m_pMaxStarts->setValue(myglobals->max_starts);

	xsupgui_request_free_config_globals(&myglobals);
}

void ConnectMgrDlg::setLoggingEnabled(bool enabled)
{
	m_pLogPath->setEnabled(enabled);
	m_pBrowse->setEnabled(enabled);
	m_pLogLevel->setEnabled(enabled);
	m_pViewLog->setEnabled(enabled);
	m_pLogsToKeep->setEnabled(enabled);
	m_pRollBySize->setEnabled(enabled);
	if ((m_pRollBySize->isChecked()) && (enabled == true))
		m_pSizeToRoll->setEnabled(true);
	else
		m_pSizeToRoll->setEnabled(false);
}

void ConnectMgrDlg::enableSaveBtns()
{
	setSaveEnabled(true);
}

void ConnectMgrDlg::setSaveEnabled(bool enabled)
{
	m_pLoggingSave->setEnabled(enabled);
	m_pAdvSettingsSave->setEnabled(enabled);
	m_pAdvTimersSave->setEnabled(enabled);
}
