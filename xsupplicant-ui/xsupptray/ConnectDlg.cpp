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

#include <QVector>
#include <algorithm>

#include "ConnectDlg.h"
#include "FormLoader.h"
#include "Emitter.h"
#include "TrayApp.h"
#include "SSIDListDlg.h"
#include "ConnectionWizard.h"
#include "ConnectionInfoDlg.h"
#include "XSupWrapper.h"
#include "helpbrowser.h"

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

static const QString editConnString = QWidget::tr("Edit Connections...");
static const QString seperatorString = "-----";

ConnectDlg::ConnectDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *trayApp)
	: QWidget(parent), 
	m_pParent(parent),
	m_pParentWindow(parentWindow),
	m_pEmitter(e),
	m_pTrayApp(trayApp)
{
	m_pSSIDListDlg = NULL;
	m_pConnWizard = NULL;
	m_pConnInfo = NULL;
	m_days = 0;
	m_volatileWirelessConn = false;
}

ConnectDlg::~ConnectDlg()
{ 
	if (m_pCloseButton != NULL)
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
	
	if (m_pWirelessBrowseButton != NULL)
		Util::myDisconnect(m_pWirelessBrowseButton, SIGNAL(clicked()), this, SLOT(showSSIDList()));
		
	if (m_pWirelessAdapterList != NULL)
		Util::myConnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
				
	if (m_pWirelessConnectionList != NULL)
		Util::myDisconnect(m_pWirelessConnectionList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessConnection(int)));		
	
	if (m_pWiredAdapterList != NULL)
		Util::myConnect(m_pWiredAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredAdapter(int)));
				
	if (m_pWiredConnectionList != NULL)
		Util::myDisconnect(m_pWiredConnectionList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredConnection(int)));	
		
	if (m_pConnWizardButton != NULL)
		Util::myDisconnect(m_pConnWizardButton, SIGNAL(clicked()), this, SLOT(launchConnectionWizard()));

	if (m_pWiredConnectButton != NULL)
		Util::myDisconnect(m_pWiredConnectButton, SIGNAL(clicked()), this, SLOT(connectDisconnectWiredConnection()));

	if (m_pWirelessConnectButton != NULL)
		Util::myDisconnect(m_pWirelessConnectButton, SIGNAL(clicked()), this, SLOT(connectDisconnectWirelessConnection()));

	if (m_pAdapterTabControl != NULL)
		Util::myConnect(m_pAdapterTabControl, SIGNAL(currentChanged(int)), this, SLOT(currentTabChanged(int)));
		
	if (m_pWirelessConnectionInfo != NULL)
		Util::myConnect(m_pWirelessConnectionInfo, SIGNAL(clicked()), this, SLOT(showWirelessConnectionInfo()));
		
	if (m_pWiredConnectionInfo != NULL)
		Util::myConnect(m_pWiredConnectionInfo, SIGNAL(clicked()), this, SLOT(showWiredConnectionInfo()));			

	Util::myDisconnect(&m_timer, SIGNAL(timeout()), this, SLOT(timerUpdate()));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalSignalStrength(const QString &, int)), this, SLOT(slotSignalUpdate(const QString &, int)));

	Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(interfaceInserted(char *)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceRemoved(char *)), this, SLOT(interfaceRemoved(char *)));		

	Util::myDisconnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(populateConnectionLists()));		
	Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
		this, SLOT(stateChange(const QString &, int, int, int, unsigned int)));
		
	Util::myDisconnect(m_pEmitter, SIGNAL(signalPSKSuccess(const QString &)), this, SLOT(pskSuccess(const QString &)));
		
	if (m_pSSIDListDlg != NULL)
		delete m_pSSIDListDlg;
		
	if (m_pConnInfo != NULL)
		delete m_pConnInfo;
		
	this->cleanupConnectionWizard();
	
	// !!! should clean up menu bar slots/signals here to be thorough
		
	if (m_pRealForm != NULL) 
		delete m_pRealForm;	
}

bool ConnectDlg::create(void)
{
	return initUI();
}

bool ConnectDlg::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("ConnectWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
	
	Qt::WindowFlags flags;
	
	// set window flags so minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMaximizeButtonHint;
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
		
	// cache pointers to objects on our UI 
	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");
	m_pWirelessBrowseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonWirelessBrowse");
	m_pAdapterTabControl = qFindChild<QTabWidget*>(m_pRealForm, "tabControlAdapterType");
	m_pWirelessAdapterList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWirelessAdapter");
	m_pWirelessConnectionList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWirelessConnection");
	m_pWiredAdapterList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWiredAdapter");
	m_pWiredConnectionList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWiredConnection");
	m_pWirelessConnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonWirelessConnect");
	m_pWiredConnectButton = qFindChild<QPushButton*>(m_pRealForm, "buttonWiredConnect");
	m_pConnWizardButton = qFindChild<QPushButton*>(m_pRealForm, "buttonNewConnection");
	m_pWirelessConnectionStatus = qFindChild<QLabel*>(m_pRealForm, "dataFieldWirelessStatus");
	m_pWiredConnectionStatus = qFindChild<QLabel*>(m_pRealForm, "dataFieldWiredStatus");
	m_pWiredConnectionInfo = qFindChild<QPushButton*>(m_pRealForm, "buttonWiredDetails");
	m_pWirelessConnectionInfo = qFindChild<QPushButton*>(m_pRealForm, "buttonWirelessDetails");
	m_pWirelessNetworkName = qFindChild<QLabel*>(m_pRealForm, "dataFieldWirelessNetwork");;
	m_pWiredNetworkName = qFindChild<QLabel*>(m_pRealForm, "dataFieldWiredNetwork");;
	m_pWirelessSignalIcon = qFindChild<QLabel*>(m_pRealForm, "dataFieldWirelessSignalIcon");

	// populate text
	
	// wireless tab
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
		
	if (m_pConnWizardButton != NULL)
		m_pConnWizardButton->setText(tr("New Connection"));
	
	if (m_pWirelessBrowseButton != NULL)
		m_pWirelessBrowseButton->setText(tr("Browse"));
	
	QLabel *pAdapterLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessAdapter");
	if (pAdapterLabel != NULL)
		pAdapterLabel->setText(tr("Adapter:"));
		
	QLabel *pConnectionLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessConnection");
	if (pConnectionLabel != NULL)
		pConnectionLabel->setText(tr("Connection:"));
				
	QLabel *pStatusLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessStatus");
	if (pStatusLabel != NULL)
		pStatusLabel->setText(tr("Status:"));
		
	QLabel *pNetworkLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessNetwork");
	if (pNetworkLabel != NULL)
		pNetworkLabel->setText(tr("Network:"));			
		
	pAdapterLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredAdapter");
	if (pAdapterLabel != NULL)
		pAdapterLabel->setText(tr("Adapter:"));
				
	pConnectionLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredConnection");
	if (pConnectionLabel != NULL)
		pConnectionLabel->setText(tr("Connection:"));
		
	pStatusLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredStatus");
	if (pStatusLabel != NULL)
		pStatusLabel->setText(tr("Status:"));
		
	pNetworkLabel = qFindChild<QLabel*>(m_pRealForm, "labelWiredNetwork");
	if (pNetworkLabel != NULL)
		pNetworkLabel->setText(tr("Network:"));		
		
	if (m_pAdapterTabControl != NULL)
	{
		m_pAdapterTabControl->setTabText(0,tr("Wireless"));
		m_pAdapterTabControl->setTabText(1,tr("Wired"));
	}

	// set up event-handling
	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));

	if (m_pWirelessBrowseButton != NULL)
		Util::myConnect(m_pWirelessBrowseButton, SIGNAL(clicked()), this, SLOT(showSSIDList()));
		
	if (m_pWirelessAdapterList != NULL)
		Util::myConnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
		
	if (m_pWirelessConnectionList != NULL)
		Util::myConnect(m_pWirelessConnectionList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessConnection(int)));
		
	if (m_pWiredAdapterList != NULL)
		Util::myConnect(m_pWiredAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredAdapter(int)));
		
	if (m_pWiredConnectionList != NULL)
		Util::myConnect(m_pWiredConnectionList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredConnection(int)));
		
	if (m_pConnWizardButton != NULL)
		Util::myConnect(m_pConnWizardButton, SIGNAL(clicked()), this, SLOT(launchConnectionWizard()));

	if (m_pWiredConnectButton != NULL)
		Util::myConnect(m_pWiredConnectButton, SIGNAL(clicked()), this, SLOT(connectDisconnectWiredConnection()));

	if (m_pWirelessConnectButton != NULL)
		Util::myConnect(m_pWirelessConnectButton, SIGNAL(clicked()), this, SLOT(connectDisconnectWirelessConnection()));	

	if (m_pAdapterTabControl != NULL)
		Util::myConnect(m_pAdapterTabControl, SIGNAL(currentChanged(int)), this, SLOT(currentTabChanged(int)));
		
	if (m_pWirelessConnectionInfo != NULL)
		Util::myConnect(m_pWirelessConnectionInfo, SIGNAL(clicked()), this, SLOT(showWirelessConnectionInfo()));
		
	if (m_pWiredConnectionInfo != NULL)
		Util::myConnect(m_pWiredConnectionInfo, SIGNAL(clicked()), this, SLOT(showWiredConnectionInfo()));		

	Util::myConnect(m_pEmitter, SIGNAL(signalConnConfigUpdate()), this, SLOT(populateConnectionLists()));		
	Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)),
		this, SLOT(stateChange(const QString &, int, int, int, unsigned int)));

	Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(interfaceInserted(char *)));
	Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceRemoved(char *)), this, SLOT(interfaceRemoved(char *)));
	Util::myConnect(m_pEmitter, SIGNAL(signalPSKSuccess(const QString &)), this, SLOT(pskSuccess(const QString &)));
	
	Util::myConnect(&m_timer, SIGNAL(timeout()), this, SLOT(timerUpdate()));
	Util::myConnect(m_pEmitter, SIGNAL(signalSignalStrength(const QString &, int)), this, SLOT(slotSignalUpdate(const QString &, int)));
	
	
	// set initial state of UI - mainly setting the active tab
	if (m_pAdapterTabControl != NULL)
		m_pAdapterTabControl->setCurrentIndex(0);
	
	if (m_pWirelessAdapterList != NULL) 
	{
		this->populateWirelessAdapterList();
		this->selectWirelessAdapter(0);
	}
	
	if (m_pWiredAdapterList != NULL)
	{
		this->populateWiredAdapterList();
		this->selectWiredAdapter(0);
	}
				
	// jking - not sure this button should exist on this screen. hiding for now			
	if (m_pConnWizardButton != NULL)
		m_pConnWizardButton->hide();				
	
	// load icons for signal strength
	QPixmap *p;
	
	p = FormLoader::loadicon("signal_0.png");
	if (p != NULL)
	{
		m_signalIcons[0] = *p;
		delete p;
	}
	
	p = FormLoader::loadicon("signal_1.png");
	if (p != NULL)
	{
		m_signalIcons[1] = *p;
		delete p;
	}

	p = FormLoader::loadicon("signal_2.png");
	if (p != NULL)
	{
		m_signalIcons[2] = *p;
		delete p;
	}
	
	p = FormLoader::loadicon("signal_3.png");
	if (p != NULL)
	{
		m_signalIcons[3] = *p;
		delete p;
	}
	
	p = FormLoader::loadicon("signal_4.png");
	if (p != NULL)
	{
		m_signalIcons[4] = *p;
		delete p;		
	}
	
	return this->buildMenuBar();
}

bool ConnectDlg::buildMenuBar(void)
{
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
				pAction->setText(tr("View Log"));
				pAction->setFont(pMenuBar->font());
				pAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_L));
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuViewLog()));
				pToolsMenu->addAction(pAction);
			}
			
			pAction = new QAction(NULL);
			if (pAction != NULL)
			{
				pAction->setText(tr("Create Troubleticket"));
				pAction->setFont(pMenuBar->font());
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuCreateTicket()));
				pToolsMenu->addAction(pAction);
			}
			
			pToolsMenu->addSeparator();
			
			pAction = new QAction(NULL);
			if (pAction != NULL)
			{
				pAction->setText(tr("&Configure..."));
				pAction->setFont(pMenuBar->font());
				Util::myConnect(pAction, SIGNAL(triggered()), this, SLOT(menuConfigure()));
				pToolsMenu->addAction(pAction);
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

void ConnectDlg::show(void)
{
	// always start out on wireless tab by default, if possible
	if (m_pAdapterTabControl != NULL)
	{
		// if wireless page enabled, or if both pages disabled, show wireless tab
		if (m_pAdapterTabControl->isTabEnabled(0) == true || m_pAdapterTabControl->isTabEnabled(1) == false)
			m_pAdapterTabControl->setCurrentIndex(0);
		else
			m_pAdapterTabControl->setCurrentIndex(1);
	}
	
	if (m_pWirelessAdapterList != NULL)
	{
		m_pWirelessAdapterList->setCurrentIndex(0);
		this->selectWirelessAdapter(0);	
	}
	
	if (m_pWiredAdapterList != NULL)
	{
		m_pWiredAdapterList->setCurrentIndex(0);
		this->selectWiredAdapter(0);	
	}	
	
	if (m_pRealForm != NULL)
		m_pRealForm->show();
		
	// alert user if no adapters found
	if ((m_pWiredAdapterList == NULL || m_pWiredAdapterList->count() == 0) 
		&& (m_pWirelessAdapterList == NULL || m_pWirelessAdapterList->count() == 0))
	{
		QMessageBox::critical(m_pRealForm, 
			tr("No Network Adapters Found!"), 
			tr("XSupplicant was unable to locate any network adapters in the system.  You will not be able to connect to any networks."));
	}
}

void ConnectDlg::populateWirelessAdapterList(void)
{
	if (m_pWirelessAdapterList != NULL)
	{
		// QT generates events while populating a combobox, so stop listening during this time
		Util::myDisconnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
		
		QString oldSelection = m_pWirelessAdapterList->itemText(m_pWirelessAdapterList->currentIndex());
		m_pWirelessAdapterList->clear();
		m_pWirelessAdapterList->setToolTip("");
		
		m_wirelessAdapters.clear();
		m_wirelessAdapters = XSupWrapper::getWirelessAdapters();
		for (int i=0; i<m_wirelessAdapters.size();i++)
			m_pWirelessAdapterList->addItem(Util::removePacketSchedulerFromName(m_wirelessAdapters.at(i)));
			
		// try to restore the previous selection
		int idx = m_pWirelessAdapterList->findText(oldSelection);
		if (idx == -1)
			idx = 0;
		
		m_pWirelessAdapterList->setCurrentIndex(idx);
		this->selectWirelessAdapter(idx);		
			
		//m_pWirelessAdapterList->setEnabled(m_wirelessAdapters.size() > 1);
		
		// check if we have any adapters. If not, disable tab
		if (m_pAdapterTabControl != NULL) {
			QWidget *widget;
			bool enable = m_wirelessAdapters.size() > 0;
			
			m_pAdapterTabControl->setTabEnabled(0,enable);
			widget = m_pAdapterTabControl->widget(0);
			if (widget)
				widget->setEnabled(enable);
		}
			
		Util::myConnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
	}
}

void ConnectDlg::populateWiredAdapterList(void)
{	
	if (m_pWiredAdapterList != NULL)
	{	
		// QT generates events while populating a combobox, so stop listening during this time
		Util::myDisconnect(m_pWiredAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredAdapter(int)));
		
		QString oldSelection = m_pWiredAdapterList->itemText(m_pWirelessAdapterList->currentIndex());
		m_pWiredAdapterList->clear();
		m_pWiredAdapterList->setToolTip("");
		
		m_wiredAdapters.clear();
		m_wiredAdapters = XSupWrapper::getWiredAdapters();
		for (int i=0; i<m_wiredAdapters.size();i++)
			m_pWiredAdapterList->addItem(Util::removePacketSchedulerFromName(m_wiredAdapters.at(i)));
			
		// try to restore the previous selection
		int idx = m_pWiredAdapterList->findText(oldSelection);
		if (idx == -1)
			idx = 0;
		
		m_pWiredAdapterList->setCurrentIndex(idx);
		this->selectWiredAdapter(idx);
					
		//m_pWiredAdapterList->setEnabled(m_wiredAdapters.size() > 1);
		
		// check if we have any adapters. If not, disable tab
		if (m_pAdapterTabControl != NULL) {
			QWidget *widget;
			bool enable = m_wiredAdapters.size() > 0;
			
			m_pAdapterTabControl->setTabEnabled(1,enable);
			widget = m_pAdapterTabControl->widget(1);
			if (widget)
				widget->setEnabled(enable);
		}
					
		Util::myConnect(m_pWiredAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWiredAdapter(int)));
	}
}

void ConnectDlg::populateConnectionLists(void)
{
	this->populateWirelessConnectionList();
	this->populateWiredConnectionList();
}

void ConnectDlg::populateWirelessConnectionList(void)
{
	if (m_pWirelessConnectionList != NULL)
	{
		QString oldSelection = m_pWirelessConnectionList->itemText(m_pWirelessConnectionList->currentIndex());
		m_pWirelessConnectionList->clear();
		
		QVector<QString> connVector;
		connVector = XSupWrapper::getConnectionListForAdapter(m_currentWirelessAdapterDesc);
		for (int i=0; i<connVector.size(); i++)
			m_pWirelessConnectionList->addItem(connVector.at(i));
				
		if (m_pWirelessConnectionList->count() == 0)
			m_pWirelessConnectionList->addItem(QString(""));
		m_pWirelessConnectionList->addItem(seperatorString);		
		m_pWirelessConnectionList->addItem(editConnString);
		
		// try to restore the previous selection
		int idx = m_pWirelessConnectionList->findText(oldSelection);
		if (idx == -1)
			idx = 0;
			
		if (m_volatileWirelessConn == true)
		{		
			// Add blank item to list so that we don't inadvertently select a different (yet valid) connection
			//
			// this is purposefully 3 spaces to get around other code elsewhere checking for empty connection names								
			m_pWirelessConnectionList->addItem(QString("   "));
			idx = m_pWirelessConnectionList->count()-1;
		}					
		
		
		m_lastWirelessConnectionIdx = idx;
		m_pWirelessConnectionList->setCurrentIndex(idx);
		this->selectWirelessConnection(idx);
		
		// it's possible that the reason we're updating this list is because a connection changed from volatile
		// to non-volatile.  As such, update the wireless state to reflect the correct connection
		this->updateWirelessState();		
	}
}

void ConnectDlg::selectWirelessAdapter(int index)
{
	if (m_pWirelessAdapterList != NULL) 
	{
		// check range so we don't index outside of vector and cause exception
		if (index >= 0 && index < m_wirelessAdapters.size())
			m_currentWirelessAdapterDesc = m_wirelessAdapters.at(index);
		else
			m_currentWirelessAdapterDesc = "";
		m_pWirelessAdapterList->setToolTip(m_currentWirelessAdapterDesc);
		
		char *pDeviceName = NULL;
		int retval;
		
		// cache off adapter name
		retval = xsupgui_request_get_devname(m_currentWirelessAdapterDesc.toAscii().data(), &pDeviceName);
		if (retval == REQUEST_SUCCESS && pDeviceName != NULL)
			m_currentWirelessAdapterName = pDeviceName;
			
		if (pDeviceName != NULL)
			free(pDeviceName);
		
		// if selected adapter is invalid, disable browse button
		if (m_pWirelessBrowseButton != NULL)
			m_pWirelessBrowseButton->setEnabled(!m_currentWirelessAdapterDesc.isEmpty());
	}
	
	this->populateWirelessConnectionList();
	this->updateWirelessState();
}

void ConnectDlg::populateWiredConnectionList(void)
{
	if (m_pWiredConnectionList != NULL)
	{
		QString oldSelection = m_pWiredConnectionList->itemText(m_pWiredConnectionList->currentIndex());
		m_pWiredConnectionList->clear();
		
		QVector<QString> connVector;
		connVector = XSupWrapper::getConnectionListForAdapter(m_currentWiredAdapterDesc);

		for (int i=0; i<connVector.size(); i++)
			m_pWiredConnectionList->addItem(connVector.at(i));
				
		if (m_pWiredConnectionList->count() == 0)
			m_pWiredConnectionList->addItem(QString(""));
		m_pWiredConnectionList->addItem(seperatorString);
		m_pWiredConnectionList->addItem(editConnString);

		// try to restore the previous selection
		int idx = m_pWiredConnectionList->findText(oldSelection);
		if (idx == -1)
			idx = 0;
			
		m_lastWiredConnectionIdx = idx;
		m_pWiredConnectionList->setCurrentIndex(idx);
		this->selectWiredConnection(idx);
	}
}

void ConnectDlg::selectWiredAdapter(int index)
{
	if (m_pWiredAdapterList != NULL) {
		if (index >=0 && index < m_wiredAdapters.size())
			m_currentWiredAdapterDesc = m_wiredAdapters.at(index);
		else
			m_currentWiredAdapterDesc = "";
			
		m_pWiredAdapterList->setToolTip(m_currentWiredAdapterDesc);
		
		char *pDeviceName = NULL;
		int retval;
		
		// cache off device name
		retval = xsupgui_request_get_devname(m_currentWiredAdapterDesc.toAscii().data(), &pDeviceName);
		if (retval == REQUEST_SUCCESS && pDeviceName != NULL)
			m_currentWiredAdapterName = pDeviceName;
			
		if (pDeviceName != NULL)
			free(pDeviceName);		
	}
	
	this->populateWiredConnectionList();
	this->updateWiredState();
}

void ConnectDlg::showSSIDList()
{	
	if (m_pSSIDListDlg == NULL)
	{
		// jking - for now assume this was launched via the connect dialog
		m_pSSIDListDlg = new SSIDListDlg(this, m_pRealForm, m_pEmitter, m_pTrayApp);
		if (m_pSSIDListDlg == NULL || m_pSSIDListDlg->create() == false)
		{
			QMessageBox::critical(m_pRealForm, tr("Form Creation Error"), tr("The SSID List Dialog form was unable to be created.  It is likely that the UI design file was not available.  Please correct this and try again."));
			if (m_pSSIDListDlg != NULL)
			{
				delete m_pSSIDListDlg;
				m_pSSIDListDlg = NULL;
			}			
		}
		else
		{
			m_pSSIDListDlg->refreshList(m_currentWirelessAdapterDesc);
			m_pSSIDListDlg->show();
		}
	}
	else
	{
		m_pSSIDListDlg->refreshList(m_currentWirelessAdapterDesc);
		m_pSSIDListDlg->show();
	}

}


void ConnectDlg::selectWirelessConnection(int connIdx)
{
	if (m_pWirelessConnectionList != NULL)
	{
		if (m_pWirelessConnectionList->itemText(connIdx) == editConnString)
		{
			// this is the "edit connections..." item.  Launch config
			m_pTrayApp->slotLaunchConfig();
			m_pWirelessConnectionList->setCurrentIndex(m_lastWirelessConnectionIdx);
		}
		else if (m_pWirelessConnectionList->itemText(connIdx) == seperatorString)
		{
			// not a valid selection. The "-----" item/separator
			m_pWirelessConnectionList->setCurrentIndex(m_lastWirelessConnectionIdx);
		}
		else
			m_lastWirelessConnectionIdx = connIdx;
			
		if (m_pWirelessConnectButton != NULL)
		{
			QString curConnName = m_pWirelessConnectionList->currentText();
			m_pWirelessConnectButton->setEnabled(!curConnName.isEmpty());
		}			
	}
}

void ConnectDlg::selectWiredConnection(int connIdx)
{
	if (m_pWiredConnectionList != NULL)
	{
		if (m_pWiredConnectionList->itemText(connIdx) == editConnString)
		{
			// this is the "edit connections..." item.  Launch config
			m_pTrayApp->slotLaunchConfig();
			m_pWiredConnectionList->setCurrentIndex(m_lastWiredConnectionIdx);
		}
		else if (m_pWiredConnectionList->itemText(connIdx) == seperatorString)
		{
			// not a valid selection. The "-----" item/separator
			m_pWiredConnectionList->setCurrentIndex(m_lastWiredConnectionIdx);
		}
		else
			m_lastWiredConnectionIdx = connIdx;
			
		if (m_pWiredConnectButton != NULL)
		{
			QString curConnName = m_pWiredConnectionList->currentText();
			m_pWiredConnectButton->setEnabled(!curConnName.isEmpty());
		}
	}
}

void ConnectDlg::launchConnectionWizard(void)
{
	if (m_pConnWizard == NULL)
	{
		// create the wizard if it doesn't already exist
		m_pConnWizard = new ConnectionWizard(this, m_pRealForm, m_pEmitter);
		if (m_pConnWizard != NULL)
		{
			if (m_pConnWizard->create() == true)
			{
				Util::myConnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
				Util::myConnect(m_pConnWizard, SIGNAL(finished(bool)), this, SLOT(finishConnectionWizard(bool)));
				m_pConnWizard->init();
				m_pConnWizard->show();
			}
			else
			{
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
		m_pConnWizard->init();
		m_pConnWizard->show();
	}
}

void ConnectDlg::finishConnectionWizard(bool)
{
	this->cleanupConnectionWizard();
}

void ConnectDlg::cleanupConnectionWizard(void)
{
	if (m_pConnWizard != NULL)
	{
		Util::myDisconnect(m_pConnWizard, SIGNAL(cancelled()), this, SLOT(cleanupConnectionWizard()));
		Util::myDisconnect(m_pConnWizard, SIGNAL(finished(bool)), this, SLOT(finishConnectionWizard(bool)));
	
		delete m_pConnWizard;
		m_pConnWizard = NULL;
	}
}

void ConnectDlg::connectWirelessConnection(void)
{
	int result = 0;

	// If the connection is already the active one, then ignore it.
	if (!XSupWrapper::isConnectionActive(m_currentWirelessAdapterName, m_pWirelessConnectionList->currentText(), true))
	{
		if ((result = XSupWrapper::connectToConnection(m_currentWirelessAdapterName, m_pWirelessConnectionList->currentText())) != REQUEST_SUCCESS)
		{
			switch (result)
			{
			case IPC_ERROR_INTERFACE_NOT_FOUND:
				QMessageBox::critical(this, tr("Connection Error"), tr("The requested interface is no longer available."));
				break;

			case IPC_ERROR_INVALID_CONN_NAME:
				QMessageBox::critical(this, tr("Connection Error"), tr("The connection name requested is invalid."));
				break;

			case IPC_ERROR_SSID_NOT_FOUND:
				QMessageBox::critical(this, tr("Connection Error"), tr("The requested wireless network was not found."));
				break;

			case IPC_ERROR_INVALID_PROF_NAME:
				QMessageBox::critical(this, tr("Connection Error"), tr("The connection you are attempting to connect to is missing a profile."));
				break;

			case IPC_ERROR_INVALID_CONTEXT:
				QMessageBox::critical(this, tr("Connection Error"), tr("The context for this connection is missing or corrupt."));
				break;

			default:
				QMessageBox::critical(this, tr("Connection Error"), tr("Unable to establish a wireless connection.  Error : %1").arg(result));
				break;
			}
		}
	}
}

void ConnectDlg::connectWiredConnection(void)
{
	int result = 0;

	// If the connection is already the active one, then ignore it.
	if (!XSupWrapper::isConnectionActive(m_currentWiredAdapterName, m_pWiredConnectionList->currentText(), false))
	{
		if ((result = XSupWrapper::connectToConnection(m_currentWiredAdapterName, m_pWiredConnectionList->currentText())) != REQUEST_SUCCESS)
		{
			switch (result)
			{
			case IPC_ERROR_INTERFACE_NOT_FOUND:
				QMessageBox::critical(this, tr("Connection Error"), tr("The requested interface is no longer available."));
				break;

			case IPC_ERROR_INVALID_CONN_NAME:
				QMessageBox::critical(this, tr("Connection Error"), tr("The connection name requested is invalid."));
				break;

			case IPC_ERROR_INVALID_PROF_NAME:
				QMessageBox::critical(this, tr("Connection Error"), tr("The connection you are attempting to connect to is missing a profile."));
				break;

			case IPC_ERROR_INVALID_CONTEXT:
				QMessageBox::critical(this, tr("Connection Error"), tr("The context for this connection is missing or corrupt."));
				break;

			default:
				QMessageBox::critical(this, tr("Connection Error"), tr("Unable to establish a wireless connection.  Error : %1").arg(result));
				break;
			}
		}
	}
}

void ConnectDlg::disconnectWirelessConnection(void)
{
	if (xsupgui_request_disconnect_connection(m_currentWirelessAdapterName.toAscii().data()) == REQUEST_SUCCESS)
	{
		stopAndClearTimer();	
	}
	else
	{
		QMessageBox::critical(NULL, tr("Disconnect Wireless"),
			tr("An error occurred while disconnecting device '%1'.\n").arg(m_currentWirelessAdapterDesc));	
	}
}

void ConnectDlg::disconnectWiredConnection(void)
{
	if (xsupgui_request_disconnect_connection(m_currentWiredAdapterName.toAscii().data()) == REQUEST_SUCCESS)
	{
		stopAndClearTimer();	
	}
	else
	{
		QMessageBox::critical(NULL, tr("Disconnect Wired"),
			tr("An error occurred while disconnecting device '%1'.\n").arg(m_currentWiredAdapterDesc));		
	}	
}

void ConnectDlg::updateWirelessState(void)
{
	int retVal = 0;
		
	if (m_currentWirelessAdapterName.isEmpty() == false)
	{
		int state = 0;
		Util::ConnectionStatus status = Util::status_idle;
		
		// get name of connection that's bound
		char *connName = NULL;
		config_connection *pConn = NULL;
		
		retVal = xsupgui_request_get_conn_name_from_int(m_currentWirelessAdapterName.toAscii().data(), &connName);
		if (retVal == REQUEST_SUCCESS && connName != NULL)
		{
			// get connection info so we can look at it when deciding 
			bool success = XSupWrapper::getConfigConnection(CONFIG_LOAD_USER, QString(connName), &pConn);
			if (success == false) success = XSupWrapper::getConfigConnection(CONFIG_LOAD_GLOBAL, QString(connName), &pConn);

			if (success == false && pConn != NULL)
			{
				XSupWrapper::freeConfigConnection(&pConn);
				pConn = NULL;
			}
		}
		else
		{
			if (connName != NULL)
				free(connName);
		}
		
		if (xsupgui_request_get_physical_state(m_currentWirelessAdapterName.toAscii().data(), &state) == REQUEST_SUCCESS)
		{
			if (state != WIRELESS_ASSOCIATED || (pConn != NULL && pConn->association.auth_type != AUTH_EAP))
			{
				status = Util::getConnectionStatusFromPhysicalState(state);
			}
			else
			{
				// only check with dot1X state machine if it's a dot1X connection
				if (xsupgui_request_get_1x_state(m_currentWirelessAdapterName.toAscii().data(), &state) == REQUEST_SUCCESS)
					status = Util::getConnectionStatusFromDot1XState(state);	
			}
		}
		
		if (m_pWirelessConnectionStatus != NULL)
			m_pWirelessConnectionStatus->setText(Util::getConnectionTextFromConnectionState(status));

		// don't mess with timer if this page isn't visible
		if (m_pAdapterTabControl != NULL && m_pAdapterTabControl->currentIndex() == 0)
		{				
			if (status == Util::status_connected)
				this->startConnectedTimer(m_currentWirelessAdapterName);
			else
				this->stopAndClearTimer();
		}
							
		if (status == Util::status_idle)
		{
			m_signalTimer.stop();
			if (m_pWirelessConnectionList != NULL)
				m_pWirelessConnectionList->setEnabled(true);
			if (m_pWirelessConnectButton != NULL)
			{
				m_pWirelessConnectButton->setText(tr("Connect"));
				m_pWirelessConnectButton->setEnabled(m_pWirelessConnectionList != NULL && m_pWirelessConnectionList->currentText().isEmpty() == false);
			}
			if (m_pWirelessConnectionInfo != NULL)
				m_pWirelessConnectionInfo->setEnabled(false);
			if (m_pWirelessNetworkName != NULL)
				m_pWirelessNetworkName->setText(QString(""));
			if (m_pWirelessSignalIcon != NULL)
			{
				m_pWirelessSignalIcon->clear();
				m_pWirelessSignalIcon->setToolTip("");
			}
			
			m_volatileWirelessConn = false;
			m_pskConnHack = "";
			
			// look for temporary item stuck in connection list for volatile wireless connection.  If we're idle, make sure
			// to clean this up
			if (m_pWirelessConnectionList != NULL)
			{
				bool selected;
				selected = m_pWirelessConnectionList->currentIndex() == m_pWirelessConnectionList->count() - 1;
				if (m_pWirelessConnectionList->itemText(m_pWirelessConnectionList->count() - 1).compare("   ") == 0)
				{
					// because QT will select a different item (and generate an event) when we remove an item,
					// select an alternate item first
					if (selected == true)
						m_pWirelessConnectionList->setCurrentIndex(0);				
					m_pWirelessConnectionList->removeItem(m_pWirelessConnectionList->count() - 1);
				}
			}			
		}
		else
		{
			m_signalTimer.start(300);
			if (m_pWirelessConnectionList != NULL)
				m_pWirelessConnectionList->setEnabled(false);
			if (m_pWirelessConnectButton != NULL)
			{
				m_pWirelessConnectButton->setText(tr("Disconnect"));
				m_pWirelessConnectButton->setEnabled(true);
			}
			if (m_pWirelessConnectionInfo != NULL)
				m_pWirelessConnectionInfo->setEnabled(true);							
			
			if (connName != NULL)
			{
				if (m_pWirelessConnectionList != NULL)
				{
					int index = m_pWirelessConnectionList->findText(QString(connName));
					if (index != -1) {
						m_pWirelessConnectionList->setCurrentIndex(index);
						if (m_volatileWirelessConn == true)
						{
							// it's possible that the connection was volatile before, but has changed to non-volatile (by the user
							// choosing to remember the password).  Detect that transition here and remove the volatile item.
							if (m_pWirelessConnectionList->itemText(m_pWirelessConnectionList->count() - 1).compare("   ") == 0)			
								m_pWirelessConnectionList->removeItem(m_pWirelessConnectionList->count() - 1);
						}							
						m_volatileWirelessConn = false;
											
					}
					else
					{
						if (pConn != NULL)
						{
							if ((pConn->flags & CONFIG_VOLATILE_CONN) == CONFIG_VOLATILE_CONN)
							{
								if (m_volatileWirelessConn == false)
								{
									m_volatileWirelessConn = true;
									
									// assume this is a volatile connection and add blank item to list so that we don't inadvertently
									// select a different (yet valid) connection
									//
									// this is purposefully 3 spaces to get around other code elsewhere checking for empty connection names								
									m_pWirelessConnectionList->addItem(QString("   "));
									m_pWirelessConnectionList->setCurrentIndex(m_pWirelessConnectionList->count()-1);
								}							
							}
							else
							{
								m_volatileWirelessConn = false;
							}
						}
					}					
				}		

				if (pConn != NULL)
				{
					if (m_pWirelessNetworkName != NULL)
						m_pWirelessNetworkName->setText(QString(pConn->ssid));
				}
				else
				{
					if (m_pWirelessNetworkName != NULL)
						m_pWirelessNetworkName->setText(tr("<Unknown>"));				
				}
			}
			else
			{
				if (m_pWirelessNetworkName != NULL)
					m_pWirelessNetworkName->setText(tr("<Unknown>"));				
			}
			
			this->updateWirelessSignalStrength();		
						
		}
		if (pConn != NULL)
		{
			XSupWrapper::freeConfigConnection(&pConn);
			pConn = NULL;
		}
		if (connName != NULL)
		{
			free(connName);
			connName = NULL;
		}
	}
	else
	{
		m_signalTimer.stop();
		
		if (m_pWirelessConnectionList != NULL)
			m_pWirelessConnectionList->setEnabled(true);
		if (m_pWirelessConnectButton != NULL)
			m_pWirelessConnectButton->setText(tr("Connect"));
		if (m_pWirelessConnectionInfo != NULL)
			m_pWirelessConnectionInfo->setEnabled(false);
		if (m_pWirelessNetworkName != NULL)
			m_pWirelessNetworkName->setText(QString(""));
		if (m_pWirelessSignalIcon != NULL)
		{
			m_pWirelessSignalIcon->clear();
			m_pWirelessSignalIcon->setToolTip("");
		}
		if (m_pWirelessConnectionStatus != NULL)
			m_pWirelessConnectionStatus->setText("");		
		m_pskConnHack = "";							
	}
}

void ConnectDlg::updateWiredState(void)
{
	int retVal = 0;
	
	if (m_currentWiredAdapterName.isEmpty() == false)
	{
		int state = 0;
		Util::ConnectionStatus status = Util::status_idle;

		if (xsupgui_request_get_1x_state(m_currentWiredAdapterName.toAscii().data(), &state) == REQUEST_SUCCESS)
		{
			status = Util::getConnectionStatusFromDot1XState(state);
			if (m_pWiredConnectionStatus != NULL)
				m_pWiredConnectionStatus->setText(Util::getConnectionTextFromConnectionState(status));
				
				// don't mess with timer if this page isn't visible
				if (m_pAdapterTabControl != NULL && m_pAdapterTabControl->currentIndex() == 1)
				{				
					if (status == Util::status_connected)
						this->startConnectedTimer(m_currentWiredAdapterName.toAscii().data());
					else
						this->stopAndClearTimer();
				}	
		}
		
		if (status == Util::status_idle)
		{
			if (m_pWiredConnectionList != NULL)
				m_pWiredConnectionList->setEnabled(true);		
			if (m_pWiredConnectButton != NULL)
				m_pWiredConnectButton->setText(tr("Connect"));
			if (m_pWiredConnectionInfo != NULL)
				m_pWiredConnectionInfo->setEnabled(false);
			if (m_pWiredNetworkName != NULL)
				m_pWiredNetworkName->setText(QString(""));					
		}
		else
		{
			if (m_pWiredConnectionList != NULL)
				m_pWiredConnectionList->setEnabled(false);
			if (m_pWiredConnectButton != NULL)
				m_pWiredConnectButton->setText(tr("Disconnect"));	
			if (m_pWiredConnectionInfo != NULL)
				m_pWiredConnectionInfo->setEnabled(true);
			if (m_pWiredNetworkName != NULL)
				m_pWiredNetworkName->setText(QString("N/A"));									
			
			// get name of connection that's bound
			char *connName;
			retVal = xsupgui_request_get_conn_name_from_int(m_currentWiredAdapterName.toAscii().data(), &connName);
			if (retVal == REQUEST_SUCCESS && connName != NULL)
			{
				if (m_pWiredConnectionList != NULL)
				{
					int index = m_pWiredConnectionList->findText(QString(connName));
					if (index != -1)
						m_pWiredConnectionList->setCurrentIndex(index);
					else
						m_pWiredConnectionList->setCurrentIndex(0);
				}			
			}		
				
			if (connName != NULL)
				free(connName);				
		}		
	}
	else
	{
		if (m_pWiredConnectionList != NULL)
			m_pWiredConnectionList->setEnabled(true);
		if (m_pWiredConnectButton != NULL)
			m_pWiredConnectButton->setText(tr("Connect"));
		if (m_pWiredConnectionInfo != NULL)
			m_pWiredConnectionInfo->setEnabled(false);
		if (m_pWiredNetworkName != NULL)
			m_pWiredNetworkName->setText(QString(""));
		if (m_pWiredConnectionStatus != NULL)
			m_pWiredConnectionStatus->setText("");					
	}
}

void ConnectDlg::timerUpdate(void)
{
	this->updateElapsedTime();
	this->showTime();
}

void ConnectDlg::updateElapsedTime()
{
	long int seconds = 0;
	if (xsupgui_request_get_seconds_authenticated(m_timerAdapterName.toAscii().data(), &seconds) == REQUEST_SUCCESS)
	{
		long int tempTime = seconds;
		int hours = 0;
		int minutes = 0;
    
		// Get days, hours, minutes and seconds the hard way - for now
		m_days = (unsigned int)(tempTime / (60*60*24));
		tempTime = tempTime % (60*60*24);
		hours = (int) (tempTime / (60*60));
		tempTime = tempTime % (60*60);
		minutes = (int) tempTime / 60;
		seconds = tempTime % 60;

		m_time.setHMS(hours, minutes, seconds);
	}
}

void ConnectDlg::startConnectedTimer(const QString &adapterName)
{
	m_timerAdapterName = adapterName;
	
	this->updateElapsedTime();
	this->showTime();
	
	m_timer.start(500);
}

void ConnectDlg::showTime()
{
	QString timeTxt = Util::getConnectionTextFromConnectionState(Util::status_connected);

	if (m_days > 0)
		timeTxt.append(QString("  (%1d, %2)").arg(m_days).arg(m_time.toString(Qt::TextDate)));
	else
		timeTxt.append(QString("  (%1)").arg(m_time.toString(Qt::TextDate)));

	if (m_pAdapterTabControl->currentIndex() == 0)
	{
		// We are showing wireless.
		m_pWirelessConnectionStatus->setText(timeTxt);
	}
	else
	{
		// We are showing wired.
		m_pWiredConnectionStatus->setText(timeTxt);
	}
}

void ConnectDlg::currentTabChanged(int tabidx)
{
	// 0 == wireless, 1 == wired
	if (tabidx == 0)
		this->updateWirelessState();
	else
		this->updateWiredState();
}

void ConnectDlg::stopAndClearTimer(void)
{
	m_timerAdapterName = "";
	m_timer.stop();
	m_time.setHMS(0, 0, 0);
}

void ConnectDlg::stateChange(const QString &intName, int, int, int, unsigned int)
{
	// We only care if it is the adapter that is currently displayed.
	if (m_pAdapterTabControl != NULL)
	{
		QString currentAdapterName;
		bool wireless;
		
		if (m_pAdapterTabControl->currentIndex() == 0)
		{
			currentAdapterName = m_currentWirelessAdapterName;
			wireless = true;
		}
		else
		{
			currentAdapterName = m_currentWiredAdapterName;
			wireless = false;
		}
			
		if (intName == currentAdapterName)
		{
			if (wireless == true)
				this->updateWirelessState();
			else
				this->updateWiredState();
		}
	}
}

void ConnectDlg::showWirelessConnectionInfo(void)
{
	if (m_pConnInfo == NULL)
	{
		m_pConnInfo= new ConnectionInfoDlg(this, m_pRealForm, m_pEmitter);
		if (m_pConnInfo != NULL && m_pConnInfo->create() != false)
		{
			m_pConnInfo->setAdapter(m_currentWirelessAdapterDesc);
			m_pConnInfo->show();
		}
		else
			QMessageBox::critical(m_pRealForm, tr("Error"), tr("An error occurred when trying to launch the Connection Info dialog"));
	}
	else
	{
		m_pConnInfo->setAdapter(m_currentWirelessAdapterDesc);
		m_pConnInfo->show();
	}
}

void ConnectDlg::showWiredConnectionInfo(void)
{
	if (m_pConnInfo == NULL)
	{
		m_pConnInfo= new ConnectionInfoDlg(this, m_pRealForm, m_pEmitter);
		if (m_pConnInfo != NULL && m_pConnInfo->create() != false)
		{
			m_pConnInfo->setAdapter(m_currentWiredAdapterDesc);
			m_pConnInfo->show();
		}
		else
			QMessageBox::critical(m_pRealForm, tr("Error"), tr("An error occurred when trying to launch the Connection Info dialog"));
	}
	else
	{
		m_pConnInfo->setAdapter(m_currentWiredAdapterDesc);
		m_pConnInfo->show();
	}
}

void ConnectDlg::interfaceInserted(char *)
{
	this->populateWirelessAdapterList();
	this->populateWiredAdapterList();
}

void ConnectDlg::interfaceRemoved(char *)
{
	this->populateWirelessAdapterList();
	this->populateWiredAdapterList();
	
	// make sure we don't show a tab that's not enabled
	if (m_pAdapterTabControl != NULL)
	{
		// if wireless page enabled, or if both pages disabled, show wireless tab
		if (m_pAdapterTabControl->isTabEnabled(0) == true || m_pAdapterTabControl->isTabEnabled(1) == false)
			m_pAdapterTabControl->setCurrentIndex(0);
		else
			m_pAdapterTabControl->setCurrentIndex(1);
	}
		
	// alert user if no adapters found
	if ((m_pWiredAdapterList == NULL || m_pWiredAdapterList->count() == 0) 
		&& (m_pWirelessAdapterList == NULL || m_pWirelessAdapterList->count() == 0))
	{
		QMessageBox::critical(m_pRealForm, 
			tr("No Network Adapters Found!"), 
			tr("XSupplicant was unable to locate any network adapters in the system.  You will not be able to connect to any networks."));
	}	
}

void ConnectDlg::connectDisconnectWiredConnection(void)
{
	if (m_pWiredConnectButton != NULL)
	{
		if (m_pWiredConnectButton->text() == tr("Connect"))
			this->connectWiredConnection();
		else
			this->disconnectWiredConnection();
	}
}

void ConnectDlg::connectDisconnectWirelessConnection(void)
{
	if (m_pWirelessConnectButton != NULL)
	{
		if (m_pWirelessConnectButton->text() == tr("Connect"))
			this->connectWirelessConnection();
		else
			this->disconnectWirelessConnection();
	}
}

void ConnectDlg::updateWirelessSignalStrength(void)
{
	int retval;
	int signal = 0;
	
	retval = xsupgui_request_get_signal_strength_percent(m_currentWirelessAdapterName.toAscii().data(), &signal);
	if (retval == REQUEST_SUCCESS)
	{
		if (m_pWirelessSignalIcon != NULL)
		{
			if (signal <= 11)
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[0]);
			else if (signal <= 37)
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[1]);
			else if (signal <= 62)
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[2]);
			else if (signal <= 88)
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[3]);
			else
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[4]);
				
			m_pWirelessSignalIcon->setToolTip(tr("Signal Strength: %1%").arg(signal));	
		}			
	}
	else
	{
		// clear out icon and label
		if (m_pWirelessSignalIcon != NULL)
		{
			m_pWirelessSignalIcon->setPixmap(m_signalIcons[0]);
			m_pWirelessSignalIcon->setToolTip(tr("Signal Strength: 0%"));
		}	
	}
}

void ConnectDlg::menuConfigure(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotLaunchConfig();
}

void ConnectDlg::menuViewLog(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotViewLog();
}

void ConnectDlg::menuAbout(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotAbout();
}

void ConnectDlg::menuQuit(void)
{
	// !!! TODO: warn about any open connections?!
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotExit();
}

void ConnectDlg::menuClose(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
}

void ConnectDlg::menuCreateTicket(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotCreateTroubleticket();
}

void ConnectDlg::menuHelp(void)
{
	HelpWindow::showPage("xsupphelp.html", "xsuploginmain");
}

void ConnectDlg::pskSuccess(const QString &)
{
}

void ConnectDlg::slotSignalUpdate(const QString &intName, int sigStrength)
{
	if (intName == m_currentWirelessAdapterName)
	{
		if (m_pWirelessSignalIcon != NULL)
		{
			if (sigStrength <= 11)
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[0]);
			else if (sigStrength <= 37)
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[1]);
			else if (sigStrength <= 62)
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[2]);
			else if (sigStrength <= 88)
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[3]);
			else
				m_pWirelessSignalIcon->setPixmap(m_signalIcons[4]);
				
			m_pWirelessSignalIcon->setToolTip(tr("Signal Strength: %1%").arg(sigStrength));	
		}			
	}
}

