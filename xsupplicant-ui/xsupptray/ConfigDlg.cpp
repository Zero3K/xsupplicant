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
#include "Util.h"
#include "FormLoader.h"
#include "ConfigDlg.h"
#include "helpbrowser.h"
#include "TrayApp.h"

ConfigDlg::ConfigDlg(XSupCalls &sup, Emitter *e, QWidget *parent, TrayApp *trayApp)
	:QWidget(parent), m_pEmitter(e), m_supplicant(sup), m_pTrayApp(trayApp)
{
	int pluginStatus = PLUGIN_LOAD_FAILURE;
	char *plugin_path = NULL;
	QString qplugin_path = QApplication::applicationDirPath() + "/Modules/";


	m_pRealForm = NULL;
	m_pConns = NULL;
	m_pProfs = NULL;

	m_pNavPanel = NULL;
	m_pConfigInfo = NULL;
	m_pPlugins = NULL;

  uiCallbacks.launchHelpP = &HelpWindow::showPage;

	// For now statically load the plugin and set its type.
	// This definitely needs to be handled differently with multiple plugins
	m_pPlugins = new UIPlugins(m_pEmitter, &m_supplicant);

	if(m_pPlugins != NULL)
	{
		qplugin_path += "PostureComplianceTab.dll";
		plugin_path = _strdup(qplugin_path.toAscii());

#ifdef WINDOWS
		Util::useBackslash(plugin_path);
#endif

		pluginStatus = m_pPlugins->loadPlugin(plugin_path);

		free(plugin_path);

		if(pluginStatus == PLUGIN_LOAD_SUCCESS)
		{
			m_pPlugins->setType(PLUGIN_TYPE_PROFILE_TAB);
			m_pPlugins->instantiateWidget();    // This *MUST* come after the setType() call.
			m_pPlugins->setCallbacks(uiCallbacks);
		}
		else
		{
			delete m_pPlugins;
			m_pPlugins = NULL;
		}
	}
}

ConfigDlg::~ConfigDlg()
{
	UIPlugins *currentPlugin = m_pPlugins;

	// It's best to delete the plugins first.
	// Qt says that deleting a widget is the best way to sever its connection with the parent
	// So we want to delete the plugins before the parent is destroyed and tries to delete us instead.
	while(currentPlugin != NULL)
	{
		currentPlugin = m_pPlugins->next;

		delete m_pPlugins;

		m_pPlugins = currentPlugin;
	}

	if (m_pConfigInfo != NULL)
	{
		delete m_pConfigInfo;
		m_pConfigInfo = NULL;
	}

	if (m_pNavPanel != NULL)
	{
		delete m_pNavPanel;
		m_pNavPanel = NULL;
	}

	if (m_pRealForm != NULL)
	{
		m_pRealForm->deleteLater();
		m_pRealForm = NULL;
	}
}

bool ConfigDlg::create()
{
	QWidget *m_pNavBox = NULL;
	QWidget *m_pConfInfo = NULL;
	Qt::WindowFlags flags;

	m_pRealForm = FormLoader::buildform("ConfigWindow.ui");

    if (m_pRealForm == NULL) 
		return false;

	// Then, get our enumerations.
	if (m_supplicant.enumAndSortConnections(&m_pConns, true) == false)
		m_pConns = NULL;

	if (m_supplicant.enumProfiles((CONFIG_LOAD_GLOBAL | CONFIG_LOAD_USER), &m_pProfs, true) == false)
		m_pProfs = NULL;

	if (m_supplicant.enumTrustedServers((CONFIG_LOAD_GLOBAL | CONFIG_LOAD_USER), &m_pTrustedServers, true) == false)
		m_pTrustedServers = NULL;

	m_pNavBox = qFindChild<QWidget*>(m_pRealForm, "backgroundTree");

	if (m_pNavBox == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QWidget by the name of 'backgroundTree'."));
		return false;
	}

	m_pNavPanel = new NavPanel(m_pNavBox, m_pConns, m_pProfs, m_pTrustedServers, m_pEmitter, &m_supplicant, this);

	if ((m_pNavPanel == NULL) || (m_pNavPanel->attach() == false)) return false;

	m_pConfInfo = qFindChild<QWidget*>(m_pRealForm, "backgroundMain");

	if (m_pConfInfo == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QWidget by the name of 'backgroundMain'."));
		return false;
	}

	m_pConfigInfo = new ConfigInfo(m_pConfInfo, &m_pConns, &m_pProfs, &m_pTrustedServers, m_pEmitter, &m_supplicant, m_pNavPanel, m_pPlugins, this);

	if ((m_pConfigInfo == NULL) || (m_pConfigInfo->attach() == false)) return false;

	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMaximizeButtonHint;
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);

	return this->buildMenuBar();
}

bool ConfigDlg::buildMenuBar(void)
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

void ConfigDlg::show()
{
	if (m_pRealForm->isVisible() == true) m_pRealForm->hide();

	m_pRealForm->show();
}

bool ConfigDlg::isVisible(void)
{
	if (m_pRealForm != NULL)
		return m_pRealForm->isVisible();
	else
		return false;
}

void ConfigDlg::bringToFront(void)
{
	if (m_pRealForm != NULL)
	{
		m_pRealForm->raise();
		m_pRealForm->activateWindow();
	}
}

void ConfigDlg::menuViewLog(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotViewLog();
}

void ConfigDlg::menuAbout(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotAbout();
}

void ConfigDlg::menuQuit(void)
{
	// !!! TODO: warn about any open connections?!
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotExit();
}

void ConfigDlg::menuClose(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
}

void ConfigDlg::menuCreateTicket(void)
{
	if (m_pTrayApp != NULL)
		m_pTrayApp->slotCreateTroubleticket();
}

void ConfigDlg::menuHelp(void)
{
	HelpWindow::showPage("xsupphelp.html", "xsupconnections");
}