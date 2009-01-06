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

#include <QRadioButton>

#include "MachineAuthWizard.h"
#include "ConnectionWizardData.h"
#include "WizardPages.h"
#include "FormLoader.h"
#include "Util.h"
#include "XSupWrapper.h"

MachineAuthWizard::MachineAuthWizard(QString adaptName, QWidget *parent, QWidget *parentWindow, Emitter *e)
	: QWidget(parent),
	m_pParent(parent),
	m_adapterName(adaptName),
	m_pParentWindow(parentWindow),
	m_pEmitter(e)
{
	for (int i=0; i<MachineAuthWizard::pageLastPage; i++)
		m_wizardPages[i] = NULL;

	m_currentPage = pageNoPage;
	m_editMode = false;
}

MachineAuthWizard::~MachineAuthWizard(void)
{
	if (m_pCancelButton != NULL)
		Util::myDisconnect(m_pCancelButton, SIGNAL(clicked()), this, SLOT(cancelWizard()));
		
	if (m_pNextButton != NULL)
		Util::myDisconnect(m_pNextButton, SIGNAL(clicked()), this, SLOT(gotoNextPage()));
		
	if (m_pBackButton != NULL)
		Util::myDisconnect(m_pBackButton, SIGNAL(clicked()), this ,SLOT(gotoPrevPage()));
		
	if (m_pRealForm != NULL)
		Util::myDisconnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(cancelWizard()));		
		
	for (int i=0; i < MachineAuthWizard::pageLastPage; i++)
	{
		delete m_wizardPages[i];
		m_wizardPages[i] = NULL;
	}
			
	if (m_pRealForm != NULL)
		delete m_pRealForm;
}

bool MachineAuthWizard::create(void)
{
	return this->initUI();
}

bool MachineAuthWizard::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("ConnectionWizardWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
	
	Qt::WindowFlags flags;
	
	// set window flags so not minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
	
	m_pRealForm->setWindowTitle(tr("Machine Authentication Wizard - XSupplicant"));

	m_pCancelButton = qFindChild<QPushButton*>(m_pRealForm, "buttonCancel");
	m_pNextButton = qFindChild<QPushButton*>(m_pRealForm, "buttonNext");
	m_pBackButton = qFindChild<QPushButton*>(m_pRealForm, "buttonBack");
	m_pHeaderLabel = qFindChild<QLabel*>(m_pRealForm, "labelHeader");
	m_pStackedWidget = qFindChild<QStackedWidget*>(m_pRealForm, "stackedWidget");
	
	// dynamically populate text
	if (m_pCancelButton != NULL)
		m_pCancelButton->setText(tr("Cancel"));
		
	if (m_pNextButton != NULL)
		m_pNextButton->setText(tr("Next >"));
		
	if (m_pBackButton != NULL)
		m_pBackButton->setText(tr("Back"));
		
	if (m_pHeaderLabel != NULL)
		m_pHeaderLabel->setText(tr("Configure Machine Authentication"));
		
	// set up event-handling
	if (m_pCancelButton != NULL)
		Util::myConnect(m_pCancelButton, SIGNAL(clicked()), this, SLOT(cancelWizard()));
		
	if (m_pNextButton != NULL)
		Util::myConnect(m_pNextButton, SIGNAL(clicked()), this, SLOT(gotoNextPage()));
		
	if (m_pBackButton != NULL)
		Util::myConnect(m_pBackButton, SIGNAL(clicked()), this ,SLOT(gotoPrevPage()));
		
	if (m_pRealForm != NULL)
		Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(cancelWizard()));
		
	return this->loadPages();
}

void MachineAuthWizard::show(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

bool MachineAuthWizard::loadPages(void)
{
	bool success = true;
	
	if (m_pStackedWidget != NULL)
	{
		// clear out any existing widgets in stack
		int cnt = m_pStackedWidget->count();
		for (int i=0; i<cnt; i++)
		{
			QWidget *tmpWidget;
			m_pStackedWidget->setCurrentIndex(0);
			tmpWidget = m_pStackedWidget->currentWidget();
			m_pStackedWidget->removeWidget(tmpWidget);
			delete tmpWidget;
		}
		
		// make sure we don't have any page objects sticking around
		for (int i=0; i<MachineAuthWizard::pageLastPage; i++)
		{
			if (m_wizardPages[i] != NULL)
				delete m_wizardPages[i];
		}
		
		for (int i=0; i<MachineAuthWizard::pageLastPage; i++)
		{
			WizardPage *newPage = NULL;
			switch (i) {
				case MachineAuthWizard::pageNetworkTypes:
					newPage = new WizardPageNetworkTypes(this, m_pStackedWidget);
					break;
				case MachineAuthWizard::pageIPOptions:
					newPage = new WizardPageIPOptions(this, m_pStackedWidget);
					break;
				case MachineAuthWizard::pageStaticIP:
					newPage = new WizardPageStaticIP(this, m_pStackedWidget);
					break;			
				case MachineAuthWizard::pageMachineAuthFinishPage:
					newPage = new WizardPageMachineAuthFinished(this, m_pStackedWidget);
					break;
				case MachineAuthWizard::pageWirelessNetwork:
					newPage = new WizardPageWirelessNetwork(this, m_pStackedWidget);
					break;
				case MachineAuthWizard::pageWirelessInfo:
					newPage = new WizardPageWirelessInfo(this, m_pStackedWidget);
					break;
				case MachineAuthWizard::pageDot1XCert:
					newPage = new WizardPageDot1XCert(this, m_pStackedWidget);
					break;									
				default:
					break;
			}

			if (newPage == NULL || newPage->create() == false || newPage->getWidget() == NULL)
			{
				// error creating page
				QMessageBox::critical(NULL, tr("Error Loading WizardPage"), tr("There was an error loading wizard page: %1").arg(i));
				success = false;
				break;	
			}
			else
			{
				m_pStackedWidget->addWidget(newPage->getWidget());
				m_wizardPages[i] = newPage;
			}
		}
	}

	m_currentPage = MachineAuthWizard::pageNoPage;
	return success;
}

void MachineAuthWizard::gotoPage(MachineAuthWizard::wizardPages newPageIdx)
{
	if (newPageIdx != MachineAuthWizard::pageNoPage && m_wizardPages[newPageIdx] != NULL) 
	{
		if (m_pHeaderLabel != NULL)
		{
			QString headerString;

			headerString = tr("Configure Machine Authentication");

			QString pageHeader = m_wizardPages[newPageIdx]->getHeaderString();
			if (!pageHeader.isEmpty())
				headerString.append(" >> ").append(pageHeader);
			
			m_pHeaderLabel->setText(headerString);
		}
		
		m_wizardPages[newPageIdx]->init(m_connData);
		
		if (m_wizardPages[newPageIdx]->isFinalPage() == true)
			m_pNextButton->setText(tr("Finish"));
		else
			m_pNextButton->setText(tr("Next").append(" >"));
		
		m_pStackedWidget->setCurrentIndex(newPageIdx);
		
		if (m_pBackButton != NULL)
			m_pBackButton->setDisabled(m_wizardHistory.size() < 1);
			
		m_currentPage = newPageIdx;
		
		if (m_pNextButton != NULL)
			m_pNextButton->setDefault(true);
	}
}

void MachineAuthWizard::gotoNextPage(void)
{
	wizardPages nextPage = pageNoPage;
	
	if (m_currentPage == pageNoPage)
		nextPage = this->getNextPage();
	else if (m_wizardPages[m_currentPage] != NULL)
	{	
		if (m_wizardPages[m_currentPage]->validate() == true)
		{
			m_connData = m_wizardPages[m_currentPage]->wizardData();
			
			// check if we're at end of wizard (now that we know data is valid and we have it)
			if (m_wizardPages[m_currentPage]->isFinalPage())
			{
				// early returns are ugly, but quick and dirty wins race
				this->finishWizard();
				return;
			}			
			
			nextPage = this->getNextPage();
		}
		else
			nextPage = pageNoPage;
	}
	
	if (m_currentPage != pageNoPage && nextPage != pageNoPage)
		m_wizardHistory.push(m_currentPage);
			
	if (nextPage != pageNoPage)
		this->gotoPage(nextPage);
}

void MachineAuthWizard::gotoPrevPage(void)
{
	// check if anything in stack
	if (m_wizardHistory.isEmpty())
		return;
		
	wizardPages prevPage = m_wizardHistory.pop();
	
	// store off data for when they return.  Don't validate tho
	m_connData = m_wizardPages[m_currentPage]->wizardData();
	this->gotoPage(prevPage);
}

void MachineAuthWizard::init(void)
{
	// start with fresh connection data
	m_connData = ConnectionWizardData();
	m_editMode = false;
	
	// load up first page
	m_currentPage = pageNoPage;
	this->gotoNextPage();
}

void MachineAuthWizard::edit(const ConnectionWizardData &connData)
{
	m_connData = connData;
	m_connData.m_newConnection = false;
	m_editMode = true;
	m_originalConnName = connData.m_connectionName;
	m_originalProfileName = connData.m_profileName;
	m_originalServerName = connData.m_serverName;
	
	m_currentPage = pageNoPage;
	this->gotoNextPage();
}

void MachineAuthWizard::cancelWizard(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
	emit cancelled();
}

void MachineAuthWizard::finishWizard(void)
{
	bool success;
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
		
	QString connName;
	
	success = this->saveConnectionData(&connName);

	if (success) success = saveGlobalSettings();

	emit finished(success, connName, m_adapterName);
}

/**
 * \brief Save machine authentication settings to the globals in the machine config.
 * 
 * In addition to writing the normal configuration pieces, we also need to write some
 * global settings to define which connection will be used for wired and wireless authentication.
 *
 * \retval true if data was saved.
 * \retval false if data wasn't saved.
 **/
bool MachineAuthWizard::saveGlobalSettings()
{
	struct config_globals *myGlobals = NULL;
	int retval = 0;

	if (xsupgui_request_get_globals_config(&myGlobals) != REQUEST_SUCCESS) return false;

	if (myGlobals->wiredMachineAuthConnection != NULL)
	{
		free(myGlobals->wiredMachineAuthConnection);
		myGlobals->wiredMachineAuthConnection = NULL;
	}

	if (m_connData.m_wired == true)
	{
		myGlobals->wiredMachineAuthConnection = _strdup(m_connData.m_connectionName.toAscii().data());
	}

	if (myGlobals->wirelessMachineAuthConnection != NULL)
	{
		free(myGlobals->wirelessMachineAuthConnection);
		myGlobals->wirelessMachineAuthConnection = NULL;
	}

	if (m_connData.m_wireless == true)
	{
		myGlobals->wirelessMachineAuthConnection = _strdup(m_connData.m_connectionName.toAscii().data());
	}

	retval = xsupgui_request_set_globals_config(myGlobals);

	xsupgui_request_free_config_globals(&myGlobals);

	if (retval != REQUEST_SUCCESS) return false;

	if (xsupgui_request_write_config(CONFIG_LOAD_GLOBAL, NULL) != REQUEST_SUCCESS) return false;

	return true;
}

bool MachineAuthWizard::saveConnectionData(QString *pConnName)
{
	bool success;
	config_connection *pConfig = NULL;
	config_profiles *pProfile = NULL;
	config_trusted_server *pServer = NULL;
	
	if (pConnName == NULL)
		return false;
		
	success = m_connData.toSupplicantProfiles(&pConfig, &pProfile, &pServer);
	
	// we at least expect a pointer to connection profile
	if (success == true && pConfig != NULL)
	{
		int retVal = REQUEST_SUCCESS;
		
		if (pServer != NULL)
		{
			retVal = xsupgui_request_set_trusted_server_config(m_connData.m_config_type, pServer);
			success = retVal == REQUEST_SUCCESS;
		}
		
		if (pProfile != NULL)
		{
			if (xsupgui_request_set_profile_config(m_connData.m_config_type, pProfile) == REQUEST_SUCCESS)
				m_pEmitter->sendProfConfigUpdate();
			else
				success = false;
		}
		
		// check if was edit and they changed name of connection).  If so, rename connection before saving
		if (m_editMode == true && QString(pConfig->name) != m_originalConnName)
			retVal = xsupgui_request_rename_connection(m_connData.m_config_type, m_originalConnName.toAscii().data(), pConfig->name);
				
		if (retVal == REQUEST_SUCCESS)
			retVal = xsupgui_request_set_connection_config(m_connData.m_config_type, pConfig);
			
		if (retVal == REQUEST_SUCCESS)
		{
			// tell everyone we changed the config
			m_pEmitter->sendConnConfigUpdate();
			XSupWrapper::writeConfig(CONFIG_LOAD_GLOBAL);
			XSupWrapper::writeConfig(CONFIG_LOAD_USER);
		}
		else
			success = false;
	}

	if (pConfig != NULL)
	{
		*pConnName = QString(pConfig->name);
		XSupWrapper::freeConfigConnection(&pConfig);
	}
	if (pProfile != NULL)
		XSupWrapper::freeConfigProfile(&pProfile);
	if (pServer != NULL)
		xsupgui_request_free_trusted_server_config(&pServer);
	return success;
}


MachineAuthWizard::wizardPages MachineAuthWizard::getNextPage(void)
{
	wizardPages nextPage = pageNoPage;
	
	switch (m_currentPage)
	{
		case MachineAuthWizard::pageNoPage:
			nextPage = MachineAuthWizard::pageNetworkTypes;
			break;
			
		case MachineAuthWizard::pageNetworkTypes:
			if (m_connData.m_wireless == true)
			{
				nextPage = MachineAuthWizard::pageWirelessNetwork;
			}
			else
			{
				nextPage =  MachineAuthWizard::pageDot1XCert;
			}
			break;
			
		case pageWirelessNetwork:
			if (m_connData.m_otherNetwork == true)
				nextPage = MachineAuthWizard::pageWirelessInfo;
			else
			{
				nextPage = MachineAuthWizard::pageDot1XCert;
			}	
			break;
			
		case pageWirelessInfo:
			nextPage = MachineAuthWizard::pageDot1XCert;
			break;
			
		case pageIPOptions:
			if (m_connData.m_staticIP == true)
				nextPage = MachineAuthWizard::pageStaticIP;
			else
				nextPage = MachineAuthWizard::pageMachineAuthFinishPage;
			break;
			
		case pageStaticIP:
			nextPage = MachineAuthWizard::pageMachineAuthFinishPage;
			break;
			
		case pageDot1XCert:
			nextPage = MachineAuthWizard::pageIPOptions;
			break;
			
		case pageMachineAuthFinishPage:
			nextPage = pageNoPage;
			break;
			
		default:
			nextPage = pageNoPage;
			break;
	}
	return nextPage;
}
