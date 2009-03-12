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
    
#include <QRadioButton>
    
#include "ConnectionWizard.h"
#include "ConnectionWizardData.h"
#include "WizardPages.h"
#include "FormLoader.h"
#include "Util.h"
#include "XSupWrapper.h"
#include "Emitter.h"
 ConnectionWizard::ConnectionWizard(QString adaptName, QWidget * parent, QWidget * parentWindow, Emitter * e) :
QWidget(parent), m_pParent(parent), m_adapterName(adaptName),
m_pParentWindow(parentWindow), m_pEmitter(e) 
{
	for (int i = 0; i < ConnectionWizard::pageLastPage; i++)
		m_wizardPages[i] = NULL;
	m_currentPage = pageNoPage;
	m_dot1Xmode = false;
	m_editMode = false;
} ConnectionWizard::~ConnectionWizard(void) 
{
	if (m_pCancelButton != NULL)
		Util::myDisconnect(m_pCancelButton, SIGNAL(clicked()), this,
				    SLOT(cancelWizard()));
	if (m_pNextButton != NULL)
		Util::myDisconnect(m_pNextButton, SIGNAL(clicked()), this,
				    SLOT(gotoNextPage()));
	if (m_pBackButton != NULL)
		Util::myDisconnect(m_pBackButton, SIGNAL(clicked()), this,
				    SLOT(gotoPrevPage()));
	if (m_pRealForm != NULL)
		Util::myDisconnect(m_pRealForm, SIGNAL(rejected()), this,
				    SLOT(cancelWizard()));
	for (int i = 0; i < ConnectionWizard::pageLastPage; i++)
		 {
		delete m_wizardPages[i];
		m_wizardPages[i] = NULL;
	} if (m_pRealForm != NULL)
		delete m_pRealForm;
}

bool ConnectionWizard::create(void) 
{
	return this->initUI();
}

bool ConnectionWizard::initUI(void)
{
	
	    // load form
	    m_pRealForm =
	    FormLoader::buildform("ConnectionWizardWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
	Qt::WindowFlags flags;
	
	    // set window flags so not minimizeable and context help thingy is turned off
	    flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);
	m_pCancelButton =
	    qFindChild < QPushButton * >(m_pRealForm, "buttonCancel");
	m_pNextButton =
	    qFindChild < QPushButton * >(m_pRealForm, "buttonNext");
	m_pBackButton =
	    qFindChild < QPushButton * >(m_pRealForm, "buttonBack");
	m_pHeaderLabel = qFindChild < QLabel * >(m_pRealForm, "labelHeader");
	m_pStackedWidget =
	    qFindChild < QStackedWidget * >(m_pRealForm, "stackedWidget");
	
	    // dynamically populate text
	    if (m_pCancelButton != NULL)
		m_pCancelButton->setText(tr("Cancel"));
	if (m_pNextButton != NULL)
		m_pNextButton->setText(tr("Next >"));
	if (m_pBackButton != NULL)
		m_pBackButton->setText(tr("Back"));
	if (m_pHeaderLabel != NULL)
		m_pHeaderLabel->setText(tr("Create New Connection"));
	
	    // set up event-handling
	    if (m_pCancelButton != NULL)
		Util::myConnect(m_pCancelButton, SIGNAL(clicked()), this,
				 SLOT(cancelWizard()));
	if (m_pNextButton != NULL)
		Util::myConnect(m_pNextButton, SIGNAL(clicked()), this,
				 SLOT(gotoNextPage()));
	if (m_pBackButton != NULL)
		Util::myConnect(m_pBackButton, SIGNAL(clicked()), this,
				 SLOT(gotoPrevPage()));
	if (m_pRealForm != NULL)
		Util::myConnect(m_pRealForm, SIGNAL(rejected()), this,
				 SLOT(cancelWizard()));
	return this->loadPages();
}

void ConnectionWizard::show(void) 
{
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

bool ConnectionWizard::loadPages(void) 
{
	bool success = true;
	if (m_pStackedWidget != NULL)
		 {
		
		    // clear out any existing widgets in stack
		int cnt = m_pStackedWidget->count();
		for (int i = 0; i < cnt; i++)
			 {
			QWidget * tmpWidget;
			m_pStackedWidget->setCurrentIndex(0);
			tmpWidget = m_pStackedWidget->currentWidget();
			m_pStackedWidget->removeWidget(tmpWidget);
			delete tmpWidget;
			} 
		    // make sure we don't have any page objects sticking around
		    for (int i = 0; i < ConnectionWizard::pageLastPage; i++)
			 {
			if (m_wizardPages[i] != NULL)
				delete m_wizardPages[i];
			}
		for (int i = 0; i < ConnectionWizard::pageLastPage; i++)
			 {
			WizardPage * newPage = NULL;
			switch (i) {
			case ConnectionWizard::pageNetworkType:
				newPage =
				    new WizardPageNetworkType(this,
							      m_pStackedWidget);
				break;
			case ConnectionWizard::pageWiredSecurity:
				newPage =
				    new WizardPageWiredSecurity(this,
								m_pStackedWidget);
				break;
			case ConnectionWizard::pageIPOptions:
				newPage =
				    new WizardPageIPOptions(this,
							    m_pStackedWidget);
				break;
			case ConnectionWizard::pageStaticIP:
				newPage =
				    new WizardPageStaticIP(this,
							   m_pStackedWidget);
				break;
			case ConnectionWizard::pageCredentials:
				newPage =
				    new WizardPageCredentials(this,
							      m_pStackedWidget);
				break;
			case ConnectionWizard::pageFinishPage:
				newPage =
				    new WizardPageFinished(this,
							   m_pStackedWidget);
				break;
			case ConnectionWizard::pageWirelessNetwork:
				newPage =
				    new WizardPageWirelessNetwork(this,
								  m_pStackedWidget);
				break;
			case ConnectionWizard::pageWirelessInfo:
				newPage =
				    new WizardPageWirelessInfo(this,
							       m_pStackedWidget);
				break;
			case ConnectionWizard::pageDot1XProtocol:
				newPage =
				    new WizardPageDot1XProtocol(this,
								m_pStackedWidget);
				break;
			case ConnectionWizard::pageDot1XInnerProtocol:
				newPage =
				    new WizardPageDot1XInnerProtocol(this,
								     m_pStackedWidget);
				break;
			case ConnectionWizard::pageFastInnerProtocol:
				newPage =
				    new WizardPageFASTInnerProtocol(this,
								    m_pStackedWidget);
				break;
			case ConnectionWizard::pageDot1XCert:
				newPage =
				    new WizardPageDot1XCert(this,
							    m_pStackedWidget);
				break;
			case ConnectionWizard::pageDot1XUserCert:
				newPage =
				    new WizardPageDot1XUserCert(this,
								m_pStackedWidget);
				break;
			case ConnectionWizard::pageSCReader:
				newPage =
				    new WizardPageSCReader(this,
							   m_pStackedWidget);
				break;
			case ConnectionWizard::pageAuthOptions:
				newPage =
				    new WizardPageAuthOptions(this,
							      m_pStackedWidget);
				break;
			default:
				break;
			}
			if (newPage == NULL || newPage->create() == false
			     || newPage->getWidget() == NULL)
				 {
				
				    // error creating page
				    QMessageBox::critical(NULL,
							  tr
							  ("Error Loading WizardPage"),
							  tr
							  ("There was an error loading wizard page: %1").
							  arg(i));
				success = false;
				break;
				}
			
			else
				 {
				m_pStackedWidget->addWidget(newPage->
							     getWidget());
				m_wizardPages[i] = newPage;
				}
			}
		}
	m_currentPage = ConnectionWizard::pageNoPage;
	return success;
}

void ConnectionWizard::gotoPage(ConnectionWizard::wizardPages newPageIdx) 
{
	if (newPageIdx != ConnectionWizard::pageNoPage
	     && m_wizardPages[newPageIdx] != NULL)
		 {
		if (m_pHeaderLabel != NULL)
			 {
			QString headerString;
			if (m_editMode == true)
				headerString = tr("Edit Connection");
			
			else
				headerString = tr("Create New Connection");
			QString pageHeader =
			    m_wizardPages[newPageIdx]->getHeaderString();
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

void ConnectionWizard::gotoNextPage(void) 
{
	wizardPages nextPage = pageNoPage;
	if (m_currentPage == pageNoPage)
		nextPage = this->getNextPage();
	
	else if (m_wizardPages[m_currentPage] != NULL)
		 {
		if (m_wizardPages[m_currentPage]->validate() == true)
			 {
			m_connData =
			    m_wizardPages[m_currentPage]->wizardData();
			
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

void ConnectionWizard::gotoPrevPage(void) 
{
	
	    // check if anything in stack
	    if (m_wizardHistory.isEmpty())
		return;
	wizardPages prevPage = m_wizardHistory.pop();
	
	    // store off data for when they return.  Don't validate tho
	    m_connData = m_wizardPages[m_currentPage]->wizardData();
	this->gotoPage(prevPage);
}

void ConnectionWizard::init(void) 
{
	
	    // start with fresh connection data
	    m_connData = ConnectionWizardData();
	m_editMode = false;
	m_dot1Xmode = false;
	
	    // load up first page
	    m_currentPage = pageNoPage;
	this->gotoNextPage();
} void ConnectionWizard::edit(const ConnectionWizardData & connData) 
{
	m_connData = connData;
	m_connData.m_newConnection = false;
	m_editMode = true;
	m_dot1Xmode = false;
	m_originalConnName = connData.m_connectionName;
	m_originalProfileName = connData.m_profileName;
	m_originalServerName = connData.m_serverName;
	m_currentPage = pageNoPage;
	this->gotoNextPage();
} void ConnectionWizard::cancelWizard(void) 
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
	emit cancelled();
}

void ConnectionWizard::finishWizard(void) 
{
	bool success;
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
	QString connName;
	success = this->saveConnectionData(&connName);
	emit finished(success, connName, m_adapterName);
}

bool ConnectionWizard::saveConnectionData(QString * pConnName) 
{
	bool success;
	config_connection * pConfig = NULL;
	config_profiles * pProfile = NULL;
	config_trusted_server * pServer = NULL;
	if (pConnName == NULL)
		return false;
	success =
	    m_connData.toSupplicantProfiles(&pConfig, &pProfile, &pServer);
	
	    // we at least expect a pointer to connection profile
	    if (success == true && pConfig != NULL)
		 {
		int retVal = REQUEST_SUCCESS;
		if (pServer != NULL)
			 {
			retVal =
			    xsupgui_request_set_trusted_server_config
			    (m_connData.m_config_type, pServer);
			success = retVal == REQUEST_SUCCESS;
			}
		if (pProfile != NULL)
			 {
			if (xsupgui_request_set_profile_config
			     (m_connData.m_config_type,
			      pProfile) == REQUEST_SUCCESS)
				m_pEmitter->sendProfConfigUpdate();
			
			else
				success = false;
			}
		
		    // check if was edit and they changed name of connection).  If so, rename connection before saving
		    if (m_editMode == true
			&& QString(pConfig->name) != m_originalConnName)
			retVal =
			    xsupgui_request_rename_connection(m_connData.
							      m_config_type,
							      m_originalConnName.
							      toAscii().data(),
							      pConfig->name);
		if (retVal == REQUEST_SUCCESS)
			retVal =
			    xsupgui_request_set_connection_config(m_connData.
								  m_config_type,
								  pConfig);
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

ConnectionWizard::wizardPages ConnectionWizard::getNextPage(void)
{
	wizardPages nextPage = pageNoPage;
	switch (m_currentPage)
		 {
	case ConnectionWizard::pageNoPage:
		if (m_dot1Xmode == true)
			nextPage = ConnectionWizard::pageDot1XProtocol;
		
		else
			nextPage = ConnectionWizard::pageNetworkType;
		break;
	case ConnectionWizard::pageNetworkType:
		if (m_connData.m_wireless == true)
			 {
			nextPage = ConnectionWizard::pageWirelessNetwork;
			}
		
		else
			 {
			nextPage = ConnectionWizard::pageWiredSecurity;
			}
		break;
	case pageWiredSecurity:
		if (m_connData.m_wiredSecurity == true)
			nextPage = ConnectionWizard::pageDot1XProtocol;
		
		else
			nextPage = ConnectionWizard::pageIPOptions;
		break;
	case pageWirelessNetwork:
		if (m_connData.m_otherNetwork == true)
			nextPage = ConnectionWizard::pageWirelessInfo;
		
		else
			 {
			if (m_connData.m_wirelessAssocMode ==
			     ConnectionWizardData::assoc_WPA_ENT
			     || m_connData.m_wirelessAssocMode ==
			     ConnectionWizardData::assoc_WPA2_ENT)
				nextPage = ConnectionWizard::pageDot1XProtocol;
			
			else
				nextPage = ConnectionWizard::pageIPOptions;
			}
		break;
	case pageWirelessInfo:
		if (m_connData.m_wirelessAssocMode ==
		     ConnectionWizardData::assoc_WPA_ENT
		     || m_connData.m_wirelessAssocMode ==
		     ConnectionWizardData::assoc_WPA2_ENT)
			nextPage = ConnectionWizard::pageDot1XProtocol;
		
		else
			nextPage = ConnectionWizard::pageIPOptions;
		break;
	case pageAuthOptions:
		if ((m_connData.m_eapProtocol != ConnectionWizardData::eap_aka)
		     && (m_connData.m_eapProtocol !=
			 ConnectionWizardData::eap_sim))
			nextPage = ConnectionWizard::pageCredentials;
		
		else
			nextPage = ConnectionWizard::pageIPOptions;
		break;
	case pageCredentials:
		nextPage = ConnectionWizard::pageIPOptions;
		break;
	case pageIPOptions:
		if (m_connData.m_staticIP == true)
			nextPage = ConnectionWizard::pageStaticIP;
		
		else
			nextPage = ConnectionWizard::pageFinishPage;
		break;
	case pageStaticIP:
		nextPage = ConnectionWizard::pageFinishPage;
		break;
	case pageSCReader:
		nextPage = pageIPOptions;
		break;
	case pageDot1XProtocol:
		if (m_connData.m_eapProtocol == ConnectionWizardData::eap_md5)
			 {
			if (m_dot1Xmode == true)
				nextPage = ConnectionWizard::pageFinishPage;
			
			else
				nextPage = ConnectionWizard::pageAuthOptions;
			}
		
		else if (m_connData.m_eapProtocol ==
			 ConnectionWizardData::eap_fast)
			 {
			nextPage = ConnectionWizard::pageFastInnerProtocol;
			}
		
		else if ((m_connData.m_eapProtocol ==
			  ConnectionWizardData::eap_aka)
			 || (m_connData.m_eapProtocol ==
			      ConnectionWizardData::eap_sim))
			 {
			nextPage = ConnectionWizard::pageSCReader;
			}
		
		else if (m_connData.m_eapProtocol ==
			 ConnectionWizardData::eap_tls)
			 {
			nextPage = ConnectionWizard::pageDot1XUserCert;
			}
		
		else
			nextPage = ConnectionWizard::pageDot1XInnerProtocol;
		break;
	case pageDot1XInnerProtocol:
		if (m_connData.m_validateCert == true)
			nextPage = ConnectionWizard::pageDot1XCert;
		
		else
			 {
			if (m_dot1Xmode == true)
				nextPage = ConnectionWizard::pageFinishPage;
			
			else
				nextPage = ConnectionWizard::pageAuthOptions;
			}
		break;
	case pageFastInnerProtocol:
		if (m_connData.m_validateCert == true)
			nextPage = ConnectionWizard::pageDot1XCert;
		
		else
			 {
			if (m_dot1Xmode == true)
				nextPage = ConnectionWizard::pageFinishPage;
			
			else
				nextPage = ConnectionWizard::pageAuthOptions;
			}
		break;
	case pageDot1XCert:
		if (m_dot1Xmode == true)
			nextPage = ConnectionWizard::pageFinishPage;
		
		else
			nextPage = ConnectionWizard::pageAuthOptions;
		break;
	case pageDot1XUserCert:
		nextPage = ConnectionWizard::pageDot1XCert;
		break;
	case pageFinishPage:
		nextPage = pageNoPage;
		break;
	default:
		nextPage = pageNoPage;
		break;
		}
	return nextPage;
}

void ConnectionWizard::editDot1XInfo(const ConnectionWizardData & wizData) 
{
	
	    // start with data passed in
	    m_connData = wizData;
	
	    // load up first page
	    m_currentPage = pageNoPage;
	m_dot1Xmode = true;
	m_editMode = false;
	this->gotoNextPage();
} 
