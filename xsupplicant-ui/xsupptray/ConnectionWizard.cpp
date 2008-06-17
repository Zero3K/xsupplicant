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

#include "ConnectionWizard.h"
#include "WizardPages.h"
#include "FormLoader.h"
#include "Util.h"

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

ConnectionWizard::ConnectionWizard(QWidget *parent, QWidget *parentWindow)
	: QWidget(parent),
	m_pParent(parent),
	m_pParentWindow(parentWindow)
{
	int i;
	for (i=0; i<ConnectionWizard::pageLastPage; i++)
		m_wizardPages[i] = NULL;
	m_currentPage = pageNoPage;
}

ConnectionWizard::~ConnectionWizard(void)
{
	if (m_pNextButton != NULL)
		Util::myDisconnect(m_pNextButton, SIGNAL(clicked()), this, SLOT(gotoNextPage()));
		
	if (m_pBackButton != NULL)
		Util::myDisconnect(m_pBackButton, SIGNAL(clicked()), this ,SLOT(gotoPrevPage()));
		
	if (m_pRealForm != NULL)
		delete m_pRealForm;
}

bool ConnectionWizard::create(void)
{
	return this->initUI();
}

bool ConnectionWizard::initUI(void)
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
		m_pHeaderLabel->setText(tr("Create New Connection"));
		
	// set up event-handling
	if (m_pCancelButton != NULL)
		Util::myConnect(m_pCancelButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
		
	if (m_pNextButton != NULL)
		Util::myConnect(m_pNextButton, SIGNAL(clicked()), this, SLOT(gotoNextPage()));
		
	if (m_pBackButton != NULL)
		Util::myConnect(m_pBackButton, SIGNAL(clicked()), this ,SLOT(gotoPrevPage()));
		
	this->loadPages();
	this->gotoNextPage();
		
	return true;
}

void ConnectionWizard::show(void)
{
	if (m_pStackedWidget != NULL)
		m_pStackedWidget->setCurrentIndex(0);
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

bool ConnectionWizard::loadPages(void)
{
	if (m_pStackedWidget != NULL)
	{
		int i;
		
		// clear out any existing widgets in stack
		for (i=0; i<m_pStackedWidget->count(); i++)
		{
			QWidget *tmpWidget;
			m_pStackedWidget->setCurrentIndex(0);
			tmpWidget = m_pStackedWidget->currentWidget();
			m_pStackedWidget->removeWidget(tmpWidget);
			delete tmpWidget;
		}
		
		// make sure we don't have any page objects sticking around
		for (i=0; i<ConnectionWizard::pageLastPage; i++)
		{
			if (m_wizardPages[i] != NULL)
				delete m_wizardPages[i];
		}
		
		for (i=0; i<ConnectionWizard::pageLastPage; i++)
		{
			WizardPage *newPage;
			switch (i) {
				case ConnectionWizard::pageNetworkType:
					newPage = new WizardPageNetworkType(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageWiredSecurity:
					newPage = new WizardPageWiredSecurity(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageIPOptions:
					newPage = new WizardPageIPOptions(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageStaticIP:
					newPage = new WizardPageStaticIP(this, m_pStackedWidget);
					break;			
				case ConnectionWizard::pageFinishPage:
					newPage = new WizardPageFinished(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageWirelessNetwork:
					newPage = new WizardPageWirelessNetwork(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageWirelessInfo:
					newPage = new WizardPageWirelessInfo(this, m_pStackedWidget);
					break;														
				default:
					break;
			}
			if (newPage == NULL || newPage->create() == false || newPage->getWidget() == NULL)
			{
				// error creating page
				QMessageBox::critical(NULL,"Error Loading WizardPage", QString("There was an error loading wizard page: %1").arg(i));	
			}
			else
			{
				m_pStackedWidget->addWidget(newPage->getWidget());
				m_wizardPages[i] = newPage;
			}
		}
	}
	m_currentPage = ConnectionWizard::pageNoPage;
	return true;
}

void ConnectionWizard::gotoPage(ConnectionWizard::wizardPages newPageIdx)
{
	if (newPageIdx != ConnectionWizard::pageNoPage && m_wizardPages[newPageIdx] != NULL) 
	{
		if (m_pHeaderLabel != NULL)
		{
			QString headerString = tr("Create New Connection");
			QString pageHeader = m_wizardPages[newPageIdx]->getHeaderString();
			if (!pageHeader.isEmpty())
				headerString.append(" >> ").append(pageHeader);
			
			m_pHeaderLabel->setText(headerString);
		}
		
		m_wizardPages[newPageIdx]->init();
		
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
		nextPage = pageNetworkType;
	else if (m_wizardPages[m_currentPage] != NULL)
		nextPage = m_wizardPages[m_currentPage]->getNextPage();
	
	if (m_currentPage != pageNoPage && nextPage != pageNoPage)
		m_wizardHistory.push(m_currentPage);
			
	this->gotoPage(nextPage);
}

void ConnectionWizard::gotoPrevPage(void)
{
	// check if anything in stack
	if (m_wizardHistory.isEmpty())
		return;
		
	wizardPages prevPage = m_wizardHistory.pop();
	
	this->gotoPage(prevPage);
}