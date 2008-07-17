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
#include "ConnectionSelectDlg.h"
#include "XSupWrapper.h"

ConnectionSelectDlg::ConnectionSelectDlg(QWidget *parent, QWidget *parentWindow, const QStringList &connections)
	:QWidget(parent), m_pParent(parent), m_pParentWindow(parentWindow), m_connectionList(connections)
{
}

ConnectionSelectDlg::~ConnectionSelectDlg(void)
{
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(cancel()));
	
	if (m_pButtonBox != NULL)
	{
		Util::myConnect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(okay()));
		Util::myConnect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(cancel()));	
	}
	
	if (m_pRealForm != NULL)
		delete m_pRealForm;
}

bool ConnectionSelectDlg::create(void)
{
	return this->initUI();
}

bool ConnectionSelectDlg::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("ConnectionPromptWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
	
	Qt::WindowFlags flags;
	
	// set window flags so minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMaximizeButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);
	
	//cache off pointers to UI objects
	m_pConnectionCombo = qFindChild<QComboBox*>(m_pRealForm, "comboBoxConnection");
	m_pButtonBox = qFindChild<QDialogButtonBox*>(m_pRealForm, "buttonBox");

	// dynamically populate text
	
	// !!! TODO: would be nice to include the network name here
	QLabel *pLabel = qFindChild<QLabel*>(m_pRealForm, "labelDialogMsg");
	if (pLabel != NULL)
		pLabel->setText(tr("More than one connection profile is configured for this network.  Please indicate which should be used to connect"));	
	
	// set up event-handling
	
	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(cancel()));
	
	if (m_pButtonBox != NULL)
	{
		Util::myConnect(m_pButtonBox, SIGNAL(accepted()), this, SLOT(okay()));
		Util::myConnect(m_pButtonBox, SIGNAL(rejected()), this, SLOT(cancel()));	
	}		
	
	// other initializations
	if (m_pConnectionCombo != NULL)
	{
		m_pConnectionCombo->clear();
		m_pConnectionCombo->addItems(m_connectionList);
	}
	
	return true;
}

void ConnectionSelectDlg::show(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

void ConnectionSelectDlg::okay(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
		
	// if only one connection for this network and adapter, connect to it

	
	if (m_pConnectionCombo != NULL)
	{
		bool success;
		config_connection *pConn = NULL;
		bool reportError = false;
		QString errMessage;
				
		success = XSupWrapper::getConfigConnection(m_pConnectionCombo->currentText(), &pConn);
		
		if (success == true && pConn != NULL)
		{
			int retVal;
			char *adapterName= NULL;
			
			retVal = xsupgui_request_get_devname(pConn->device, &adapterName);
			
			if (retVal == REQUEST_SUCCESS && adapterName != NULL)
				retVal = xsupgui_request_set_connection(adapterName, pConn->name);
			else
				reportError = true;
				
			if (retVal != REQUEST_SUCCESS)
				reportError = true;
				
			errMessage = tr("An error occurred while connecting to the network '%1'.").arg(QString(pConn->ssid));
				
			if (adapterName != NULL)
				free(adapterName);				
		}
		else
		{
			reportError = true;
			errMessage = tr("An error occurred while connecting to the network.");
		}
		
		if (pConn != NULL)
			XSupWrapper::freeConfigConnection(&pConn);
		
		if (reportError == true)
			QMessageBox::critical(m_pRealForm,tr("Error Connecting to Network"),errMessage);
	}
						
	emit close();
}

void ConnectionSelectDlg::cancel(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
	emit close();
}