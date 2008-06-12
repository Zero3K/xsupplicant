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

#include "ConnectDlg.h"
#include "FormLoader.h"
#include "Emitter.h"
#include "TrayApp.h"
#include "SSIDListDlg.h"

ConnectDlg::ConnectDlg(QWidget *parent, QWidget *parentWindow, Emitter *e, TrayApp *supplicant)
	: QWidget(parent), 
	m_pParent(parent),
	m_pParentWindow(parentWindow),
	m_pEmitter(e),
	m_pSupplicant(supplicant)
{
	m_pSSIDListDlg = NULL;
}

ConnectDlg::~ConnectDlg()
{ 
	if (m_pCloseButton != NULL)
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
	
	if (m_pBrowseWirelessNetworksButton != NULL)
		Util::myDisconnect(m_pBrowseWirelessNetworksButton, SIGNAL(clicked()), this, SLOT(showSSIDList()));
	
	if (m_pSSIDListDlg != NULL)
		delete m_pSSIDListDlg;
		
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
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
		
	// cache pointers to objects on our UI 
	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");
	m_pBrowseWirelessNetworksButton = qFindChild<QPushButton*>(m_pRealForm, "buttonBrowseWireless");
	m_pAdapterTabControl = qFindChild<QTabWidget*>(m_pRealForm, "adapterTypeTabControl");
	m_pWirelessAdapterList = qFindChild<QComboBox*>(m_pRealForm, "comboBoxWirelessAdapter");
	
	
	// populate text
	
	// wireless tab
	if (m_pCloseButton != NULL)
		m_pCloseButton->setText(tr("Close"));
	
	if (m_pBrowseWirelessNetworksButton != NULL)
		m_pBrowseWirelessNetworksButton->setText(tr("Browse Networks"));
	
	QLabel *pAdapterLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessAdapter");
	if (pAdapterLabel != NULL)
		pAdapterLabel->setText(tr("Adapter:"));
		
	QLabel *pStatusLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessStatus");
	if (pStatusLabel != NULL)
		pStatusLabel->setText(tr("Status:"));
		
	QLabel *pConnectionLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessConnectConnection");
	if (pConnectionLabel != NULL)
		pConnectionLabel->setText(tr("Connection:"));
		
	pConnectionLabel = qFindChild<QLabel*>(m_pRealForm, "labelWirelessConnectedConnection");
	if (pConnectionLabel != NULL)
		pConnectionLabel->setText(tr("Connection:"));
			
	if (m_pAdapterTabControl != NULL)
	{
		m_pAdapterTabControl->setTabText(0,tr("Wireless"));
		m_pAdapterTabControl->setTabText(1,tr("Wired"));
	}

	// set up event-handling
	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));

	if (m_pBrowseWirelessNetworksButton != NULL)
		Util::myConnect(m_pBrowseWirelessNetworksButton, SIGNAL(clicked()), this, SLOT(showSSIDList()));
		
	if (m_pWirelessAdapterList != NULL)
		Util::myConnect(m_pWirelessAdapterList, SIGNAL(currentIndexChanged(int)), this, SLOT(selectWirelessAdapter(int)));
		
	
	// set initial state of UI - mainly setting the active tab
	if (m_pAdapterTabControl != NULL)
	{
		m_pAdapterTabControl->setCurrentIndex(0);
	}
	
	if (m_pWirelessAdapterList != NULL) 
	{
		populateWirelessAdapterList();
		selectWirelessAdapter(0);
	}
					
	return true;
}

void ConnectDlg::show(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

void ConnectDlg::populateWirelessAdapterList(void)
{
	int_enum *pInterfaceList = NULL;
	int retVal;	
	
	m_pWirelessAdapterList->clear();
	
	retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
	if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
	{
		int i = 0;
		while (pInterfaceList[i].desc != NULL)
		{
			if (pInterfaceList[i].is_wireless == TRUE)
			{
				m_pWirelessAdapterList->addItem(QString(pInterfaceList[i].desc));
			}
			
			++i;
		}
		xsupgui_request_free_int_enum(&pInterfaceList);
		pInterfaceList = NULL;
		
	}
	else
	{
		// bad things man
	}
}

void ConnectDlg::selectWirelessAdapter(int index)
{
	if (m_pWirelessAdapterList != NULL)
		m_currentWirelessAdapter = m_pWirelessAdapterList->itemText(index);
		
	// need to update status and all that jazz
}

void ConnectDlg::showSSIDList()
{	
	if (m_pSSIDListDlg == NULL)
	{
		// jking - for now assume this was launched via the connect dialog
		m_pSSIDListDlg = new SSIDListDlg(this, m_pRealForm, m_pEmitter, m_pSupplicant);
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
			m_pSSIDListDlg->refreshList(m_currentWirelessAdapter);
			m_pSSIDListDlg->show();
		}
	}
	else
	{
		m_pSSIDListDlg->refreshList(m_currentWirelessAdapter);
		m_pSSIDListDlg->show();
	}

}