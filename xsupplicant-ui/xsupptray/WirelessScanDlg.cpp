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

#include "wirelessScanDlg.h"
#include "FormLoader.h"
#include "Util.h"

#include <QLabel>

WirelessScanDlg::WirelessScanDlg(QWidget *parent, QWidget *parentWindow)
	: QWidget(parent),
	m_pParent(parent),
	m_pParentWindow(parentWindow)
{
	m_pProgressTimer = new QTimer(this);
	initUI();
}

WirelessScanDlg::~WirelessScanDlg()
{
	if (m_pCancelButton != NULL)
		Util::myDisconnect(m_pCancelButton, SIGNAL(clicked()), this, SIGNAL(scanCancelled()));	
		
	if (m_pRealForm != NULL)
		delete m_pRealForm;
		
	if (m_pProgressTimer != NULL)
	{
		Util::myDisconnect(m_pProgressTimer, SIGNAL(timeout()), this, SLOT(updateProgress()));
		delete m_pProgressTimer;
	}
}

bool WirelessScanDlg::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("WirelessScanDialog.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;	

	// set window flags so not minimizeable and context help thingy is turned off
	Qt::WindowFlags flags;
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
	
	// cache pointers to objects we'll reference frequently
	m_pCancelButton = qFindChild<QPushButton*>(m_pRealForm, "buttonCancel");
	m_pProgressBar = qFindChild<QProgressBar*>(m_pRealForm, "progressBar");

	// populate text labels
	QLabel *pMessageLabel = qFindChild<QLabel*>(m_pRealForm, "labelScanMsg");
	if (pMessageLabel != NULL)
		pMessageLabel->setText(tr("Scanning For Wireless Networks -- Please Wait"));
		
	if (m_pCancelButton != NULL)
		m_pCancelButton->setText(tr("Cancel"));
		
	// set up event handling
	if (m_pCancelButton != NULL)
		Util::myConnect(m_pCancelButton, SIGNAL(clicked()), this, SIGNAL(scanCancelled()));	
		
	if (m_pProgressTimer != NULL)
		Util::myConnect(m_pProgressTimer, SIGNAL(timeout()), this, SLOT(updateProgress()));
		
	// misc
	if (m_pProgressBar != NULL)
	{
		m_pProgressBar->setMinimum(0);
		m_pProgressBar->setMaximum(8);
	}
	return true;
}

void WirelessScanDlg::show(void)
{
	if (m_pProgressBar != NULL)
		m_pProgressBar->setValue(0);
	if (m_pProgressTimer != NULL)
		m_pProgressTimer->start(200);
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

void WirelessScanDlg::hide(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
	if (m_pProgressTimer != NULL)
		m_pProgressTimer->stop();
}

void WirelessScanDlg::updateProgress(void)
{
	if (m_pProgressBar != NULL)
	{
		if (m_pProgressBar->value() == m_pProgressBar->maximum())
			m_pProgressBar->setValue(m_pProgressBar->minimum());
		else
			m_pProgressBar->setValue(m_pProgressBar->value()+1);
	}
}