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
#include "PasswordDlg.h"
#include "Util.h"
#include "FormLoader.h"

PasswordDlg::PasswordDlg(const QString &connection, const QString &eapMethod, const QString &challengeString)
{
	m_connName = connection;
	m_eapType = eapMethod;
	m_challenge = challengeString;

	m_pRealForm = NULL;
	m_pOKBtn = NULL;
	m_pResponseField = NULL;
	m_pServerChallenge = NULL;
}

PasswordDlg::~PasswordDlg(void)
{
	if (m_pOKBtn != NULL)
	{
		Util::myDisconnect(m_pOKBtn, SIGNAL(clicked()), this, SIGNAL(signalDone()));
	}

	if (m_pRealForm != NULL) delete m_pRealForm;
}

void PasswordDlg::show()
{
	if (m_pRealForm != NULL) 
	{
		m_pRealForm->show();
		m_pResponseField->setFocus();
	}
}

bool PasswordDlg::attach()
{
	Qt::WindowFlags flags;

	m_pRealForm = FormLoader::buildform("GTCWindow.ui");

	if (m_pRealForm == NULL) return false;

	m_pOKBtn = qFindChild<QPushButton*>(m_pRealForm, "buttonOK");
	if (m_pOKBtn == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QPushButton named 'buttonOK' does not exist!  Please fix the form!"));
		return false;
	}

	m_pResponseField = qFindChild<QLineEdit*>(m_pRealForm, "dataFieldYourResponse");
	if (m_pResponseField == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QLineEdit named 'dataFieldYourResponse' does not exist!  Please fix the form!"));
		return false;
	}

	m_pServerChallenge = qFindChild<QLabel*>(m_pRealForm, "dataFieldServerRequest");
	if (m_pServerChallenge == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QLabel named 'dataFieldServerRequest' does not exist!  Please fix the form!"));
		return false;
	}

	m_pServerChallenge->setText(m_challenge);

	Util::myConnect(m_pOKBtn, SIGNAL(clicked()), this, SIGNAL(signalDone()));

	flags = m_pRealForm->windowFlags();
	flags &= (~Qt::WindowContextHelpButtonHint);
	m_pRealForm->setWindowFlags(flags);

	return true;
}

QString PasswordDlg::getPassword()
{
	return m_pResponseField->text();
}

QString PasswordDlg::getConnName()
{
	return m_connName;
}



