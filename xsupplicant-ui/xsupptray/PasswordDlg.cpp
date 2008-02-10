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
#include "PasswordDlg.h"
#include "Util.h"

PasswordDlg::PasswordDlg(const QString &connection, const QString &eapMethod, const QString &challengeString):
  m_message(this)
{
  QLabel *pConnection = new QLabel(connection);
  QLabel *pEapMethod = new QLabel(eapMethod);
  QLabel *pChallengeString = new QLabel(challengeString);
  QLabel *pMainLabel = new QLabel(tr("The network you are attempting to authenticate to, requires an additional password.  You will need to enter it here."));
  
  QLabel *pPasswordLabel = new QLabel(tr("Enter response"));
  m_pPasswordField = new QTextEdit();
  Util::setWidgetWidth(m_pPasswordField, "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW");
  QHBoxLayout *pPasswordLayout = new QHBoxLayout();
  pPasswordLayout->addWidget(pPasswordLabel);
  pPasswordLayout->addWidget(m_pPasswordField, Qt::AlignRight);

  QDialogButtonBox *pButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  QVBoxLayout *pLayout = new QVBoxLayout();
  pLayout->addWidget(pConnection);
  pLayout->addWidget(pEapMethod);
  pLayout->addWidget(pChallengeString);
  pLayout->addWidget(pMainLabel);
  pLayout->addLayout(pPasswordLayout);
  pLayout->addWidget(pButtonBox);
  setLayout(pLayout);
  setWindowTitle(tr("Password Response"));
  Util::myConnect(pButtonBox, SIGNAL(accepted()), this, SLOT(slotSave()));
  Util::myConnect(pButtonBox, SIGNAL(rejected()), this, SLOT(slotCancel()));
}

PasswordDlg::~PasswordDlg(void)
{
}

void PasswordDlg::slotSave()
{
  // XXX This needs to be fixed up to use some sane QT calls.
  /*
  m_message.DisplayMessage( MessageClass::INFORMATION_TYPE, tr("Password"), tr("Save the password"));
  accept();
  */
}


void PasswordDlg::slotCancel()
{
  // XXX This needs to be fixed up to use some sane QT calls.
  /*
  m_message.DisplayMessage( MessageClass::INFORMATION_TYPE, tr("Password"), tr("Cancel the authentication"));
  reject();
  */
}

void PasswordDlg::slotHelp()
{

}
