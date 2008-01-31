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
#include "MessageDlg.h"
#include "helpbrowser.h"

MessageDlg::MessageDlg(QWidget *parent):
  QDialog(parent)
{
  setAttribute(Qt::WA_GroupLeader);

  m_pMessageEdit = NULL;

  setupFields();
  setWindowFlags(windowFlags() | Qt::WindowMinimizeButtonHint);
  resize(500, 400);
}


MessageDlg::~MessageDlg(void)
{
	if (m_pMessageEdit != NULL) delete m_pMessageEdit;
}

//! setupFields
/*!
  \brief Set up the GUI controls
  \return Nothing
*/
void MessageDlg::setupFields()
{
  bool bcode = true;
  QPixmap p;
  m_pMessageEdit = new QTextEdit();
  m_pMessageEdit->setWordWrapMode(QTextOption::WordWrap);
  m_pMessageEdit->setReadOnly(true);
  m_pMessageTitle = Util::createLabel("", 
    tr("These are errors that were encountered by the XSupplicant before the GUI started up."));

  Util::myConnect(m_pMessageEdit, SIGNAL(copyAvailable(bool)), this, SLOT(slotCopy(bool))); 
  QPushButton *pCloseButton = Util::createButton(tr("&Close"), this, SLOT(accept()), tr("Close this dialog"));
  QPushButton *pHelpButton = Util::createButton(tr("&Help"), this, SLOT(slotHelp()), tr("Display the help for these messages."));

  QDialogButtonBox *pButtonLayout = new QDialogButtonBox();
  pButtonLayout->setOrientation(Qt::Horizontal);
  pButtonLayout->addButton(pCloseButton, QDialogButtonBox::AcceptRole);
  pButtonLayout->addButton(pHelpButton, QDialogButtonBox::HelpRole);

  QVBoxLayout *pMainLayout = new QVBoxLayout();
  pMainLayout->addWidget(m_pMessageTitle);
  pMainLayout->addWidget(m_pMessageEdit);
  pMainLayout->addWidget(pButtonLayout, 0, Qt::AlignCenter);
#ifdef TNC
  bcode = p.load(":/images/idbugclr0256.png");
#else
  bcode = p.load(":/images/opensea.png");
#endif
  if (bcode)
  {
    QIcon i(p);
    this->setWindowIcon(i);
  }
  setLayout(pMainLayout);
}


//! setInfo
/*!
  \brief Sets the dynamic data
  \param[in] title - the title text
  \param[in] text - the messages to display
  \param[in] helpFile - the help file to us
  \param[in] helpLocation - the location in the help file
  \return Nothing
*/
void MessageDlg::setInfo(QString &title, QString &text, QString &helpFile, QString &helpLocation)
{
  setWindowTitle(tr("XSupplicant Startup Log"));
  m_pMessageTitle->setText(title);
  m_pMessageEdit->setText(text);
  m_helpFile = helpFile;
  m_helpLocation = helpLocation;
}

//! slotCopy
/*!
  \brief Sets the dynamic data
  \param[in] bCopy - the flag that determines whether to copy the data or not
  \return Nothing
*/
void MessageDlg::slotCopy(bool bCopy)
{
  if (bCopy)
  {
    m_pMessageEdit->copy();
  }
}

//! slotHelp
/*!
  \brief Sets the dynamic data
  \return Nothing
*/
void MessageDlg::slotHelp()
{
  HelpBrowser::showPage(m_helpFile, m_helpLocation);
}
