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

#include "Util.h"
#include "MyMessageBox.h"
#include <qmessagebox.h>
#include "helpbrowser.h"

MyMessageBox::MyMessageBox(QWidget *parent, QString &title, QString &text, char *pHelpLocation, messageTypeE type):
  QDialog(parent)
{
  m_errorText = "";
  setupFields(title, text, pHelpLocation, type);
  setWindowFlags(windowFlags() | Qt::WindowMinMaxButtonsHint);
}


MyMessageBox::MyMessageBox(QWidget *parent, QString &title, QString &text, QString &errorText, 
                           char *pHelpLocation, messageTypeE type):
  QDialog(parent)
{
  m_errorText = errorText; // write this to a file or display on the window or both
  setupFields(title, text, pHelpLocation, type);
  setWindowFlags(windowFlags() | Qt::WindowMinMaxButtonsHint);
}

MyMessageBox::~MyMessageBox(void)
{
}

//! setupFields
/*!
  \brief Set up the GUI controls
  \return Nothing
*/
void MyMessageBox::setupFields(QString &title, QString &text, char *pHelpLocation, messageTypeE type)
{
  bool bcode = true;
  QPixmap p;
  QWidget *pExtension = NULL;

#ifdef TNC
  bcode = p.load(":/images/idbugclr0256.png");
#else
  bcode = p.load(":/images/opensea.png");
#endif 
  QIcon windowIcon(p);
  setWindowIcon(windowIcon);
  if (pHelpLocation)
  {
    m_helpLocation = pHelpLocation;
  }
  else
  {
    m_helpLocation = "Top";
  }
  m_pMessageText = new QLabel(text);
  m_pMessageText->setWordWrap(true);
  m_pMessageTitle = Util::createLabel(title, tr("XSupplicant Message"));

  QPushButton *pHelpButton = Util::createButton(tr("&Help"), this, SLOT(slotHelp()), tr("Display the help for these messages."));
  pHelpButton->setAutoDefault(false);
  QDialogButtonBox *pButtonLayout = new QDialogButtonBox();
  pButtonLayout->setOrientation(Qt::Horizontal);
  if (type == Question)
  {
    setWindowTitle(tr("Response Needed"));
    QPushButton *pYesButton = Util::createButton(tr("Yes"), this, SLOT(slotYes()), tr("Select yes for this question."));
    QPushButton *pNoButton = Util::createButton(tr("No"), this, SLOT(slotNo()), tr("Select no for this question."));
    pYesButton->setDefault(true);
    pNoButton->setAutoDefault(false);
    pButtonLayout->addButton(pYesButton, QDialogButtonBox::AcceptRole);
    pButtonLayout->addButton(pNoButton, QDialogButtonBox::RejectRole);
  }
  else
  {
    QPushButton *pCloseButton = Util::createButton(tr("Close"), this, SLOT(accept()), tr("Close this dialog"));
    pCloseButton->setDefault(true);
    pButtonLayout->addButton(pCloseButton, QDialogButtonBox::AcceptRole);
  }
  QMessageBox m;
  QPixmap pixmap;
  switch (type)
  {
    case Question:
      setWindowTitle(tr("Response Needed"));
      m.setIcon(QMessageBox::Question);
      pixmap = m.iconPixmap();
      break;
    case Info:
      setWindowTitle(tr("Information"));
      m.setIcon(QMessageBox::Information);
      pixmap = m.iconPixmap();
      break;
    case Warning:
      setWindowTitle(tr("Warning"));
      m.setIcon(QMessageBox::Warning);
      pixmap = m.iconPixmap();
      break;
    case Critical:
      setWindowTitle(tr("Error"));
      m.setIcon(QMessageBox::Critical);
      pixmap = m.iconPixmap();
      break;
  }


  // Other code
  pButtonLayout->addButton(pHelpButton, QDialogButtonBox::HelpRole);
  QLabel *icon = new QLabel();
  icon->setPixmap(pixmap);
  QVBoxLayout *pTopLayout = new QVBoxLayout();
  pTopLayout->addWidget(icon, 0, Qt::AlignCenter);
  pTopLayout->addWidget(m_pMessageTitle, 0, Qt::AlignCenter);
  pTopLayout->addWidget(m_pMessageText);
  pTopLayout->addStretch(1);

  QVBoxLayout *pMainLayout = new QVBoxLayout();
  pMainLayout->addLayout(pTopLayout);

  // New code to display details of error
  if (!m_errorText.isEmpty())
  {
    QPushButton *pDetailsButton = new QPushButton(tr("&Details"));
    pDetailsButton->setWhatsThis(tr("Get more details for your system administrator and support to use"));
    pDetailsButton->setToolTip(tr("Get more details for your system administrator and support to use"));

    pExtension = new QWidget;
    QLabel *pTopLine = new QLabel();
    pTopLine->setFrameStyle(QFrame::HLine);
    pTopLine->setLineWidth(2);
    QLabel *pBottomLine = new QLabel();
    pBottomLine->setFrameStyle(QFrame::HLine);
    pBottomLine->setLineWidth(2);
    QLabel *pHeader = new QLabel(tr("Details"));
    QLabel *pDetailsLabel = new QLabel(m_errorText);
    pDetailsLabel->setWordWrap(true);
    QVBoxLayout *pDetailsLayout = new QVBoxLayout();

    // Handle the button
    pDetailsButton->setCheckable(true);
    pDetailsButton->setAutoDefault(false);
    Util::myConnect(pDetailsButton, SIGNAL(toggled(bool)), pExtension, SLOT(setVisible(bool)));
    pButtonLayout->addButton(pDetailsButton, QDialogButtonBox::ActionRole);

    // Handle the layout of the extension
    pDetailsLayout->setMargin(0);
    pDetailsLayout->addWidget(pTopLine);
    pDetailsLayout->addWidget(pHeader, 0, Qt::AlignCenter);
    pDetailsLayout->addWidget(pDetailsLabel);
    pDetailsLayout->addWidget(pBottomLine);
    pExtension->setLayout(pDetailsLayout);

    // Add the extension to the main layout and hide it
    pMainLayout->addWidget(pExtension);
  }
  pMainLayout->addWidget(pButtonLayout, 0, Qt::AlignCenter);
  pMainLayout->setSizeConstraint(QLayout::SetFixedSize);
  setLayout(pMainLayout);
  if (pExtension)
  {
    pExtension->hide();
  }
}

//! slotHelp
/*!
  \brief Sets the dynamic data
  \return Nothing
*/
void MyMessageBox::slotHelp()
{
  HelpWindow::showPage("xsupphelp.html", m_helpLocation);
}

void MyMessageBox::slotYes()
{
  done(Accepted);
}

void MyMessageBox::slotNo()
{
  done(Rejected);
}

