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

#include <QtGui>
#include "stdafx.h"
#include "helpbrowser.h"
#include "FormLoader.h"
#include "Util.h"

HelpWindow *HelpWindow::s_pBrowser = NULL;

HelpWindow::HelpWindow(QWidget *parent):
  QWidget(parent)
{
  setAttribute(Qt::WA_DeleteOnClose);
  setAttribute(Qt::WA_GroupLeader);

  m_pRealForm = NULL;
  m_pTextBrowser = NULL;
  m_pHomeButton = NULL;
  m_pBackButton = NULL;
  m_pCloseButton = NULL;
}

HelpWindow::~HelpWindow()
{
	if (m_pRealForm != NULL)
	{
		delete m_pRealForm;
		m_pRealForm = NULL;
	}

  s_pBrowser = NULL;
}

bool HelpWindow::create()
{
	Qt::WindowFlags flags;

	m_pRealForm = FormLoader::buildform("HelpWindow.ui");

    if (m_pRealForm == NULL) return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(close()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pTextBrowser = qFindChild<QTextBrowser*>(m_pRealForm, "dataFieldHelpWindow");

	if (m_pTextBrowser == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'Help Dialog' did not contain the 'dataFieldHelpWindow' text box."));
		return false;
	}

	m_pHomeButton = qFindChild<QPushButton*>(m_pRealForm, "buttonHome");

	// We don't care if the button is there or not, but if it is make it work.
	if (m_pHomeButton != NULL)
	{
		Util::myConnect(m_pHomeButton, SIGNAL(clicked()), m_pTextBrowser, SLOT(home()));
	}

	m_pBackButton = qFindChild<QPushButton*>(m_pRealForm, "buttonBack");

	// We don't care if the button is there or not, but if it is make it work.
	if (m_pBackButton != NULL)
	{
		Util::myConnect(m_pBackButton, SIGNAL(clicked()), m_pTextBrowser, SLOT(backward()));
	}

	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");

	// We don't care if the button is there or not, but if it is make it work.
	if (m_pCloseButton != NULL)
	{
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), this, SLOT(close()));
	}

	flags = m_pRealForm->windowFlags();
	flags &= (~Qt::WindowContextHelpButtonHint);
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);

	return true;
}

void HelpWindow::show()
{
	// This will cause the window to come to the front if it is already built.
	if (m_pRealForm->isVisible() == true) m_pRealForm->hide();

	m_pRealForm->show();
}

void HelpWindow::setSource(const QString &path, const QString &file, const QString &page)
{
  QString fullPath = QString ("%1/%2").arg(path).arg(file);
  QString fullPage = QString ("%1#%2").arg(file).arg(page);

  if (QFile::exists(fullPath))
  {
    m_pTextBrowser->setSearchPaths(QStringList() << path << ":/images");
    m_pTextBrowser->setSource(fullPage);
  }
  else
  {
    QMessageBox::information(this, tr("Help Not Available"), tr("The help file '%1' was not found.  You may need to reinstall the application.").arg(fullPath));
    return;
  }
}

// This is the singleton use and also the display of the page
void HelpWindow::showPage(const QString &file, const QString &page)
{
  QString path = QApplication::applicationDirPath() + "/Docs";

  // This is a singleton 
  if (s_pBrowser == NULL)
  {
    s_pBrowser = new HelpWindow();
  }

  if (s_pBrowser->create() == true)
  {
	s_pBrowser->setSource(path, file, page);
	s_pBrowser->show();
  }
  else
  {
	  if (s_pBrowser != NULL)
	  {
		  delete s_pBrowser;
		  s_pBrowser = NULL;
	  }
  }
}

