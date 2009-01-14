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

#include <QtGui>
#include "stdafx.h"
#include "helpbrowser.h"
#include "FormLoader.h"
#include "Util.h"

HelpWindow *HelpWindow::m_pInstance = NULL;

HelpWindow *HelpWindow::Instance(void)
{
	if (m_pInstance == NULL) {
		m_pInstance = new HelpWindow();
		if (m_pInstance->create() == false)
		{
			delete m_pInstance;
			m_pInstance = NULL;
		}
	}
	
	return m_pInstance;
}

HelpWindow::HelpWindow()
	:QWidget(NULL)
{
}

HelpWindow::HelpWindow(const HelpWindow &)
	:QWidget(NULL)
{
}

bool HelpWindow::create()
{
	Qt::WindowFlags flags;

	m_pRealForm = FormLoader::buildform("HelpWindow.ui");

	if (m_pRealForm == NULL)
		return false;

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pTextBrowser = qFindChild<QTextBrowser*>(m_pRealForm, "dataFieldHelpWindow");

	if (m_pTextBrowser == NULL)
	{
		QMessageBox::critical(m_pRealForm, tr("Form Design Error!"), tr("The form loaded for the 'Help Dialog' did not contain the 'dataFieldHelpWindow' text box."));
		return false;
	}

	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");

	// We don't care if the button is there or not, but if it is make it work.
	if (m_pCloseButton != NULL)
	{
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), m_pRealForm, SLOT(hide()));
	}

	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags |= Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);

	return true;
}

void HelpWindow::show()
{
	if (m_pRealForm != NULL)
	{
		// show, bring to front, and activate
		m_pRealForm->show();
		m_pRealForm->raise();
		m_pRealForm->activateWindow();
	}
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
		QMessageBox::information(m_pRealForm, tr("Help Not Available"), tr("The help file '%1' was not found.  You may need to reinstall the application.").arg(fullPath));
	}
}

// This is the singleton use and also the display of the page
void HelpWindow::showPage(const QString &file, const QString &page)
{
	HelpWindow *pInstance = HelpWindow::Instance();
	if (pInstance != NULL)
	{
		QString path = QApplication::applicationDirPath() + "/Docs";
		pInstance->setSource(path, file, page);
		pInstance->show();
	}
}


