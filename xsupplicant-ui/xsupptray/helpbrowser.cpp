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

QWidget *HelpWindow::m_pRealForm = NULL;
QTextBrowser *HelpWindow::m_pTextBrowser = NULL;
QPushButton *HelpWindow::m_pCloseButton = NULL;

bool HelpWindow::create()
{
	if (m_pRealForm == NULL)
	{
		Qt::WindowFlags flags;

		HelpWindow::m_pRealForm = FormLoader::buildform("HelpWindow.ui");

		if (HelpWindow::m_pRealForm == NULL)
			return false;

		// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
		HelpWindow::m_pTextBrowser = qFindChild<QTextBrowser*>(HelpWindow::m_pRealForm, "dataFieldHelpWindow");

		if (m_pTextBrowser == NULL)
		{
			QMessageBox::critical(HelpWindow::m_pRealForm, tr("Form Design Error!"), tr("The form loaded for the 'Help Dialog' did not contain the 'dataFieldHelpWindow' text box."));
			return false;
		}

		HelpWindow::m_pCloseButton = qFindChild<QPushButton*>(HelpWindow::m_pRealForm, "buttonClose");

		// We don't care if the button is there or not, but if it is make it work.
		if (HelpWindow::m_pCloseButton != NULL)
		{
			Util::myConnect(HelpWindow::m_pCloseButton, SIGNAL(clicked()), HelpWindow::m_pRealForm, SLOT(hide()));
		}

		flags = HelpWindow::m_pRealForm->windowFlags();
		flags &= ~Qt::WindowContextHelpButtonHint;
		flags |= Qt::WindowMinimizeButtonHint;
		HelpWindow::m_pRealForm->setWindowFlags(flags);
	}
	return true;
}

void HelpWindow::show()
{
	if (HelpWindow::m_pRealForm != NULL)
	{
		// show, bring to front, and activate
		HelpWindow::m_pRealForm->show();
		HelpWindow::m_pRealForm->raise();
		HelpWindow::m_pRealForm->activateWindow();
	}
}

void HelpWindow::setSource(const QString &path, const QString &file, const QString &page)
{
	if (HelpWindow::m_pRealForm != NULL || HelpWindow::create() == true)
	{
		QString fullPath = QString ("%1/%2").arg(path).arg(file);
		QString fullPage = QString ("%1#%2").arg(file).arg(page);

		if (QFile::exists(fullPath))
		{
			HelpWindow::m_pTextBrowser->setSearchPaths(QStringList() << path << ":/images");
			HelpWindow::m_pTextBrowser->setSource(fullPage);
		}
		else
		{
			QMessageBox::information(HelpWindow::m_pRealForm, tr("Help Not Available"), tr("The help file '%1' was not found.  You may need to reinstall the application.").arg(fullPath));
		}
	}
}

// This is the singleton use and also the display of the page
void HelpWindow::showPage(const QString &file, const QString &page)
{
	if (HelpWindow::m_pRealForm != NULL || HelpWindow::create() == true)
	{
		QString path = QApplication::applicationDirPath() + "/Docs";
		HelpWindow::setSource(path, file, page);
		HelpWindow::show();
	}
}

