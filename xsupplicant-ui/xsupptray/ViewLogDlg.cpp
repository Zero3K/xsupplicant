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
#include "ViewLogDlg.h"
#include <stdio.h>
#include "Util.h"
#include "FormLoader.h"
#include "helpbrowser.h"

uiWindowViewLogs::uiWindowViewLogs(QString &folderPath)
{
  int size = folderPath.size();
  if (folderPath.at(size-1) != '/' && folderPath.at(size-1) != '\\')
  {
    m_filePath = QString("%1/%2").arg(folderPath).arg(QString("xsupplicant.log"));
  }
  else
  {
    m_filePath = QString ("%1%2").arg(folderPath).arg(QString("xsupplicant.log"));
  }

  m_pBrowseButton = NULL;
  m_pHelpButton = NULL;
  m_pCloseButton = NULL;
  m_pCopyToClipboard = NULL;
  m_bConnected = false;
}


uiWindowViewLogs::~uiWindowViewLogs(void)
{
	if (m_pBrowseButton != NULL)
	{
		Util::myDisconnect(m_pBrowseButton, SIGNAL(clicked()), this, SLOT(slotBrowse()));
	}

	if (m_pHelpButton != NULL)
	{
		Util::myDisconnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotHelp()));
	}

	if (m_pCloseButton != NULL)
	{
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), this, SIGNAL(close()));
	}

	if (m_pCopyToClipboard != NULL)
	{
		Util::myDisconnect(m_pCopyToClipboard, SIGNAL(clicked()), this, SLOT(slotCopyToClipboard()));
	}

	if (m_bConnected)
	{
		Util::myConnect(m_pRealWidget, SIGNAL(rejected()), this, SIGNAL(close()));
	}

	if (m_pRealWidget != NULL)
	{
		delete m_pRealWidget;
	}
}

bool uiWindowViewLogs::attach()
{
	m_pRealWidget = FormLoader::buildform("ViewLogWindow.ui");
	if (m_pRealWidget == NULL) return false;

	m_pBrowseButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonBrowse");

	m_pCloseButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonClose");

	m_pHelpButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonHelp");

	m_pPathName = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldLogFileDirectory");

	m_pLogView = qFindChild<QTextEdit*>(m_pRealWidget, "dataFieldLogWindow");
	if (m_pLogView == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The QTextBox called 'dataFieldLogWindow' couldn't be found."));
		return false;
	}

	m_pCopyToClipboard = qFindChild<QPushButton*>(m_pRealWidget, "buttonCopy");
	if (m_pCopyToClipboard != NULL)
	{
		Util::myConnect(m_pCopyToClipboard, SIGNAL(clicked()), this, SLOT(slotCopyToClipboard()));
	}

	Util::myConnect(m_pRealWidget, SIGNAL(rejected()), this, SIGNAL(close()));
	m_bConnected = true;

	if (m_pBrowseButton != NULL)
	{
		Util::myConnect(m_pBrowseButton, SIGNAL(clicked()), this, SLOT(slotBrowse()));
	}

	if (m_pCloseButton != NULL)
	{
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), this, SIGNAL(close()));
	}

	if (m_pHelpButton != NULL)
	{
		Util::myConnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotHelp()));
	}

	m_pPathName->setText(m_filePath);

	open();

	return true;
}

void uiWindowViewLogs::slotCopyToClipboard()
{
	QTextCursor cursor;

	if (m_pLogView != NULL)
	{
		m_pLogView->selectAll();
		m_pLogView->copy();
	
		cursor = m_pLogView->textCursor();
		cursor.clearSelection();
		m_pLogView->setTextCursor(cursor);  // Clear the selection area.
		QMessageBox::information(this, tr("Text Copied"), tr("The log data has been copied to the clipboard."));
	}
}

void uiWindowViewLogs::slotBrowse()
{
  QString temp = QFileDialog::getOpenFileName(m_pRealWidget, tr("Select Log File to View"), m_filePath);
  if (temp.isEmpty())
  {
    return;
  }

  m_filePath = temp ;
  m_pPathName->setText(temp);
  open();
}

bool uiWindowViewLogs::open()
{
  if (m_filePath.isEmpty())
  {
    return false;
  }
  QCursor q(Qt::BusyCursor);
  QCursor oldCursor = cursor();
  QFile file(m_filePath);
  // If the file is larger than 3 mb, warn the user
  if (file.size() > 3000000)
  {
    if (QMessageBox::information(NULL, tr("Large file warning"),
      tr("The file '%1' is very large (%2 bytes) and may take some time to read. "
      "Do you still want to proceed to view this file?").arg(m_filePath).arg(file.size()),
      QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
      return false;
  }
  if (file.open(QIODevice::ReadOnly))
  {
    QApplication::setOverrideCursor(q);
    m_pLogView->setText(file.readAll());
    QApplication::setOverrideCursor(oldCursor);
  }
  else
  {
    QMessageBox::warning(this, tr("Open File Error"), tr("Can't open the log file '%1'.\nError: '%2 - %3'")
      .arg(m_filePath).arg(file.error()).arg(getErrorText(file.error())));
    return false;
  }
  return true;
}

/*
void uiWindowViewLogs::slotClose()
{
  accept();
}*/

void uiWindowViewLogs::slotHelp()
{
  HelpWindow::showPage("xsupphelp.html","xsupviewlogwin");
}

QString uiWindowViewLogs::getErrorText(QFile::FileError e)
{
  QString message = "";
  switch (e)
  {
  case QFile::NoError:
    break;
  case QFile::ReadError:
    message =tr("An error occurred when reading from the file.");
    break;
  case QFile::WriteError:
    message =tr("An error occurred when writing to the file.");
    break;
  case QFile::FatalError:
    message =tr("A fatal error occurred.");
    break;
  case QFile::ResourceError:
    message =tr("A resource error occurred.");
    break;
  case QFile::OpenError:
    message =tr("The file could not be opened.");
    break;
  case QFile::AbortError:
    message =tr("The operation was aborted.");
    break;
  case QFile::TimeOutError:
    message =tr("A timeout occurred.");
    break;
  case QFile::UnspecifiedError:
    message =tr("An unspecified error occurred.");
    break;
  case QFile::RemoveError:
    message =tr("The file could not be removed.");
    break;
  case QFile::RenameError:
    message =tr("The file could not be renamed.");
    break;
  case QFile::PositionError:
    message =tr("The position in the file could not be changed.");
    break;
  case QFile::ResizeError:
    message =tr("The file could not be resized.");
    break;
  case QFile::PermissionsError:
    message =tr("The file could not be accessed because of insufficient permissions, you don't have rights to see the contents of this file.");
    break;
  case QFile::CopyError:
    message =tr("The file could not be copied.");
    break;
  }
  return message;
}

void uiWindowViewLogs::show()
{
	m_pRealWidget->show();
}


