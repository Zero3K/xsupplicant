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

#include "LoggingConsole.h"
#include "EventListenerThread.h"
#include "PasswordDlg.h"
#include "libxsupgui/xsupgui_events.h"
#include "FormLoader.h"
#include "Util.h"

//! Constructor
/*!
  \param [in] parent is the parent widget
  \return Nothing
*/
LoggingConsole::LoggingConsole(QWidget *parent, Emitter *e)
  : QWidget(parent), 
  m_bUpdateCalled(false),
  m_message(parent), m_pEmitter(e),
  m_supplicant(parent)
{
	m_pCopyToClipboard = NULL;

  Util::myConnect(m_pEmitter, SIGNAL(signalLogMessage(const QString)), this, SLOT(slotAddXSupplicantLogMessage(const QString)));
  Util::myConnect(m_pEmitter, SIGNAL(signalStartLogMessage(const QString)), this, SLOT(slotStartLogMessage(const QString)));
  Util::myConnect(m_pEmitter, SIGNAL(signalUIMessage(const QString)), this, SLOT(slotAddUILogMessage(const QString)));
  Util::myConnect(m_pEmitter, SIGNAL(signalRequestPasswordMessage(const QString &, const QString &, const QString &)), this, SLOT(slotRequestPasswordMessage(const QString &, const QString &, const QString &)));
  Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(slotInterfaceInsertedMessage(char *)));
  Util::myConnect(m_pEmitter, SIGNAL(signalXSupplicantShutDown()), this, SLOT(slotXSupplicantShutDown()));
}

//! Destructor
/*!
  \return Nothing
*/
LoggingConsole::~LoggingConsole(void)
{
	if (m_pCopyToClipboard != NULL)
	{
		QObject::disconnect(m_pCopyToClipboard, SIGNAL(clicked()), this, SLOT(slotCopyToClipboard()));
	}

  Util::myDisconnect(m_pEmitter, SIGNAL(signalLogMessage(const QString)), this, SLOT(slotAddXSupplicantLogMessage(const QString)));
  Util::myDisconnect(m_pEmitter, SIGNAL(signalStartLogMessage(const QString)), this, SLOT(slotStartLogMessage(const QString)));
  Util::myDisconnect(m_pEmitter, SIGNAL(signalUIMessage(const QString)), this, SLOT(slotAddUILogMessage(const QString)));
  Util::myDisconnect(m_pEmitter, SIGNAL(signalRequestPasswordMessage(const QString &, const QString &, const QString &)), this, SLOT(slotRequestPasswordMessage(const QString &, const QString &, const QString &)));
  Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)), this, SLOT(slotInterfaceInsertedMessage(char *)));
  Util::myDisconnect(m_pEmitter, SIGNAL(signalXSupplicantShutDown()), this, SLOT(slotXSupplicantShutDown()));

	delete m_pRealForm;
}

/**
 * \brief Load the form from the disk, and get it ready to be displayed.
 *
 * \retval true if the form was loaded and processed correctly
 * \retval false if the form can't be loaded.
 **/
bool LoggingConsole::create()
{
	m_pRealForm = FormLoader::buildform("LogDlg.ui");

    if (m_pRealForm == NULL) return false;

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pLogEdit = qFindChild<QTextEdit*>(m_pRealForm, "logEdit");
	if (m_pLogEdit == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form loaded for the 'Logging Dialog' did not contain the 'logEdit' text edit window.  Log information will not be shown."));
	}

	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "clsBtn");
	// If this one isn't around, ignore it.
	if (m_pCloseButton != NULL)
	{
	    QObject::connect(m_pCloseButton, SIGNAL(clicked()),
		                  this, SIGNAL(close()));
	}

	m_pClearButton = qFindChild<QPushButton*>(m_pRealForm, "clearBtn");
	// If this one isn't around, ignore it.
	if (m_pClearButton != NULL)
	{
		QObject::connect(m_pClearButton, SIGNAL(clicked()),
			this, SLOT(slotClear()));
	}

	m_pCopyToClipboard = qFindChild<QPushButton*>(m_pRealForm, "copyBtn");
	if (m_pCopyToClipboard != NULL)
	{
		QObject::connect(m_pCopyToClipboard, SIGNAL(clicked()), this, SLOT(slotCopyToClipboard()));
	}

    m_pRealForm->setWindowFlags(windowFlags() | Qt::WindowMinimizeButtonHint);

	return true;
}

/**
 * \brief Hide the logging window from view.  (This is the same as "close".)
 **/
void LoggingConsole::hide()
{
	m_pRealForm->hide();
}

void LoggingConsole::slotCopyToClipboard()
{
	QTextCursor cursor;

	if (m_pLogEdit != NULL)
	{
		m_pLogEdit->selectAll();
		m_pLogEdit->copy();

		cursor = m_pLogEdit->textCursor();
		cursor.clearSelection();
		m_pLogEdit->setTextCursor(cursor);  // Clear the selection area.
		QMessageBox::information(this, tr("Text Copied"), tr("The log data has been copied to the clipboard."));
	}
}

//! showLog
/*!
  \brief Shows the log window - if it is hidden - unhides it
  \return Nothing
*/
void LoggingConsole::showLog()
{
	if (m_pRealForm != NULL)
	{
		m_pRealForm->show();
		if (m_pLogEdit != NULL) m_pLogEdit->moveCursor(QTextCursor::End);
		m_pRealForm->activateWindow();
		m_pRealForm->setFocus();
	}
}

//! slotStartLogMessage
/*!
  \brief Adds a message to the log
  \param [in] message is the message add (without preceding date and time)
  \return Nothing
  \todo Don't really need this one now
*/
void LoggingConsole::slotStartLogMessage(const QString &message)
{
  addMessage(message);
}

//! slotAddUISupplicantLogMessage
/*!
  \brief Adds a message to the log
  \param [in] message is the message to send
  \return Nothing
*/
void LoggingConsole::slotAddUILogMessage(const QString &message)
{
	QDate myDate;
	QTime myTime;

	QString text = tr("%1  %2 - %3").arg(QDate::currentDate().toString("yyyy-MM-dd")).arg(QTime::currentTime().toString("HH:mm:ss.zzz"))
		.arg(message);

  addMessage(text);
}

//! slotAddXSupplicantLogMessage
/*!
  \brief Adds a message to the log
  \param [in] message is the message to send
  \return Nothing
*/
void LoggingConsole::slotAddXSupplicantLogMessage(const QString &message)
{
  QString text = tr("%1")
    .arg(message);

  addMessage(text);
}

void LoggingConsole::addMessage(const QString &message)
{
	QString test;
	int index = 0;
	int position = 0;
	int i = 0;
	QTextCursor cursor;

  if (m_pLogEdit != NULL)
  {
	  if (m_pLogEdit->toPlainText().count(QChar('\n')) > 1000)
	  {
		  cursor = m_pLogEdit->textCursor();
		  position = cursor.position();
		  test = m_pLogEdit->toPlainText();

		  index = 0;

		  for (i=0; i<100; i++)
		  {
			index = test.indexOf(QChar('\n'), index+1);
		  }

		  if (index >= 0)
		  {
			test.remove(0, (index+1));  // Remove 100 lines.
			position = test.size();     // Stay at the bottom of the log window.
			m_pLogEdit->setPlainText(test);
			cursor.setPosition(position);
			m_pLogEdit->setTextCursor(cursor);
		  }
	  }

	  m_pLogEdit->append(tr("%1")
		.arg(message));
  }
}

//! getSupplicant
/*!
  \brief Get function to get the supplicant object
  \return supplicant
*/
XSupCalls &LoggingConsole::getSupplicant() 
{
  return m_supplicant;
}


//! slotRequestPasswordMessage
/*!
  \brief Appends a state message to the log file
  \param [in] connName
  \param [in] eapMethod
  \param [in] challengeString
  \return Nothing
*/
void LoggingConsole::slotRequestPasswordMessage(const QString &connName, const QString &eapMethod, const QString &challengeStr)
{
  // Enter the password - what information do I display about why we are asking for a password?
  PasswordDlg dlg(connName, eapMethod, challengeStr);
  dlg.exec();
  // Return the password, how is this done?
}

//! slotRemediation
/*!
  \brief Gives information from the TNC system
*/
void LoggingConsole::slotRemediation()
{ 
	/*
  tnc_msg_batch *pMessageBatch = NULL;
  pMessageBatch = (tnc_msg_batch *)malloc((TNC_MSG_IDSIZE+1)*sizeof(tnc_msg_batch));
  for (int i = 0; i < TNC_MSG_IDSIZE; i++)
  {
    pMessageBatch[i].msgid  = i;
    pMessageBatch[i].oui = 1;
    QString message = QString("Server message goes here for message #%1").arg(i);
     pMessageBatch[i].parameter = Util::myNullStrdup(message.toAscii());
  }
  pMessageBatch[TNC_MSG_IDSIZE].oui = 0;
  slotTNCUIRequestBatchMessage(0, 0, 0, 0, pMessageBatch);
  */
}


/*! slotInterfaceInsertedMessage()
  \brief Called when the interface inserted message is receiveddetail what has gone out of compliance
  \return Nothing
  \todo Check to see if this works
*/
void LoggingConsole::slotInterfaceInsertedMessage(char *)
{
  // add the interface to the config file
  // do this by calling the update adapters api
  m_supplicant.updateAdapters(false);
}

/*! slotShutDownMessage()
  \brief Called when the IPC channel with the supplicant says it has gone down.
  This will attempt to reconnect to the supplicant, and if it can't and the user doesn't want
  to continue to wait, it will shut down the GUI
  \return Nothing
*/
void LoggingConsole::slotXSupplicantShutDown()
{
  this->m_message.DisplayMessage( MessageClass::ERROR_TYPE, tr("XSupplicant Status"),
    tr("The communications with the XSupplicant has been terminated.  This application will now terminate.\n"
    "If you know how to restart the XSupplicant do so, otherwise, contact your network administrator for help.\n"
    "\nThe application will go into a 'disconnected' state (red tray icon) until the XSupplicant restarts."));

  emit signalSupplicantDownRestart(); // this should be received by the trayapp class which will delete all objects and go into a wait state
}
/*! slotClear()
  \brief Called when the interface inserted message is receiveddetail what has gone out of compliance
  \return Nothing
  \todo Check to see if this works
*/

void LoggingConsole::slotClear()
{
  if (m_pLogEdit != NULL) m_pLogEdit->clear();
  addMessage(tr("Log entries cleared by user"));
}
