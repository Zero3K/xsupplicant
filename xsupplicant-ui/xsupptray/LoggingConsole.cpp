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

#include "EventListenerThread.h"
#include "PasswordDlg.h"
#include "libxsupgui/xsupgui_events.h"
#include "FormLoader.h"
#include "Util.h"
#include "Emitter.h"
#include "MessageClass.h"
#include "LoggingConsole.h"

//! Constructor
/*!
  \param [in] parent is the parent widget
  \return Nothing
*/
LogWindow::LogWindow(QWidget * parent, Emitter * e)
 : 
QWidget(parent), m_bUpdateCalled(false), m_pEmitter(e), m_supplicant(parent)
{
	m_pCopyToClipboard = NULL;
	m_pPassword = NULL;

	Util::myConnect(m_pEmitter, SIGNAL(signalLogMessage(const QString)),
			this,
			SLOT(slotAddXSupplicantLogMessage(const QString)));
	Util::myConnect(m_pEmitter,
			SIGNAL(signalStartLogMessage(const QString)), this,
			SLOT(slotStartLogMessage(const QString)));
	Util::myConnect(m_pEmitter, SIGNAL(signalUIMessage(const QString)),
			this, SLOT(slotAddUILogMessage(const QString)));
	Util::myConnect(m_pEmitter,
			SIGNAL(signalRequestPasswordMessage
			       (const QString &, const QString &,
				const QString &)), this,
			SLOT(slotRequestPasswordMessage
			     (const QString &, const QString &,
			      const QString &)));
	Util::myConnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)),
			this, SLOT(slotInterfaceInsertedMessage(char *)));
	Util::myConnect(m_pEmitter, SIGNAL(signalXSupplicantShutDown()), this,
			SLOT(slotXSupplicantShutDown()));
	Util::myConnect(m_pEmitter, SIGNAL(signalClearLoginPopups()), this,
			SLOT(slotClearGTC()));
}

//! Destructor
/*!
  \return Nothing
*/
LogWindow::~LogWindow(void)
{
	if (m_pCopyToClipboard != NULL) {
		QObject::disconnect(m_pCopyToClipboard, SIGNAL(clicked()), this,
				    SLOT(slotCopyToClipboard()));
	}

	Util::myDisconnect(m_pEmitter, SIGNAL(signalLogMessage(const QString)),
			   this,
			   SLOT(slotAddXSupplicantLogMessage(const QString)));
	Util::myDisconnect(m_pEmitter,
			   SIGNAL(signalStartLogMessage(const QString)), this,
			   SLOT(slotStartLogMessage(const QString)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalUIMessage(const QString)),
			   this, SLOT(slotAddUILogMessage(const QString)));
	Util::myDisconnect(m_pEmitter,
			   SIGNAL(signalRequestPasswordMessage
				  (const QString &, const QString &,
				   const QString &)), this,
			   SLOT(slotRequestPasswordMessage
				(const QString &, const QString &,
				 const QString &)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalInterfaceInserted(char *)),
			   this, SLOT(slotInterfaceInsertedMessage(char *)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalXSupplicantShutDown()),
			   this, SLOT(slotXSupplicantShutDown()));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalClearLoginPopups()), this,
			   SLOT(slotClearGTC()));

	if (m_pPassword != NULL) {
		Util::myDisconnect(m_pPassword, SIGNAL(signalDone()), this,
				   SLOT(slotFinishPassword()));
		delete m_pPassword;
	}

	if (m_pRealForm != NULL)
		delete m_pRealForm;
}

/**
 * \brief Load the form from the disk, and get it ready to be displayed.
 *
 * \retval true if the form was loaded and processed correctly
 * \retval false if the form can't be loaded.
 **/
bool LogWindow::create()
{
	m_pRealForm = FormLoader::buildform("LogWindow.ui");

	if (m_pRealForm == NULL)
		return false;

	m_pRealForm->
	    setWindowFlags(windowFlags() | Qt::WindowMinimizeButtonHint);

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pLogEdit =
	    qFindChild < QTextEdit * >(m_pRealForm, "dataFieldLogWindow");
	if (m_pLogEdit == NULL) {
		QMessageBox::critical(this, tr("Form Design Error"),
				      tr
				      ("The form loaded for the 'Logging Dialog' did not contain the 'dataFieldLogWindow' text edit window.  Log information will not be shown."));
	}

	m_pCloseButton =
	    qFindChild < QPushButton * >(m_pRealForm, "buttonClose");
	// If this one isn't around, ignore it.
	if (m_pCloseButton != NULL) {
		m_pCloseButton->setText(tr("Close"));
		QObject::connect(m_pCloseButton, SIGNAL(clicked()),
				 this, SIGNAL(close()));
	}

	m_pClearButton =
	    qFindChild < QPushButton * >(m_pRealForm, "buttonClear");
	// If this one isn't around, ignore it.
	if (m_pClearButton != NULL) {
		m_pClearButton->setText(tr("Clear"));
		QObject::connect(m_pClearButton, SIGNAL(clicked()),
				 this, SLOT(slotClear()));
	}

	m_pCopyToClipboard =
	    qFindChild < QPushButton * >(m_pRealForm, "buttonCopy");
	if (m_pCopyToClipboard != NULL) {
		QObject::connect(m_pCopyToClipboard, SIGNAL(clicked()), this,
				 SLOT(slotCopyToClipboard()));
	}

	return true;
}

/**
 * \brief Hide the logging window from view.  (This is the same as "close".)
 **/
void LogWindow::hide()
{
	m_pRealForm->hide();
}

void LogWindow::slotCopyToClipboard()
{
	QTextCursor cursor;

	if (m_pLogEdit != NULL) {
		m_pLogEdit->selectAll();
		m_pLogEdit->copy();

		cursor = m_pLogEdit->textCursor();
		cursor.clearSelection();
		m_pLogEdit->setTextCursor(cursor);	// Clear the selection area.
		QMessageBox::information(this, tr("Text Copied"),
					 tr
					 ("The log data has been copied to the clipboard."));
	}
}

//! showLog
/*!
  \brief Shows the log window - if it is hidden - unhides it
  \return Nothing
*/
void LogWindow::showLog()
{
	if (m_pRealForm != NULL) {
		if (m_pLogEdit != NULL) {
			// move cursor to last line
			m_pLogEdit->moveCursor(QTextCursor::End,
					       QTextCursor::MoveAnchor);
			m_pLogEdit->moveCursor(QTextCursor::StartOfLine,
					       QTextCursor::MoveAnchor);
		}
		m_pRealForm->show();
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
void LogWindow::slotStartLogMessage(const QString & message)
{
	addMessage(message);
}

//! slotAddUISupplicantLogMessage
/*!
  \brief Adds a message to the log
  \param [in] message is the message to send
  \return Nothing
*/
void LogWindow::slotAddUILogMessage(const QString & message)
{
	QDate myDate;
	QTime myTime;

	QString text =
	    tr("%1  %2 - %3").arg(QDate::currentDate().toString("yyyy-MM-dd")).
	    arg(QTime::currentTime().toString("HH:mm:ss.zzz"))
	    .arg(message);

	addMessage(text);
}

//! slotAddXSupplicantLogMessage
/*!
  \brief Adds a message to the log
  \param [in] message is the message to send
  \return Nothing
*/
void LogWindow::slotAddXSupplicantLogMessage(const QString & message)
{
	QString text = tr("%1")
	    .arg(message);

	addMessage(text);
}

void LogWindow::addMessage(const QString & message)
{
	QString test;
	int index = 0;
	int position = 0;
	int i = 0;
	QTextCursor cursor;

	if (m_pLogEdit != NULL) {
		if (m_pLogEdit->toPlainText().count(QChar('\n')) > 1000) {
			cursor = m_pLogEdit->textCursor();
			position = cursor.position();
			test = m_pLogEdit->toPlainText();

			index = 0;

			for (i = 0; i < 100; i++) {
				index = test.indexOf(QChar('\n'), index + 1);
			}

			if (index >= 0) {
				test.remove(0, (index + 1));	// Remove 100 lines.
				position = test.size();	// Stay at the bottom of the log window.
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
XSupCalls & LogWindow::getSupplicant()
{
	return m_supplicant;
}

//! slotRequestPasswordMessage
/*!
  \brief 
  \param [in] connName
  \param [in] eapMethod
  \param [in] challengeString
  \return Nothing
*/
void LogWindow::slotRequestPasswordMessage(const QString & connName,
					   const QString & eapMethod,
					   const QString & challengeStr)
{
	if (m_pPassword != NULL)
		return;		// We are already displaying a dialog.

	m_pPassword = new PasswordDlg(connName, eapMethod, challengeStr);
	if (m_pPassword != NULL) {
		if (m_pPassword->attach() == true) {
			Util::myConnect(m_pPassword, SIGNAL(signalDone()), this,
					SLOT(slotFinishPassword()));
			m_pPassword->show();
		}
	} else {
		QMessageBox::critical(this, tr("Form Error"),
				      tr
				      ("Failed to load the password prompting form!"));
	}
}

void LogWindow::slotClearGTC()
{
	if (m_pPassword == NULL)
		return;

	Util::myDisconnect(m_pPassword, SIGNAL(signalDone()), this,
			   SLOT(slotFinishPassword()));

	delete m_pPassword;
	m_pPassword = NULL;
}

void LogWindow::slotFinishPassword()
{
	QString password;
	QString connection;
	int result = 0;

	password = m_pPassword->getPassword();
	connection = m_pPassword->getConnName();

	if (password == "") {
		QMessageBox::critical(this, tr("No token response provided"),
				      tr
				      ("No token response was provided.  Please provide a valid token response."));
		return;
	}

	if ((result =
	     xsupgui_request_set_connection_pw(connection.toAscii().data(),
					       password.toAscii().data())) !=
	    REQUEST_SUCCESS) {
		QMessageBox::critical(this, tr("Error Setting Token Response"),
				      tr
				      ("Unable to send the provided token response.  Error %1.").
				      arg(result));
	}

	slotClearGTC();
}

//! slotRemediation
/*!
  \brief Gives information from the TNC system
*/
void LogWindow::slotRemediation()
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
void LogWindow::slotInterfaceInsertedMessage(char *)
{
	// add the interface to the config file
	// do this by calling the update adapters api
	if (m_supplicant.updateAdapters(false))
		m_pEmitter->sendNewInterfaceInserted();
}

/*! slotShutDownMessage()
  \brief Called when the IPC channel with the supplicant says it has gone down.
  This will attempt to reconnect to the supplicant, and if it can't and the user doesn't want
  to continue to wait, it will shut down the GUI
  \return Nothing
*/
void LogWindow::slotXSupplicantShutDown()
{
	QMessageBox::critical(this, tr("XSupplicant Status"),
			      tr
			      ("The communications with XSupplicant have been terminated. \n"
			       "If you know how to restart XSupplicant do so, otherwise, contact your network administrator for help.\n"
			       "\nThe application will go into a 'disconnected' state until the XSupplicant service restarts."));

	emit signalSupplicantDownRestart();	// this should be received by the trayapp class which will delete all objects and go into a wait state
}

/*! slotClear()
  \brief Called when the interface inserted message is received detail what has gone out of compliance
  \return Nothing
*/
void LogWindow::slotClear()
{
	if (m_pLogEdit != NULL)
		m_pLogEdit->clear();
	addMessage(tr("--- Log entries cleared by user ---\n"));
}
