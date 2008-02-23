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
#include <libxml/tree.h>
#include <libxsupgui/xsupgui_request.h>
#include <xsup_err.h>
#include "CharC.h"
#include "MessageDlg.h"
#include "MyMessageBox.h"
#include "MessageClass.h"
#include "helpbrowser.h"

MessageS MessageClass::m_xSupCalls[] = 
{
  REQUEST_SUCCESS,                tr("Request success"),
  REQUEST_TIMEOUT,                tr("Request Timeout"),
  REQUEST_FAILURE,                tr("Request Failure"), 
  REQUEST_NOT_IMPLEMENTED,        tr("The capability has not yet been implemented. Contact IDEngines support if this appears in a released product (non-beta)."),
  IPC_ERROR_NONE,                 tr("No Error - if you're seeing this, you shouldn't be.  There is no problem."),
  IPC_ERROR_CANT_ALLOCATE_NODE,   tr("Unable the allocate a node in the XML tree."),
  IPC_ERROR_UNKNOWN_REQUEST,      tr("Requested information we know nothing about."),
  IPC_ERROR_CANT_LOCATE_NODE,     tr("Couldn't find the node we needed in a request."),
  IPC_ERROR_INVALID_INTERFACE,    tr("Couldn't locate the interface that was requested."),
  IPC_ERROR_INVALID_CONTEXT,      tr("The context requested didn't contain all of the information we needed."),
  IPC_ERROR_INVALID_SIGNAL_STRENGTH, tr("The signal strength value isn't available."),
  IPC_ERROR_INVALID_REQUEST,      tr("The request didn't contain the information needed."),
  IPC_ERROR_INTERFACE_NOT_FOUND,  tr("The interface requested was not found."),
  IPC_ERROR_COULDNT_CHANGE_UPW,   tr("The username and/or password couldn't be changed."),
  IPC_ERROR_INVALID_ROOT_NODE,    tr("The root node in the request was invalid."),
  IPC_ERROR_INVALID_CONN_NAME,    tr("The connection name requested was invalid."),
  IPC_ERROR_INVALID_PROF_NAME,    tr("The profile name requested was invalid."),
  IPC_ERROR_INT_NOT_WIRELESS,     tr("The requested interface is not wireless."),
  IPC_ERROR_CANT_GET_IP,          tr("Couldn't obtain the IP address for requested interface!"),
  IPC_ERROR_CANT_GET_NETMASK,     tr("Couldn't obtain the netmask for requested interface."),
  IPC_ERROR_CANT_GET_GATEWAY,     tr("Couldn't obtain the default gateway for requested interface."),
  IPC_ERROR_CANT_FIND_SSID,       tr("Couldn't locate the requested SSID in the SSID cache."),
  IPC_ERROR_NO_INTERFACES,        tr("The supplicant is not currently managing any interfaces."),
  IPC_ERROR_INVALID_FILE,         tr("The filename requested is invalid."),
  IPC_ERROR_CANT_WRITE_CONFIG,    tr("Couldn't write the configuration file."),
  IPC_ERROR_INVALID_NODE,         tr("Couldn't locate node!"),
  IPC_ERROR_CANT_GET_CONFIG,      tr("Couldn't get requested configuration information!"),
  IPC_ERROR_INVALID_OU_NAME,      tr("Couldn't locate the requested OU."),
  IPC_ERROR_INVALID_TRUSTED_SVR,  tr("Couldn't locate the requested trusted server."),
  IPC_ERROR_PARSING,              tr("Attempt to parse requested configuration block failed."),
  IPC_ERROR_MALLOC,               tr("Failed to allocate memory!"),
  IPC_ERROR_CANT_CHANGE_CONFIG ,  tr("Failed to change requested configuration data."),
  IPC_ERROR_CANT_PASSIVE_SCAN,    tr("The OS doesn't know how to passive scan, or the interface won't allow it."),
  IPC_ERROR_UNKNOWN_SCAN_ERROR,   tr("An unhandled error occurred while attempting to scan."),
  IPC_ERROR_CERT_STORE_ERROR,     tr("An error occurred obtaining access to the certificate store."),
  IPC_ERROR_CANT_GET_CERT_INFO,   tr("Unable to locate the certificate information requested."),
  IPC_ERROR_BAD_TNC_UI_RESPONSE,  tr("The attempt to trigger the response to a TNC UI request failed."),
  IPC_ERROR_INTERFACE_IN_USE,     tr("The requested interface is already in use."),
  IPC_ERROR_NO_CONNECTION,        tr("The interface doesn't have a connection name assigned to it."),
  IPC_ERROR_NEW_ERRORS_IN_QUEUE,  tr("There are errors to be read from the error queue."),
  IPC_ERROR_CANT_DEL_CONN_IN_USE, tr("Cannot delete the connection because it is currently in use. Please disconnect this connection before attempting to delete it."),
  IPC_ERROR_NO_CONNECTION,        tr("The interface doesn't have a connection assigned."),
  IPC_ERROR_NEW_ERRORS_IN_QUEUE,  tr("There are errors to be read from the error queue."),
  IPC_ERROR_CANT_DEL_CONN_IN_USE, tr("Cannot delete the connection.  It is currently in use."),
  IPC_ERROR_CANT_GET_SYS_UPTIME,  tr("Unable to determine the system uptime."),
  IPC_ERROR_NEED_USERNAME,        tr("No username was provided for an EAP authentication."),
  IPC_ERROR_NEED_PASSWORD,        tr("No password was provided for the authentication."),
  IPC_ERROR_CANT_RENAME,          tr("Unable to rename connection/profile/trusted server."),
  IPC_ERROR_NAME_IN_USE,		  tr("The connection/profile/trusted server name is already in use."),

  // Error messages that can be generated by xsupgui internal calls.
  IPC_ERROR_CANT_FIND_RESPONSE,   tr("The required response header was not found in the response message."),
  IPC_ERROR_CANT_CREATE_REQUEST,  tr("The XML request document couldn't be created."),
  IPC_ERROR_CANT_CREATE_REQ_HDR,  tr("Unable to create the XML document framework."),
  IPC_ERROR_UNSPEC_REQ_FAILURE,   tr("The request failed for an unspecified reason."),
  IPC_ERROR_BAD_RESPONSE,         tr("The response XML document was invalid."),
  IPC_ERROR_CANT_FIND_REQ_ROOT_NODE, tr("The root node in the request document couldn't be located."),
  IPC_ERROR_CANT_CREATE_INT_NODE,   tr("The <Interface> node couldn't be created for the request."),
  IPC_ERROR_CANT_FIND_RESP_ROOT_NODE, tr("The root node in the response document couldn't be located."),
  IPC_ERROR_INVALID_PARAMETERS,   tr("The parameters passed in to the function were invalid."),
  IPC_ERROR_NULL_DOCUMENT,        tr("The document presented to the function is NULL."),
  IPC_ERROR_NO_ERROR_CODE,        tr("Got an error document that didn't contain an error code node."),
  IPC_ERROR_NULL_RESPONSE,        tr("The response document from the supplicant was NULL or didn't contain valid information."),
  IPC_ERROR_NULL_REQUEST        , tr("The request document was NULL or invalid after conversion."),
  IPC_ERROR_BAD_RESPONSE_DATA   , tr("The data included in the response document was invalid, or could not be parsed."),
  IPC_ERROR_CANT_ALLOCATE_MEMORY , tr("Unable to allocate memory to store response data."),
  IPC_ERROR_NOT_ACK             , tr("The response was not the ACK that was expected."),
  IPC_ERROR_NOT_PONG            , tr("The response to a PING request was not a PONG."),
  IPC_ERROR_INVALID_RESP_DATA   , tr("The response data didn't pass validation tests."),
  IPC_ERROR_CANT_ADD_NODE       , tr("The function was unable to add the newly created node to the existing tree."), 
  IPC_ERROR_INVALID_NUMBER_OF_EVENTS, tr("The number of events specified in the return document was invalid."),
  IPC_ERROR_CANT_SEND_IPC_MSG,    tr("Unable to send IPC message to the supplicant.  This may mean the supplicant has exited."),
  IPC_ERROR_SEND_SIZE_MISMATCH,   tr("The data to send was a different size than the data that was sent."),
  IPC_ERROR_UNABLE_TO_READ,       tr("Data appeared to be ready, but couldn't be read."),
  IPC_ERROR_RECV_IPC_RUNT,        tr("Received an IPC runt fragment."),
  IPC_ERROR_CANT_MALLOC_LOCAL,    tr("Unable to malloc memory in the local process."),
  IPC_ERROR_NOT_INITIALIZED,      tr("A variable was not properly initialized."),
  IPC_ERROR_STALE_BUFFER_DATA,    tr("There was stale data in the event buffer."),
  IPC_ERROR_CTRL_ALREADY_CONNECTED,tr("The IPC control channel was already connected."),
  IPC_ERROR_CTRL_NOT_CONNECTED,   tr("The IPC control channel is not connected."),
  IPC_ERROR_EVT_ALREADY_CONNECTED,tr("The event channel was already connected."),
  IPC_ERROR_EVT_NOT_CONNECTED,    tr("The event channel is not connected."),
  IPC_ERROR_RUNT_RESPONSE,        tr("The response data was not large enough to be a valid response.")

};



//! myMsgHandler()
/*!
  \brief A Qt message handler - this doesn't work very well - for some reason
  \param [in] type - the type of the message
  \param [in] msg
  \return nothing
*/
void myMsgHandler(QtMsgType type , const char *msg)
{
  QString text;
  if (strstr(msg, "Object::connect:") != NULL)
  {
    return;
  }
  switch (type) 
  {
     case QtDebugMsg:
       text = QString ("Debug: %1\n").arg(msg);
       break;
     case QtWarningMsg:
       text = QString ("Warning: %1\n").arg(msg);
       break;
     case QtCriticalMsg:
       text = QString ("Critical: %1\n").arg(msg);
       break;
     case QtFatalMsg:
       text = QString ("Fatal: %1\n").arg(msg);
       break;
  }

  // Display a message to the user inside the gui thread
  if (QThread::currentThread() == qApp->thread())
  {
    QMessageBox::information(NULL, QString("Error"), text);
  }
  /*
  
  if (msgHandler)
  {
    // call the default windows handler
        msgHandler(type, msg);
    }
    else
    {
        fprintf(stderr, qPrintable(text));
    }
    */

  // This is a windows only type call  - how do I determine
#ifdef WINDOWS
  OutputDebugStringA(text.toAscii().data());
#else
  fprintf(stderr, text.toAscii());
#endif

  if (type == QtFatalMsg)
  {
    abort();
  }
  return;
}

MessageClass::MessageClass(QWidget *pParent)
{
  m_pParent = pParent;
}

//! Destructor
/*!
  \brief Make sure all data is freed
  \return Nothing
*/
MessageClass::~MessageClass(void)
{
}

//! DisplayMessage
/*!
  \brief Logs and displays a message (all errors are logged, if the bDisplay is set to true (the default),
   it also displays the message in a message box
  \param [in] type - the type of the message MESSAGE_TYPE enum
  \param [in] titleString - the string to display in the title of the box
  \param [in] formatted String - the detail string to display
  \param [in] parent - if the message needs to be modal, this must be non-null
  \param [in] bDisplay - whether or not to display the message in a message box
  \param [in] pHelpInfo - the tag in the help file to display with this message
  \return StandardButton
*/
int MessageClass::DisplayMessage(MESSAGE_TYPE type, 
                                 QString &titleString, 
                                 QString &formattedString,  
                                 char *pHelpLocation)
{
  return MessageClass::DisplayMessage(type, titleString, formattedString, 0, "", pHelpLocation);
}

//! DisplayMessage
/*!
  \brief Logs and displays a message (all errors are logged, if the bDisplay is set to true (the default),
   it also displays the message in a message box
  \param [in] type - the type of the message MESSAGE_TYPE enum
  \param [in] titleString - the string to display in the title of the box
  \param [in] formatted String - the detail string to display
  \param [in] error - if this is due to an error, this will be non-null - it will look up the error in the list
  \param [in] parent - if the message needs to be modal, this must be non-null
  \param [in] bDisplay - whether or not to display the message in a message box
  \param [in] pHelpInfo - the tag in the help file to display with this message
  \return int - usually StandardButton
  \todo Implement the log file option
*/
int MessageClass::DisplayMessage(MESSAGE_TYPE type, 
                                 QString &titleString, 
                                 QString &formattedString, 
                                 int error, 
                                 char *function,
                                 char *pHelpLocation)
{
  m_pHelpLocation = pHelpLocation;
  int retval;
  QString errorText;
  QString fullString = formattedString;
  if (error != 0)
  {
    errorText = QString(tr("\n\nInternal Function Error\nAPI: %1\nError Code: '%2'\n'%3'\n\n")
      .arg(function)
      .arg(error)
      .arg(MessageClass::getMessageString(error)));
    if (error == IPC_ERROR_CANT_SEND_IPC_MSG)
    {
      // the supplicant may have gone down - emit a signal to that effect - need to link the signal to supplicant down message
      fullString.append(tr("XSupplicant may have exited.  If you get this message more than once, you may need to restart the supplicant and then restart XSupplicant (this application) before proceeding.\n\n"));
    }
  }
    switch (type)
    {
      default:
      case  QUESTION_TYPE:
        {
          MyMessageBox mbox(m_pParent, titleString, fullString, pHelpLocation, MyMessageBox::Question);
          retval = mbox.exec();
        }
        break;
      case INFORMATION_TYPE:
        {
          MyMessageBox mbox(m_pParent, titleString, fullString, pHelpLocation, MyMessageBox::Info);
          retval = mbox.exec();
        }
        break;
      case WARNING_TYPE:
        {
          MyMessageBox mbox(m_pParent, titleString, fullString, pHelpLocation, MyMessageBox::Warning);
          retval = mbox.exec();
        }
        break;
      case ERROR_TYPE:
        {
          MyMessageBox mbox(m_pParent, titleString, fullString, errorText, pHelpLocation, MyMessageBox::Critical);
          retval = mbox.exec();
        }
        break;
    }

  return retval;
}

void MessageClass::slotHelp()
{
  if (m_pHelpFile && m_pHelpLocation)
  {
    HelpWindow::showPage(m_pHelpFile, m_pHelpLocation);
  }
  else
  {
    HelpWindow::showPage("xsupphelp.html","xsupuserguide"); // generic help if none is passed in
  }
}
//! DisplayMessageModeless
/*!
  \brief Displays a modeless dialog that always stays on top of all other windows
  \param [in] type - the type of the message MESSAGE_TYPE enum
  \param [in] titleString - the string to display in the title of the box
  \param [in] formatted String - the detail string to display
  \param [in] parent - if the message needs to be modal, this must be non-null
  \param [in] bDisplay - whether or not to display the message in a message box
  \param [in] pHelpInfo - the tag in the help file to display with this message
  \return StandardButton
*/
void MessageClass::DisplayMessageModeless(QString &titleString, 
                                          QString &formattedString,
                                          QString &helpLocation)
{
  QString temp = "xsupphelp.html";

  msgDlg.setInfo(titleString, formattedString, temp, helpLocation);
  msgDlg.setWindowFlags(msgDlg.windowFlags() | Qt::WindowStaysOnTopHint);
  msgDlg.show();
}

QString MessageClass::getMessageString(int errorNumber)
{
  QString message;
  bool bFound = false;
  int x = sizeof(m_xSupCalls)/sizeof(m_xSupCalls[0]);
  for (int i = 0; i < x; i++)
  {
    if (m_xSupCalls[i].messageNumber == errorNumber)
    {
      message = m_xSupCalls[i].text;
      bFound = true;
      break;
    }
  }
  if (!bFound)
  {
    message = tr("Unknown error");
  }
  return message;
}
