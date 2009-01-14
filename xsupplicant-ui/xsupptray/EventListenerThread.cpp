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
#include "LoggingConsole.h"
#include "Util.h"
#include "xsupcalls.h"
#include "TrayApp.h"

//! Constructor
/*!
  \brief Constructs the listener class with a pointer to the logging console
  \param [in] pLog - the logging console that we will be outputting message to - 
    also get the supplicant from the logging window
  \return Nothing
*/
EventListenerThread::EventListenerThread(XSupCalls *m_pXSCalls, Emitter *e, QWidget *parent):
  m_supplicant(m_pXSCalls), myEmit(e)
{
  m_pParent = parent;
}

//! Destructor
/*!
  \brief Also, disconnect from the XSupEventListener
  \return Nothing
*/
EventListenerThread::~EventListenerThread(void)
{
  quit();
  m_supplicant->disconnectEventListener();
}

void EventListenerThread::run()
{
  waitForEvents((*myEmit)); // when this returns, the thread will exit - but it never returns currently
}

//! connectXSupEventListener
/*!
  \brief Also, disconnect from the XSupEventListener
  \return Nothing
*/
bool EventListenerThread::connectXSupEventListener(bool bDisplay)
{
  return m_supplicant->connectEventListener(bDisplay); 
}

//! disconnectXSupEventListener
/*!
  \brief Disconnect from the XSupEventListener
  \return Nothing
*/
void EventListenerThread::disconnectXSupEventListener()
{
  m_supplicant->disconnectEventListener();
}

//! waitForEvents
/*!
  \brief Also, disconnect from the XSupEventListener
  \param [in] e the Signal emitter
  \return return code from m_supplicant.waitForEvents()
*/
bool EventListenerThread::waitForEvents(Emitter &e)
{ 
  emit e.sendStartLogMessage(tr("--- Start of log entries ---\n")); 
  return m_supplicant->waitForEvents(e);
}

//! getErrorText
/*!
  \brief Get function to get the error text
  \return error text
*/
QString EventListenerThread::getErrorText()
{
  return m_errorText;
}


