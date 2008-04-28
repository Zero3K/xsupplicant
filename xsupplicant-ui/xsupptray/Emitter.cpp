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
#include <QtGui>
#include "UIPlugins.h"

//! Emitter
/*!
  \brief Constructor
  \return Nothing
*/
Emitter::Emitter()
{
}

void Emitter::sendSupWarningEvent(const QString &warning)
{
	emit signalSupWarningEvent(warning);
}

void Emitter::sendSupErrorEvent(const QString &error)
{
	emit signalSupErrorEvent(error);
}

//! sendStartLogMessage
/*!
  \brief emit's a logMessage signal
  \param [in] str is the string we want to convert to a char *
  \return Nothing
*/
void Emitter::sendStartLogMessage(const QString &str)
{
	emit signalStartLogMessage(str);
}

//! sendLogMessage
/*!
  \brief emit's a logMessage signal
  \param [in] str is the string we want to convert to a char *
  \return Nothing
*/
void Emitter::sendLogMessage(const QString &str)
{
	emit signalLogMessage(str);
}

void Emitter::sendBadPSK(QString &intName)
{
	emit signalBadPSK(intName);
}

//! sendIPAddressSet
/*!
  \brief emit a signalIPAddressSet signal
*/
void Emitter::sendIPAddressSet()
{
	emit signalIPAddressSet();
}

//! sendStateMessage
/*!
  \brief emit's a logMessage 
  \param [in] str is the string we are going to send with the signal
  \return Nothing
*/
void Emitter::sendStateMessage(const QString &str)
{
	emit signalStateMessage(str);
}

//! sendStateChange
/*!
  \brief emit a state change message for an interface
  \param [in] intName is the OS specific interface name that generated the event
  \param [in] sm is the state machine that generated the event
  \param [in] oldstate is the state that we used to be in
  \param [in] newstate is the state that we are now in
*/
void Emitter::sendStateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid)
{
	emit signalStateChange(intName, sm, oldstate, newstate, tncconnectionid);
}

//! sendStateMessageToScreen
/*!
  \brief emit's a state change signal to the Login Status dialog
  \param [in] machine - the machine that is changing
  \param [in] str - the string representation of the current state
  \return Nothing
*/
void Emitter::sendStateMessageToScreen(int machine, int state, const QString &str)
{
	emit signalStateMessageToScreen(machine, state, str);
}

//! sendUpdate
/*!
  \brief emit's a signal to let listeners know that we have updated our connection
         configuration.
  \return Nothing
*/
void Emitter::sendConnConfigUpdate()
{
  emit signalConnConfigUpdate();
}

void Emitter::sendProfConfigUpdate()
{
	emit signalProfConfigUpdate();
}

//! sendScanComplete
/*!
  \brief emit's a logMessage 
  \return Nothing
*/
void Emitter::sendScanComplete(const QString &s)
{
  emit signalScanCompleteMessage(s);
}

//! sendUIMessage
/*!
  \brief emit's a message to be displayed by the UI
  \param [in] str is the string we are going to send with the signal
  \return Nothing
*/
void Emitter::sendUIMessage(const QString &str)
{
	emit signalUIMessage(str);
}

//! sendRequestPassword
/*!
  \brief emit's a message that the password needs to be entered
  \return Nothing
*/
void Emitter::sendRequestPassword(const QString &connName, const QString &eapMethod, const QString &challengeStr)
{
  emit signalRequestPasswordMessage(connName, eapMethod, challengeStr);
}

//! sendTNCUIEvent
/*!
  \brief emit's a message from the TNC that doesn't require a response - just informational
  \return Nothing
*/
void Emitter::sendTNCUIEvent(int oui, int notification)
{
  emit signalTNCUIMessage(oui, notification);
}

//! sendTNCUIRequestEvent
/*!
  \brief emit's a message from the TNC that DOES require a response
  \return Nothing
*/
void Emitter::sendTNCUIRequestEvent(int imc, int connID, int oui, int request)
{
  emit signalTNCUIRequestMessage(imc, connID, oui, request);
}

//! sendTNCUIRequestBatchEvent
/*!
  \brief emit's a message from the TNC that DOES require a response
  \return Nothing
*/
void Emitter::sendTNCUIRequestBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages)
{
  emit signalTNCUIRequestBatchMessage(imc, connID, oui, request, pTNCMessages);
}

//! sendTNCUIResponseBatchEvent
/*!
  \brief emit's a message from the TNC that DOES require a response
  \return Nothing
*/
void Emitter::sendTNCUIResponseBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages)
{
  emit signalTNCUIResponseBatchMessage(imc, connID, oui, request, pTNCMessages);
}

//! sendTNCUIReconnectBatchEvent
/*!
  \brief The supplicant wants to know if it's ok to reconnect the user to the network. 
  \return Nothing
*/
void Emitter::sendTNCUIReconnectBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages)
{
  emit signalTNCUIReconnectBatchMessage(imc, connID, oui, request, pTNCMessages);
}

//! sendTNCUIRemediationStartedBatchEvent
/*!
  \brief The supplicant wants the UI to know that remediation fix actions have begun. 
  \return Nothing
*/
void Emitter::sendTNCUIRemediationStartedBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages)
{
  emit signalTNCUIRemediationStartedBatchMessage(imc, connID, oui, request, pTNCMessages);
}

//! sendTNCUIRemediationStartedBatchEvent
/*!
  \brief The supplicant wants the UI to know that remediation fix actions have begun. 
  \return Nothing
*/
void Emitter::sendTNCUIRemediationStatusUpdateBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages)
{
  emit signalTNCUIRemediationStatusUpdateBatchMessage(imc, connID, oui, request, pTNCMessages);
}

//! sendTNCUIComplianceBatchEvent
/*!
  \brief emit's a message from the TNC that DOES require a response
  \return Nothing
*/
void Emitter::sendTNCUIComplianceBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages)
{
  emit signalTNCUIComplianceBatchMessage(imc, connID, oui, request, pTNCMessages);
}

void Emitter::sendTNCReply(uint32_t imc, uint32_t connID, uint32_t oui, uint32_t request, bool bDisplayError, int answer)
{
	emit signalTNCReply(imc, connID, oui, request, bDisplayError, answer);
}

//! sendTNCUILoginWindowStatusUpdateEvent
/*!
    \brief emit's a message that the login window catches to update its TNC status.
    \return Nothing
*/
void Emitter::sendTNCUILoginWindowStatusUpdateEvent(unsigned int imc, unsigned int connID, unsigned int oui, unsigned int newState)
{
    emit signalTNCUILoginWindowStatusUpdateEvent(imc, connID, oui, newState);   
}

//! sendSignalStrength()
/*!
  \brief emit's a signal that the signal strength has changed
  \return Nothing
*/
void Emitter::sendSignalStrength(int s)
{
  emit signalSignalStrength(s);
}

//! sendInterfaceInsertedMessage()
/*!
  \brief emit's a signal that the signal strength has changed
  \return Nothing
*/
void Emitter::sendInterfaceInsertedEvent(char *intface)
{
  emit signalInterfaceInserted(intface);
}

void Emitter::sendLinkDownEvent(char *intface)
{
	emit signalLinkDown(intface);
}

void Emitter::sendLinkUpEvent(char *intface)
{
	emit signalLinkUp(intface);
}

//! sendInterfaceInsertedMessage()
/*!
  \brief emit's a signal that the signal strength has changed
  \return Nothing
*/
void Emitter::sendXSupplicantShutDownMessage()
{
  emit signalXSupplicantShutDown();
}

void Emitter::sendShowConfig()
{
	emit signalShowConfig();
}

void Emitter::sendInterfaceRemovedEvent(char *interfaces)
{
	emit signalInterfaceRemoved(interfaces);
}

void Emitter::sendPluginLoaded(UIPlugins *plugin)
{
	if(plugin != NULL)
	{
		emit signalPluginLoaded(plugin);

//		this->sendUIMessage(tr("Got a 'Plugin Loaded' event for a plugin at %1!").arg((qlonglong)plugin));
	}
	else
	{
//		this->sendUIMessage(tr("Got a 'Plugin Loaded' event for a NULL plugin!"));
	}
}

void Emitter::sendPluginUnloading(UIPlugins *plugin)
{
	if(plugin != NULL)
	{
		emit signalPluginUnloading(plugin);
//		this->sendUIMessage(tr("Got a 'Plugin Unloading' event for a plugin at %1!").arg((qlonglong)plugin));

	}
	else
	{
//		this->sendUIMessage(tr("Got a 'Plugin Unloading' event for a NULL plugin!"));
	}
}

void Emitter::sendPluginObjectInstantiated(UIPlugins *plugin)
{
	if(plugin != NULL)
	{
		emit signalPluginObjectInstantiated(plugin);

//		this->sendUIMessage(tr("Got a 'Plugin Instantiated' event for a plugin at %1!").arg((qlonglong)plugin));
	}
	else
	{
//		this->sendUIMessage(tr("Got a 'Plugin Instantiated' event for a NULL plugin!"));
	}
}

void Emitter::sendPluginObjectDestroyed(UIPlugins *plugin)
{
	if(plugin != NULL)
	{
		emit signalPluginObjectDestroyed(plugin);
//		this->sendUIMessage(tr("Got a 'Plugin Destroyed' event for a plugin at %1!").arg((qlonglong)plugin));

	}
	else
	{
//		this->sendUIMessage(tr("Got a 'Plugin Destroyed' event for a NULL plugin!"));
	}
}

void Emitter::sendAuthTimeout(QString &intName)
{
	emit signalAuthTimeout(intName);
}

void Emitter::sendClearLoginPopups()
{
	emit signalClearLoginPopups();
}

void Emitter::sendWokeUp()
{
	emit signalWokeUp();
}

void Emitter::sendInterfaceControl(bool xsupCtrl)
{
	emit signalInterfaceControl(xsupCtrl);
}
