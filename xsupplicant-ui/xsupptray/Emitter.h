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

#ifndef _EMITTER_H_
#define _EMITTER_H_

#include <QObject>
#include "stdafx.h"



extern "C" {
#include "libxsupgui/xsupgui_events.h"
}

class UIPlugins;

//!\class Emitter
/*!\brief Emitter class - used to emit signals
          from the Brief description.
*/
class Emitter : public QObject
{
    Q_OBJECT

signals:
  void signalLogMessage(const QString &s);
  void signalXSupplicantShutDown();
  void signalStartLogMessage(const QString &s);
  void signalStateMessage(const QString &s);
  void signalStateMessageToScreen(int machineType, int state, const QString &statusStr);
  void signalUIMessage(const QString &s);
  void signalSignalStrength(int s);
  void signalRequestPasswordMessage(const QString &connName, const QString &eapMethod, const QString &challengeString);
  void signalTNCUIMessage(int oui, int notification);
  void signalTNCUIRequestMessage(int imc, int connID, int oui, int request);
  void signalTNCUIRemediationRequestedBatchMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIComplianceReportBatchMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIComplianceFailureBatchMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIReconnectBatchMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIRemediationWillBeginBatchMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIRemediationStatusItemStartedMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIRemediationStatusItemSuccessMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIRemediationStatusItemFailureMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIRemediationWillEndBatchMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIRemediationEventBatchMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCUIPurgeConnectionBatchMessage(int imc, int connID, int oui, int request, tnc_msg_batch *pMessageBatch);
  void signalTNCReply(uint32_t imc, uint32_t connID, uint32_t oui, uint32_t request, bool bDisplayError, int answer);
  void signalTNCUILoginWindowStatusUpdateEvent(unsigned int imc, unsigned int connID, unsigned int oui, unsigned int newState);
  void signalTNCUIConnectionStatusRequest(unsigned int connID);
  void signalScanCompleteMessage(const QString &);
  void signalConnConfigUpdate();
  void signalProfConfigUpdate();
  void signalInterfaceInserted(char *);
  void signalInterfaceRemoved(char *);
  void signalLinkUp(char *);
  void signalLinkDown(char *);
  void signalSupWarningEvent(const QString &error);
  void signalSupErrorEvent(const QString &error);
  void signalStateChange(const QString &, int, int, int, unsigned int);
  void signalIPAddressSet();
  void signalShowConfig();
  void signalShowLog();
  void signalPluginLoaded(UIPlugins *plugin);
  void signalPluginUnloading(UIPlugins *plugin);
  void signalPluginObjectInstantiated(UIPlugins *plugin);
  void signalPluginObjectDestroyed(UIPlugins *plugin);
  void signalBadPSK(const QString &);
  void signalAuthTimeout(const QString &);
  void signalClearLoginPopups();
  void signalWokeUp();
  void signalInterfaceControl(bool);
  void signalTroubleTicketDone();
  void signalTroubleTicketError();
  void signalRequestUPW(const QString &);
  void signalPostConnectTimeout(const QString &);
  void signalConnectionDisconnected(const QString &);
  void signalPSKSuccess(const QString &);
  void signalNewInterfaceInserted();
  void signalBadCreds(const QString &);
  void signalNetworkConnectDisconnect();
  void signalPSKTimeout(const QString &);
  void signalConnectionUnbound(const QString &);
  void signalAutoConnectionChange(const QString &);

public:
  Emitter();
  void sendInterfaceInsertedEvent(char *interfaces);
  void sendInterfaceRemovedEvent(char *interfaces);
  void sendLinkUpEvent(char *interfaces);
  void sendLinkDownEvent(char *interfaces);
  void sendStartLogMessage(const QString &str);
  void sendLogMessage(const QString &s);
  void sendXSupplicantShutDownMessage();
  void sendStateMessage(const QString &s);
  void sendStateMessageToScreen(int machine, int state, const QString &str);
  void sendUIMessage(const QString &s);
  void sendScanComplete(const QString &s); 
  void sendConnConfigUpdate();
  void sendProfConfigUpdate();
  void sendSignalStrength(int);
  void sendRequestPassword(const QString &connname, const QString &eapmethod, const QString &chalstr);
  void sendTNCUIEvent(int oui, int notification);
  void sendTNCUIRequestEvent(int imc, int connID, int oui, int request);
  void sendTNCUIRemediationRequestedBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIResponseBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIReconnectBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIRemediationWillBeginBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIRemediationStatusItemStartedEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIRemediationStatusItemSuccessEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIRemediationStatusItemFailureEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIRemediationWillEndBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIRemediationEventBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIPurgeConnectionBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCReply(uint32_t imc, uint32_t connID, uint32_t oui, uint32_t request, bool bDisplayError, int answer);
  void sendTNCUIComplianceReportBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUIComplianceFailureBatchEvent(int imc, int connID, int oui, int request, tnc_msg_batch *pTNCMessages);
  void sendTNCUILoginWindowStatusUpdateEvent(unsigned int imc, unsigned int connID, unsigned int oui, unsigned int newState);
  void sendTNCUIConnectionStatusRequest(unsigned int connID);
  void sendStateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid);
  void sendIPAddressSet();
  void sendSupWarningEvent(const QString &warning);
  void sendSupErrorEvent(const QString &error);
  void sendShowConfig();
  void sendPluginLoaded(UIPlugins *plugin);
  void sendPluginUnloading(UIPlugins *plugin);
  void sendPluginObjectInstantiated(UIPlugins *plugin);
  void sendPluginObjectDestroyed(UIPlugins *plugin);
  void sendBadPSK(const QString &intName);
  void sendAuthTimeout(const QString &intName);
  void sendClearLoginPopups();
  void sendWokeUp();
  void sendInterfaceControl(bool);
  void sendTroubleTicketDone();
  void sendTroubleTicketError();
  void sendRequestUPW(const QString &);
  void sendPostConnectTimeout(const QString &);
  void sendConnectionDisconnected(const QString &);
  void sendPSKSuccess(const QString &);
  void sendBadCreds(const QString &);
  void sendNewInterfaceInserted();
  void sendNetworkConnectDisconnect();
  void sendPSKTimeout(QString);
  void sendConnectionUnbound(QString);
  void sendAutoConnectionChange(QString);
};

#endif  // _EMITTER_H_

