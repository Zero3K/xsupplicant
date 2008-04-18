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

#ifndef _XSUPCALLS_H_
#define _XSUPCALLS_H_

#include "MessageClass.h"
#include "Emitter.h"

class Emitter;

extern "C" 
{
#include "libxml/parser.h"
#include "libxsupgui/xsupgui_request.h"
#include "libxsupgui/xsupgui_xml_common.h"
#include "libxsupgui/xsupgui.h"
#include "ipc_events_index.h"
#include "libxsupgui/xsupgui_events.h"
#include "libxsupgui/xsupgui_events_state.h"
#include "xsupconfig_structs.h"
#include "xsupconfig.h"
#include "xsupconfig_defaults.h"
#include "libxsupgui/xsupgui_mac_utils.h"
#include "xsup_err.h"
#include "supdetect.h"
}

static int ID_ENGINES_OUI = 25065; 

#include "ipinfoclass.h"

typedef struct tncmessages
{
  int messageNumber; // the message number
  QString text;      // the associated text for this message
  int autoFix;       // whether or not this problem can be resolved by the supplicant
}TNCMessageS;

enum ConnSortType{
  SORT_BY_NAME,
  SORT_BY_PRIORITY
};

//!\class XSupCalls
/*!\brief Class to interface with the supplicant
*/
class XSupCalls : public QObject
{
	Q_OBJECT

public:

  XSupCalls(QWidget *parent);
  virtual ~XSupCalls(void);
  bool checkSupplicantVersion(QString &numberString);
  bool connectionDisconnect(QString &connectionName);
  bool connectEventListener(bool bDisplayMessage);
  bool connectToSupplicant();

  bool createNewConnection(QString &name, config_connection **newConnection);
  bool createNewConnectionDefaults(QString &name, config_connection **pConfig);

  bool createNewTrustedServer(QString &name, config_trusted_server **pTServer);
  bool createNewTrustedServerDefaults(QString &name, config_trusted_server **pConfig);

  bool createNewProfile(QString &name, config_profiles **m_pConfig);
  bool createNewProfileDefaults(QString &name, config_profiles **pConfig);

  bool createNewInterface(QString &name, QString &deviceName, QString &mac, bool bWireless, bool bDisplayError);
  bool createNewInterfaceDefaults(QString &name, config_interfaces **pConfig);


  void displaySupplicantError(QString &numberString);
  bool deleteConnectionConfig(QString &name);
  void deleteConfigEapMethod(config_eap_method **p);
  bool deleteProfileConfig(QString &name);
  bool deleteTrustedServerConfig(QString &name);
  bool disconnectEventListener();
  void disconnectXSupplicant();
  bool disassociateWireless(QString &deviceName, QString &desc);
  bool logoffWired(QString &deviceName, QString &desc);

  bool enumCertificates(cert_enum **pCertificates, bool bDisplayError = true);
  bool enumAndSortConnections(conn_enum **pConn, bool b);
  bool enumAndSortPossibleConnections(poss_conn_enum **pConn, bool b);
  bool enumConfigInterfaces(int_config_enum **pInterfaceData, bool bDisplayError = true);
  bool enumLiveInterfaces(int_enum **mydata, bool bDisplayError = true);
  bool enumProfiles(profile_enum **pProfiles, bool bDisplayError = true);
  bool enumTrustedServers(trusted_servers_enum **pServers, bool bDisplayError = true);

  void getAndDisplayErrors();
  bool getLiveInterfaceData(QString &Name, QString &description, 
    QString &mac, bool &bWireless, bool bDisplayError = false);
  bool getCertInfo(QString &storetype, QString &location, cert_info **certInfo, bool bDisplayError);
  bool getConfigInterface(QString &interfaceName, config_interfaces **pInterfaceData, bool bDisplayError = true);
  bool getConfigGlobals(config_globals **myglobs, bool bDisplayError = true);
  bool getConfigProfile(QString &profileName, config_profiles **pProfiles, bool bDisplayError = true);
  bool getConfigTrustedServer(QString &server, config_trusted_server **pConfig, bool bDisplayError = true);
  bool getConfigConnection(QString &connection, config_connection **pConfig, bool bDisplayError = true);
  bool getUIEventString(int uiEvent, QString &desc);
  bool getConfigConnectionName(QString &deviceDescription, QString &m_deviceName, QString &connName, 
    bool bDisplayError = false);

  bool getAssociation(QString &deviceDesc, QString &deviceName, QString &value, bool bDisplayError);
  bool getAuthTime(QString &deviceName, long int &timeauthed, bool bDisplayError);
  bool getDefaultSettings(config_globals **p);
  void getTunnelNames(config_eap_method *pMethod, QString &outer, QString &inner);
  void getInnerTunnelName(int innerMethod, void *pMethodData, QString &inner);


  bool getConnectionInformation(QString &connectionName, int &authType, 
    QString &userNameString, QString &passwordString, bool b);
  bool getDeviceName(const QString &deviceDescription, QString &deviceName, bool bDisplayError = true);
  bool getDeviceDescription(const QString &deviceName, QString &deviceDescription, bool bDisplayError = true);
  bool getEncryption(QString &device, QString &encryptionType, bool bDisplay);
  bool getInterfaceData(QString &intName, QString &description, QString &mac, bool &bWireless);
  bool getIPInfo(QString &device, IPInfoClass &info, bool b);
  bool getPhysicalState(QString &deviceDescription, 
                                 QString &deviceName, 
                                 QString &status, 
                                 int &state,
                                 bool bDisplayError);
  bool get1xState(QString &deviceDescription, 
                    QString &deviceName, 
                    QString &status, 
                    int &state,
                    bool bDisplayError);
  bool getSignalStrength(QString &deviceDesc, QString &deviceName, int &retval, bool bDisplayError = false);
  bool getSSID(QString &deviceDesc, QString &device, QString &ssidString, bool bDisplayError = false);
  bool getBroadcastSSIDs(QString &deviceDesc, QString &deviceName, ssid_info_enum **pssids);
  bool getBroadcastSSIDs(QString &deviceDescription, ssid_info_enum **pssids); 
  bool getTextFor1xState(int state, QString &status);
  bool getAndCheckSupplicantVersion(QString &fullVersion, QString &numberString, bool bDisplay = true);
  void getUserAndPasswordFromProfile(config_profiles *prof, QString &innerUser, QString &password);

  bool isLiveInterface(const int_enum *pLiveInts, const char *pConfigInterfaceName);
  static bool isOnlyInstance(char *executableName);
  bool isServerUsedInProfile(config_profiles *pProfile, QString &server);

  bool networkDisconnect(QString &deviceName, QString &deviceDescription, bool bWireless);

  bool pauseWireless(QString &device, QString &desc);
  bool renameConnection(QString &oldName, QString &newName);
  bool renameProfile(QString &oldName, QString &newName);
  bool renameTrustedServer(QString &oldName, QString &newName);

  void mapPhysicalState(int state, QString &status);
  void map1XState(int state, QString &status);
  bool setConnection(QString &deviceName, QString &currentConnection);
  bool processEvent(Emitter &e, int result);
  bool applyPriorities(conn_enum *pConns);

  void sendXStatus(Emitter &e);
  void sendPStatus(Emitter &e);

  bool setConfigConnection(config_connection *pConfig);
  bool setConfigGlobals(config_globals *globals);
  bool setConfigInterface(config_interfaces *pConfig);
  bool setConfigProfile(config_profiles *pProfile);
  void setProfileUserNameAndPassword(char *pProfileName, const QString &userName, const QString &password);
  bool setConfigTrustedServer(config_trusted_server *pConfig);
  bool setUserNameAndPassword(const QString &connectionName, const QString &userName, const QString &password, 
    int authType);
  void setUserNameIntoProfile(config_profiles *pProfile, const QString &userName);
  void setPasswordIntoProfile(config_profiles *pProfile, const QString &password);
  bool startWirelessScan(QString &device);
  bool waitForEvent();
  bool waitForEvents(Emitter &e);
  bool sendPing();
  void sortPossibleConnections(poss_conn_enum *pConns, poss_conn_enum **pSortedConns);
  void sortConnections(conn_enum *pConns, conn_enum **pSortedConns);
  void stateTransition(Emitter &e, bool bDebug, char *intf, int sm, int oldstate, int newstate, QString &newState, QString &fullText);
  //bool TNCReply(uint32_t imc, uint32_t connID, uint32_t oui, uint32_t batchType, bool bDisplayError);
  bool updateAdapters(bool bDisplayError);

  // Free functions
  void freeCertInfo(cert_info **certInfo);
  void freeConfigConnection(config_connection **p);
  void freeConfigAssociation(struct config_association *p);
  void freeConfigGlobals(config_globals **conn);
  void freeConfigInterface(config_interfaces **p);
  void freeConfigProfile(config_profiles **profile);
  void freeConfigTrustedServer(config_trusted_server **conn);
  void freeEnumConnections(conn_enum **p);
  void freeEnumPossibleConnections(poss_conn_enum **p);
  void freeEnumStaticInt(int_config_enum **p);
  void freeEnumLiveInt(int_enum **p);
  void freeEnumProfile(profile_enum **p);
  void freeEnumSSID(ssid_info_enum **pssids);
  void freeEnumTrustedServer(trusted_servers_enum **p);
  void freeEnumCertificates(cert_enum **pCerts);
  void freeConfigEAPMethod(struct config_eap_method **method);

  int createTroubleTicket(char *filename, char *scratchdir, int overwrite);

  bool writeConfig();
  
  static int CONNECTION_DEFAULT_PRIORITY;
  // These were static methods, but I've changed them all now to be member methods
  int config_get_ttls_pwd(struct config_eap_method *meth, char **pPassword);
  int config_get_pwd(struct config_eap_method *meth, char **pPassword);

  int config_get_peap_user(struct config_eap_method *meth, char **pUser);
  int config_get_ttls_user(struct config_eap_method *meth, char **pUser);
  int config_get_user(struct config_eap_method *meth, char **pUser);

  int config_set_ttls_user(struct config_eap_method *meth, char *pUser);
  int config_set_peap_user(struct config_eap_method *meth, char *pUser);
  int config_set_user(struct config_eap_method *meth, char *pUser);

signals:
  void signalStateChange(QString &, int, int, int, unsigned int);
  void signalIPAddressSet();

public slots:
  bool TNCReply(uint32_t imc, uint32_t connID, uint32_t oui, uint32_t batchType, bool bDisplayError, int answer);
  
private:
  XSupCalls(const XSupCalls &);

  MessageClass m_message;

  QMutex m_mutex;
  QMutex m_adapterMutex;
  static bool m_bEventsConnected;
  bool connectXSupplicant(); // only called from within the xsupcalls library
};

#endif  // _XSUPCALLS_H_

