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

#ifndef _CONNECTIONWIZARDDATA_H_
#define _CONNECTIONWIZARDDATA_H_

#include <QString>
#include <QStringList>

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

class ConnectionWizardData
{
public:
	ConnectionWizardData();
	~ConnectionWizardData();
	
public:
	bool toSupplicantProfiles(config_connection **, config_profiles **, config_trusted_server **);
	bool initFromSupplicantProfiles(config_connection const * const pConfig, config_profiles const * const pProfile, config_trusted_server const * const pServer);	
	
private:
	bool toProfileEAP_PEAPProtocol(config_profiles * const, config_trusted_server const * const);
	bool toProfileEAP_MD5Protocol(config_profiles * const);
	bool toProfileEAP_AKAProtocol(config_profiles * const);
	bool toProfileEAP_SIMProtocol(config_profiles * const);
	bool toProfileEAP_TTLSProtocol(config_profiles * const, config_trusted_server const * const);
	bool toProfileEAP_FASTProtocol(config_profiles * const, config_trusted_server const * const);
	bool toProfileOuterIdentity(config_profiles * const);
	bool toServerData(config_trusted_server **);
	bool toProfileData(config_profiles **, config_trusted_server const * const);
	bool toConnectionData(config_connection **, config_profiles const * const);

public:

	bool m_newConnection;
	
	// general settings
	bool m_wireless;
	QString m_adapterDesc;
	QString m_connectionName;
	QString m_serverName;
	QString m_profileName;	
	
	// wireless settings
	QString m_networkName;
	
	typedef enum {
		assoc_none,
		assoc_WEP,
		assoc_WPA_PSK,
		assoc_WPA_ENT,
		assoc_WPA2_PSK,
		assoc_WPA2_ENT
	} assocMode;
	
	assocMode m_wirelessAssocMode;
	
	typedef enum {
		encrypt_WEP,
		encrypt_TKIP,
		encrypt_CCMP
	} encryptMethod;
	
	encryptMethod m_wirelessEncryptMeth;
	bool m_hiddenNetwork;
	bool m_otherNetwork;
	
	// wired settings
	bool m_wiredSecurity;
	
	// IP settings
	bool m_renewOnReauth;
	bool m_staticIP;
	QString m_IPAddress;
	QString m_netmask;
	QString m_gateway;
	QString m_primaryDNS;
	QString m_secondaryDNS;
	
	// 802.1X settings
	typedef enum {
		eap_peap,
		eap_ttls,
		eap_aka,
		eap_sim,
		eap_fast,
		eap_md5
	} Dot1XProtocol;
	
	typedef enum {
		inner_pap,
		inner_chap,
		inner_mschap,
		inner_mschapv2,
		inner_eap_md5,
		inner_eap_mschapv2,
		inner_eap_gtc
	} Dot1XInnerProtocol;
	
	Dot1XProtocol m_eapProtocol;
	QString m_outerIdentity;
	QString m_SCreader;
	bool m_autoRealm;
	bool m_anonymousProvisioning;
	bool m_authenticatedProvisioning;
	bool m_validateCert;
	Dot1XInnerProtocol m_innerPEAPProtocol;
	Dot1XInnerProtocol m_innerTTLSProtocol;
	Dot1XInnerProtocol m_innerFASTProtocol;
	QStringList m_serverCerts;
	bool m_verifyCommonName;
	QStringList m_commonNames;
	
	// data for bookkeeping
	bool m_hasProfile;
	bool m_hasServer;

	bool m_nameChanged; // so we know how to properly turn into profiles
};

#endif