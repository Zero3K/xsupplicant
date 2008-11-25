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

#include "ConnectionWizardData.h"
#include "XSupWrapper.h"

ConnectionWizardData::ConnectionWizardData()
{
	m_newConnection = true;
	
	// default to wired connection
	m_wireless = false;
	
	m_adapterDesc = "";
	
	// get distinct name
	m_connectionName = XSupWrapper::getUniqueConnectionName(QWidget::tr("New Connection"));
	
	m_profileName = m_connectionName;
	m_profileName.append(QWidget::tr("_Profile"));
	
	m_serverName = m_connectionName;
	m_serverName.append(QWidget::tr("_Server"));	
	
	// wireless settings
	m_networkName = "";
	m_hiddenNetwork = false;
	m_wirelessAssocMode = ConnectionWizardData::assoc_none;
	m_wirelessEncryptMeth = ConnectionWizardData::encrypt_TKIP;
	
	// default to 802.1X for wired
	m_wiredSecurity = true;
	
	// default to DHCP
	m_staticIP = false;
	m_renewOnReauth = false;
	
	// !!! need better defaults for these 
	m_IPAddress = "";
	m_netmask = "";
	m_gateway = "";
	m_primaryDNS = "";
	m_secondaryDNS = "";
	
	m_eapProtocol = ConnectionWizardData::eap_peap;
	m_outerIdentity = "";
	m_validateCert = true;
	m_innerPEAPProtocol = ConnectionWizardData::inner_mschapv2;
	m_innerTTLSProtocol = ConnectionWizardData::inner_pap;
	m_serverCerts = QStringList();
	m_verifyCommonName = false;
	m_commonNames = QStringList();
	
	m_hasProfile = false;
	m_hasServer = false;
	m_nameChanged = false;

	m_config_type = CONFIG_LOAD_USER;
}

ConnectionWizardData::~ConnectionWizardData()
{
	// nothing special to do. No pointers.
}

bool ConnectionWizardData::toProfileOuterIdentity(config_profiles * const pProfile)
{
	if (pProfile == NULL)
		return false;
		
	if (pProfile->identity != NULL)
		free(pProfile->identity);
	if (m_outerIdentity.isEmpty())
		pProfile->identity = _strdup("anonymous");
	else
		pProfile->identity = _strdup(m_outerIdentity.toAscii().data());
		
	return true;
}

bool ConnectionWizardData::toProfileEAP_AKAProtocol(config_profiles * const pProfile)
{
	bool success  = true;
	struct config_eap_aka *akaData = NULL;

	if (pProfile->method == NULL)
	{
		pProfile->method = (config_eap_method *)malloc(sizeof(config_eap_method));
		if (pProfile->method == NULL)
			success = false;
		else
		{
			memset(pProfile->method, 0x00, sizeof(config_eap_method));
			pProfile->method->method_num = EAP_TYPE_AKA;
			pProfile->method->method_data = (config_eap_aka *)malloc(sizeof(config_eap_aka));
			if (pProfile->method->method_data == NULL)
				success = false;
			else
			{
				memset(pProfile->method->method_data, 0x00, sizeof(config_eap_aka));

				akaData = (struct config_eap_aka *)pProfile->method->method_data;
				akaData->reader = _strdup(m_SCreader.toAscii().data());

				if (m_autoRealm == true)
				{
					akaData->auto_realm = TRUE;
				}
				else
				{
					akaData->auto_realm = FALSE;
				}
			}
		}
	}
	else
		success = false;// unexpected

	return success;
}

bool ConnectionWizardData::toProfileEAP_SIMProtocol(config_profiles * const pProfile)
{
	bool success  = true;
	struct config_eap_sim *simData = NULL;

	if (pProfile->method == NULL)
	{
		pProfile->method = (config_eap_method *)malloc(sizeof(config_eap_method));
		if (pProfile->method == NULL)
			success = false;
		else
		{
			memset(pProfile->method, 0x00, sizeof(config_eap_method));
			pProfile->method->method_num = EAP_TYPE_SIM;
			pProfile->method->method_data = (config_eap_sim *)malloc(sizeof(config_eap_sim));
			if (pProfile->method->method_data == NULL)
				success = false;
			else
			{
				memset(pProfile->method->method_data, 0x00, sizeof(config_eap_sim));

				simData = (struct config_eap_sim *)pProfile->method->method_data;
				simData->reader = _strdup(m_SCreader.toAscii().data());

				if (m_autoRealm == true)
				{
					simData->auto_realm = TRUE;
				}
				else
				{
					simData->auto_realm = FALSE;
				}
			}
		}
	}
	else
		success = false;// unexpected

	return success;
}

// assumes profile is being built from scratch and thus none of this data is populated
bool ConnectionWizardData::toProfileEAP_MD5Protocol(config_profiles * const pProfile)
{
	bool success  = true;

	if (pProfile->method == NULL)
	{
		pProfile->method = (config_eap_method *)malloc(sizeof(config_eap_method));
		if (pProfile->method == NULL)
			success = false;
		else
		{
			memset(pProfile->method, 0x00, sizeof(config_eap_method));
			pProfile->method->method_num = EAP_TYPE_MD5;
			pProfile->method->method_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
			if (pProfile->method->method_data == NULL)
				success = false;
			else
				memset(pProfile->method->method_data, 0x00, sizeof(config_pwd_only));
		}
	}
	else
		success = false;// unexpected

	return success;
}

bool ConnectionWizardData::toProfileEAP_PEAPProtocol(config_profiles * const pProfile, config_trusted_server const * const pServer)
{
	bool success = true;
	if (pProfile == NULL)
		return false;
		
	if (m_eapProtocol == ConnectionWizardData::eap_peap) {
		this->toProfileOuterIdentity(pProfile);
	
		if (pProfile->method == NULL)
		{
			pProfile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
			if (pProfile->method == NULL)
				success = false;
			else
			{	
				memset(pProfile->method, 0x00, sizeof(config_eap_method));
				pProfile->method->method_num = EAP_TYPE_PEAP;

				pProfile->method->method_data = malloc(sizeof(config_eap_peap));
				if (pProfile->method->method_data == NULL)
					success = false;
				else
				{
					config_eap_peap *mypeap;
					mypeap = (config_eap_peap *)pProfile->method->method_data;					
					memset(mypeap, 0x00, sizeof(config_eap_peap));
					
					mypeap->force_peap_version = 0xff;
					
					// server cert
					if (m_validateCert == true)
					{
						if (pServer != NULL)
						{
							mypeap->validate_cert = TRUE;
							mypeap->trusted_server = _strdup(pServer->name);
						}
						else
						{
							// we should have had a trusted server passed in
							mypeap->validate_cert = FALSE;
							success = false;
						}
					}
					else
						mypeap->validate_cert = FALSE;
					
					// inner protocol
					if (m_innerPEAPProtocol == ConnectionWizardData::inner_eap_mschapv2)
					{
						mypeap->phase2 = (config_eap_method *)malloc(sizeof(config_eap_method));
						if (mypeap->phase2 == NULL) 
							success = false;
						else
						{
							config_eap_method *myeap;
							myeap = (config_eap_method *)mypeap->phase2;
							memset(myeap, 0x00, sizeof(config_eap_method));
					
							myeap->method_num = EAP_TYPE_MSCHAPV2;
							myeap->method_data = (config_eap_mschapv2 *)malloc(sizeof(config_eap_mschapv2));
							if (myeap->method_data == NULL) 
								success = false;
							else
							{
								config_eap_mschapv2 *mscv2;
								mscv2 = (config_eap_mschapv2 *)myeap->method_data;
								memset(mscv2, 0x00, sizeof(config_eap_mschapv2));

								// Set some defaults.
								UNSET_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_IAS_QUIRK);
								mscv2->nthash = NULL;
								mscv2->password = NULL;
							}
						}
					}
					else if (m_innerPEAPProtocol == ConnectionWizardData::inner_eap_gtc)
					{
						mypeap->phase2 = (config_eap_method *)malloc(sizeof(config_eap_method));
						if (mypeap->phase2 == NULL) 
							success = false;
						else
						{
							config_eap_method *myeap = NULL;
							myeap = (config_eap_method *)mypeap->phase2;
							memset(myeap, 0x00, sizeof(config_eap_method));
							myeap->method_num = EAP_TYPE_GTC;
							myeap->method_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
							if (myeap->method_data == NULL)
								success = false;
							else
								memset(myeap->method_data, 0x00, sizeof(config_pwd_only));
						}				
					}
					else
					{
						// invalid value
						success = false;
					}
				}
			}
		}
		else
		{
			// unexpected
			success = false;
		}
	}
	else
		success = false;
		
	return success;	
}

bool ConnectionWizardData::toProfileEAP_TLSProtocol(config_profiles * const pProfile, config_trusted_server const * const pServer)
{
	bool success = true;
	if (pProfile == NULL)
		return false;
		
	if (m_eapProtocol == ConnectionWizardData::eap_tls) {
		this->toProfileOuterIdentity(pProfile);
	
		if (pProfile->method == NULL)
		{
			pProfile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
			if (pProfile->method == NULL)
				success = false;
			else
			{	
				memset(pProfile->method, 0x00, sizeof(config_eap_method));
				pProfile->method->method_num = EAP_TYPE_TLS;

				pProfile->method->method_data = malloc(sizeof(config_eap_tls));
				if (pProfile->method->method_data == NULL)
					success = false;
				else
				{
					config_eap_tls *mytls;
					mytls = (config_eap_tls *)pProfile->method->method_data;					
					memset(mytls, 0x00, sizeof(config_eap_tls));
										
					// server cert
					if (pServer != NULL)
					{
						mytls->trusted_server = _strdup(pServer->name);
					}
					else
					{
						// We don't allow users to not verify the server cert with TLS, so return an error.
						success = false;
					}

					// Now, add the TLS user cert to the config.
				}
			}
		}
		else
		{
			// unexpected
			success = false;
		}
	}
	else
		success = false;
		
	return success;	
}

bool ConnectionWizardData::toProfileEAP_FASTProtocol(config_profiles * const pProfile, config_trusted_server const * const pServer)
{
	bool success = true;

	if (pProfile == NULL)
		return false;
		
	if (m_eapProtocol == ConnectionWizardData::eap_fast) {
		this->toProfileOuterIdentity(pProfile);
	
		if (pProfile->method == NULL)
		{
			pProfile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
			if (pProfile->method == NULL)
				success = false;
			else
			{	
				memset(pProfile->method, 0x00, sizeof(config_eap_method));
				pProfile->method->method_num = EAP_TYPE_FAST;

				pProfile->method->method_data = malloc(sizeof(config_eap_fast));
				if (pProfile->method->method_data == NULL)
					success = false;
				else
				{
					config_eap_fast *myfast = NULL;
					myfast = (config_eap_fast *)pProfile->method->method_data;					
					memset(myfast, 0x00, sizeof(config_eap_fast));
					
					// We don't allow users to disable provisioning when using the wizard.
					SET_FLAG(myfast->provision_flags, EAP_FAST_PROVISION_ALLOWED);

					if (m_anonymousProvisioning == true)
					{
						SET_FLAG(myfast->provision_flags, EAP_FAST_PROVISION_ANONYMOUS);
					}
					else
					{
						UNSET_FLAG(myfast->provision_flags, EAP_FAST_PROVISION_ANONYMOUS);
					}

					if (m_authenticatedProvisioning == true)
					{
						SET_FLAG(myfast->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED);
					}
					else
					{
						UNSET_FLAG(myfast->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED);
					}

					// server cert
					if (m_validateCert == true)
					{
						if ((pServer != NULL) && (m_authenticatedProvisioning == true))
						{
							myfast->validate_cert = TRUE;
							myfast->trusted_server = _strdup(pServer->name);
						}
						else
						{
							// we should have had a trusted server passed in
							myfast->validate_cert = FALSE;
							success = false;
						}
					}
					else
						myfast->validate_cert = FALSE;
					
					// inner protocol
					if (m_innerFASTProtocol == ConnectionWizardData::inner_eap_mschapv2)
					{
						myfast->phase2 = (config_eap_method *)malloc(sizeof(config_eap_method));
						if (myfast->phase2 == NULL) 
							success = false;
						else
						{
							config_eap_method *myeap = NULL;
							myeap = (config_eap_method *)myfast->phase2;
							memset(myeap, 0x00, sizeof(config_eap_method));
					
							myeap->method_num = EAP_TYPE_MSCHAPV2;
							myeap->method_data = (config_eap_mschapv2 *)malloc(sizeof(config_eap_mschapv2));
							if (myeap->method_data == NULL) 
								success = false;
							else
							{
								config_eap_mschapv2 *mscv2 = NULL;
								mscv2 = (config_eap_mschapv2 *)myeap->method_data;
								memset(mscv2, 0x00, sizeof(config_eap_mschapv2));

								// Set some defaults.
								UNSET_FLAG(mscv2->flags, FLAGS_EAP_MSCHAPV2_IAS_QUIRK);
								mscv2->nthash = NULL;
								mscv2->password = NULL;
							}
						}
					}
					else if (m_innerFASTProtocol == ConnectionWizardData::inner_eap_gtc)
					{
						myfast->phase2 = (config_eap_method *)malloc(sizeof(config_eap_method));
						if (myfast->phase2 == NULL) 
							success = false;
						else
						{
							config_eap_method *myeap = NULL;
							myeap = (config_eap_method *)myfast->phase2;
							memset(myeap, 0x00, sizeof(config_eap_method));
							myeap->method_num = EAP_TYPE_GTC;
							myeap->method_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
							if (myeap->method_data == NULL)
								success = false;
							else
								memset(myeap->method_data, 0x00, sizeof(config_pwd_only));
						}				
					}
					else
					{
						// invalid value
						success = false;
					}
				}
			}
		}
		else
		{
			// unexpected
			success = false;
		}
	}
	else
		success = false;
		
	return success;	
}

bool ConnectionWizardData::toProfileEAP_TTLSProtocol(config_profiles * const pProfile, config_trusted_server const * const pServer)
{
	bool success = true;
	if (pProfile == NULL)
		return false;
		
	// make sure this is the right function
	if (m_eapProtocol != ConnectionWizardData::eap_ttls)
		return false;

	if (pProfile->method == NULL)
	{
		pProfile->method = (config_eap_method *)malloc(sizeof(config_eap_method));
		if (pProfile->method == NULL)
			success = false;
		else
		{
			memset(pProfile->method, 0x00, sizeof(config_eap_method));
	
			pProfile->method->method_num = EAP_TYPE_TTLS;
			this->toProfileOuterIdentity(pProfile);

			pProfile->method->method_data = malloc(sizeof(config_eap_ttls));
			if (pProfile->method->method_data == NULL)
				success = false;
			else
			{
				config_eap_ttls *myttls = NULL;
				myttls = (config_eap_ttls *)pProfile->method->method_data;
			
				memset(myttls, 0x00, sizeof(config_eap_ttls));
		
				if (m_validateCert == true)
				{
					if (pServer != NULL)
					{
						myttls->validate_cert = TRUE;
						myttls->trusted_server = _strdup(pServer->name);
					}
					else
					{
						// expected to have trusted server passed in
						myttls->validate_cert = FALSE;
						success = false;
					}
				}
				else
				{
					myttls->validate_cert = FALSE;
				}

				// Determine the inner method in use...
				if (m_innerTTLSProtocol == ConnectionWizardData::inner_pap)
				{
					myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_PAP;
					myttls->phase2_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
					if (myttls->phase2_data == NULL)
						success = false;
					else
						memset(myttls->phase2_data, 0x00, sizeof(config_pwd_only));
				}
				else if (m_innerTTLSProtocol == ConnectionWizardData::inner_chap)
				{
					myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_CHAP;
					myttls->phase2_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
					if (myttls->phase2_data == NULL)
						success = false;
					else
						memset(myttls->phase2_data, 0x00, sizeof(config_pwd_only));
				}
				else if (m_innerTTLSProtocol == ConnectionWizardData::inner_mschap)
				{
					myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_MSCHAP;
					myttls->phase2_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
					if (myttls->phase2_data == NULL)
						success = false;
					else
						memset(myttls->phase2_data, 0x00, sizeof(config_pwd_only));
				}
				else if (m_innerTTLSProtocol == ConnectionWizardData::inner_mschapv2)
				{
					myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_MSCHAPV2;
					myttls->phase2_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
					if (myttls->phase2_data == NULL)
						success = false;
					else
						memset(myttls->phase2_data, 0x00, sizeof(config_pwd_only));
				}	
				else if (m_innerTTLSProtocol == ConnectionWizardData::inner_eap_md5)
				{
					myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_EAP;
					myttls->phase2_data = (config_eap_method *)malloc(sizeof(config_eap_method));
					if (myttls->phase2_data == NULL)
						success = false;
					else
					{
						config_eap_method *myeap;
						myeap = (config_eap_method *)myttls->phase2_data;
						memset(myeap, 0x00, sizeof(config_eap_method));
						myeap->method_num = EAP_TYPE_MD5;
						myeap->method_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
						if (myeap->method_data == NULL)
							success = false;
						else
							memset(myeap->method_data, 0x00, sizeof(config_pwd_only));
					}
				}	
			}
		}
	}	

	return success;
}

bool ConnectionWizardData::toProfileData(config_profiles **retProfile, config_trusted_server const * const pServer)
{
	bool success = true;
	
	config_profiles *pProfile = NULL;
	
	// can't do anything
	if (retProfile == NULL)
		return false;
		
	// if dot1X, create profile
	if ((m_wireless == false && m_wiredSecurity == true)
		|| (m_wireless == true 
		&& (m_wirelessAssocMode == ConnectionWizardData::assoc_WPA_ENT
		|| m_wirelessAssocMode == ConnectionWizardData::assoc_WPA2_ENT)))
	{
		// create profile
		success = XSupWrapper::createNewProfile(m_profileName,&pProfile,(m_newConnection == false && m_hasProfile == true));
		if (success == true && pProfile != NULL)
		{
			switch (m_eapProtocol)
			{
				case ConnectionWizardData::eap_peap:
					success = this->toProfileEAP_PEAPProtocol(pProfile, pServer);
					break;
				case ConnectionWizardData::eap_ttls:
					success = this->toProfileEAP_TTLSProtocol(pProfile,pServer);
					break;
				case ConnectionWizardData::eap_fast:
					success = this->toProfileEAP_FASTProtocol(pProfile, pServer);
					break;
				case ConnectionWizardData::eap_aka:
					success = this->toProfileEAP_AKAProtocol(pProfile);
					break;
				case ConnectionWizardData::eap_sim:
					success = this->toProfileEAP_SIMProtocol(pProfile);
					break;
				case ConnectionWizardData::eap_md5:
					success = this->toProfileEAP_MD5Protocol(pProfile);
					break;
				default:
					pProfile->method = NULL;
			}
		}
		else
		{
			// in case this was allocated
			XSupWrapper::freeConfigProfile(&pProfile);
			pProfile = NULL;
			success = false;
		}
	}
	*retProfile = pProfile;
	
	return success;
}

bool ConnectionWizardData::toConnectionData(config_connection **retConnection, config_profiles const * const pProfile)
{
	config_connection *pConn;
	bool success = true;
	
	// can't do anything
	if (retConnection == NULL)
		return false;
		
	pConn = NULL;
		
	success = XSupWrapper::createNewConnection(m_connectionName, &pConn, m_newConnection == false);
	if (success == false)
	{
		XSupWrapper::freeConfigConnection(&pConn);
		pConn = NULL;
	}
	
	*retConnection = pConn;
	
	// TODO: it's possible that name gets changed above, if new connection was added before we
	// save out. That = bad
	
	if (pConn != NULL)
	{
		pConn->priority = DEFAULT_PRIORITY;
		pConn->profile = NULL;
		pConn->device = _strdup(m_adapterDesc.toAscii().data());
		if (m_wireless == true)
		{
			pConn->ssid = _strdup(m_networkName.toAscii().data());
			switch (m_wirelessAssocMode)
			{
				case ConnectionWizardData::assoc_none:
					pConn->association.association_type = ASSOC_OPEN;
					pConn->association.auth_type = AUTH_NONE;				
					break;
				case ConnectionWizardData::assoc_WEP:
					pConn->association.association_type = ASSOC_OPEN;
					pConn->association.auth_type = AUTH_NONE;
					pConn->association.txkey = 1;					
					break;
				case ConnectionWizardData::assoc_WPA2_PSK:
					pConn->association.association_type = ASSOC_WPA2;
					pConn->association.auth_type = AUTH_PSK;					
					break;
				case ConnectionWizardData::assoc_WPA_PSK:
					pConn->association.association_type = ASSOC_WPA;
					pConn->association.auth_type = AUTH_PSK;				
					break;					
				case ConnectionWizardData::assoc_WPA2_ENT:
					pConn->association.association_type = ASSOC_WPA2;
					pConn->association.auth_type = AUTH_EAP;
					if (pProfile != NULL)
						pConn->profile = _strdup(pProfile->name);
					else
						success = false;  // we should have a profile
					break;
				case ConnectionWizardData::assoc_WPA_ENT:
					pConn->association.association_type = ASSOC_WPA;
					pConn->association.auth_type = AUTH_EAP;
					if (pProfile != NULL)
						pConn->profile = _strdup(pProfile->name);
					else
						success = false;  // we should have a profile				
					break;	
			}
			
			if (m_hiddenNetwork == true)
			{
				pConn->flags |= CONFIG_NET_IS_HIDDEN;
				if (m_wirelessEncryptMeth == ConnectionWizardData::encrypt_CCMP)
					pConn->association.pairwise_keys |= CRYPT_FLAGS_CCMP;
				if (m_wirelessEncryptMeth == ConnectionWizardData::encrypt_TKIP)
					pConn->association.pairwise_keys |= CRYPT_FLAGS_TKIP;					
				if (m_wirelessEncryptMeth == ConnectionWizardData::encrypt_WEP)
					pConn->association.pairwise_keys |= CRYPT_FLAGS_WEP104;					
			}
		}
		else
		{
			if (m_wiredSecurity == true)
			{
				if (pProfile != NULL)
					pConn->profile = _strdup(pProfile->name);
				else
					success = false;  // we should have a profile
			}
		}
		
		if (m_staticIP == true)
		{
			pConn->ip.type = CONFIG_IP_USE_STATIC;
			pConn->ip.ipaddr = _strdup(m_IPAddress.toAscii().data());
			if (m_gateway != "") pConn->ip.gateway = _strdup(m_gateway.toAscii().data());
			pConn->ip.netmask = _strdup(m_netmask.toAscii().data());
			pConn->ip.dns1 = _strdup(m_primaryDNS.toAscii().data());
			if (m_secondaryDNS != "") pConn->ip.dns2 = _strdup(m_secondaryDNS.toAscii().data());
		}
		else
		{
			pConn->ip.type = CONFIG_IP_USE_DHCP;
			pConn->ip.renew_on_reauth = m_renewOnReauth == true ? TRUE : FALSE; // correct default?
		}
	}
	
	return success;
}

bool ConnectionWizardData::toServerData(config_trusted_server **retServer)
{
	config_trusted_server *pServer = NULL;
	bool success = true;
	
	if (retServer == NULL)
		return false;
	
	// if 802.1X
	if ((m_wireless == false && m_wiredSecurity == true)
		|| (m_wireless == true 
		&& (m_wirelessAssocMode == ConnectionWizardData::assoc_WPA_ENT
		|| m_wirelessAssocMode == ConnectionWizardData::assoc_WPA2_ENT)))
	{
		// only if eap-peap and eap-ttls and validate server cert is true
		if ((m_eapProtocol == ConnectionWizardData::eap_peap || m_eapProtocol == ConnectionWizardData::eap_ttls
			|| m_eapProtocol == ConnectionWizardData::eap_fast) && m_validateCert == true)
		{
			success = XSupWrapper::createNewTrustedServer(m_serverName,&pServer, (m_newConnection == false && m_hasServer == true));
			if (success && pServer != NULL)
			{
				if (m_verifyCommonName == true) 
				{
					pServer->common_name = _strdup((m_commonNames.join(",")).toAscii().data());
					pServer->exact_common_name = FALSE; // not sure when this is ever 'true'?
				}

				int numCerts = m_serverCerts.size();
				
				if (numCerts > 0)
				{
#ifdef WINDOWS
					pServer->store_type = _strdup("WINDOWS");
#endif
					pServer->location = (char**)malloc(numCerts * sizeof(char *));
					if (pServer->location != NULL)
					{
						memset(pServer->location, 0x00, numCerts * sizeof(char *));
						
						for (int i=0; i<numCerts; i++)
							pServer->location[i] = _strdup(m_serverCerts.at(i).toAscii().data());
					}
					else
						success = false;
				}
					
				pServer->num_locations = numCerts;	
			}
			else
			{
				success = false;
				if (pServer != NULL)
					XSupWrapper::freeConfigServer(&pServer);
				pServer = NULL;
			}
		}
	}	
	*retServer = pServer;
	return success;
}

bool ConnectionWizardData::toSupplicantProfiles(config_connection **retConnection, config_profiles **retProfile, config_trusted_server **retServer)
{
	bool success;
	config_connection *pConn = NULL;
	config_profiles *pProfile = NULL;
	config_trusted_server *pServer = NULL;
	
	// create trusted server and pass to profile data
	success = this->toServerData(&pServer);
	success = this->toProfileData(&pProfile, pServer) == true && success == true;
	success = this->toConnectionData(&pConn, pProfile) == true && success == true;
	
	if (success == true)
	{
		if (retConnection != NULL)
			*retConnection = pConn;
		if (retProfile != NULL)
			*retProfile = pProfile;
		if (retServer != NULL)
			*retServer = pServer;
	}
	else
	{
		// if anything failed ,just throw out everything we've been given
		
		if (pConn != NULL)
		{
			XSupWrapper::freeConfigConnection(&pConn);
			if (retConnection != NULL)
				*retConnection = NULL;			
		}
		if (pProfile != NULL)
		{
			XSupWrapper::freeConfigProfile(&pProfile);
			if (retProfile != NULL)
				*retProfile = NULL;
		}
		if (pServer != NULL)
		{
			xsupgui_request_free_trusted_server_config(&pServer);
			if (retServer != NULL)
				*retServer = NULL;
		}
	}	
		
	// what do we consider a "success" to pass down?
	return success;
}

bool ConnectionWizardData::initFromSupplicantProfiles(unsigned char config_type, config_connection const * const pConfig, config_profiles const * const pProfile, config_trusted_server const * const pServer)
{
	if (pConfig == NULL && pProfile == NULL && pServer == NULL)
		return false;  // no data to convert
	
	// first fill out all connection info	
	m_wireless = pConfig->ssid != NULL && QString(pConfig->ssid).isEmpty() == false;
	m_adapterDesc = pConfig->device;
	m_connectionName = pConfig->name;
	m_config_type = config_type;
	
	if (m_wireless == true)
	{
		if (pConfig->ssid == NULL)
			;// bad.
		else
			m_networkName = pConfig->ssid;
		
		switch (pConfig->association.association_type)
		{
			case ASSOC_OPEN:
				if (pConfig->association.txkey == 1)
					m_wirelessAssocMode = ConnectionWizardData::assoc_WEP;
				else
					m_wirelessAssocMode = ConnectionWizardData::assoc_none;
				break;
			case ASSOC_WPA:
				if (pConfig->association.auth_type == AUTH_PSK)
					m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_PSK;
				else
					m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_ENT;
				break;
			case ASSOC_WPA2:
				if (pConfig->association.auth_type == AUTH_PSK)
					m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_PSK;
				else
					m_wirelessAssocMode = ConnectionWizardData::assoc_WPA_ENT;
				break;			
		}
		
		if ((pConfig->association.pairwise_keys & CRYPT_FLAGS_CCMP) == CRYPT_FLAGS_CCMP)
			m_wirelessEncryptMeth = ConnectionWizardData::encrypt_CCMP;
		else if ((pConfig->association.pairwise_keys & CRYPT_FLAGS_CCMP) == CRYPT_FLAGS_TKIP)
			m_wirelessEncryptMeth = ConnectionWizardData::encrypt_TKIP;
		else if ((pConfig->association.pairwise_keys & (CRYPT_FLAGS_WEP104 | CRYPT_FLAGS_WEP40)) != 0)					
			m_wirelessEncryptMeth = ConnectionWizardData::encrypt_WEP;
			
		m_hiddenNetwork = (pConfig->flags & CONFIG_NET_IS_HIDDEN) == CONFIG_NET_IS_HIDDEN;		
	}
	else
	{
		// should verify profile actually exists? most likely	
		m_wiredSecurity = (pConfig->profile != NULL && QString(pConfig->profile).isEmpty() == false);
	}
	
	if (pConfig->ip.type == CONFIG_IP_USE_STATIC)
	{
		m_staticIP = true;
		m_IPAddress = pConfig->ip.ipaddr;
		m_gateway = pConfig->ip.gateway;
		m_netmask = pConfig->ip.netmask;
		m_primaryDNS = pConfig->ip.dns1;
		m_secondaryDNS = pConfig->ip.dns2;	
	}
	else
		m_staticIP = false;
		
	m_renewOnReauth = (pConfig->ip.renew_on_reauth == TRUE);
		
	if (pProfile != NULL)
	{
		m_profileName = pProfile->name;
		m_hasProfile = true;
		if (pProfile->identity != NULL) 
		{
			if (QString(pProfile->identity) != QString("anonymous"))
				m_outerIdentity = QString(pProfile->identity);
		}	
			
		if (pProfile->method != NULL)
		{
			config_eap_method *pEAPMethod = (config_eap_method*)pProfile->method;
			if (pEAPMethod->method_num == EAP_TYPE_MD5)
			{
				m_eapProtocol = ConnectionWizardData::eap_md5;
			}
			else if (pEAPMethod->method_num == EAP_TYPE_AKA)
			{
				config_eap_aka *pAKAData = (config_eap_aka *)pEAPMethod->method_data;
				m_eapProtocol = ConnectionWizardData::eap_aka;
				m_SCreader = pAKAData->reader;
				if (pAKAData->auto_realm == TRUE)
				{
					m_autoRealm = true;
				}
				else
				{
					m_autoRealm = false;
				}
			}
			else if (pEAPMethod->method_num == EAP_TYPE_SIM)
			{
				config_eap_sim *pSIMData = (config_eap_sim *)pEAPMethod->method_data;
				m_eapProtocol = ConnectionWizardData::eap_sim;
				m_SCreader = pSIMData->reader;
				if (pSIMData->auto_realm == TRUE)
				{
					m_autoRealm = true;
				}
				else
				{
					m_autoRealm = false;
				}
			}
			else if (pEAPMethod->method_num == EAP_TYPE_TTLS)
			{
				m_eapProtocol = ConnectionWizardData::eap_ttls;
				if (pEAPMethod->method_data != NULL)
				{
					config_eap_ttls *pTTLSData = (config_eap_ttls *)pEAPMethod->method_data;
					if (pTTLSData->phase2_type == TTLS_PHASE2_PAP)
						m_innerTTLSProtocol = ConnectionWizardData::inner_pap;
					else if (pTTLSData->phase2_type == TTLS_PHASE2_CHAP)
						m_innerTTLSProtocol = ConnectionWizardData::inner_chap;
					else if (pTTLSData->phase2_type == TTLS_PHASE2_MSCHAP)
						m_innerTTLSProtocol = ConnectionWizardData::inner_mschap;
					else if (pTTLSData->phase2_type == TTLS_PHASE2_MSCHAPV2)
						m_innerTTLSProtocol = ConnectionWizardData::inner_mschapv2;										
					else if (pTTLSData->phase2_type == TTLS_PHASE2_EAP)
						m_innerTTLSProtocol = ConnectionWizardData::inner_eap_md5;
						
					if (pTTLSData->validate_cert == TRUE)
						m_validateCert = true;
					else
						m_validateCert = false;			
				}
				
			}
			else if (pEAPMethod->method_num == EAP_TYPE_PEAP)
			{
				m_eapProtocol = ConnectionWizardData::eap_peap;
				if (pEAPMethod->method_data != NULL)
				{
					config_eap_peap *pPEAPData = (config_eap_peap *)pEAPMethod->method_data;
					if (pPEAPData->phase2 != NULL)
					{
						config_eap_method *myeap = NULL;
						myeap = (config_eap_method *)pPEAPData->phase2;					
						if (myeap->method_num == EAP_TYPE_MSCHAPV2)
							m_innerPEAPProtocol = ConnectionWizardData::inner_mschapv2;
						else if (myeap->method_num == EAP_TYPE_GTC)
							m_innerPEAPProtocol = ConnectionWizardData::inner_eap_gtc;
					}
						
					if (pPEAPData->validate_cert == TRUE)
						m_validateCert = true;
					else
						m_validateCert = false;			
				}				
			}
			else if (pEAPMethod->method_num == EAP_TYPE_FAST)
			{
				m_eapProtocol = ConnectionWizardData::eap_fast;
				if (pEAPMethod->method_data != NULL)
				{
					config_eap_fast *pFASTData = (config_eap_fast *)pEAPMethod->method_data;
					if (pFASTData->phase2 != NULL)
					{
						config_eap_method *myeap = NULL;
						myeap = (config_eap_method *)pFASTData->phase2;					
						if (myeap->method_num == EAP_TYPE_MSCHAPV2)
							m_innerFASTProtocol = ConnectionWizardData::inner_mschapv2;
						else if (myeap->method_num == EAP_TYPE_GTC)
							m_innerFASTProtocol = ConnectionWizardData::inner_eap_gtc;
					}
						
					if (pFASTData->validate_cert == TRUE)
						m_validateCert = true;
					else
						m_validateCert = false;			

					if (TEST_FLAG(pFASTData->provision_flags, EAP_FAST_PROVISION_ANONYMOUS))
					{
						m_anonymousProvisioning = true;
					}
					else
					{
						m_anonymousProvisioning = false;
					}

					if (TEST_FLAG(pFASTData->provision_flags, EAP_FAST_PROVISION_AUTHENTICATED))
					{
						m_authenticatedProvisioning = true;
					}
					else
					{
						m_authenticatedProvisioning = false;
					}
				}				
			}

		}
	}
	
	if (pServer != NULL)
	{
		m_hasServer = true;
		m_serverName = pServer->name;
		if (pServer->common_name != NULL && QString(pServer->common_name).isEmpty() == false)
		{
			m_commonNames = QString(pServer->common_name).split(",");
			m_verifyCommonName = true;
		}
		else
			m_verifyCommonName = false;
			
		if (pServer->num_locations > 0 && pServer->location != NULL)
		{
			for (int i=0;i<pServer->num_locations;i++)
				m_serverCerts.append(pServer->location[i]);
		}
	}
	
	return true;
}