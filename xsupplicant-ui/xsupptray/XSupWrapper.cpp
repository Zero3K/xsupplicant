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

#include "XSupWrapper.h"
#include <algorithm>

extern "C"
{
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupgui/xsupgui_request.h"
#include "xsupconfig_defaults.h"
#include "xsupconfig.h"
}


// NOTE: this function may create a connection with a different name than is passed in
bool XSupWrapper::createNewConnection(const QString &suggName, config_connection **newConnection, bool forceName /* = false */)
{
	if (newConnection == NULL)
		return false;
		
	// First, ensure a connection with this name doesn't already exist
	// If it does, add a _1 _2 etc., to the name until a unique name is found
	QString newName;
	if (forceName == true)
		newName = suggName;
	else
		newName = XSupWrapper::getUniqueConnectionName(suggName);
	config_connection *pConfig = NULL;	
	
	pConfig = (config_connection*)malloc(sizeof(config_connection));
	if (pConfig != NULL)
	{	
		memset(pConfig, 0x00, sizeof(config_connection));
		pConfig->name = _strdup(newName.toAscii().data());
	}

	(*newConnection) = pConfig;
	return (pConfig != NULL);
}

bool XSupWrapper::getConfigConnection(const QString &connName, config_connection **pConfig)
{
	if (pConfig == NULL)
		return false;
		
	*pConfig = NULL;

	if (connName.isEmpty())
		return false;

	int retVal = xsupgui_request_get_connection_config(connName.toAscii().data(), pConfig);
	if (retVal != REQUEST_SUCCESS || *pConfig == NULL)
	{
		*pConfig = NULL;
		return false;
	}
	
	return true;
}

void XSupWrapper::freeConfigConnection(config_connection **p)
{
  if (p != NULL)
	 xsupgui_request_free_connection_config(p);
}

bool XSupWrapper::deleteConnectionConfig(const QString &connName)
{
	int retVal = xsupgui_request_delete_connection_config(connName.toAscii().data());
	if (retVal == REQUEST_SUCCESS)
		return true;
	else
		return false;
}

bool XSupWrapper::writeConfig()
{
	int retval = 0;
	retval = xsupgui_request_write_config(NULL);

	if (retval == REQUEST_SUCCESS)
		return true;
	else
		return false;
}

QString XSupWrapper::getUniqueConnectionName(const QString &suggestedName)
{
	QString newName(suggestedName);
	config_connection *pConfig = NULL;	
  
	int i=1;
	while (getConfigConnection(newName, &pConfig) == true)
	{
		newName = QString ("%1_%2").arg(suggestedName).arg(i);
		++i;

		XSupWrapper::freeConfigConnection(&pConfig);
		pConfig = NULL;
	}

	return newName;
}

QString XSupWrapper::getUniqueServerName(const QString &suggestedName)
{
	QString newName(suggestedName);
	config_trusted_server *pServer = NULL;	
  
	int i=1;
	while (getConfigServer(newName, &pServer) == true)
	{
		newName = QString ("%1_%2").arg(suggestedName).arg(i);
		++i;

		XSupWrapper::freeConfigServer(&pServer);
		pServer = NULL;
	}

	return newName;
}

QString XSupWrapper::getUniqueProfileName(const QString &suggestedName)
{
	QString newName(suggestedName);
	config_profiles *pProfile = NULL;	
  
	int i=1;
	while (getConfigProfile(newName, &pProfile) == true)
	{
		newName = QString ("%1_%2").arg(suggestedName).arg(i);
		++i;

		freeConfigProfile(&pProfile);
		pProfile = NULL;
	}

	return newName;
}

void XSupWrapper::freeConfigProfile(config_profiles **pProfile)
{
 if (pProfile != NULL)
	 xsupgui_request_free_profile_config(pProfile);
}

bool XSupWrapper::getConfigProfile(const QString &profileName, config_profiles **pProfile)
{
	if (pProfile == NULL)
		return false;
		
	*pProfile = NULL;

	if (profileName.isEmpty())
		return false;

	int retVal = xsupgui_request_get_profile_config(profileName.toAscii().data(), pProfile);
	if (retVal != REQUEST_SUCCESS || *pProfile == NULL)
	{
		*pProfile = NULL;
		return false;
	}
	
	return true;
}

// create a blank new profile w/ only name filled out
bool XSupWrapper::createNewProfile(const QString &suggName, config_profiles **newProfile, bool forceName /* = false */)
{
	if (newProfile == NULL)
		return false;
		
	// First, ensure a connection with this name doesn't already exist
	// If it does, add a _1 _2 etc., to the name until a unique name is found
	QString newName;
	if (forceName == true)
		newName = suggName;
	else
		newName = XSupWrapper::getUniqueProfileName(suggName);
		
	config_profiles *pProfile = NULL;	
	
	pProfile = (config_profiles*)malloc(sizeof(config_profiles));
	if (pProfile != NULL)
	{	
		memset(pProfile, 0x00, sizeof(config_profiles));
		pProfile->name = _strdup(newName.toAscii().data());
	}

	(*newProfile) = pProfile;
	return (pProfile != NULL);
}

// creates a blank new trusted server profile w/ only name filled out
bool XSupWrapper::createNewTrustedServer(const QString &suggName, config_trusted_server **newServer, bool forceName /* = false */)
{
	if (newServer == NULL)
		return false; 
	
	QString newName;
	if (forceName == true)
		newName = suggName;
	else
		newName = XSupWrapper::getUniqueServerName(suggName);
	config_trusted_server *pServer = NULL;
	
	pServer = (config_trusted_server*)malloc(sizeof(config_trusted_server));
	if (pServer != NULL)
	{
		memset(pServer, 0x00, sizeof(config_trusted_server));
		pServer->name = _strdup(newName.toAscii().data());
	}
	
	(*newServer) = pServer;
	return (pServer != NULL);
}

bool XSupWrapper::isDefaultWiredConnection(const QString &connName)
{
	bool success;
	bool isDefault = false;
	if (connName.isEmpty())
		return false;
		
	// first, check if wired
	config_connection *pConn;
	success = XSupWrapper::getConfigConnection(connName,&pConn);
	if (success == true)
	{
		// check if wired
		if (pConn->ssid == NULL || QString(pConn->ssid).isEmpty())
		{
			int_config_enum *pInterfaceList = NULL;
			int retVal;
			
			retVal = xsupgui_request_enum_ints_config(&pInterfaceList);
			if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
			{
				int i = 0;
				while (pInterfaceList[i].desc != NULL)
				{
					if (pInterfaceList[i].is_wireless == FALSE)
					{
						if (pInterfaceList[i].default_connection != NULL)
						{
							if (QString(pInterfaceList[i].default_connection) == connName)
							{
								isDefault = true;
								break;
							}	
						}
					}
					++i;	
				}
				xsupgui_request_free_int_config_enum(&pInterfaceList);
			}			
		}
	}
	return isDefault;
}

void XSupWrapper::freeConfigServer(config_trusted_server **pServer)
{
 if (pServer != NULL)
	 xsupgui_request_free_trusted_server_config(pServer);
}

bool XSupWrapper::getConfigServer(const QString &serverName, config_trusted_server **pServer)
{
	if (pServer == NULL)
		return false;
		
	*pServer = NULL;

	if (serverName.isEmpty())
		return false;

	int retVal = xsupgui_request_get_trusted_server_config(serverName.toAscii().data(), pServer);
	if (retVal != REQUEST_SUCCESS || *pServer == NULL)
	{
		*pServer = NULL;
		return false;
	}
	
	return true;
}

bool XSupWrapper::isProfileInUse(const QString &profileName)
{
	bool inUse = false;
	if (!profileName.isEmpty())
	{
		conn_enum * pConfig;
		int retVal;
		retVal = xsupgui_request_enum_connections(&pConfig);
		if (retVal == REQUEST_SUCCESS && pConfig != NULL)
		{
			int i=0;
			while (pConfig[i].name != NULL)
			{
				config_connection *pConn;
				retVal = xsupgui_request_get_connection_config(pConfig[i].name, &pConn);
				if (retVal == REQUEST_SUCCESS && pConn != NULL)
				{
					if (QString(pConn->profile) == profileName)
					{
						inUse = true;
						XSupWrapper::freeConfigConnection(&pConn);
						break;
					}
					XSupWrapper::freeConfigConnection(&pConn);
				}
				++i;
			}
			xsupgui_request_free_conn_enum(&pConfig);
		}
	}
	return inUse;
}

bool XSupWrapper::deleteProfileConfig(const QString &profileName)
{
	if (profileName.isEmpty() == false)
	{
		int retVal;
		retVal = xsupgui_request_delete_profile_config(profileName.toAscii().data(), TRUE);
		if (retVal == REQUEST_SUCCESS)
			return true;
	}
	return false;
}

bool XSupWrapper::deleteServerConfig(const QString &serverName)
{
	if (serverName.isEmpty() == false)
	{
		int retVal;
		retVal = xsupgui_request_delete_trusted_server_config(serverName.toAscii().data(), TRUE);
		if (retVal == REQUEST_SUCCESS)
			return true;
	}
	return false;
}

bool XSupWrapper::getTrustedServerForProfile(const QString &profileName, config_trusted_server **pServer)
{
	bool success = false;
	if (pServer == NULL)
		return success;

	*pServer = NULL;
	config_profiles *pProfile = NULL;
	XSupWrapper::getConfigProfile(profileName, &pProfile);
	if (pProfile != NULL && pProfile->method != NULL)
	{
		config_eap_method *pMethod = pProfile->method;
		if (pMethod->method_num == EAP_TYPE_PEAP)
		{
			config_eap_peap *mypeap;
			mypeap = (config_eap_peap *)pProfile->method->method_data;
			if (mypeap != NULL)
			{
				QString serverName;
				serverName = mypeap->trusted_server;
				if (!serverName.isEmpty())
				{
					XSupWrapper::getConfigServer(serverName, pServer);
					if (*pServer != NULL)
						success = true;
				}
			}
		}
		else if (pMethod->method_num == EAP_TYPE_TTLS)
		{
			config_eap_ttls *myttls;
			myttls = (config_eap_ttls *)pProfile->method->method_data;
			if (myttls != NULL)
			{
				QString serverName;
				serverName = myttls->trusted_server;
				if (!serverName.isEmpty())
				{
					XSupWrapper::getConfigServer(serverName, pServer);
					if (*pServer != NULL)
						success = true;
				}
			}
		}
		
		XSupWrapper::freeConfigProfile(&pProfile);
	}
	
	return success;
}

bool XSupWrapper::isTrustedServerInUse(const QString &serverName)
{
	bool inUse = false;
	profile_enum *pProfile = NULL;
	int retVal;
	
	retVal = xsupgui_request_enum_profiles(&pProfile);
	if (retVal == REQUEST_SUCCESS && pProfile != NULL)
	{
		int i=0;
		while (pProfile[i].name != NULL && inUse == false)
		{
			config_trusted_server *pServer;
			XSupWrapper::getTrustedServerForProfile(QString(pProfile[i].name), &pServer);
			if (pServer != NULL)
			{
				if (QString(pServer->name) == serverName)
					inUse = true;
					
				XSupWrapper::freeConfigServer(&pServer);
			}
			++i;
		}
	}
	return inUse;
}

QStringList XSupWrapper::getWirelessInterfaceList(void)
{
	QStringList intList;
	int retVal;
	
	int_enum *pInterface;
	retVal = xsupgui_request_enum_live_ints(&pInterface);
	
	if (retVal == REQUEST_SUCCESS && pInterface != NULL)
	{
		int i = 0;
		while (pInterface[i].name != NULL)
		{
			if (pInterface[i].is_wireless == TRUE)
				intList.append(QString(pInterface[i].desc));
			++i;
		}
	}
	xsupgui_request_free_int_enum(&pInterface);
	return intList;
}

bool XSupWrapper::setProfileUsername(const QString &profileName, const QString &username)
{
	bool success;
	config_profiles *pProfile = NULL;
	
	success = XSupWrapper::getConfigProfile(profileName, &pProfile);
	
	if (success == true && pProfile != NULL)
	{
		if (pProfile->method != NULL)
		{
			if (pProfile->method->method_num == EAP_TYPE_MD5)
			{
				if (pProfile->identity != NULL)
					free(pProfile->identity);
				pProfile->identity = _strdup(username.toAscii().data());
			}
			else if (pProfile->method->method_num == EAP_TYPE_PEAP)
			{
				if (pProfile->method->method_data != NULL)
				{
					config_eap_peap *peap = (config_eap_peap *)pProfile->method->method_data;
					if (peap->identity != NULL)
						free (peap->identity);
					peap->identity = _strdup(username.toAscii().data());
				}
				else
					success = false;	
			}
			else if (pProfile->method->method_num == EAP_TYPE_TTLS)
			{
				config_eap_ttls *ttls;

				ttls = (struct config_eap_ttls *)pProfile->method->method_data;
				if (ttls == NULL)
					success = false;
				else
				{
					switch (ttls->phase2_type)
					{
						case TTLS_PHASE2_PAP:
						case TTLS_PHASE2_CHAP:
						case TTLS_PHASE2_MSCHAP:
						case TTLS_PHASE2_MSCHAPV2:
						case TTLS_PHASE2_EAP:
							if (ttls->inner_id != NULL)
								free(ttls->inner_id);
							ttls->inner_id = _strdup(username.toAscii().data());
							break;
						default:
							success = false;
							break;
					}
				}
			}
			else
				QMessageBox::critical(NULL,"Unhandle EAP type", "Unhandled EAP Type in SetProfileUsername()");
			
		}
		else
			success = false;
			
		if (success == true)
			success = xsupgui_request_set_profile_config(pProfile) == REQUEST_SUCCESS;
	}
	
	if (pProfile != NULL)
		XSupWrapper::freeConfigProfile(&pProfile);
		
	return success;
}

bool XSupWrapper::setProfilePassword(const QString &profileName, const QString &password)
{
	bool success;
	config_profiles *pProfile = NULL;
	
	success = XSupWrapper::getConfigProfile(profileName, &pProfile);
	
	if (success == true && pProfile != NULL)
	{
		int retval = config_change_pwd(pProfile->method, password.toAscii().data());
		success = retval == XENONE;

		if (success == true)
			success = xsupgui_request_set_profile_config(pProfile) == REQUEST_SUCCESS;				
	}
	
	if (pProfile != NULL)
		XSupWrapper::freeConfigProfile(&pProfile);
		
	return success;
}

bool XSupWrapper::disconnectAdapter(const QString &adapterDesc)
{
	bool success = false;
	int retVal = 0;
	char *pDeviceName = NULL;

	// Using the device description - get the device name
	retVal = xsupgui_request_get_devname(adapterDesc.toAscii().data(), &pDeviceName);
	if (retVal == REQUEST_SUCCESS && pDeviceName != NULL)
	{
		config_interfaces *pInterface;
		retVal =xsupgui_request_get_interface_config(adapterDesc.toAscii().data(),&pInterface);
		if (retVal == REQUEST_SUCCESS && pInterface != NULL)
		{
			if ((pInterface->flags & CONFIG_INTERFACE_IS_WIRELESS) == CONFIG_INTERFACE_IS_WIRELESS)
			{
				if (xsupgui_request_set_disassociate(pDeviceName, 1) == REQUEST_SUCCESS)
				{
					// Lock the connection in a disconnected state so that we don't change to something else.
					xsupgui_request_set_connection_lock(pDeviceName, TRUE);
					xsupgui_request_unbind_connection(pDeviceName);		
					success = true;	
				}
			}
			else // if wired
			{
				if (xsupgui_request_logoff(pDeviceName) == REQUEST_SUCCESS)
				{
					xsupgui_request_unbind_connection(pDeviceName);
					success = true;
				}
			}
		}
		if (pInterface != NULL)
			xsupgui_request_free_interface_config(&pInterface);
	}
	
	if (pDeviceName != NULL) 
		free(pDeviceName);

	
	return success;
}

void XSupWrapper::getAndDisplayErrors(void)
{
	error_messages *msgs = NULL;

	int retval = xsupgui_request_get_error_msgs(&msgs);
	if (retval == REQUEST_SUCCESS)
	{
		if (msgs && msgs[0].errmsgs)
		{
			int i = 0;
			QString errors;
			
			// If we have at least one message, display it here
			while (msgs[i].errmsgs != NULL)
			{
				errors += QString ("- %1\n").arg(msgs[i].errmsgs);
				i++;
			}

			QMessageBox::critical(NULL, QWidget::tr("XSupplicant Error Summary"),
				QWidget::tr("The following errors were returned from XSupplicant while attempting to connect:\n%1")
				.arg(errors));
		}
	}
	else
	{
		QMessageBox::critical(NULL, QWidget::tr("Get Error Message error"),
			QWidget::tr("An error occurred while checking for errors from the XSupplicant."));
	}

	xsupgui_request_free_error_msgs(&msgs);
}

// returns descriptions of wireless adapters in system
QVector<QString> XSupWrapper::getWirelessAdapters(void)
{
	QVector<QString> adapterVec;
	int_enum *pInterfaceList = NULL;
	int retVal;	
			
	retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
	if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
	{
		int i = 0;
		while (pInterfaceList[i].desc != NULL)
		{
			if (pInterfaceList[i].is_wireless == TRUE)
				adapterVec.push_back(QString(pInterfaceList[i].desc));
			
			++i;
		}
	}	
	
	if (pInterfaceList != NULL)
		xsupgui_request_free_int_enum(&pInterfaceList);
	
	std::sort(adapterVec.begin(), adapterVec.end());
	return adapterVec;
}

// returns descriptions of wired adapters in system
QVector<QString> XSupWrapper::getWiredAdapters(void)
{	
	QVector<QString> adapterVec;
	int_enum *pInterfaceList = NULL;
	int retVal;	
			
	retVal = xsupgui_request_enum_live_ints(&pInterfaceList);
	if (retVal == REQUEST_SUCCESS && pInterfaceList != NULL)
	{
		int i = 0;
		while (pInterfaceList[i].desc != NULL)
		{
			if (pInterfaceList[i].is_wireless == FALSE)
				adapterVec.push_back(QString(pInterfaceList[i].desc));
			
			++i;
		}
	}	
	
	if (pInterfaceList != NULL)
		xsupgui_request_free_int_enum(&pInterfaceList);
	
	std::sort(adapterVec.begin(), adapterVec.end());
	return adapterVec;
} 

QVector<QString> XSupWrapper::getConnectionListForAdapter(const QString &adapterDesc)
{
	QVector<QString> retVector;
	if (adapterDesc.isEmpty() == false)
	{
		conn_enum *pConn;
		int retVal;
		
		retVal = xsupgui_request_enum_connections(&pConn);
		if (retVal == REQUEST_SUCCESS && pConn != NULL)
		{
			int i = 0;
			while (pConn[i].name != NULL)
			{
				if (pConn[i].dev_desc == adapterDesc)
				{
					bool success;
					config_connection *pConfig;
					success = XSupWrapper::getConfigConnection(QString(pConn[i].name), &pConfig);
					if (success == true && pConfig != NULL)
					{
						if ((pConfig->flags & CONFIG_VOLATILE_CONN) == 0)
							retVector.append(QString(pConn[i].name));
						
					}
					else
						retVector.append(QString(pConn[i].name));
						
					if (pConfig != NULL)
						XSupWrapper::freeConfigConnection(&pConfig);
				}
				++i;
			}
		}
		
		if (pConn != NULL)
			xsupgui_request_free_conn_enum(&pConn);
		
		std::sort(retVector.begin(), retVector.end());
	}
	return retVector;
}

/**
 * \brief Determine if the connection named \ref connectName is already active and
 *        in a connected or authenticated state.
 *
 * @param[in] interfaceDesc   The interface description we are looking at.
 * @param[in] connectionName   The description of the connection we want to check.
 * @param[in] isWireless   Is the interface wireless or not?
 *
 * \retval true if it is in use
 * \retval false if it isn't in use
 **/
bool XSupWrapper::isConnectionActive(const QString &interfaceName, const QString &connectionName, bool isWireless)
{
	int retval = 0;
	bool isActive = false;

	if (interfaceName.isEmpty() == false)
	{
		char *pName = NULL;
		
		// See if a connection is bound to the interface in question.
		retval = xsupgui_request_get_conn_name_from_int(interfaceName.toAscii().data(), &pName);
		if (retval = REQUEST_SUCCESS && pName != NULL)
		{
			// If they match, then check the status of the connection to determine if the connection
			// is active.
			if (connectionName.compare(pName) == 0) 
			{
				int state = 0;
				
				if (isWireless == true)
				{
					if (xsupgui_request_get_physical_state(interfaceName.toAscii().data(), &state) == REQUEST_SUCCESS)
					{
						if ((state != WIRELESS_INT_STOPPED) && (state != WIRELESS_INT_HELD))
							isActive = true;
					}
				}
				else
				{
					// It is wired, we only care if it is in 802.1X authenticated state or not.
					if (xsupgui_request_get_1x_state(interfaceName.toAscii().data(), &state) == REQUEST_SUCCESS)
						isActive = (state != DISCONNECTED);
				}
			}
		}
		
		if (pName != NULL)
			free(pName);			
	}

	return isActive;
}

/**
 * \brief Issue a request to the engine to establish a connection.
 *
 * @param[in] interfaceDesc   The interface description that we want to use with the
 *							  connection.
 * @param[in] connectionName   The connection name that we want the interface to attach to.
 *
 * \retval true if the connection attempt should succeed.
 * \retval false if the connection attempt failed.
 **/
bool XSupWrapper::connectToConnection(const QString &interfaceName, const QString &connectionName)
{
	bool success = false;

	if (interfaceName.isEmpty() == false)
	{
		int retval = 0;
		retval = xsupgui_request_set_connection(interfaceName.toAscii().data(), connectionName.toAscii().data());
		if (retval == REQUEST_SUCCESS)
			success = true;
		else if (retval == IPC_ERROR_NEW_ERRORS_IN_QUEUE)
			XSupWrapper::getAndDisplayErrors();
	}
		
	return success;
}