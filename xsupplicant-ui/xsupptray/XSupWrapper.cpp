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

extern "C"
{
#include "libxsupconfig/xsupconfig_structs.h"
#include "libxsupgui/xsupgui_request.h"
#include "xsupconfig_defaults.h"
#include "xsupconfig.h"
}


// NOTE: this function may create a connection with a different name than is passed in
bool XSupWrapper::createNewConnection(const QString &suggName, config_connection **newConnection)
{
	if (newConnection == NULL)
		return false;
		
	// First, ensure a connection with this name doesn't already exist
	// If it does, add a _1 _2 etc., to the name until a unique name is found
	QString newName = XSupWrapper::getUniqueConnectionName(suggName);
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
bool XSupWrapper::createNewProfile(const QString &suggName, config_profiles **newProfile)
{
	if (newProfile == NULL)
		return false;
		
	// First, ensure a connection with this name doesn't already exist
	// If it does, add a _1 _2 etc., to the name until a unique name is found
	QString newName = XSupWrapper::getUniqueProfileName(suggName);
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
bool XSupWrapper::createNewTrustedServer(const QString &suggName, config_trusted_server **newServer)
{
	if (newServer == NULL)
		return false; 
	
	QString newName = XSupWrapper::getUniqueServerName(suggName);
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