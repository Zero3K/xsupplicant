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
	// First, ensure a connection with this name doesn't already exist
	// If it does, add a _1 _2 etc., to the name until a unique name is found
	QString newName(suggName);
	config_connection *pConfig = NULL;	
  
	int i=1;
	while (getConfigConnection(newName, &pConfig) == true)
	{
		newName = QString ("%1_%2").arg(suggName).arg(i);
		i++;

		freeConfigConnection(&pConfig);
		pConfig = NULL;
	}
	
	// free connection info from last iteration of loop
	freeConfigConnection(&pConfig);
	
	if (!createNewConnectionDefaults(&pConfig) || pConfig == NULL)
	{
		return false;
	}
	
	// give the new connection meaningful settings
	pConfig->name = _strdup(newName.toAscii().data());
	pConfig->priority = DEFAULT_PRIORITY;
	pConfig->association.association_type = ASSOC_WPA2;
	pConfig->association.auth_type = AUTH_EAP;

	(*newConnection) = pConfig;

	return true;	
}

bool XSupWrapper::getConfigConnection(const QString &connName, config_connection **pConfig)
{
	Q_ASSERT(pConfig);
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

bool XSupWrapper::createNewConnectionDefaults(config_connection **pConfig)
{
	if (pConfig == NULL)
		return false;

	int retVal = xsupconfig_defaults_create_connection(pConfig);
	
	if (retVal != REQUEST_SUCCESS || pConfig == NULL)
		return false;
		
	return true;
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