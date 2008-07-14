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

#include "CredentialsManager.h"
#include "Util.h"
#include "XSupWrapper.h"

extern "C"
{
#include "libxsupgui/xsupgui_request.h"
}

CredentialsManager::CredentialsManager(Emitter *e)
	: QWidget(NULL), m_pEmitter(e)
{
	Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(handleStateChange(const QString &, int, int, int, unsigned int)));
	Util::myConnect(m_pEmitter, SIGNAL(signalPSKSuccess(const QString &)), this, SLOT(pskSuccess(const QString &)));
	Util::myConnect(m_pEmitter, SIGNAL(signalConnectionDisconnected(const QString &)), this, SLOT(connectionDisconnected(const QString&)));
}

CredentialsManager::~CredentialsManager()
{
	Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(handleStateChange(const QString &, int, int, int, unsigned int)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalPSKSuccess(const QString &)), this, SLOT(pskSuccess(const QString &)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalConnectionDisconnected(const QString &)), this, SLOT(connectionDisconnected(const QString&)));
}

void CredentialsManager::storeCredentials(const QString &connectionName, const QString &userName, const QString &password)
{	
	// make sure there's only one entry per adapter (if there's already an entry for this adapter it's stale)
	if (connectionName.isEmpty() == false)	
	{
		QString intDesc;
		bool success;
		config_connection *pConn;
		
		// get device for connection passed in
		success = XSupWrapper::getConfigConnection(connectionName, &pConn);
		if (success == true && pConn != NULL)
		{
			intDesc = pConn->device;
			if (pConn != NULL)
				XSupWrapper::freeConfigConnection(&pConn);
	
			// look at each entry we have stored off, and compare the device with the one for the connection
			// passed in. If a match, delete the old entry
			QVector<CredentialsManager::CredData>::iterator iter;
			for (iter = m_credVector.begin(); iter != m_credVector.end(); iter++)
			{
				success = XSupWrapper::getConfigConnection(iter->m_connectionName, &pConn);
				if (success == true && pConn != NULL)
				{
					if (intDesc.compare(pConn->device) == 0)
					{
						m_credVector.erase(iter);
						break;
					}
				}
				if (pConn != NULL)
					XSupWrapper::freeConfigConnection(&pConn);
			}
		}
		if (pConn != NULL)
			XSupWrapper::freeConfigConnection(&pConn);
	}
	
	m_credVector.push_back(CredentialsManager::CredData(connectionName, userName, password));
}

void CredentialsManager::handleStateChange(const QString &intName, int sm, int, int newstate, unsigned int)
{		
	if (sm == IPC_STATEMACHINE_8021X && (newstate == AUTHENTICATED || newstate == S_FORCE_AUTH))
	{	
		char *connName;
		int retval = xsupgui_request_get_conn_name_from_int(intName.toAscii().data(), &connName);
		
		if (retval == REQUEST_SUCCESS && connName != NULL)
		{
			bool success;
			config_connection *pConn = NULL;
			
			success = XSupWrapper::getConfigConnection(QString(connName), &pConn);
			
			if (success == true && pConn != NULL)
			{
				// for PSK we must watch for a different message
				if (pConn->association.auth_type != AUTH_PSK)
				{
					QVector<CredentialsManager::CredData>::iterator iter;
					for (iter = m_credVector.begin(); iter != m_credVector.end(); iter++)
					{
						if (iter->m_connectionName.compare(connName) == 0)
						{
							QString errMsg;
							
							pConn->flags &= ~CONFIG_VOLATILE_CONN;					
							if (pConn->association.auth_type == AUTH_EAP)
							{
								success = XSupWrapper::setProfileUsername(pConn->profile, iter->m_userName);
								success = XSupWrapper::setProfilePassword(pConn->profile, iter->m_password) && success == true;
								
								// if we fail to write out configuration
								errMsg = tr("Unable to save your credentials");				
							}
							else // assume WEP as auth_type is AUTH_NONE
							{
								if (pConn->association.keys != NULL)
								{
									if (pConn->association.keys[1] != NULL)
										free(pConn->association.keys[1]);
									pConn->association.keys[1] = _strdup(iter->m_password.toAscii().data());	
								}
								else
									success = false;
									
								// if we fail to write out configuration
								errMsg = tr("Unable to save your WEP key");			
							}
							
							// save off changes to config
							if (success == true && xsupgui_request_set_connection_config(pConn) == REQUEST_SUCCESS)
							{
								// tell everyone we changed the config
								m_pEmitter->sendConnConfigUpdate();
													
								// this may fail.  No need to prompt user if it does
								XSupWrapper::writeConfig();	
							}
							else
								QMessageBox::critical(NULL, tr("error"),errMsg);					
								
							m_credVector.erase(iter);
							break;											
						}
					}	
				}
			}
			
			if (pConn != NULL)
				XSupWrapper::freeConfigConnection(&pConn);
		}
		
		if (connName != NULL)
			free(connName);
	}
}

// On this signal, check if we have credentials cached for this PSK
// network.  If so, store them permanently
void CredentialsManager::pskSuccess(const QString &intName)
{
	char *connName;
	int retval = xsupgui_request_get_conn_name_from_int(intName.toAscii().data(), &connName);
		
	if (retval == REQUEST_SUCCESS && connName != NULL)
	{
		bool success;
		config_connection *pConn = NULL;
		
		success = XSupWrapper::getConfigConnection(QString(connName), &pConn);
		
		if (success == true && pConn != NULL)
		{
			// if this isn't PSK we have issues
			if (pConn->association.auth_type == AUTH_PSK)
			{
				QVector<CredentialsManager::CredData>::iterator iter;
				for (iter = m_credVector.begin(); iter != m_credVector.end(); iter++)
				{
					if (iter->m_connectionName.compare(connName) == 0)
					{
						QString errMsg;
						
						// make sure config isn't marked as volatile
						pConn->flags &= ~CONFIG_VOLATILE_CONN;
						
						// there shouldn't be a password saved, but if there is, clear it
						if (pConn->association.psk != NULL)
							free(pConn->association.psk);

						pConn->association.psk = _strdup(iter->m_password.toAscii().data());						
						
						// save off changes to config
						if (xsupgui_request_set_connection_config(pConn) == REQUEST_SUCCESS)
						{
							// tell everyone we changed the config
							m_pEmitter->sendConnConfigUpdate();
												
							// this may fail.  No need to prompt user if it does
							XSupWrapper::writeConfig();	
						}
						else
							QMessageBox::critical(NULL, tr("error"),tr("Unable to save your PSK password"));					
							
						m_credVector.erase(iter);
						break;					
					}
				}
			}
		}
		if (pConn != NULL)
			XSupWrapper::freeConfigConnection(&pConn);
	}							
	
	if (connName != NULL)
		free(connName);
}

void CredentialsManager::connectionDisconnected(const QString &intName)
{
	// since we can't get the connection name from the device, we'll have to just look at everything in the
	// vector and see which are bound to this adapter.  There should only be one entry per adapter, so
	// this should be a safe course of action
	
	if (m_credVector.empty() == false)
	{
		char *intDesc = NULL;
		int retval;
		
		retval = xsupgui_request_get_devdesc(intName.toAscii().data(), &intDesc);
		
		if (retval == REQUEST_SUCCESS && intDesc != NULL)
		{	
			QVector<CredentialsManager::CredData>::iterator iter;
			for (iter = m_credVector.begin(); iter != m_credVector.end(); iter++)
			{
				bool success;
				config_connection *pConn;
				
				success = XSupWrapper::getConfigConnection(iter->m_connectionName, &pConn);
				if (success == true && pConn != NULL)
				{
					if (strcmp(pConn->device, intDesc) == 0)
					{
						m_credVector.erase(iter);
						if (pConn != NULL)
							XSupWrapper::freeConfigConnection(&pConn);						
						break;
					}
				}
				if (pConn != NULL)
					XSupWrapper::freeConfigConnection(&pConn);
			}
		}
		if (intDesc != NULL)
			free(intDesc);
	}
}