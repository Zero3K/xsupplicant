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
    
#ifndef _XSUPWRAPPER_H_
#define _XSUPWRAPPER_H_
    
#include <QString>
#include <QStringList>
#include <QVector>
extern "C"  {
	
#include "libxsupconfig/xsupconfig_structs.h"
}   class XSupWrapper  {
 public:static bool createNewConnection(const QString & suggName,
					 config_connection ** newConnection,
					 bool forceName = false);
	static bool getConfigConnection(unsigned char config_type,
					 const QString & connName,
					 config_connection ** pConfig);
	static void freeConfigConnection(config_connection ** p);
	static bool deleteConnectionConfig(unsigned char config_type,
					    const QString & connName);
	static bool writeConfig(unsigned char config_type);
	static QString getUniqueConnectionName(const QString & suggestedName);
	static QString getUniqueProfileName(const QString & suggestedName);
	static QString getUniqueServerName(const QString & suggestedName);
	static bool createNewProfile(const QString & suggName,
				      config_profiles ** newProfile,
				      bool forceName = false);
	static bool getConfigProfile(unsigned char config_type,
				      const QString & profileName,
				      config_profiles ** pProfile);
	static void freeConfigProfile(config_profiles ** p);
	static bool isDefaultWiredConnection(const QString & connName);
	static bool createNewTrustedServer(const QString & suggName,
					    config_trusted_server ** newServer,
					    bool forceName = false);
	static bool getConfigServer(unsigned char config_type,
				     const QString & serverName,
				     config_trusted_server ** pServer);
	static void freeConfigServer(config_trusted_server ** p);
	static bool isProfileInUse(const QString & profileName);
	static bool getTrustedServerForProfile(unsigned char config_type,
						const QString & profileName,
						config_trusted_server **
						pServer,
						unsigned char *inconfig);
	static bool deleteProfileConfig(unsigned char config_type,
					 const QString & profileName);
	static bool deleteServerConfig(unsigned char config_type,
					const QString & serverName);
	static bool isTrustedServerInUse(const QString & serverName);
	static QStringList getWirelessInterfaceList(void);
	static bool setProfileUsername(unsigned char config_type,
					const QString & profileName,
					const QString & username);
	static bool setProfilePassword(unsigned char config_type,
					const QString & profileName,
					const QString & password);
	static void getAndDisplayErrors(void);
	static QVector < QString > getWirelessAdapters(void);	// returns descriptions of wireless adapters in system
	static QVector < QString > getWiredAdapters(void);	// returns descriptions of wired adapters in system
	static QVector < QString > getConnectionListForAdapter(bool isWireless);
	static bool isConnectionActive(const QString & interfaceName,
					const QString & connectionName,
					bool isWireless);
	static int connectToConnection(const QString & interfaceName,
					const QString & connectionName);
};


#endif	/*  */
