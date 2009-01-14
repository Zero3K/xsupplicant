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

#ifndef _CREDENTIALSMANAGER_H_
#define _CREDENTIALSMANAGER_H_

#include <QWidget>
#include <QVector>
#include <QString>

class Emitter;

class CredentialsManager : public QWidget
{
	Q_OBJECT

public:

	CredentialsManager(Emitter *e);
	~CredentialsManager();
	void storeCredentials(unsigned char config_type, const QString &connectionName, const QString &adaptDesc, const QString &userName, const QString &password);

private slots:
	void handleStateChange(const QString &intName, int sm, int, int newstate, unsigned int);
	void pskSuccess(const QString &);
	void connectionDisconnected(const QString &);
	
private:

	class CredData
	{
	public:
		CredData() {};
		CredData(const QString &connectionName, const QString &adapterDesc, const QString &userName, const QString &password)
			: m_connectionName(connectionName), m_adapterDesc(adapterDesc), m_userName(userName), m_password(password) {};
	public:
		QString m_connectionName;
		QString m_adapterDesc;
		QString m_userName;
		QString m_password;
	};
	
	QVector<CredentialsManager::CredData> m_credVector;
	Emitter *m_pEmitter;
};

#endif