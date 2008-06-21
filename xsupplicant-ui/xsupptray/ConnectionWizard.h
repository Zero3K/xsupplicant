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

#ifndef _CONNECTIONWIZARD_H_
#define _CONNECTIONWIZARD_H_

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QStackedWidget>
#include <QStack>

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

class WizardPage;
class Emitter;

class ConnectionWizardData
{
public:
	ConnectionWizardData();
	~ConnectionWizardData();
	
public:
	bool toSupplicantProfiles(config_connection **, config_profiles **, config_trusted_server **);
	
private:
	bool toProfileEAP_GTCInnerProtocol(config_profiles * const pProfile);
	bool toProfileEAPMSCHAPv2InnerProtocol(config_profiles * const pProfile);
	bool toProfileEAP_MSCHAPProtocol(config_profiles * const);
	bool toProfileEAP_MD5Protocol(config_profiles * const);
	bool toProfileOuterIdentity(config_profiles * const);
	bool toProfileData(config_profiles **);
	bool toConnectionData(config_connection **);

public:

	// general settings
	bool m_wireless;
	QString m_adapterDesc;
	QString m_connectionName;
	
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
	bool m_validateCert;
	Dot1XInnerProtocol m_innerProtocol;
	QStringList m_serverCerts;
	bool m_verifyCommonName;
	QStringList m_commonNames;
};

class ConnectionWizard : public QWidget
{
	Q_OBJECT
	
public:
	ConnectionWizard(QWidget *parent, QWidget *parentWindow, Emitter *e);
	~ConnectionWizard(void);
	bool create(void);
	
	// set up to create a new connection, with defaults
	void init(void);
	
	// edit an existing connection
	void edit(const ConnectionWizardData &);
	
	void show(void);
	
	static bool SupplicantProfilesToWizardData(config_connection const * const pConfig, config_profiles const * const pProfile, config_trusted_server const * const pServer, ConnectionWizardData **);
	
	typedef enum {
		pageNoPage=-1,
		pageNetworkType=0,
		pageWiredSecurity,
		pageWirelessNetwork,
		pageWirelessInfo,
		pageIPOptions,
		pageStaticIP,
		pageDot1XProtocol,
		pageDot1XInnerProtocol,
		pageDot1XCert,
		pageFinishPage,
		pageLastPage,
	} wizardPages;
	
signals:
	void cancelled(void);
	void finished(bool);
	
private:
	bool initUI(void);
	bool loadPages(void);
	void gotoPage(wizardPages newPageIdx);
	void finishWizard(void);
	bool saveConnectionData(void);
	wizardPages getNextPage(void);
	
private slots:
	void gotoNextPage(void);
	void gotoPrevPage(void);
	void cancelWizard(void);
	
private:
	QWidget *m_pParent;
	QWidget *m_pParentWindow;
	QWidget *m_pRealForm;
	QPushButton *m_pCancelButton;
	QPushButton *m_pBackButton;
	QPushButton *m_pNextButton;
	QLabel *m_pHeaderLabel;
	QStackedWidget *m_pStackedWidget;
	
	WizardPage *m_wizardPages[pageLastPage];
	ConnectionWizardData m_connData;
	Emitter *m_pEmitter;
	
	QStack<wizardPages> m_wizardHistory;
	wizardPages m_currentPage;
};
#endif