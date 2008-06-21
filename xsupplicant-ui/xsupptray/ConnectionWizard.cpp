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

#include <QRadioButton>

#include "ConnectionWizard.h"
#include "WizardPages.h"
#include "FormLoader.h"
#include "Util.h"
#include "XSupWrapper.h"

ConnectionWizardData::ConnectionWizardData()
{
	// default to wired connection
	m_wireless = false;
	
	m_adapterDesc = "";
	
	// get distinct name
	m_connectionName = XSupWrapper::getUniqueConnectionName(QWidget::tr("New Connection"));
	
	m_networkName = "";
	m_hiddenNetwork = false;
	m_wirelessAssocMode = ConnectionWizardData::assoc_none;
	m_wirelessEncryptMeth = ConnectionWizardData::encrypt_TKIP;
	
	// default to 802.1X for wired
	m_wiredSecurity = true;
	
	// default to DHCP
	m_staticIP = false;
	
	// !!! need better defaults for these 
	m_IPAddress = "";
	m_netmask = "";
	m_gateway = "";
	m_primaryDNS = "";
	m_secondaryDNS = "";
	
	m_eapProtocol = ConnectionWizardData::eap_peap;
	m_outerIdentity = "";
	m_validateCert = true;
	m_innerProtocol = ConnectionWizardData::inner_mschapv2;
	m_serverCerts = QStringList();
	m_verifyCommonName = false;
	m_commonNames = QStringList();
}

ConnectionWizardData::~ConnectionWizardData()
{
	// nothing special to do. No pointers.
}

ConnectionWizard::ConnectionWizard(QWidget *parent, QWidget *parentWindow, Emitter *e)
	: QWidget(parent),
	m_pParent(parent),
	m_pParentWindow(parentWindow),
	m_pEmitter(e)
{
	int i;
	for (i=0; i<ConnectionWizard::pageLastPage; i++)
		m_wizardPages[i] = NULL;
	m_currentPage = pageNoPage;
}

ConnectionWizard::~ConnectionWizard(void)
{
	if (m_pCancelButton != NULL)
		Util::myDisconnect(m_pCancelButton, SIGNAL(clicked()), this, SLOT(cancelWizard()));
		
	if (m_pNextButton != NULL)
		Util::myDisconnect(m_pNextButton, SIGNAL(clicked()), this, SLOT(gotoNextPage()));
		
	if (m_pBackButton != NULL)
		Util::myDisconnect(m_pBackButton, SIGNAL(clicked()), this ,SLOT(gotoPrevPage()));
		
	if (m_pRealForm != NULL)
		Util::myDisconnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(cancelWizard()));		
		
	for (int i=0; i < ConnectionWizard::pageLastPage; i++)
	{
		delete m_wizardPages[i];
		m_wizardPages[i] = NULL;
	}
			
	if (m_pRealForm != NULL)
		delete m_pRealForm;
}

bool ConnectionWizard::create(void)
{
	return this->initUI();
}

bool ConnectionWizard::initUI(void)
{
	// load form
	m_pRealForm = FormLoader::buildform("ConnectionWizardWindow.ui", m_pParentWindow);
	if (m_pRealForm == NULL)
		return false;
	
	Qt::WindowFlags flags;
	
	// set window flags so not minimizeable and context help thingy is turned off
	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);	
	
	m_pCancelButton = qFindChild<QPushButton*>(m_pRealForm, "buttonCancel");
	m_pNextButton = qFindChild<QPushButton*>(m_pRealForm, "buttonNext");
	m_pBackButton = qFindChild<QPushButton*>(m_pRealForm, "buttonBack");
	m_pHeaderLabel = qFindChild<QLabel*>(m_pRealForm, "labelHeader");
	m_pStackedWidget = qFindChild<QStackedWidget*>(m_pRealForm, "stackedWidget");
	
	// dynamically populate text
	if (m_pCancelButton != NULL)
		m_pCancelButton->setText(tr("Cancel"));
		
	if (m_pNextButton != NULL)
		m_pNextButton->setText(tr("Next >"));
		
	if (m_pBackButton != NULL)
		m_pBackButton->setText(tr("Back"));
		
	if (m_pHeaderLabel != NULL)
		m_pHeaderLabel->setText(tr("Create New Connection"));
		
	// set up event-handling
	if (m_pCancelButton != NULL)
		Util::myConnect(m_pCancelButton, SIGNAL(clicked()), this, SLOT(cancelWizard()));
		
	if (m_pNextButton != NULL)
		Util::myConnect(m_pNextButton, SIGNAL(clicked()), this, SLOT(gotoNextPage()));
		
	if (m_pBackButton != NULL)
		Util::myConnect(m_pBackButton, SIGNAL(clicked()), this ,SLOT(gotoPrevPage()));
		
	if (m_pRealForm != NULL)
		Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(cancelWizard()));
		
	this->loadPages();
		
	return true;
}

void ConnectionWizard::show(void)
{
	if (m_pStackedWidget != NULL)
		m_pStackedWidget->setCurrentIndex(0);
	if (m_pRealForm != NULL)
		m_pRealForm->show();
}

bool ConnectionWizard::loadPages(void)
{
	if (m_pStackedWidget != NULL)
	{
		int i;
		
		// clear out any existing widgets in stack
		for (i=0; i<m_pStackedWidget->count(); i++)
		{
			QWidget *tmpWidget;
			m_pStackedWidget->setCurrentIndex(0);
			tmpWidget = m_pStackedWidget->currentWidget();
			m_pStackedWidget->removeWidget(tmpWidget);
			delete tmpWidget;
		}
		
		// make sure we don't have any page objects sticking around
		for (i=0; i<ConnectionWizard::pageLastPage; i++)
		{
			if (m_wizardPages[i] != NULL)
				delete m_wizardPages[i];
		}
		
		for (i=0; i<ConnectionWizard::pageLastPage; i++)
		{
			WizardPage *newPage;
			switch (i) {
				case ConnectionWizard::pageNetworkType:
					newPage = new WizardPageNetworkType(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageWiredSecurity:
					newPage = new WizardPageWiredSecurity(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageIPOptions:
					newPage = new WizardPageIPOptions(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageStaticIP:
					newPage = new WizardPageStaticIP(this, m_pStackedWidget);
					break;			
				case ConnectionWizard::pageFinishPage:
					newPage = new WizardPageFinished(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageWirelessNetwork:
					newPage = new WizardPageWirelessNetwork(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageWirelessInfo:
					newPage = new WizardPageWirelessInfo(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageDot1XProtocol:
					newPage = new WizardPageDot1XProtocol(this, m_pStackedWidget);
					break;
				case ConnectionWizard::pageDot1XInnerProtocol:
					newPage = new WizardPageDot1XInnerProtocol(this, m_pStackedWidget);
					break;	
				case ConnectionWizard::pageDot1XCert:
					newPage = new WizardPageDot1XCert(this, m_pStackedWidget);
					break;																													
				default:
					break;
			}
			if (newPage == NULL || newPage->create() == false || newPage->getWidget() == NULL)
			{
				// error creating page
				QMessageBox::critical(NULL,"Error Loading WizardPage", QString("There was an error loading wizard page: %1").arg(i));	
			}
			else
			{
				m_pStackedWidget->addWidget(newPage->getWidget());
				m_wizardPages[i] = newPage;
			}
		}
	}
	m_currentPage = ConnectionWizard::pageNoPage;
	return true;
}

void ConnectionWizard::gotoPage(ConnectionWizard::wizardPages newPageIdx)
{
	if (newPageIdx != ConnectionWizard::pageNoPage && m_wizardPages[newPageIdx] != NULL) 
	{
		if (m_pHeaderLabel != NULL)
		{
			QString headerString = tr("Create New Connection");
			QString pageHeader = m_wizardPages[newPageIdx]->getHeaderString();
			if (!pageHeader.isEmpty())
				headerString.append(" >> ").append(pageHeader);
			
			m_pHeaderLabel->setText(headerString);
		}
		
		m_wizardPages[newPageIdx]->init(m_connData);
		
		if (m_wizardPages[newPageIdx]->isFinalPage() == true)
			m_pNextButton->setText(tr("Finish"));
		else
			m_pNextButton->setText(tr("Next").append(" >"));
		
		m_pStackedWidget->setCurrentIndex(newPageIdx);
		
		if (m_pBackButton != NULL)
			m_pBackButton->setDisabled(m_wizardHistory.size() < 1);
			
		m_currentPage = newPageIdx;
		
		if (m_pNextButton != NULL)
			m_pNextButton->setDefault(true);
	}
}

void ConnectionWizard::gotoNextPage(void)
{
	wizardPages nextPage = pageNoPage;
	
	if (m_currentPage == pageNoPage)
		nextPage = pageNetworkType;
	else if (m_wizardPages[m_currentPage] != NULL)
	{	
		if (m_wizardPages[m_currentPage]->validate() == true)
		{
			m_connData = m_wizardPages[m_currentPage]->wizardData();
			
			// check if we're at end of wizard (now that we know data is valid and we have it)
			if (m_wizardPages[m_currentPage]->isFinalPage())
			{
				// early returns are ugly, but quick and dirty wins race
				this->finishWizard();
				return;
			}			
			
			nextPage = this->getNextPage();
		}
		else
			nextPage = pageNoPage;
	}
	
	if (m_currentPage != pageNoPage && nextPage != pageNoPage)
		m_wizardHistory.push(m_currentPage);
			
	if (nextPage != pageNoPage)
		this->gotoPage(nextPage);
}

void ConnectionWizard::gotoPrevPage(void)
{
	// check if anything in stack
	if (m_wizardHistory.isEmpty())
		return;
		
	wizardPages prevPage = m_wizardHistory.pop();
	
	// store off data for when they return.  Don't validate tho
	m_connData = m_wizardPages[m_currentPage]->wizardData();
	this->gotoPage(prevPage);
}

void ConnectionWizard::init(void)
{
	// start with fresh connection data
	m_connData = ConnectionWizardData();
	
	// load up first page
	m_currentPage = pageNoPage;
	this->gotoNextPage();
}

void ConnectionWizard::edit(const ConnectionWizardData &connData)
{
	m_connData = connData;
	
	m_currentPage = pageNoPage;
	this->gotoNextPage();
}

void ConnectionWizard::cancelWizard(void)
{
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
	emit cancelled();
}

void ConnectionWizard::finishWizard(void)
{
	bool success;
	if (m_pRealForm != NULL)
		m_pRealForm->hide();
	success = this->saveConnectionData();
	emit finished(success);
}

// static func = no access to member variables, no "this"
bool SupplicantProfilesToWizardData(config_connection const * const pConfig, config_profiles const * const pProfile, config_trusted_server const * const pServer, ConnectionWizardData **pWizData)
{
	if (pWizData == NULL)
		return false;	// nothing we can do
		
	*pWizData = NULL;
	
	if (pConfig == NULL && pProfile == NULL && pServer == NULL)
		return false;  // no data to convert
	return true;
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

bool ConnectionWizardData::toProfileEAPMSCHAPv2InnerProtocol(config_profiles * const pProfile)
{
	bool success = true;
	
	if (pProfile == NULL)
		return false;
	
	if (m_innerProtocol == ConnectionWizardData::inner_eap_mschapv2)
	{
		config_eap_method *myeap = NULL;
		config_eap_mschapv2 *mscv2 = NULL;
		config_eap_peap *mypeap = NULL;

		mypeap = (config_eap_peap *)pProfile->method->method_data;
		if (mypeap != NULL)
		{
			if (mypeap->phase2 == NULL)
			{
				mypeap->phase2 = (config_eap_method *)malloc(sizeof(struct config_eap_method));
				if (mypeap->phase2 == NULL) 
					success = false;
				else
					memset(mypeap->phase2, 0x00, sizeof(struct config_eap_method));
			}
			
			myeap = (config_eap_method *)mypeap->phase2;
			
			if (myeap != NULL)
			{
				if ((myeap->method_num != EAP_TYPE_MSCHAPV2) && (myeap->method_data != NULL))
				{
					XSupWrapper::freeConfigEAPMethod((config_eap_method **)&mypeap->phase2);
				}

				if (myeap->method_data == NULL)
				{
					myeap->method_data = (config_eap_mschapv2 *)malloc(sizeof(config_eap_mschapv2));
					if (myeap->method_data == NULL) 
						success = false;
					else
						memset(myeap->method_data, 0x00, sizeof(struct config_eap_mschapv2));

					mscv2 = (config_eap_mschapv2 *)myeap->method_data;
					
					if (mscv2 != NULL)
					{
						// Set some defaults.
						mscv2->ias_quirk = FALSE;
						mscv2->nthash = NULL;
						mscv2->password = NULL;
					}
				}

				myeap->method_num = EAP_TYPE_MSCHAPV2;
				mscv2 = (config_eap_mschapv2 *)myeap->method_data;
				if (mscv2 != NULL && mscv2->password != NULL)
				{
					free(mscv2->password);
					mscv2->password = NULL;
				}
			}
		}
		else
			success = false;
	}
	else
		success = false;
	
	return success;
}

bool ConnectionWizardData::toProfileEAP_GTCInnerProtocol(config_profiles * const pProfile)
{
	bool success = true;
	
	if (pProfile == NULL)
		return false;
		
	if (m_innerProtocol == ConnectionWizardData::inner_eap_gtc)
	{
		config_eap_peap *mypeap = NULL;

		mypeap = (config_eap_peap *)pProfile->method->method_data;
		if (mypeap != NULL)
		{
			config_eap_method *myeap = NULL;
			if (mypeap->phase2 == NULL)
			{
				mypeap->phase2 = (config_eap_method *)malloc(sizeof(config_eap_method));
				if (mypeap->phase2 == NULL) 
					success = false;
				else
					memset(mypeap->phase2, 0x00, sizeof(config_eap_method));
			}

			myeap = (config_eap_method *)mypeap->phase2;
			
			if (myeap != NULL)
			{
				if ((myeap->method_num != EAP_TYPE_GTC) && (myeap->method_data != NULL))
				{
					XSupWrapper::freeConfigEAPMethod((config_eap_method **)&mypeap->phase2);
				}

				if (myeap->method_data == NULL)
				{
					myeap->method_data = (struct config_pwd_only *)malloc(sizeof(config_pwd_only));
					if (myeap->method_data == NULL) 
						success = false;
					else
					{
						// Set everything to defaults.
						memset(myeap->method_data, 0x00, sizeof(config_pwd_only));
					}
				}

				myeap->method_num = EAP_TYPE_GTC;

				config_pwd_only *pwdonly = NULL;
				pwdonly = (config_pwd_only *)myeap->method_data;
				if (pwdonly != NULL)
				{
					if (pwdonly->password != NULL)
					{
						free(pwdonly->password);
						pwdonly->password = NULL;
					}				
				}
				else
					success = false;
			}
			else
				success = false;
		}
		else
			success = false;
	}
	else
		success = false;
	
	return success;
}

bool ConnectionWizardData::toProfileEAP_MD5Protocol(config_profiles * const pProfile)
{
	bool success  = true;

	if (pProfile->method == NULL)
	{
		pProfile->method = (config_eap_method *)malloc(sizeof(config_eap_method));
		if (pProfile->method == NULL)
			success = false;
		else
			memset(pProfile->method, 0x00, sizeof(config_eap_method));

		if (pProfile->method != NULL)
		{
			pProfile->method->method_num = EAP_TYPE_MD5;

			pProfile->method->method_data = (config_pwd_only *)malloc(sizeof(config_pwd_only));
			if (pProfile->method->method_data == NULL)
				success = false;
			else
				memset(pProfile->method->method_data, 0x00, sizeof(config_pwd_only));
		}
	}

	if (pProfile->method->method_data != NULL)
	{
		config_pwd_only *mydata = NULL;
		mydata = (config_pwd_only *)pProfile->method->method_data;
		
		if (mydata->password != NULL)
		{
			free(mydata->password);
			mydata->password = NULL;
		}
	}
	
	if (pProfile->identity != NULL)
	{
		free(pProfile->identity);
		pProfile->identity = NULL;
	}

	return success;
}

bool ConnectionWizardData::toProfileEAP_MSCHAPProtocol(config_profiles * const pProfile)
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
				config_eap_peap *mypeap = NULL;
				
				memset(pProfile->method, 0x00, sizeof(config_eap_method));
				pProfile->method->method_num = EAP_TYPE_PEAP;
				if (pProfile->method->method_data == NULL)
				{
					pProfile->method->method_data = malloc(sizeof(config_eap_peap));
					if (pProfile->method->method_data == NULL)
						success = false;
					else
					{
						memset(pProfile->method->method_data, 0x00, sizeof(config_eap_peap));

						mypeap = (config_eap_peap *)pProfile->method->method_data;
						mypeap->force_peap_version = 0xff;
					}
				}
				else
				{
					mypeap = (config_eap_peap *)pProfile->method->method_data;
				}
				
				if (mypeap != NULL)
				{
					// ensure no username/password
					if (mypeap->identity != NULL)
					{
						free(mypeap->identity);
						mypeap->identity = NULL;
					}
					
					// server cert
					if (m_validateCert == true)
					{
						mypeap->validate_cert = TRUE;

						if (mypeap->trusted_server != NULL)
							free(mypeap->trusted_server);

						//mypeap->trusted_server = _strdup(m_pTrustedServerCombo->currentText().toAscii());
					}
					else
					{
						mypeap->validate_cert = FALSE;

						if (mypeap->trusted_server != NULL)
						{
							free(mypeap->trusted_server);
							mypeap->trusted_server = NULL;
						}
					}
					
					// inner protocol
					if (m_innerProtocol == ConnectionWizardData::inner_eap_mschapv2)
						success = this->toProfileEAPMSCHAPv2InnerProtocol(pProfile);
					else if (m_innerProtocol == ConnectionWizardData::inner_eap_gtc)
						success = this->toProfileEAP_GTCInnerProtocol(pProfile);
					else
					{
						// invalid value
					}
				}
				else
					success = false;
			}
		}
		else
		{
			// unexpected
		}
	}
	else
		success = false;
		
	return success;	
}

bool ConnectionWizardData::toProfileData(config_profiles **retProfile)
{
	bool success;
	
	config_profiles *pProfile;
	
	// can't do anything
	if (retProfile == NULL)
		return false;
		
	pProfile = NULL;
		
	// if dot1X, create profile
	if ((m_wireless == false && m_wiredSecurity == true)
		|| (m_wireless == true 
		&& (m_wirelessAssocMode == ConnectionWizardData::assoc_WPA_ENT
		|| m_wirelessAssocMode == ConnectionWizardData::assoc_WPA2_ENT)))
	{
		// create profile
		QString profileName = m_connectionName;
		profileName.append(QWidget::tr("_Profile"));
		success = XSupWrapper::createNewProfile(profileName,&pProfile);
		*retProfile = pProfile;
		if (success == true && pProfile != NULL)
		{
			switch (m_eapProtocol)
			{
				case ConnectionWizardData::eap_peap:
					success = this->toProfileEAP_MSCHAPProtocol(pProfile);					
					break;
				case ConnectionWizardData::eap_ttls:
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
	
	return success;
}

bool ConnectionWizardData::toConnectionData(config_connection **retConnection)
{
	config_connection *pConn;
	bool success = true;
	
	// can't do anything
	if (retConnection == NULL)
		return false;
		
	pConn = NULL;
		
	success = XSupWrapper::createNewConnection(m_connectionName, &pConn) == true;
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
					break;
				case ConnectionWizardData::assoc_WPA_ENT:
					pConn->association.association_type = ASSOC_WPA;
					pConn->association.auth_type = AUTH_EAP;				
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
		
		if (m_staticIP == true)
		{
			pConn->ip.type = CONFIG_IP_USE_STATIC;
			pConn->ip.ipaddr = _strdup(m_IPAddress.toAscii().data());
			pConn->ip.gateway = _strdup(m_gateway.toAscii().data());
			pConn->ip.netmask = _strdup(m_netmask.toAscii().data());
			pConn->ip.dns1 = _strdup(m_primaryDNS.toAscii().data());
			pConn->ip.dns2 = _strdup(m_secondaryDNS.toAscii().data());
		}
		else
		{
			pConn->ip.type = CONFIG_IP_USE_DHCP;
			pConn->ip.renew_on_reauth = TRUE; // correct default?
		}
	}
	
	return success;
}

// static func = no access to member variables, no "this"
bool ConnectionWizardData::toSupplicantProfiles(config_connection **retConnection, config_profiles **retProfile, config_trusted_server **retServer)
{
	bool success;
	config_connection *pConn = NULL;
	config_profiles *pProfile = NULL;
	config_trusted_server *pServer = NULL;
	
	success = this->toProfileData(&pProfile);
	success = this->toConnectionData(&pConn) == true && success == true;
	
	if (pProfile != NULL && QString(pProfile->name).isEmpty() == false)
	{
		if (pConn->profile != NULL)
			free(pConn->profile);
		pConn->profile = _strdup(pProfile->name);
	}
	
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
			pConn = NULL;
		}
		if (pProfile != NULL)
		{
			XSupWrapper::freeConfigProfile(&pProfile);
			pProfile = NULL;
		}
		if (pServer != NULL)
		{
			xsupgui_request_free_trusted_server_config(&pServer);
			pServer = NULL;
		}
	}	
		
	// what do we consider a "success" to pass down?
	return success;
}

bool ConnectionWizard::saveConnectionData(void)
{
	bool success;
	config_connection *pConfig = NULL;
	config_profiles *pProfile = NULL;
	config_trusted_server *pServer = NULL;
	
	success = m_connData.toSupplicantProfiles(&pConfig, &pProfile, &pServer);
	
	// we at least expect a pointer to connection profile
	if (success == true && pConfig != NULL)
	{
		int retVal;
		
		if (pServer != NULL)
		{
			retVal = xsupgui_request_set_trusted_server_config(pServer);
			success = retVal == REQUEST_SUCCESS;
			if (retVal == REQUEST_SUCCESS)
				success = true;
			else
				success = false;
		}
		
		if (pProfile != NULL)
		{
			retVal = xsupgui_request_set_profile_config(pProfile);
			if (retVal == REQUEST_SUCCESS)
				m_pEmitter->sendProfConfigUpdate();
			else
				success = false;
		}
		
		retVal = xsupgui_request_set_connection_config(pConfig);
		if (retVal == REQUEST_SUCCESS)
		{
			// tell everyone we changed the config
			m_pEmitter->sendConnConfigUpdate();
		}
		else
			success = false;
		
		XSupWrapper::writeConfig();
	}

	if (pConfig != NULL)
		XSupWrapper::freeConfigConnection(&pConfig);
	if (pProfile != NULL)
		XSupWrapper::freeConfigProfile(&pProfile);
	if (pServer != NULL)
		xsupgui_request_free_trusted_server_config(&pServer);
	return success;
}


ConnectionWizard::wizardPages ConnectionWizard::getNextPage(void)
{
	wizardPages nextPage = pageNoPage;
	
	switch (m_currentPage)
	{
		case ConnectionWizard::pageNoPage:
			nextPage = ConnectionWizard::pageNetworkType;
			break;
			
		case ConnectionWizard::pageNetworkType:
			// jking - TODO: need to go to adapter selection page if more than one adapter!!!
			if (m_connData.m_wireless == true)
				nextPage = ConnectionWizard::pageWirelessNetwork;
			else
				nextPage =  ConnectionWizard::pageWiredSecurity;
			break;
			
		case pageWiredSecurity:
			if (m_connData.m_wiredSecurity == true)
				nextPage = ConnectionWizard::pageDot1XProtocol;
			else
				nextPage = ConnectionWizard::pageIPOptions;
			break;
			
		case pageWirelessNetwork:
			if (m_connData.m_otherNetwork == true)
				nextPage = ConnectionWizard::pageWirelessInfo;
			else
			{
				if (m_connData.m_wirelessAssocMode == ConnectionWizardData::assoc_WPA_ENT || m_connData.m_wirelessAssocMode == ConnectionWizardData::assoc_WPA2_ENT)
					nextPage = ConnectionWizard::pageDot1XProtocol;
				else
					nextPage = ConnectionWizard::pageIPOptions;				
			}	
			break;
			
		case pageWirelessInfo:
			if (m_connData.m_wirelessAssocMode == ConnectionWizardData::assoc_WPA_ENT || m_connData.m_wirelessAssocMode == ConnectionWizardData::assoc_WPA2_ENT)
				nextPage = ConnectionWizard::pageDot1XProtocol;
			else
				nextPage = ConnectionWizard::pageIPOptions;			
			break;
			
		case pageIPOptions:
			if (m_connData.m_staticIP == true)
				nextPage = ConnectionWizard::pageStaticIP;
			else
				nextPage = ConnectionWizard::pageFinishPage;
			break;
			
		case pageStaticIP:
			nextPage = ConnectionWizard::pageFinishPage;
			break;
			
		case pageDot1XProtocol:
			if (m_connData.m_eapProtocol == ConnectionWizardData::eap_md5)
				nextPage = ConnectionWizard::pageFinishPage;
			else
				nextPage = ConnectionWizard::pageDot1XInnerProtocol;
			break;
			
		case pageDot1XInnerProtocol:
			if (m_connData.m_validateCert == true)
				nextPage = ConnectionWizard::pageDot1XCert;
			else
				nextPage = ConnectionWizard::pageFinishPage;
			break;
			
		case pageDot1XCert:
			nextPage = ConnectionWizard::pageFinishPage;
			break;
			
		case pageFinishPage:
			nextPage = pageNoPage;
			break;
			
		default:
			nextPage = pageNoPage;
			break;
	}
	return nextPage;
}