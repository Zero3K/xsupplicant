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
#include "Util.h"
#include "helpbrowser.h"
#include "ConfigProfileTabs.h"
#include "TabPlugins.h"

#ifdef WIN32
#include <windows.h>
#endif // WIN32

ConfigProfileTabs::ConfigProfileTabs(QWidget *pRealWidget, XSupCalls *pSupplicant, config_profiles *pProf, QWidget *parent, UIPlugins *pPlugins):
	m_pProfile(pProf), m_pParent(parent), m_pRealWidget(pRealWidget), m_pSupplicant(pSupplicant), m_pPlugins(pPlugins)
{
	m_bDataChanged = false;
	m_bPwdShowing = false;
	m_bConnected = false;
	m_bNewProfile = false;
}

ConfigProfileTabs::~ConfigProfileTabs()
{
	if (m_bConnected)
	{ 
	 // Hook up the signal that data has changed to the slot to update the value.
	 Util::myDisconnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));
	 Util::myDisconnect(this, SIGNAL(signalDataChanged()), m_pParent, SLOT(slotDataChanged()));

	 // Hook up the show/hide button on the User Credentials page
	 Util::myDisconnect(m_pShowBtn, SIGNAL(clicked()), this, SLOT(showBtnClicked()));

	 // Hook up the validate servers checkbox.
	 Util::myDisconnect(m_pValidateServer, SIGNAL(stateChanged(int)), this, SLOT(slotValidateServerChanged(int)));
	 Util::myDisconnect(m_pValidateServer, SIGNAL(stateChanged(int)), this, SIGNAL(signalDataChanged()));

	 // Hook up the outer identity radio buttons.
	 Util::myDisconnect(m_pUseThisIdent, SIGNAL(toggled(bool)), this, SLOT(slotPickIdentity(bool)));
	 Util::myDisconnect(m_pUseThisIdent, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
	 Util::myDisconnect(m_pPhase1Ident, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	 Util::myDisconnect(m_pAnonIdent, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));

	 // Hook up the inner identity radio buttons.
	 Util::myDisconnect(m_pPromptForUPW, SIGNAL(toggled(bool)), this, SLOT(slotSetPromptForUPW(bool)));
	 Util::myDisconnect(m_pPromptForPWD, SIGNAL(toggled(bool)), this, SLOT(slotSetPromptForPWD(bool)));
	 Util::myDisconnect(m_pDontPrompt, SIGNAL(toggled(bool)), this, SLOT(slotDontPrompt(bool)));

	 Util::myDisconnect(m_pPromptForUPW, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
 	 Util::myDisconnect(m_pPromptForPWD, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
	 Util::myDisconnect(m_pDontPrompt, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));

	 Util::myDisconnect(m_pUsername, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	 Util::myDisconnect(m_pPassword, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));

 	 Util::myDisconnect(m_pInnerMethod, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	 Util::myDisconnect(m_pTrustedServerCombo, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	 Util::myDisconnect(m_pTrustedServerCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotDifferentServerSelected(int)));	

	 //Util::myDisconnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));

	}
}

bool ConfigProfileTabs::checkPwdSettings()
{
	if ((m_pPromptForPWD->isChecked() || m_pDontPrompt->isChecked()) && (m_pUsername->text() == ""))
	{
		QMessageBox::critical(this, tr("Configuration Error"), tr("You have selected not to prompt for a Username, but you have not provided one."));
		return false;
	}

	if (m_pDontPrompt->isChecked() && (m_pPassword->text() == ""))
	{
		QMessageBox::critical(this, tr("Configuration Error"), tr("You have selected not to prompt for a password, but you have not provided one."));
		return false;
	}

	return true;
}

bool ConfigProfileTabs::saveEAPMD5Data()
{
	struct config_pwd_only *mydata = NULL;

	if (checkPwdSettings() != true) return false;

	if (m_pProfile->method == NULL)
	{
		m_pProfile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
		if (m_pProfile->method == NULL)
		{
			QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store the EAP method data."));
			return false;
		}

		memset(m_pProfile->method, 0x00, sizeof(struct config_eap_method));

		m_pProfile->method->method_num = EAP_TYPE_MD5;

		m_pProfile->method->method_data = (struct config_pwd_only *)malloc(sizeof(struct config_pwd_only));
		if (m_pProfile->method->method_data == NULL)
		{
			QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store the EAP method data."));
			return false;
		}

		memset(m_pProfile->method->method_data, 0x00, sizeof(struct config_pwd_only));
	}

	mydata = (struct config_pwd_only *)m_pProfile->method->method_data;
	
	if (mydata->password != NULL)
	{
		free(mydata->password);
		mydata->password = NULL;
	}

	// Only reset the password if there is something to set.
	if (m_pPassword->text() != "")
	{
		mydata->password = _strdup(m_pPassword->text().toAscii());
	}

	if (m_pProfile->identity != NULL)
	{
		free(m_pProfile->identity);
		m_pProfile->identity = NULL;
	}

	m_pProfile->identity = _strdup(m_pUsername->text().toAscii());

	return true;
}

void ConfigProfileTabs::setIdentity()
{
	if (m_pProfile->identity != NULL)
	{
		free(m_pProfile->identity);
		m_pProfile->identity = NULL;
	}

	if (m_pUseThisIdent->isChecked())
	{
		// Need to read the value from the identity field.
		if (m_pPhase1Ident->text() != "")
		{
			m_pProfile->identity = _strdup(m_pPhase1Ident->text().toAscii());
		}
	}
	else
	{
		// Need to populate the identity field with anonymous.
		m_pProfile->identity = _strdup("anonymous");
	}
}

bool ConfigProfileTabs::saveEAPTTLSData()
{
	struct config_eap_ttls *myttls = NULL;
	struct config_eap_method *myeap = NULL;

	if (m_pProfile->method == NULL)
	{
		m_pProfile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
		if (m_pProfile->method == NULL)
		{
			QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory needed to save this profile."));
			return false;
		}

		memset(m_pProfile->method, 0x00, sizeof(struct config_eap_method));
		m_pProfile->method->method_num = EAP_TYPE_TTLS;
	}

	if (m_pProfile->method->method_data == NULL)
	{
		m_pProfile->method->method_data = malloc(sizeof(struct config_eap_ttls));
		if (m_pProfile->method->method_data == NULL)
		{
			QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory needed to save this profile."));
			return false;
		}

		memset(m_pProfile->method->method_data, 0x00, sizeof(struct config_eap_ttls));
	}

	myttls = (struct config_eap_ttls *)m_pProfile->method->method_data;

	if (checkPwdSettings() != true) return false;

	setIdentity();

	if (m_pUsername->text() != "")
	{
		if (myttls->inner_id != NULL) free(myttls->inner_id);
		myttls->inner_id = _strdup(m_pUsername->text().toAscii());
	}
	else
	{
		if (myttls->inner_id != NULL) free(myttls->inner_id);
		myttls->inner_id = NULL;
	}

	if (m_pValidateServer->isChecked() == true)
	{
		myttls->validate_cert = TRUE;

		if (myttls->trusted_server != NULL)
		{
			free(myttls->trusted_server);
			myttls->trusted_server = NULL;
		}

		if (m_pTrustedServerCombo->currentIndex() > 0)
		{
			myttls->trusted_server = _strdup(m_pTrustedServerCombo->currentText().toAscii());
		}
	}
	else
	{
		myttls->validate_cert = FALSE;

		if (myttls->trusted_server != NULL)
		{
			free(myttls->trusted_server);
			myttls->trusted_server = NULL;
		}
	}

	// Determine the inner method in use...
	if (m_pInnerMethod->currentText() == "PAP")
	{
		if (myttls->phase2_type != TTLS_PHASE2_PAP) 
		{
			freeTTLSInner(myttls);
		}

		myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_PAP;

		if (m_pPassword->text() != "")
		{
			if (myttls->phase2_data == NULL)
			{
				myttls->phase2_data = (struct config_pwd_only *)malloc(sizeof(struct config_pwd_only));
				if (myttls->phase2_data == NULL)
				{
					QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store user's password."));
					return false;
				}

				memset(myttls->phase2_data, 0x00, sizeof(struct config_pwd_only));
			}

			((struct config_pwd_only *)(myttls->phase2_data))->password = _strdup(m_pPassword->text().toAscii());
		}
		else
		{
			if (myttls->phase2_data != NULL)
			{
				free(((struct config_pwd_only *)(myttls->phase2_data))->password);
				((struct config_pwd_only *)(myttls->phase2_data))->password = NULL;
			}
		}
	}
	else if (m_pInnerMethod->currentText() == "CHAP")
	{
		if (myttls->phase2_type != TTLS_PHASE2_CHAP) 
		{
			freeTTLSInner(myttls);
		}

		myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_CHAP;

		if (m_pPassword->text() != "")
		{
			if (myttls->phase2_data == NULL)
			{
				myttls->phase2_data = (struct config_pwd_only *)malloc(sizeof(struct config_pwd_only));
				if (myttls->phase2_data == NULL)
				{
					QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store user's password."));
					return false;
				}

				memset(myttls->phase2_data, 0x00, sizeof(struct config_pwd_only));
			}

			((struct config_pwd_only *)(myttls->phase2_data))->password = _strdup(m_pPassword->text().toAscii());
		}
		else
		{
			if (myttls->phase2_data != NULL)
			{
				free(((struct config_pwd_only *)(myttls->phase2_data))->password);
				((struct config_pwd_only *)(myttls->phase2_data))->password = NULL;
			}
		}
	}
	else if (m_pInnerMethod->currentText() == "MS-CHAP")
	{
		if (myttls->phase2_type != TTLS_PHASE2_MSCHAP) 
		{
			freeTTLSInner(myttls);
		}

		myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_MSCHAP;

		if (m_pPassword->text() != "")
		{
			if (myttls->phase2_data == NULL)
			{
				myttls->phase2_data = (struct config_pwd_only *)malloc(sizeof(struct config_pwd_only));
				if (myttls->phase2_data == NULL)
				{
					QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store user's password."));
					return false;
				}

				memset(myttls->phase2_data, 0x00, sizeof(struct config_pwd_only));
			}

			((struct config_pwd_only *)(myttls->phase2_data))->password = _strdup(m_pPassword->text().toAscii());
		}
		else
		{
			if (myttls->phase2_data != NULL)
			{
				free(((struct config_pwd_only *)(myttls->phase2_data))->password);
				((struct config_pwd_only *)(myttls->phase2_data))->password = NULL;
			}
		}
	}
	else if (m_pInnerMethod->currentText() == "MS-CHAPv2")
	{
		if (myttls->phase2_type != TTLS_PHASE2_MSCHAPV2) 
		{
			freeTTLSInner(myttls);
		}

		myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_MSCHAPV2;

		if (m_pPassword->text() != "")
		{
			if (myttls->phase2_data == NULL)
			{
				myttls->phase2_data = (struct config_pwd_only *)malloc(sizeof(struct config_pwd_only));
				if (myttls->phase2_data == NULL)
				{
					QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store user's password."));
					return false;
				}

				memset(myttls->phase2_data, 0x00, sizeof(struct config_pwd_only));
			}

			((struct config_pwd_only *)(myttls->phase2_data))->password = _strdup(m_pPassword->text().toAscii());
		}
		else
		{
			if (myttls->phase2_data != NULL)
			{
				free(((struct config_pwd_only *)(myttls->phase2_data))->password);
				((struct config_pwd_only *)(myttls->phase2_data))->password = NULL;
			}
		}
	}
	else if (m_pInnerMethod->currentText() == "EAP-MD5")
	{
		if (myttls->phase2_type != TTLS_PHASE2_EAP) 
		{
			freeTTLSInner(myttls);
			myttls->phase2_data = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
			if (myttls->phase2_data == NULL)
			{
				QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store TTLS-EAP data."));
				return false;
			}

			memset(myttls->phase2_data, 0x00, sizeof(struct config_eap_method));

			myeap = (struct config_eap_method *)myttls->phase2_data;
			myeap->method_num = EAP_TYPE_MD5;

			myeap->method_data = (struct config_pwd_only *)malloc(sizeof(struct config_pwd_only));
			if (myeap->method_data == NULL)
			{
				QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store TTLS-EAP data."));
				return false;
			}

			memset(myeap->method_data, 0x00, sizeof(struct config_pwd_only));
		}

		myttls->phase2_type = (ttls_phase2_type)TTLS_PHASE2_EAP;
		myeap = (struct config_eap_method *)myttls->phase2_data;

		if (m_pPassword->text() != "")
		{
			((struct config_pwd_only *)(myeap->method_data))->password = _strdup(m_pPassword->text().toAscii());
		}
		else
		{
			if (((struct config_pwd_only *)(myeap->method_data))->password != NULL)
			{
				free(((struct config_pwd_only *)(myeap->method_data))->password);
				((struct config_pwd_only *)(myeap->method_data))->password = NULL;
			}
		}
	}
	else
	{
		QMessageBox::critical(this, tr("Invalid Phase 2 Method"), tr("The phase 2 method selected isn't known as a valid TTLS phase 2 method.  Please select a different one, and try again."));
		return false;
	}

	return true;
}

void ConfigProfileTabs::freeTTLSInner(struct config_eap_ttls *ttlsdata)
{
	if (ttlsdata->phase2_data == NULL) return;  // Nothing to do.

	switch (ttlsdata->phase2_type)
	{
	case TTLS_PHASE2_PAP:
	case TTLS_PHASE2_CHAP:
	case TTLS_PHASE2_MSCHAP:
	case TTLS_PHASE2_MSCHAPV2:
		if (ttlsdata->phase2_data != NULL)
		{
			if (((struct config_pwd_only *)(ttlsdata->phase2_data))->password != NULL)
			{
				free(((struct config_pwd_only *)(ttlsdata->phase2_data))->password);
			}

			free(ttlsdata->phase2_data);
			ttlsdata->phase2_data = NULL;
		}
		break;

	case TTLS_PHASE2_EAP:
		m_pSupplicant->freeConfigEAPMethod((struct config_eap_method **)&ttlsdata->phase2_data);
		break;

	default:
		QMessageBox::critical(this, tr("Unknown inner method"), tr("There was an unknown phase 2 method selected for EAP-TTLS."));
		break;
	}
}

bool ConfigProfileTabs::saveEAPGTCInner(struct config_eap_peap *mypeap)
{
	struct config_eap_method *myeap = NULL;
	struct config_pwd_only *pwdonly = NULL;

	if (mypeap->phase2 == NULL)
	{
		mypeap->phase2 = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
		if (mypeap->phase2 == NULL) return false;

		memset(mypeap->phase2, 0x00, sizeof(struct config_eap_method));
	}

	myeap = (struct config_eap_method *)mypeap->phase2;
	
	if ((myeap->method_num != EAP_TYPE_GTC) && (myeap->method_data != NULL))
	{
		m_pSupplicant->freeConfigEAPMethod((struct config_eap_method **)&mypeap->phase2);
	}

	if (myeap->method_data == NULL)
	{
		myeap->method_data = (struct config_pwd_only *)malloc(sizeof(struct config_pwd_only));
		if (myeap->method_data == NULL) return false;

		// Set everything to defaults.
		memset(myeap->method_data, 0x00, sizeof(struct config_pwd_only));
	}

	myeap->method_num = EAP_TYPE_GTC;

	pwdonly = (struct config_pwd_only *)myeap->method_data;

	if (m_pPassword->text() != "")
	{
		pwdonly->password = _strdup(m_pPassword->text().toAscii());
	}
	else
	{
		if (pwdonly->password != NULL)
		{
			free(pwdonly->password);
			pwdonly->password = NULL;
		}
	}
	
	return true;
}

bool ConfigProfileTabs::saveEAPMSCHAPv2Inner(struct config_eap_peap *mypeap)
{
	struct config_eap_method *myeap = NULL;
	struct config_eap_mschapv2 *mscv2 = NULL;

	if (mypeap->phase2 == NULL)
	{
		mypeap->phase2 = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
		if (mypeap->phase2 == NULL) return false;

		memset(mypeap->phase2, 0x00, sizeof(struct config_eap_method));
	}

	myeap = (struct config_eap_method *)mypeap->phase2;
	
	if ((myeap->method_num != EAP_TYPE_MSCHAPV2) && (myeap->method_data != NULL))
	{
		m_pSupplicant->freeConfigEAPMethod((struct config_eap_method **)&mypeap->phase2);
	}

	if (myeap->method_data == NULL)
	{
		myeap->method_data = (struct config_eap_mschapv2 *)malloc(sizeof(struct config_eap_mschapv2));
		if (myeap->method_data == NULL) 
		{
			QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store PEAP-MSCHAPv2 data."));
			return false;
		}

		memset(myeap->method_data, 0x00, sizeof(struct config_eap_mschapv2));

		mscv2 = (struct config_eap_mschapv2 *)myeap->method_data;
		
		// Set some defaults.
		mscv2->ias_quirk = FALSE;
		mscv2->nthash = NULL;
		mscv2->password = NULL;
	}

	myeap->method_num = EAP_TYPE_MSCHAPV2;
	mscv2 = (struct config_eap_mschapv2 *)myeap->method_data;

	if (m_pPassword->text() != "")
	{
		mscv2->password = _strdup(m_pPassword->text().toAscii());
	}
	else
	{
		if (mscv2->password != NULL)
		{
			free(mscv2->password);
			mscv2->password = NULL;
		}
	}

	return true;
}

bool ConfigProfileTabs::saveEAPPEAPData()
{
	struct config_eap_peap *mypeap = NULL;

	if (m_pProfile->method == NULL)
	{
		m_pProfile->method = (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
		if (m_pProfile->method == NULL)
		{
			QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory needed to save this profile."));
			return false;
		}

		memset(m_pProfile->method, 0x00, sizeof(struct config_eap_method));
		m_pProfile->method->method_num = EAP_TYPE_PEAP;
	}

	if (m_pProfile->method->method_data == NULL)
	{
		m_pProfile->method->method_data = malloc(sizeof(struct config_eap_peap));
		if (m_pProfile->method->method_data == NULL)
		{
			QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory needed to save this profile."));
			return false;
		}

		memset(m_pProfile->method->method_data, 0x00, sizeof(struct config_eap_peap));

		mypeap = (struct config_eap_peap *)m_pProfile->method->method_data;
		mypeap->force_peap_version = 0xff;
	}
	else
	{
		mypeap = (struct config_eap_peap *)m_pProfile->method->method_data;
	}

	if (checkPwdSettings() != true) return false;

	setIdentity();

	if (m_pUsername->text() != "")
	{
		if (mypeap->identity != NULL) free(mypeap->identity);
		mypeap->identity = _strdup(m_pUsername->text().toAscii());
	}
	else
	{
		if (mypeap->identity != NULL) free(mypeap->identity);
		mypeap->identity = NULL;
	}

	if (m_pValidateServer->isChecked() == true)
	{
		mypeap->validate_cert = TRUE;

		if (mypeap->trusted_server != NULL)
		{
			free(mypeap->trusted_server);
			mypeap->trusted_server = NULL;
		}

		if (m_pTrustedServerCombo->currentIndex() > 0)
		{
			mypeap->trusted_server = _strdup(m_pTrustedServerCombo->currentText().toAscii());
		}
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

	// Determine the inner method in use...
	if (m_pInnerMethod->currentText() == "EAP-MSCHAPv2")
	{
		if (saveEAPMSCHAPv2Inner(mypeap) == false) return false;
	}
	else if (m_pInnerMethod->currentText() == "EAP-GTC")
	{
		if (saveEAPGTCInner(mypeap) == false) return false;
	}
	else
	{
		QMessageBox::critical(this, tr("Unknown EAP Type Selected"), tr("The EAP method selected for the inner method is unknown.  Please select a different one."));
		return false;
	}

	return true;
}

bool ConfigProfileTabs::saveEAPData()
{
	if (m_EAPTypeInUse == "EAP-MD5")
	{
		return saveEAPMD5Data();
	}
	else if (m_EAPTypeInUse == "EAP-TTLS")
	{
		return saveEAPTTLSData();
	}
	else if (m_EAPTypeInUse == "EAP-PEAP")
	{
		return saveEAPPEAPData();
	}

	return false;
}

bool ConfigProfileTabs::save()
{
	UIPlugins *currentPlugin = (TabPlugins *)m_pPlugins;
	bool pluginsDidSave = false;

	if ((m_pProfile->method != NULL) && (eaptypeFromString(m_EAPTypeInUse) != m_pProfile->method->method_num))
	{
		// We changed EAP types, so clear out the one we were using.
		m_pSupplicant->freeConfigEAPMethod(&m_pProfile->method);
		m_pProfile->method = NULL;
	}

	while(currentPlugin != NULL)
	{
		if(currentPlugin->isType(PLUGIN_TYPE_PROFILE_TAB))
		{
			if(currentPlugin->save())
			{
				pluginsDidSave = true;
			}
		}

		currentPlugin = currentPlugin->next;
	}

	// Not sure if this is 100% accurate...
	if (((saveEAPData() == false) || pluginsDidSave == false)) return false;

	m_bNewProfile = false;

	return true;
}

bool ConfigProfileTabs::attach()
{
	UIPlugins *currentPlugin       = NULL;
	int pluginStatus                = 0;

	m_pProfileTabs = qFindChild<QTabWidget*>(m_pRealWidget, "widgetTabsProfiles");
	if (m_pProfileTabs == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QTabWidget called 'widgetTabsProfiles'."));
		return false;
	}

	// Now load the profile tab plugins into the tab widget.
	currentPlugin = (TabPlugins *)m_pPlugins;

	while(currentPlugin != NULL)
	{
		// Is it a profile tab plugin?
		if(currentPlugin->isType(PLUGIN_TYPE_PROFILE_TAB))
		{
			if(currentPlugin->isInitialized() != TRUE)
			{
				pluginStatus = currentPlugin->instantiateWidget();
			}
			
			// Pass the profile in so this plugin can populate the structures as needed.
			currentPlugin->setProfile(m_pProfile);

			// Insert the tab into our QTabWidget
			currentPlugin->addToParent(this);
		}

		currentPlugin = (TabPlugins*)currentPlugin->next;
	}

	m_pProfileTabs->setCurrentIndex(0);  // Always start at tab 0.

	 m_pValidateServer = qFindChild<QCheckBox*>(m_pRealWidget, "dataCheckboxProfilesValidateServer");
	 if (m_pValidateServer == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QCheckBox called 'dataCheckboxProfilesValidateServer'."));
		 return false;
	 }

	 m_pTrustedServerCombo = qFindChild<QComboBox*>(m_pRealWidget, "dataComboProfilesTrustedServers");
	 if (m_pTrustedServerCombo == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox called 'dataComboProfilesTrustedServers'."));
		 return false;
	 }

	 m_pAnonIdent = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioProfilesAnonymousIdentity");
	 if (m_pAnonIdent == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton called 'dataRadioProfilesAnonymousIdentity'."));
		 return false;
	 }
 
	 m_pUseThisIdent = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioProfilesUseThisIdentity");
	 if (m_pUseThisIdent == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton called 'dataRadioProfilesUseThisIdentity'."));			
		 return false;
	 }

	 m_pPhase1Ident = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldProfilesUseThisIdentity");
	 if (m_pPhase1Ident == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFieldProfilesUseThisIdentity'."));
		 return false;
	 }

	 m_pInnerMethod = qFindChild<QComboBox*>(m_pRealWidget, "dataComboProfilesTunneledProtocols");
	 if (m_pInnerMethod == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox called 'dataComboProfilesTunneledProtocols'."));
		 return false;
	 }

	 m_pPromptForUPW = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioProfilesPromptUsernamePassword");
	 if (m_pPromptForUPW == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton called 'dataRadioProfilesPromptUsernamePassword'."));
		 return false;
	 }

	 m_pPromptForPWD = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioProfilesPromptPassword");
	 if (m_pPromptForPWD == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton called 'dataRadioProfilesPromptPassword'."));
		 return false;
	 }

	 m_pDontPrompt = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioProfilesPromptNone");
	 if (m_pDontPrompt == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton called 'dataRadioProfilesPromptNone'."));
		 return false;
	 }

	 m_pUsername = qFindChild<QLineEdit*>(m_pRealWidget, "dataFrameProfilesUsername");
	 if (m_pUsername == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFrameProfilesUsername'."));
		 return false;
	 }

	 m_pPassword = qFindChild<QLineEdit*>(m_pRealWidget, "dataFrameProfilesPassword");
	 if (m_pPassword == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFrameProfilesPassword'."));
		 return false;
	 }

	 m_pShowBtn = qFindChild<QPushButton*>(m_pRealWidget, "buttonProfilesShowPassword");
	 if (m_pShowBtn == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QPushButton called 'buttonProfilesShowPassword'."));
		 return false;
	 }

	 m_pTSLabel = qFindChild<QLabel*>(m_pRealWidget, "labelComboProfilesTrustedServers");

 	if (m_pProfile == NULL)
	{
		setPeapPhase2Types();

		populateTrustedServerList();
	}
	else
	{
		updateWindow();
	}

	 // Hook up the signal that data has changed to the slot to update the value.
	 Util::myConnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));
	 Util::myConnect(this, SIGNAL(signalDataChanged()), m_pParent, SLOT(slotDataChanged()));

	 // Hook up the show/hide button on the User Credentials page
	 Util::myConnect(m_pShowBtn, SIGNAL(clicked()), this, SLOT(showBtnClicked()));

	 // Hook up the validate servers checkbox.
	 Util::myConnect(m_pValidateServer, SIGNAL(stateChanged(int)), this, SLOT(slotValidateServerChanged(int)));
	 Util::myConnect(m_pValidateServer, SIGNAL(stateChanged(int)), this, SIGNAL(signalDataChanged()));

	 // Hook up the outer identity radio buttons.
	 Util::myConnect(m_pUseThisIdent, SIGNAL(toggled(bool)), this, SLOT(slotPickIdentity(bool)));
	 Util::myConnect(m_pUseThisIdent, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pPhase1Ident, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pAnonIdent, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));

	 // Hook up the inner identity radio buttons.
	 Util::myConnect(m_pPromptForUPW, SIGNAL(toggled(bool)), this, SLOT(slotSetPromptForUPW(bool)));
	 Util::myConnect(m_pPromptForPWD, SIGNAL(toggled(bool)), this, SLOT(slotSetPromptForPWD(bool)));
	 Util::myConnect(m_pDontPrompt, SIGNAL(toggled(bool)), this, SLOT(slotDontPrompt(bool)));

	 Util::myConnect(m_pPromptForUPW, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
 	 Util::myConnect(m_pPromptForPWD, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pDontPrompt, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));

	 Util::myConnect(m_pUsername, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pPassword, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));

	 Util::myConnect(m_pInnerMethod, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pTrustedServerCombo, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pTrustedServerCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotDifferentServerSelected(int)));

	Util::myConnect(this, SIGNAL(signalDataChanged()), this, SLOT(slotDataChanged()));

	m_bConnected = true;

	return true;
}

void ConfigProfileTabs::detach()
{
	UIPlugins *currentPlugin       = m_pPlugins;

	// First, remove all plugins
	while(currentPlugin != NULL)
	{
		if(currentPlugin->isType(PLUGIN_TYPE_PROFILE_TAB))
		{
			currentPlugin->destroyWidget();
		}

		currentPlugin = currentPlugin->next;
	}
	
}

void ConfigProfileTabs::populateOnePhase()
{
	char *password;

	hideProtSettingsTab();  // We won't edit that one with this EAP method.

	m_pUsername->setText(QString(m_pProfile->identity));

	if (m_pProfile->method->method_num == EAP_TYPE_MD5)
	{
		m_EAPTypeInUse = "EAP-MD5";
		password = ((struct config_pwd_only *)(m_pProfile->method->method_data))->password;
		m_pPassword->setText(QString(password));
	}
	else
	{
		QMessageBox::critical(this, tr("EAP Method Error"), tr("EAP method appeared to be a one phase type, but we don't know what that type is!"));
	}

	if (m_pProfile->identity == NULL)
	{
		// Set the no username/password stored radio button.
		m_pPromptForUPW->setChecked(true);
		m_pPromptForPWD->setChecked(false);
		m_pDontPrompt->setChecked(false);
		m_pUsername->setEnabled(false);
		m_pPassword->setEnabled(false);
	}
	else if ((m_pProfile->identity != NULL) && (password == NULL))
	{
		m_pPromptForUPW->setChecked(false);
		m_pPromptForPWD->setChecked(true);
		m_pDontPrompt->setChecked(false);
		m_pUsername->setEnabled(true);
		m_pPassword->setEnabled(false);
	}
	else
	{
		m_pPromptForUPW->setChecked(false);
		m_pPromptForPWD->setChecked(false);
		m_pDontPrompt->setChecked(true);
		m_pUsername->setEnabled(true);
		m_pPassword->setEnabled(true);
	}
}

void ConfigProfileTabs::populatePEAPData()
{
	struct config_eap_peap *peapdata = NULL;
	struct config_eap_mschapv2 *mscv2 = NULL;
	struct config_pwd_only *gtc = NULL;
	char *password = NULL;
	int index = 0;

	m_EAPTypeInUse = "EAP-PEAP";

	if (m_pProfile->method == NULL)   // This is a new profile being created.
	{
		m_pValidateServer->setChecked(true);
		m_pUsername->clear();
		m_pPassword->clear();
		m_pAnonIdent->setChecked(true);
		m_pUseThisIdent->setChecked(false);
		m_pPhase1Ident->clear();
		m_pPromptForUPW->setChecked(true);
		m_pPromptForPWD->setChecked(false);
		m_pDontPrompt->setChecked(false);
		m_pUsername->setEnabled(false);
		m_pPassword->setEnabled(false);
		slotDifferentServerSelected(0);   // Set the trusted server stuff to invalid.
		return;
	}

	peapdata = (struct config_eap_peap *)m_pProfile->method->method_data;

	if (peapdata->validate_cert == TRUE)
	{
		m_pValidateServer->setChecked(true);
		index = m_pTrustedServerCombo->findText(QString(peapdata->trusted_server));
		if (index < 0) index = 0;
		m_pTrustedServerCombo->setCurrentIndex(index);
		m_pTrustedServerCombo->setEnabled(true);
	}
	else
	{
		m_pValidateServer->setChecked(false);
		m_pTrustedServerCombo->setCurrentIndex(0);  // Will cause it to show <None>
		m_pTrustedServerCombo->setEnabled(false);
	}

	if (peapdata->identity != NULL)
	{
		m_pUsername->setText(QString(peapdata->identity));
	}

	switch (peapdata->phase2->method_num)
	{
	case EAP_TYPE_MSCHAPV2:
		mscv2 = (struct config_eap_mschapv2 *)peapdata->phase2->method_data;
		if (mscv2->password == NULL)
		{
			m_pPassword->clear();
		}
		else
		{
			m_pPassword->setText(QString(mscv2->password));
			password = mscv2->password;
		}
		index = m_pInnerMethod->findText(QString("EAP-MSCHAPv2"));
		m_pInnerMethod->setCurrentIndex(index);
		break;

	case EAP_TYPE_GTC:
		gtc = (struct config_pwd_only *)peapdata->phase2->method_data;
		if (gtc->password == NULL)
		{
			m_pPassword->clear();
		}
		else
		{
			m_pPassword->setText(QString(gtc->password));
			password = gtc->password;
		}
		index = m_pInnerMethod->findText(QString("EAP-GTC"));
		m_pInnerMethod->setCurrentIndex(index);
		break;

	default:
		QMessageBox::critical(this, tr("EAP Configuration Error"), tr("There was an unknown inner EAP method used.  Configuration data will be empty."));
		m_pUsername->clear();
		m_pPassword->clear();
		break;
	}

	if (peapdata->identity == NULL)
	{
		// Set the no username/password stored radio button.
		m_pPromptForUPW->setChecked(true);
		m_pPromptForPWD->setChecked(false);
		m_pDontPrompt->setChecked(false);
		m_pUsername->setEnabled(false);
		m_pPassword->setEnabled(false);
	}
	else if ((peapdata->identity != NULL) && (password == NULL))
	{
		m_pPromptForUPW->setChecked(false);
		m_pPromptForPWD->setChecked(true);
		m_pDontPrompt->setChecked(false);
		m_pUsername->setEnabled(true);
		m_pPassword->setEnabled(false);
	}
	else
	{
		m_pPromptForUPW->setChecked(false);
		m_pPromptForPWD->setChecked(false);
		m_pDontPrompt->setChecked(true);
		m_pUsername->setEnabled(true);
		m_pPassword->setEnabled(true);
	}
}

void ConfigProfileTabs::populateTTLSData()
{
	struct config_eap_ttls *ttlsdata = NULL;
	struct config_pwd_only *pwdonly = NULL;
	struct config_eap_method *eapmethod = NULL;
	char *password = NULL;
	int index = 0;

	m_EAPTypeInUse = "EAP-TTLS";

	ttlsdata = (struct config_eap_ttls *)m_pProfile->method->method_data;

	if (ttlsdata->validate_cert == TRUE)
	{
		m_pValidateServer->setChecked(true);
		index = m_pTrustedServerCombo->findText(QString(ttlsdata->trusted_server));
		if (index < 0) index = 0;
		m_pTrustedServerCombo->setCurrentIndex(index);
		m_pTrustedServerCombo->setEnabled(true);
	}
	else
	{
		m_pValidateServer->setChecked(false);
		m_pTrustedServerCombo->setCurrentIndex(0);  // Will cause it to be set to <None>
		m_pTrustedServerCombo->setEnabled(false);
	}

	if (ttlsdata->inner_id != NULL)
	{
		m_pUsername->setText(QString(ttlsdata->inner_id));
	}

	switch (ttlsdata->phase2_type)
	{
	case TTLS_PHASE2_PAP:
		index = m_pInnerMethod->findText(QString("PAP"));
		m_pInnerMethod->setCurrentIndex(index);
		break;

	case TTLS_PHASE2_CHAP:
		index = m_pInnerMethod->findText(QString("CHAP"));
		m_pInnerMethod->setCurrentIndex(index);
		break;

	case TTLS_PHASE2_MSCHAP:
		index = m_pInnerMethod->findText(QString("MS-CHAP"));
		m_pInnerMethod->setCurrentIndex(index);
		break;

	case TTLS_PHASE2_MSCHAPV2:
		index = m_pInnerMethod->findText(QString("MS-CHAPv2"));
		m_pInnerMethod->setCurrentIndex(index);
		break;

	case TTLS_PHASE2_EAP:
		index = m_pInnerMethod->findText(QString("EAP-MD5"));
		m_pInnerMethod->setCurrentIndex(index);
		break;

	default:
		QMessageBox::critical(this, tr("Unknown Phase 2 Method"), tr("An unknown phase 2 method was found in your configuration file!"));
	}

	switch (ttlsdata->phase2_type)
	{
	case TTLS_PHASE2_PAP:
	case TTLS_PHASE2_CHAP:
	case TTLS_PHASE2_MSCHAP:
	case TTLS_PHASE2_MSCHAPV2:
		pwdonly = (struct config_pwd_only *)ttlsdata->phase2_data;
		if ((pwdonly != NULL) && (pwdonly->password != NULL))
		{
			m_pPassword->setText(QString(pwdonly->password));
			password = pwdonly->password;
		}
		else
		{
			m_pPassword->clear();
		}
		break;

	case TTLS_PHASE2_EAP:
		eapmethod = (struct config_eap_method *)ttlsdata->phase2_data;

		if (eapmethod->method_num == EAP_TYPE_MD5)
		{
			pwdonly = (struct config_pwd_only *)eapmethod->method_data;
			if (pwdonly != NULL)
			{
				m_pPassword->setText(QString(pwdonly->password));
				password = pwdonly->password;
			}
			else
			{
				m_pPassword->clear();
			}
		}
		break;

	default:
		QMessageBox::critical(this, tr("EAP TTLS Configuration Error"), tr("TTLS has been configured with an unknown phase 2 method!"));
		m_pPassword->clear();
		break;
	}

	if (ttlsdata->inner_id == NULL)
	{
		// Set the no username/password stored radio button.
		m_pPromptForUPW->setChecked(true);
		m_pPromptForPWD->setChecked(false);
		m_pDontPrompt->setChecked(false);
		m_pUsername->setEnabled(false);
		m_pPassword->setEnabled(false);
	}
	else if ((ttlsdata->inner_id != NULL) && (password == NULL))
	{
		m_pPromptForUPW->setChecked(false);
		m_pPromptForPWD->setChecked(true);
		m_pDontPrompt->setChecked(false);
		m_pUsername->setEnabled(true);
		m_pPassword->setEnabled(false);
	}
	else
	{
		m_pPromptForUPW->setChecked(false);
		m_pPromptForPWD->setChecked(false);
		m_pDontPrompt->setChecked(true);
		m_pUsername->setEnabled(true);
		m_pPassword->setEnabled(true);
	}
}

void ConfigProfileTabs::populateTwoPhase()
{
	showAllTabs();
	populateTrustedServerList();

#ifdef WINDOWS
	if ((m_pProfile->identity == NULL) || (_stricmp(m_pProfile->identity, "anonymous") == 0))
#else
	  if ((m_pProfile->identity == NULL) || (strcasecmp(m_pProfile->identity, "anonymous") == 0))
#endif
	{
		m_pPhase1Ident->setText(QString(""));
		m_pPhase1Ident->setEnabled(false);
		m_pAnonIdent->setChecked(true);
		m_pUseThisIdent->setChecked(false);
	}
	else
	{
		m_pPhase1Ident->setText(QString(m_pProfile->identity));
		m_pPhase1Ident->setEnabled(true);
		m_pAnonIdent->setChecked(false);
		m_pUseThisIdent->setChecked(true);
	}

	if ((m_pProfile->method == NULL) || (m_pProfile->method->method_num == EAP_TYPE_PEAP))
	{
		setPeapPhase2Types();
		populatePEAPData();
	}
	else if (m_pProfile->method->method_num == EAP_TYPE_TTLS)
	{
		setTtlsPhase2Types();
		populateTTLSData();
	}
}

void ConfigProfileTabs::updateWindow()
{
	if ((m_pProfile->method != NULL) && (m_pProfile->method->method_num == EAP_TYPE_MD5))
	{
		populateOnePhase();
	}
	else
	{
		populateTwoPhase();
	}
}

bool ConfigProfileTabs::dataChanged()
{
	return m_bDataChanged;
}

void ConfigProfileTabs::discard()
{
	// Don't need to do anything here.
}

void ConfigProfileTabs::showHelp()
{
	switch (m_pProfileTabs->currentIndex())
	{
	case PROTOCOL_SETTINGS_TAB:
		HelpWindow::showPage("xsupphelp.html", "xsupprofiles");
		break;

	case USER_CREDENTIALS_TAB:
		HelpWindow::showPage("xsupphelp.html", "xsupuser");
		break;

	default:
		// XXX This is a band-aid fix to show posture help for the IDE version of the UI.
		HelpWindow::showPage("xsupphelp.html", "idngcompliance");
		break;
	}
}

void ConfigProfileTabs::hideProtSettingsTab()
{
	m_pProfileTabs->setTabEnabled(PROTOCOL_SETTINGS_TAB, false);
}

void ConfigProfileTabs::showAllTabs()
{
	m_pProfileTabs->setTabEnabled(PROTOCOL_SETTINGS_TAB, true);
}

void ConfigProfileTabs::showBtnClicked()
{
	if (m_bPwdShowing)
	{
		// Hide it
		m_pPassword->setEchoMode(QLineEdit::Password);
		m_pShowBtn->setText(tr("Show"));
		m_bPwdShowing = false;
	}
	else
	{
		// Show it.
		m_pPassword->setEchoMode(QLineEdit::Normal);
		m_pShowBtn->setText(tr("Hide"));
		m_bPwdShowing = true;
	}
}

void ConfigProfileTabs::setPeapPhase2Types()
{
	m_pInnerMethod->clear();
	m_pInnerMethod->addItem("EAP-MSCHAPv2");
	//m_pInnerMethod->addItem("EAP-GTC");
}

void ConfigProfileTabs::setTtlsPhase2Types()
{
	m_pInnerMethod->clear();
	m_pInnerMethod->addItem("PAP");
	m_pInnerMethod->addItem("CHAP");
	m_pInnerMethod->addItem("MS-CHAP");
	m_pInnerMethod->addItem("MS-CHAPv2");
	m_pInnerMethod->addItem("EAP-MD5");
}

void ConfigProfileTabs::populateTrustedServerList()
{
	trusted_servers_enum *pServers = NULL;
	int i = 0;

	m_pTrustedServerCombo->clear();

	m_pTrustedServerCombo->addItem("  <None>  ");

	if (m_pSupplicant->enumTrustedServers(&pServers, true) == true)
	{
		while (pServers[i].name != NULL)
		{
			m_pTrustedServerCombo->addItem(QString(pServers[i].name));
			i++;
		}

		m_pSupplicant->freeEnumTrustedServer(&pServers);
	}

	m_pTrustedServerCombo->setCurrentIndex(0);  // Start at <None> the loaders that follow will change it if needed.
}

void ConfigProfileTabs::slotValidateServerChanged(int newState)
{
	if (newState == Qt::Checked)
	{
		m_pTrustedServerCombo->setEnabled(true);
		slotDifferentServerSelected(m_pTrustedServerCombo->currentIndex());
	}
	else
	{
		m_pTrustedServerCombo->setEnabled(false);
		setLabelValid(m_pTSLabel);
		m_pTrustedServerCombo->setToolTip("");
	}
}

void ConfigProfileTabs::slotPickIdentity(bool isChecked)
{
	if (isChecked)
	{
		m_pPhase1Ident->setEnabled(true);
	}
	else
	{
		m_pPhase1Ident->setEnabled(false);
	}
}

void ConfigProfileTabs::slotSetPromptForUPW(bool isChecked)
{
	if (isChecked)
	{
		m_pUsername->clear();
		m_pUsername->setEnabled(false);
		m_pPassword->clear();
		m_pPassword->setEnabled(false);
	}
}

void ConfigProfileTabs::slotSetPromptForPWD(bool isChecked)
{
	if (isChecked)
	{
		m_pUsername->setEnabled(true);
		m_pPassword->setEnabled(false);
		m_pPassword->clear();
	}
}

void ConfigProfileTabs::slotDontPrompt(bool isChecked)
{
	if (isChecked)
	{
		m_pUsername->setEnabled(true);
		m_pPassword->setEnabled(true);
	}
}

void ConfigProfileTabs::slotDataChanged()
{
	m_bDataChanged = true;
}

void ConfigProfileTabs::setPhase1EAPType(QString newEAPtype)
{
	m_EAPTypeInUse = newEAPtype;

	// If we are using EAP-MD5 we need to hide a tab, for everything else, make sure all tabs are exposed.
	if (newEAPtype == "EAP-MD5")
	{
		// Hide the first tab.
		hideProtSettingsTab();
	}
	else if (newEAPtype == "EAP-PEAP")
	{
		// Show all tabs.
		showAllTabs();
		setPeapPhase2Types();
	}
	else if (newEAPtype == "EAP-TTLS")
	{
		// Show all tabs.
		showAllTabs();
		setTtlsPhase2Types();
	}
	else
	{
		QMessageBox::critical(this, tr("Unknown EAP Method"), tr("The EAP method %1 is unknown to this program.").arg(newEAPtype));
	}
}

int ConfigProfileTabs::eaptypeFromString(QString eapName)
{
	if (eapName == "EAP-MD5") return EAP_TYPE_MD5;
	if (eapName == "EAP-PEAP") return EAP_TYPE_PEAP;
	if (eapName == "EAP-TTLS") return EAP_TYPE_TTLS;
	if (eapName == "EAP-GTC") return EAP_TYPE_GTC;
	if (eapName == "EAP-MSCHAPv2") return EAP_TYPE_MSCHAPV2;
	if (eapName == "EAP-FAST") return EAP_TYPE_FAST;

	return -1;  // We don't know what to return.
}

void ConfigProfileTabs::pluginDataChanged()
{
	emit signalDataChanged();
}

void ConfigProfileTabs::setLabelInvalid(QLabel *toEditLabel)
{
	QPalette *mypalette;

	if (toEditLabel == NULL) return;

	m_NormalColor = toEditLabel->palette().color(QPalette::WindowText);

	mypalette = new QPalette();

	mypalette->setColor(QPalette::WindowText, QColor(255, 0, 0));  // Set the color to red.
	toEditLabel->setPalette((*mypalette));

	delete mypalette;

	toEditLabel->setToolTip(tr("You cannot use this Profile until you select a valid Trusted Server."));
	m_pTrustedServerCombo->setToolTip(tr("You cannot use this Profile until you select a valid Trusted Server."));	
}

void ConfigProfileTabs::setLabelValid(QLabel *toEditLabel)
{
	QPalette *mypalette;

	if (toEditLabel == NULL) return;

	mypalette = new QPalette();

	mypalette->setColor(QPalette::WindowText, m_NormalColor);

	toEditLabel->setPalette((*mypalette));

	toEditLabel->setToolTip("");  // Clear the tool tip.
	m_pTrustedServerCombo->setToolTip("");
}

void ConfigProfileTabs::slotDifferentServerSelected(int selectedItem)
{
	if (m_pValidateServer->isChecked())  // Which, 99.999% of the time it will be. ;)
	{
		if (selectedItem == 0)
		{
			setLabelInvalid(m_pTSLabel);
			m_pTrustedServerCombo->setToolTip(tr("You cannot use this Profile until you select a valid Trusted Server."));
		}
		else
		{
			setLabelValid(m_pTSLabel);
			m_pTrustedServerCombo->setToolTip("");
		}
	}
	// Otherwise, do nothing.
}
