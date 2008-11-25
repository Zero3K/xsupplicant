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

#ifndef _CONFIGPROFILETABS_H_
#define _CONFIGPROFILETABS_H_

#include "TabWidgetBase.h"
#include "xsupcalls.h"
#include "TabPlugins.h"

class ConfigProfileTabs : public TabWidgetBase
 {
     Q_OBJECT

 public:
	 ConfigProfileTabs(QWidget *pRealWidget, XSupCalls *pSupplicant, config_profiles *pProf, QWidget *parent, UIPlugins *pPlugins);
	 ~ConfigProfileTabs();

	 bool attach();
	 void detach();
	 bool save();
	 bool dataChanged();
	 void discard();
	 void showHelp();
	 void hideProtSettingsTab();
	 void showUserCertTab();
	 void showPEAPTTLSTabs();
	 void showSIMTabs();
	 void showFASTTabs();

	 void setPhase1EAPType(QString);
	 void setPeapPhase2Types();
	 void setTtlsPhase2Types();

	 // Plugin related hooks
	 void pluginDataChanged();
	 int insertTab( int index, QWidget * widget, const QString & label );
	 void removeTab(int index);

signals:
	 void signalDataChanged();

private slots:
	 void showBtnClicked();
	 void slotValidateServerChanged(int);
	 void slotDifferentServerSelected(int);
	 void slotPickIdentity(bool);
	 void slotSetPromptForUPW(bool);
	 void slotSetPromptForPWD(bool);
	 void slotDontPrompt(bool);
	 void slotDataChanged();
	 void slotInnerMethodChanged(int);
	 void slotFastAllowProvision(bool);

 private:
	 enum {
		 PROTOCOL_SETTINGS_TAB,
		 USER_CREDENTIALS_TAB,
		 USER_CERTIFICATE_TAB,
		 EAP_FAST_TAB,
		 SIM_AKA_TAB
	 };

	 void populateTrustedServerList();
	 void populateSIMReaders();
	 bool saveEAPData();
	 bool saveEAPMD5Data();
	 bool saveEAPTTLSData();
	 bool saveEAPPEAPData();
	 bool saveEAPFASTData();
	 bool saveEAPSIMData();
	 bool saveEAPAKAData();
	 bool saveEAPTLSData();
	 bool checkPwdSettings();
	 int eaptypeFromString(QString);
	 void setIdentity();
	 void updateWindow();
	 void populateOnePhase();
	 void populateTwoPhase();
	 void populateSimAka();
	 void populateEAPSIM();
	 void populateEAPAKA();
	 void populatePEAPData();
	 void populateFASTData();
	 void populateTTLSData();
	 void populateEAPTLSData();
	 void freeTTLSInner(struct config_eap_ttls *ttlsdata);
	 bool saveEAPGTCInner(struct config_eap_method **mymeth);
	 bool saveEAPMSCHAPv2Inner(struct config_eap_method **mymeth);
	 void setLabelInvalid(QLabel *toEditLabel);
	 void setLabelValid(QLabel *toEditLabel);

	 config_profiles *m_pProfile;

	 QWidget *m_pParent;

	 QWidget *m_pRealWidget;

	 QCheckBox *m_pValidateServer;
	 QComboBox *m_pTrustedServerCombo;
	 QRadioButton *m_pUseThisIdent;
	 QRadioButton *m_pAnonIdent;
	 QLineEdit *m_pPhase1Ident;
	 QComboBox *m_pInnerMethod;
	 QComboBox *m_pSIMReaders;
	 QRadioButton *m_pPromptForUPW;
	 QRadioButton *m_pPromptForPWD;
	 QRadioButton *m_pDontPrompt;
	 QLineEdit *m_pUsername;
	 QLineEdit *m_pPassword;
	 QPushButton *m_pShowBtn;
	 QLabel *m_pTSLabel;
	 QCheckBox *m_pAutoRealm;
	 QCheckBox *m_pFASTAllowProvision;
	 QCheckBox *m_pFASTAuthProvision;
	 QCheckBox *m_pFASTAnonProvision;
	 QTableWidget *m_pUserCertTable;

	 XSupCalls *m_pSupplicant;

	 QColor m_NormalColor;

	 bool m_bDataChanged;
	 bool m_bPwdShowing;
	 bool m_bConnected;
	 bool m_bProfileRenamed;
	 bool m_bNewProfile;

	 QString m_EAPTypeInUse;

	 UIPlugins *m_pPlugins;
};

#endif  // _CONFIGPROFILETABS_H_

