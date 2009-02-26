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

#ifndef _WIZARDPAGES_H_
#define _WIZARDPAGES_H_

#include <QWidget>
#include <QRadioButton>
#include <QLineEdit>
#include <QTableWidget>
#include <QCheckBox>
#include <QComboBox>

#include "ConnectionWizard.h"
#include "SSIDList.h"

extern "C" {
#include "libxsupgui/xsupgui_request.h"
}

class WizardPage : public QWidget
{
	Q_OBJECT
	
public:
	WizardPage(QWidget *parent, QWidget *parentWidget);
	virtual ~WizardPage() { if (m_pRealForm != NULL) delete m_pRealForm; };
	
	// called to perform initialization on page independent of data,
	// namely loading form representing page, populating any static
	// text, etc. Returns "true" if everything loaded/initialized
	// successfully
	virtual bool create(void) = 0;
	
	// return QWidget representing UI of this page.  Page class
	// is responsible for loading this
	QWidget *getWidget(void) { return m_pRealForm; };
	
	// initialize page with data from wizard
	virtual void init(const ConnectionWizardData &data) = 0;
	
	// is this a terminal page in wizard
	virtual bool isFinalPage(void) { return false; }
	
	// return string to display in wizard header for this page
	virtual QString getHeaderString(void) { return QString(""); };
	
	// called before transitioning away from page. Validate user input, prompting if input
	// is invalid.  Returns "true" if info is valid and can leave page
	virtual bool validate(void) = 0;
	
	// return Connection Wizard data with info from this page filled in
	virtual const ConnectionWizardData &wizardData(void) = 0;

protected:

	// QWidget representing wizard page
	QWidget *m_pRealForm;
	
	//parent object(should be connection wizard)
	QWidget *m_pParent;
	
	// QWidget represenging parent object
	QWidget *m_pParentWidget;
	
	// pointer to wizard data for current connection.
	ConnectionWizardData m_curData;
};

class WizardPageNetworkType : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageNetworkType(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual bool validate(void) { return true; };
	virtual const ConnectionWizardData &wizardData(void);
private:
	QRadioButton *m_pRadioButtonWireless;
	QRadioButton *m_pRadioButtonWired;
	int m_numWiredAdapters;
	int m_numWirelessAdapters;
};

class WizardPageWiredSecurity : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageWiredSecurity(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("Network Security Type"); };
	virtual bool validate(void) { return true; };
	virtual const ConnectionWizardData &wizardData(void);
private:
	QRadioButton *m_pRadioButtonDot1X;
	QRadioButton *m_pRadioButtonNone;
};

class WizardPageIPOptions : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageIPOptions(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("IP Address"); };
	virtual bool validate(void) { return true; };
	virtual const ConnectionWizardData &wizardData(void);
private:
	QRadioButton *m_pRadioButtonAuto;
	QRadioButton *m_pRadioButtonStatic;
};

class WizardPageCredentials : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageCredentials(QWidget *parent, QWidget *parentWidget);
	virtual ~WizardPageCredentials();
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("Credentials"); };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);
private:
	QRadioButton *m_pRadioButtonPrompt;
	QRadioButton *m_pRadioButtonStore;
	QLineEdit *m_pUsernameEdit;
	QLineEdit *m_pPasswordEdit;
	QLabel *m_pUsernameLabel;
	QLabel *m_pPasswordLabel;

private slots:
	void slotToggled(bool checked);
};

class WizardPageStaticIP : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageStaticIP(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("Static IP Settings"); };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);
private:
	QLineEdit *m_pIPAddress;
	QLineEdit *m_pNetmask;
	QLineEdit *m_pGateway;
	QLineEdit *m_pPrimaryDNS;
	QLineEdit *m_pSecondaryDNS;
};

class WizardPageFinished : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageFinished(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("Finished"); };
	virtual bool isFinalPage(void) { return true; };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);
private:
	QPushButton *m_pConnectButton;
	QLineEdit *m_pConnectionName;
};

class WizardPageWirelessNetwork : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageWirelessNetwork(QWidget *parent, QWidget *parentWidget);
	virtual ~WizardPageWirelessNetwork();
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("Choose Wireless Network"); };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);
	
private slots:
	void handleVisibleClicked(bool);
	void handleSSIDSelection(const WirelessNetworkInfo &);
	
private:
	QRadioButton *m_pRadioButtonVisible;
	QRadioButton *m_pRadioButtonOther;
	QTableWidget *m_pTableWidget;
	SSIDList *m_pSSIDList;
	WirelessNetworkInfo m_networkInfo;
};

class WizardPageWirelessInfo : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageWirelessInfo(QWidget *parent, QWidget *parentWidget);
	virtual ~WizardPageWirelessInfo();
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("Wireless Network Settings"); };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);
private slots:
	void hiddenStateChanged(int);
	void assocModeChanged(int newIndex);
private:
	QLineEdit *m_pNetworkName;
	QComboBox *m_pAssocMode;
	QComboBox *m_pEncryption;
	QCheckBox *m_pHiddenNetwork;
	QLabel *m_pEncryptionLabel;
};

class WizardPageDot1XProtocol : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageDot1XProtocol(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("802.1X Protocol"); };
	virtual bool validate(void) { return true; };
	virtual const ConnectionWizardData &wizardData(void);	
private:
	QComboBox *m_pProtocol;
};

class WizardPageDot1XInnerProtocol : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageDot1XInnerProtocol(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("802.1X Protocol Settings"); };
	virtual bool validate(void) { return true; };
	virtual const ConnectionWizardData &wizardData(void);	
private:
	QComboBox *m_pProtocol;
	QLineEdit *m_pOuterID;
	QCheckBox *m_pValidateCert;
	QCheckBox *m_pSessionResume;
};

class WizardPageFASTInnerProtocol : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageFASTInnerProtocol(QWidget *parent, QWidget *parentWidget);
	virtual ~WizardPageFASTInnerProtocol();
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("802.1X Protocol Settings"); };
	virtual bool validate(void) { return true; };
	virtual const ConnectionWizardData &wizardData(void);	

private slots:
	void slotToggleRadioButton(bool checked);

private:
	QComboBox *m_pProtocol;
	QLineEdit *m_pOuterID;
	QCheckBox *m_pValidateCert;
	QRadioButton *m_pAnonymousProvision;
	QRadioButton *m_pAuthenticatedProvision;
};

class WizardPageDot1XCert : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageDot1XCert(QWidget *parent, QWidget *parentWidget);
	virtual ~WizardPageDot1XCert();
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("802.1X Server Certificate"); };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);
private slots:
	void handleValidateChecked(int checkState);
	void handleCertTableClick(int, int);
private:
	QTableWidget *m_pCertTable;
	QLineEdit *m_pNameField;
	QCheckBox *m_pVerifyName;
	cert_enum *m_pCertArray; // hate to use this datatype here
	int m_numCerts;
};

class WizardPageDot1XUserCert : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageDot1XUserCert(QWidget *parent, QWidget *parentWidget);
	virtual ~WizardPageDot1XUserCert();
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("802.1X User Certificate"); };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);
private slots:
	void handleCertTableClick(int, int);
private:
	QTableWidget *m_pCertTable;
	cert_enum *m_pCertArray; 
	int m_numCerts;
};

class WizardPageSCReader : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageSCReader(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("Smartcard Reader"); };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);	
private:
	void populateSIMReaders();

	QComboBox *m_pReader;
	QCheckBox *m_pAutoRealm;
};

class WizardPageNetworkTypes : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageNetworkTypes(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual bool validate(void) { return true; };
	virtual const ConnectionWizardData &wizardData(void);
private:
	QCheckBox *m_pCheckBoxWireless;
	QCheckBox *m_pCheckBoxWired;
};

class WizardPageAuthOptions : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageAuthOptions(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual bool validate(void) { return true; };
	virtual const ConnectionWizardData &wizardData(void);
private:
	QCheckBox *m_pCheckBoxUseLogonCreds;
};

class WizardPageMachineAuthFinished : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageMachineAuthFinished(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual void init(const ConnectionWizardData &data);
	virtual QString getHeaderString(void) { return tr("Finished"); };
	virtual bool isFinalPage(void) { return true; };
	virtual bool validate(void);
	virtual const ConnectionWizardData &wizardData(void);
private:
	QLabel *m_pMsgLabel;
};

#endif