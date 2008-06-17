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

#ifndef _WIZARDPAGES_H_
#define _WIZARDPAGES_H_

#include <QWidget>
#include <QRadioButton>
#include <QLineEdit>
#include <QTableWidget>
#include <QCheckBox>
#include <QComboBox>

#include "ConnectionWizard.h"

class SSIDList;

class WizardPage : public QWidget
{
	Q_OBJECT
	
public:
	WizardPage(QWidget *parent, QWidget *parentWidget);
	virtual ~WizardPage() { if (m_pRealForm) delete m_pRealForm; };
	virtual bool create(void) = 0;
	QWidget *getWidget(void) { return m_pRealForm; };
	virtual ConnectionWizard::wizardPages getNextPage(void) = 0;
	virtual void init(void) = 0;
	virtual bool isFinalPage(void) { return false; }
	virtual QString getHeaderString(void) { return QString(""); };

protected:
	QWidget *m_pRealForm;
	QWidget *m_pParent;
	QWidget *m_pParentWidget;	
};

class WizardPageNetworkType : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageNetworkType(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual ConnectionWizard::wizardPages getNextPage(void);
	virtual void init(void) {};
private:
	QRadioButton *m_pRadioButtonWireless;
	QRadioButton *m_pRadioButtonWired;
};

class WizardPageWiredSecurity : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageWiredSecurity(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual ConnectionWizard::wizardPages getNextPage(void);
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("Network Security Type"); };
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
	virtual ConnectionWizard::wizardPages getNextPage(void);
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("IP Address"); };
private:
	QRadioButton *m_pRadioButtonAuto;
	QRadioButton *m_pRadioButtonStatic;
};

class WizardPageStaticIP : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageStaticIP(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual ConnectionWizard::wizardPages getNextPage(void) { return ConnectionWizard::pageFinishPage; };
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("Static IP Settings"); };
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
	virtual ConnectionWizard::wizardPages getNextPage(void) { return ConnectionWizard::pageNoPage; };
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("Finished"); };
	virtual bool isFinalPage(void) { return true; }
private:
	QPushButton *m_pConnectButton;
	QLineEdit *m_pConnectionName;
};

class WizardPageWirelessNetwork : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageWirelessNetwork(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual ConnectionWizard::wizardPages getNextPage(void);
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("Choose Wireless Network"); };
private:
	QRadioButton *m_pRadioButtonVisible;
	QRadioButton *m_pRadioButtonOther;
	QTableWidget *m_pTableWidget;
	SSIDList *m_pSSIDList;
};

class WizardPageWirelessInfo : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageWirelessInfo(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual ConnectionWizard::wizardPages getNextPage(void);
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("Wireless Network Settings"); };
private slots:
	void hiddenStateChanged(int);
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
	virtual ConnectionWizard::wizardPages getNextPage(void);
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("802.1X Settings"); };
private:
	QComboBox *m_pProtocol;
};

class WizardPageDot1XInnerProtocol : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageDot1XInnerProtocol(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual ConnectionWizard::wizardPages getNextPage(void);
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("802.1X Settings"); };
private:
	QComboBox *m_pProtocol;
	QLineEdit *m_pOuterID;
	QCheckBox *m_pValidateCert;
};

class WizardPageDot1XCert : public WizardPage
{
	Q_OBJECT
	
public:
	WizardPageDot1XCert(QWidget *parent, QWidget *parentWidget);
	virtual bool create(void);
	virtual ConnectionWizard::wizardPages getNextPage(void) { return ConnectionWizard::pageIPOptions; };
	virtual void init(void) {};
	virtual QString getHeaderString(void) { return tr("802.1X Settings"); };
private:
	QTableWidget *m_pCertTable;
	QLineEdit *m_pNameField;
	QCheckBox *m_pVerifyName;
};
#endif