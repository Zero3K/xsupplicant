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
#include "ConfigConnAdaptTabWireless.h"

ConfigConnAdaptTabWireless::ConfigConnAdaptTabWireless(QWidget *pRealWidget, Emitter *e, XSupCalls *pSupplicant, config_connection *pConn, QString adaptName, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pSupplicant(pSupplicant), m_pConn(pConn), m_pParent(parent), m_pEmitter(e), m_AdapterName(adaptName)
{
	m_bConnected = false;
	m_bDataChanged = false;
	m_bTimerConnected = false;
}

ConfigConnAdaptTabWireless::~ConfigConnAdaptTabWireless()
{
	if (m_bTimerConnected)
	{
		Util::myDisconnect(&m_Timer, SIGNAL(timeout()), this, SLOT(slotScanTimeout()));
	}

	if (m_bConnected == true)
	{

		Util::myDisconnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

		if (m_pShowButton != NULL)
		{
			Util::myDisconnect(m_pShowButton, SIGNAL(clicked()), this, SLOT(slotShowHidePSK()));
		}

		 if (m_pRescan != NULL)
		 {
			 Util::myDisconnect(m_pRescan, SIGNAL(clicked()), this, SLOT(slotRescan()));
		 }

		Util::myDisconnect(m_pEmitter, SIGNAL(signalScanCompleteMessage(const QString &)), this, SLOT(slotScanComplete(const QString &)));

		Util::myDisconnect(m_pHiddenSSID, SIGNAL(toggled(bool)), this, SLOT(slotHiddenToggled(bool)));
		Util::myDisconnect(m_pHiddenSSID, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));

		Util::myDisconnect(m_pBroadcastCombo, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pHiddenName, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pAssociationType, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pProfile, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pProfile, SIGNAL(currentIndexChanged(int)), this, SLOT(slotProfileChanged(int)));
		Util::myDisconnect(m_pPSK, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pWEPLength, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pWEPLength, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChangeBitDepth(int)));
		Util::myDisconnect(m_pWEPKey, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
		Util::myDisconnect(m_pKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	}

	m_pBroadcastCombo = NULL;
}

void ConfigConnAdaptTabWireless::slotDataChanged()
{
	m_bDataChanged = true;
}

bool ConfigConnAdaptTabWireless::attach()
{
	 m_pBroadcastSSID = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioBroadcastSSID");
	 if (m_pBroadcastSSID == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton called 'dataRadioBroadcastSSID'."));
		 return false;
	 }

	 m_pHiddenSSID = qFindChild<QRadioButton*>(m_pRealWidget, "dataRadioHiddenSSID");
	 if (m_pHiddenSSID == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QRadioButton called 'dataRadioHiddenSSID'."));
		 return false;
	 }

	 m_pBroadcastCombo = qFindChild<QComboBox*>(m_pRealWidget, "dataComboBroadcastSSID");
	 if (m_pBroadcastCombo == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox called 'dataComboBroadcastSSID'."));
		 return false;
	 }

	 m_pHiddenName = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldHiddenSSID");
	 if (m_pHiddenName == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFieldHiddenSSID'."));
		 return false;
	 }

	 m_pAssociationType = qFindChild<QComboBox*>(m_pRealWidget, "dataComboWirelessAssociationMode");
	 if (m_pAssociationType == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox called 'dataComboWirelessAssociationMode'."));
		 return false;
	 }

	 m_pProfile = qFindChild<QComboBox*>(m_pRealWidget, "dataComboWirelessProfile");
	 if (m_pProfile == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox called 'dataComboWirelessProfile'."));
		 return false;
	 }

	 m_pPSK = qFindChild<QLineEdit*>(m_pRealWidget, "dataFieldWirelessPSK");
	 if (m_pPSK == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'dataFieldWirelessPSK'."));
		 return false;
	 }

	 m_pWEPLength = qFindChild<QComboBox*>(m_pRealWidget, "dataComboWEPKeyLength");
	 if (m_pWEPLength == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox called 'dataComboWEPKeyLength'."));
		 return false;
	 }

	 m_pWEPLength->setCurrentIndex(0);

	 m_pWEPKey = qFindChild<QLineEdit*>(m_pRealWidget, "wepKeyEdit");
	 if (m_pWEPKey == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLineEdit called 'wepKeyEdit'."));
		 return false;
	 }

	 m_pStack = qFindChild<QStackedWidget*>(m_pRealWidget, "widgetStackWirelessAuthentication");
	 if (m_pStack == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QWidgetStack called 'widgetStackWirelessAuthentication'."));
		 return false;
	 }

	 m_pKeyTypeLabel = qFindChild<QLabel*>(m_pRealWidget, "labelComboKeyType");
	 if (m_pKeyTypeLabel == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QLabel called 'labelComboKeyType'."));
		 return false;
	 }

	 m_pKeyTypeCombo = qFindChild<QComboBox*>(m_pRealWidget, "dataComboKeyType");
	 if (m_pKeyTypeCombo == NULL)
	 {
		 QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox called 'dataComboKeyType'."));
		 return false;
	 }

	 m_pShowButton = qFindChild<QPushButton*>(m_pRealWidget, "buttonShowPSK");

	 m_pRescan = qFindChild<QPushButton*>(m_pRealWidget, "buttonRescan");

	 m_pWirelessProfileLabel = qFindChild<QLabel*>(m_pRealWidget, "labelComboWirelessProfile");

	 m_pHexKeyLabel = qFindChild<QLabel*>(m_pRealWidget, "dataFieldHexCharacters");

	 m_pPSK->setEchoMode(QLineEdit::Password);
	 updateWindow();

	 // An SSID can be a MAX of 32 characters.
	 m_pHiddenName->setValidator(new QRegExpValidator(QRegExp("^[\\w|\\W]{0,32}$"), m_pHiddenName));
	 m_pBroadcastCombo->setValidator(new QRegExpValidator(QRegExp("^[\\w|\\W]{0,32}$"), m_pBroadcastCombo));
	 m_pWEPKey->setValidator(new QRegExpValidator(QRegExp("^[A-Fa-f0-9]{10,10}$"), m_pWEPKey));

	 if (m_pHexKeyLabel != NULL)
	 {
		 m_pHexKeyLabel->setText(tr("Enter 10 characters 0-9 or A-F"));
	 }

	 // A PSK *MUST* be at least 8 characters, but less than 64.
	 m_pPSK->setValidator(new QRegExpValidator(QRegExp("^[\\w|\\W]{8,32}$"), m_pPSK));

	 Util::myConnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

	 if (m_pShowButton != NULL)
	 {
		Util::myConnect(m_pShowButton, SIGNAL(clicked()), this, SLOT(slotShowHidePSK()));
	 }

	 if (m_pRescan != NULL)
	 {
		 Util::myConnect(m_pRescan, SIGNAL(clicked()), this, SLOT(slotRescan()));
		 m_pRescan->setText(tr("Rescan"));
	 }

	 Util::myConnect(m_pEmitter, SIGNAL(signalScanCompleteMessage(const QString &)), this, SLOT(slotScanComplete(const QString &)));

	 Util::myConnect(m_pHiddenSSID, SIGNAL(toggled(bool)), this, SLOT(slotHiddenToggled(bool)));
	 Util::myConnect(m_pHiddenSSID, SIGNAL(toggled(bool)), this, SIGNAL(signalDataChanged()));

	 Util::myConnect(m_pBroadcastCombo, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pHiddenName, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pAssociationType, SIGNAL(currentIndexChanged(const QString &)), this, SLOT(slotAssocChanged()));
	 Util::myConnect(m_pAssociationType, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pProfile, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pProfile, SIGNAL(currentIndexChanged(int)), this, SLOT(slotProfileChanged(int)));
	 Util::myConnect(m_pPSK, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pWEPLength, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pWEPLength, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChangeBitDepth(int)));
	 Util::myConnect(m_pWEPKey, SIGNAL(textChanged(const QString &)), this, SIGNAL(signalDataChanged()));
	 Util::myConnect(m_pKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SIGNAL(signalDataChanged()));

	 m_pSupplicant->getDeviceName(m_AdapterName, m_DeviceName, false);

	 m_bConnected = true;

	return true;
}

void ConfigConnAdaptTabWireless::updateWindow()
{
	clearFields();
	updateSSIDData();
	updateAssocData();
}

void ConfigConnAdaptTabWireless::clearFields()
{
	m_pBroadcastCombo->clear();
	m_pHiddenName->clear();
	m_pPSK->clear();
	m_pWEPKey->clear();
}

void ConfigConnAdaptTabWireless::populateSSIDs()
{
	ssid_info_enum *pSSIDs = NULL;
	int i = 0;

	m_pBroadcastCombo->clear();

	// If the interface isn't live, we should get an error, and skip the population of the SSIDs.
	if (m_pSupplicant->getBroadcastSSIDs(m_AdapterName, &pSSIDs))
	{
		// List them.
		while (pSSIDs[i].ssidname != NULL)
		{
			if ((pSSIDs[i].ssidname != NULL) && (strlen(pSSIDs[i].ssidname) > 0))
			{
				if (m_pBroadcastCombo->findText(QString(pSSIDs[i].ssidname)) < 0)
				{
					m_pBroadcastCombo->addItem(QString(pSSIDs[i].ssidname), QVariant(pSSIDs[i].abil));	
				}
			}
			i++;
		}

		m_pSupplicant->freeEnumSSID(&pSSIDs);
	}
}

void ConfigConnAdaptTabWireless::updateSSIDData()
{
	int index =  0;

	populateSSIDs();   // Will also return if the interface is enabled.

	if (m_pConn->flags & CONFIG_NET_IS_HIDDEN)
	{
		m_pBroadcastSSID->setChecked(false);
		m_pHiddenSSID->setChecked(true);
		m_pHiddenName->setText(QString(m_pConn->ssid));
		m_pRescan->setEnabled(false);
		slotHiddenToggled(true);

		if (m_pConn->association.pairwise_keys & CRYPT_FLAGS_CCMP)
		{
			m_pKeyTypeCombo->setCurrentIndex(0);
		}
		else if (m_pConn->association.pairwise_keys & CRYPT_FLAGS_TKIP)
		{
			m_pKeyTypeCombo->setCurrentIndex(1);
		}
		else if (m_pConn->association.pairwise_keys & CRYPT_FLAGS_WEP104)
		{
			m_pKeyTypeCombo->setCurrentIndex(2);
		}
		else
		{
			m_pKeyTypeCombo->setCurrentIndex(0);
		}
	}
	else
	{
		m_pRescan->setEnabled(true);
		m_pBroadcastSSID->setChecked(true);
		m_pHiddenSSID->setChecked(false);
		m_pHiddenName->clear();
		m_pHiddenName->setEnabled(false);

		if (m_pConn->ssid != NULL)
		{
			index = m_pBroadcastCombo->findText(QString(m_pConn->ssid));
			if (index < 0)  // It wasn't found.
			{
				m_pBroadcastCombo->addItem(QString(m_pConn->ssid), QVariant(0));
				index = m_pBroadcastCombo->findText(QString(m_pConn->ssid));
				m_pBroadcastCombo->setCurrentIndex(index);
			}
			else
			{
				m_pBroadcastCombo->setCurrentIndex(index);
			}
		}
		else
		{
			m_pBroadcastCombo->setCurrentIndex(0);
		}

		slotHiddenToggled(false);
	}
}

void ConfigConnAdaptTabWireless::setOpenNoAuth()
{
	int index = 0;

	if (m_pConn->association.txkey == 0)
	{
		index = m_pAssociationType->findText(tr("Open"));
		if (index < 0)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The association combo box seems to be missing the WPA2-Enterprise type!"));
			return;
		}
		m_pAssociationType->setCurrentIndex(index);
		m_pStack->setCurrentIndex(NO_AUTH_PAGE);
	}
	else
	{
		index = m_pAssociationType->findText(tr("Static WEP"));
		if (index < 0)
		{
			QMessageBox::critical(this, tr("Form Design Error"), tr("The association combo box seems to be missing the WPA2-Enterprise type!"));
			return;
		}
		m_pAssociationType->setCurrentIndex(index);
		m_pStack->setCurrentIndex(STATIC_WEP_PAGE);

		m_pWEPKey->setText(QString(m_pConn->association.keys[1]));
		if (m_pConn->association.keys[1] != NULL) 
		{
			if ((strlen(m_pConn->association.keys[1])/2) == 13)  // 104 bit wep.
			{
				m_pWEPLength->setCurrentIndex(1);
				m_pWEPKey->setValidator(new QRegExpValidator(QRegExp("^[A-Fa-f0-9]{26}$"), m_pWEPKey));
			}
			else
			{
				m_pWEPLength->setCurrentIndex(0);
				m_pWEPKey->setValidator(new QRegExpValidator(QRegExp("^[A-Fa-f0-9]{10}$"), m_pWEPKey));
			}
		}
	}
}

void ConfigConnAdaptTabWireless::setOpenEAP()
{
	int index = 0;

	index = m_pAssociationType->findText(tr("Dynamic WEP 802.1X"));
	if (index < 0)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The association combo box seems to be missing the WPA2-Enterprise type!"));
		return;
	}

	if (index < 0) index = 0;
	m_pAssociationType->setCurrentIndex(index);
	m_pStack->setCurrentIndex(PROFILE_PAGE);
}

void ConfigConnAdaptTabWireless::setWPAPSK()
{
	int index = 0;

	index = m_pAssociationType->findText(tr("WPA-Personal (PSK)"));
	if (index < 0)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The association combo box seems to be missing the WPA2-Enterprise type!"));
		return;
	}
	m_pAssociationType->setCurrentIndex(index);
	m_pStack->setCurrentIndex(PSK_PAGE);

	m_pPSK->setText(QString(m_pConn->association.psk));
}

void ConfigConnAdaptTabWireless::setWPA2PSK()
{
	int index = 0;

	index = m_pAssociationType->findText(tr("WPA2-Personal (PSK)"));
	if (index < 0)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The association combo box seems to be missing the WPA2-Enterprise type!"));
		return;
	}
	m_pAssociationType->setCurrentIndex(index);
	m_pStack->setCurrentIndex(PSK_PAGE);

	m_pPSK->setText(QString(m_pConn->association.psk));
}

void ConfigConnAdaptTabWireless::setWPAEAP()
{
	int index = 0;

	index = m_pAssociationType->findText(tr("WPA-Enterprise"));
	if (index < 0)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The association combo box seems to be missing the WPA2-Enterprise type!"));
		return;
	}

	if (index < 0) index = 0;

	m_pAssociationType->setCurrentIndex(index);
	m_pStack->setCurrentIndex(PROFILE_PAGE);
}

void ConfigConnAdaptTabWireless::setWPA2EAP()
{
	int index = 0;

	index = m_pAssociationType->findText(tr("WPA2-Enterprise"));
	if (index < 0)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The association combo box seems to be missing the WPA2-Enterprise type!"));
		return;
	}

	if (index < 0) index = 0;

	m_pAssociationType->setCurrentIndex(index);
	m_pStack->setCurrentIndex(PROFILE_PAGE);
}

void ConfigConnAdaptTabWireless::updateAssocData()
{
	switch (m_pConn->association.association_type)
	{
	case ASSOC_AUTO:
		// This will happen when a connection is first created, or when a user has manually created a connection.
		// In either case, we should set a new default so that everything works properly.
		setWPA2EAP();
		break;

	case ASSOC_OPEN:
		// Are we doing 802.1X?
		switch (m_pConn->association.auth_type)
		{
		default:
		case AUTH_UNKNOWN:
		case AUTH_PSK:
			// These types are either not, allowed, or we don't know what to do with them.
			QMessageBox::information(this, tr("Configuration Warning"), tr("This connection has it's authentication type set to a type that we cannot "
				"show valid information for.   If you make any changes, and attempt to save them, this configuration will be overwritten!"));
			break;

		case AUTH_NONE:
			// Set it to Open.
			setOpenNoAuth();
			break;

		case AUTH_EAP:
			// Set it to Dynamic WEP
			setOpenEAP();
			break;
		}
		break;

	case ASSOC_SHARED:
		// Not currently supported.
		QMessageBox::information(this, tr("Configuration Warning"), tr("This connection is using a shared key WEP association/authentication.  This UI "
			"doesn't support this method.  If you make any changes, and attempt to save them, this configuration will be overwritten!"));
		break;

	case ASSOC_LEAP:
		// Not currently supported.
		QMessageBox::information(this, tr("Configuration Warning"), tr("This connection is using Cisco's Network EAP association.  This UI does not "
			"support this method.  If you make any changes, and attempt to save them, this configuration will be overwritten!"));
		break;

	case ASSOC_WPA:
		// 802.1X, or PSK?
		switch (m_pConn->association.auth_type)
		{
		default:
		case AUTH_UNKNOWN:
		case AUTH_NONE:
			// These types are either not, allowed, or we don't know what to do with them.
			QMessageBox::information(this, tr("Configuration Warning"), tr("This connection has it's authentication type set to a type that we cannot "
				"show valid information for.   If you make any changes, and attempt to save them, this configuration will be overwritten!"));
			break;

		case AUTH_PSK:
			// Set it to PSK
			setWPAPSK();
			break;

		case AUTH_EAP:
			// Set it to Dynamic WEP
			setWPAEAP();
			break;
		}
		break;

	case ASSOC_WPA2:
		// 802.1X or PSK?
		switch (m_pConn->association.auth_type)
		{
		default:
		case AUTH_UNKNOWN:
		case AUTH_NONE:
			// These types are either not, allowed, or we don't know what to do with them.
			QMessageBox::information(this, tr("Configuration Warning"), tr("This connection has it's authentication type set to a type that we cannot "
				"show valid information for.   If you make any changes, and attempt to save them, this configuration will be overwritten!"));
			break;

		case AUTH_PSK:
			// Set it to Open.
			setWPA2PSK();
			break;

		case AUTH_EAP:
			// Set it to Dynamic WEP
			setWPA2EAP();
			break;
		}
		break;

	default:
		QMessageBox::critical(this, tr("Association Type Error"), tr("Your configuration references an association type that this UI doesn't understand."));
		break;
	}
}

void ConfigConnAdaptTabWireless::slotShowHidePSK()
{
	if (m_pPSK->echoMode() == QLineEdit::Password)
	{
		m_pShowButton->setText(tr("Hide"));
		m_pPSK->setEchoMode(QLineEdit::Normal);
	}
	else
	{
		m_pShowButton->setText(tr("Show"));
		m_pPSK->setEchoMode(QLineEdit::Password);
	}
}

void ConfigConnAdaptTabWireless::slotHiddenToggled(bool enabled)
{
	if (enabled)
	{
		m_pBroadcastCombo->setEnabled(false);
		m_pHiddenName->setEnabled(true);
		m_pRescan->setEnabled(false);
		m_pKeyTypeCombo->setEnabled(true);
		m_pKeyTypeLabel->setEnabled(true);
	}
	else
	{
		m_pBroadcastCombo->setEnabled(true);
		m_pHiddenName->setEnabled(false);
		m_pRescan->setEnabled(true);
		m_pKeyTypeCombo->setEnabled(false);
		m_pKeyTypeLabel->setEnabled(false);
	}
}

bool ConfigConnAdaptTabWireless::setSSIDdata()
{
	if (m_pHiddenSSID->isChecked())
	{
		// Save hidden SSID data.
		if (m_pHiddenName->text() == "")
		{
			QMessageBox::critical(this, tr("Invalid Data"), tr("You must specify the name of the SSID for a hidden network."));
			return false;
		}

		m_pConn->flags |= CONFIG_NET_IS_HIDDEN;

		if (m_pConn->ssid != NULL)
		{
			free(m_pConn->ssid);
			m_pConn->ssid = NULL;
		}

		m_pConn->ssid = _strdup(m_pHiddenName->text().toAscii());
	}
	else
	{
		// Save broadcast SSID data.
		if (m_pBroadcastCombo->currentText() == "")
		{
			QMessageBox::critical(this, tr("Invalid Data"), tr("You must select an SSID from the broadcast SSID drop down list."));
			return false;
		}

		m_pConn->flags &= (~CONFIG_NET_IS_HIDDEN);  // This is a broadcast network.

		if (m_pConn->ssid != NULL)
		{
			free(m_pConn->ssid);
			m_pConn->ssid = NULL;
		}

		m_pConn->ssid = _strdup(m_pBroadcastCombo->currentText().toAscii());
	}
	
	return true;
}

bool ConfigConnAdaptTabWireless::setKeyType()
{
	if (m_pHiddenSSID->isChecked())
	{
		switch (m_pKeyTypeCombo->currentIndex())
		{
		case 0:  // CCMP
			m_pConn->association.pairwise_keys = CRYPT_FLAGS_CCMP;
			break;

		case 1:  // TKIP
			m_pConn->association.pairwise_keys = CRYPT_FLAGS_TKIP;
			break;

		case 2:  // WEP
			m_pConn->association.pairwise_keys = CRYPT_FLAGS_WEP104;
			break;

		default:
			QMessageBox::critical(this, tr("Invalid Data"), tr("An invalid key method of '%1' was selected!").arg(m_pKeyTypeCombo->currentText()));
			return false;
		}
	}

	return true;
}

bool ConfigConnAdaptTabWireless::saveWPA2Enterprise()
{
	m_pSupplicant->freeConfigAssociation(&m_pConn->association);

	setKeyType();

	m_pConn->association.association_type = ASSOC_WPA2;
	m_pConn->association.auth_type = AUTH_EAP;

	if (m_pConn->profile != NULL)
	{
		free(m_pConn->profile);
		m_pConn->profile = NULL;
	}

	if (m_pProfile->currentIndex() > 0)
	{
		m_pConn->profile = _strdup(m_pProfile->currentText().toAscii());
	}

	return true;
}

bool ConfigConnAdaptTabWireless::saveWPA2PSK()
{
	m_pSupplicant->freeConfigAssociation(&m_pConn->association);

	setKeyType();

	m_pConn->association.association_type = ASSOC_WPA2;
	m_pConn->association.auth_type = AUTH_PSK;

	if (m_pConn->profile != NULL)
	{
		free(m_pConn->profile);
		m_pConn->profile = NULL;
	}

	if (m_pConn->association.psk != NULL)
	{
		free(m_pConn->association.psk);
		m_pConn->association.psk = NULL;
	}


	if (m_pPSK->text() != "")
	{
		if (strlen(m_pPSK->text().toAscii()) < 8)
		{
			QMessageBox::critical(this, tr("Configuration Error"), tr("Your pre-shared key (PSK) must be at least 8 characters long."));
			return false;
		}

		m_pConn->association.psk = _strdup(m_pPSK->text().toAscii());
	}

	return true;
}

bool ConfigConnAdaptTabWireless::saveWPAEnterprise()
{
	m_pSupplicant->freeConfigAssociation(&m_pConn->association);

	setKeyType();

	m_pConn->association.association_type = ASSOC_WPA;
	m_pConn->association.auth_type = AUTH_EAP;

	if (m_pConn->profile != NULL)
	{
		free(m_pConn->profile);
		m_pConn->profile = NULL;
	}

	if (m_pProfile->currentIndex() > 0)
	{
		m_pConn->profile = _strdup(m_pProfile->currentText().toAscii());
	}

	return true;
}

bool ConfigConnAdaptTabWireless::saveWPAPSK()
{
	m_pSupplicant->freeConfigAssociation(&m_pConn->association);

	setKeyType();

	m_pConn->association.association_type = ASSOC_WPA;
	m_pConn->association.auth_type = AUTH_PSK;

	if (m_pConn->profile != NULL)
	{
		free(m_pConn->profile);
		m_pConn->profile = NULL;
	}

	if (m_pConn->association.psk != NULL)
	{
		free(m_pConn->association.psk);
		m_pConn->association.psk = NULL;
	}


	if (m_pPSK->text() != "")
	{
		if (strlen(m_pPSK->text().toAscii()) < 8)
		{
			QMessageBox::critical(this, tr("Configuration Error"), tr("Your pre-shared key (PSK) must be at least 8 characters long."));
			return false;
		}

		m_pConn->association.psk = _strdup(m_pPSK->text().toAscii());
	}

	return true;
}

bool ConfigConnAdaptTabWireless::saveWEPdot1X()
{
	m_pSupplicant->freeConfigAssociation(&m_pConn->association);

	m_pConn->association.association_type = ASSOC_OPEN;
	m_pConn->association.auth_type = AUTH_EAP;

	if (m_pConn->profile != NULL)
	{
		free(m_pConn->profile);
		m_pConn->profile = NULL;
	}

	if (m_pProfile->currentIndex() > 0)
	{
		m_pConn->profile = _strdup(m_pProfile->currentText().toAscii());
	}

	return true;
}

bool ConfigConnAdaptTabWireless::saveStaticWEP()
{
	if ((m_pWEPLength->currentIndex() == 0) && (strlen(m_pWEPKey->text().toAscii()) != 10))
	{
		QMessageBox::critical(this, tr("Configuration Error"), tr("The WEP key you entered is invalid.  It must be exactly 10 characters long."));
		return false;
	}
	else if ((m_pWEPLength->currentIndex() == 1) && (strlen(m_pWEPKey->text().toAscii()) != 26))
	{
		QMessageBox::critical(this, tr("Configuration Error"), tr("The WEP key you entered is invalid.  It must be exactly 26 characters long."));
		return false;
	}

	m_pSupplicant->freeConfigAssociation(&m_pConn->association);

	m_pConn->association.association_type = ASSOC_OPEN;
	m_pConn->association.auth_type = AUTH_NONE;

	m_pConn->association.txkey = 1;  // Always 1 for now.

	if (m_pConn->association.keys[1] != NULL)
	{
		free(m_pConn->association.keys[1]);
		m_pConn->association.keys[1] = NULL;
	}

	m_pConn->association.keys[1] = _strdup(m_pWEPKey->text().toAscii());

	if (m_pConn->profile != NULL)
	{
		free(m_pConn->profile);
		m_pConn->profile = NULL;
	}

	return true;
}

bool ConfigConnAdaptTabWireless::saveOpen()
{
	m_pSupplicant->freeConfigAssociation(&m_pConn->association);

	m_pConn->association.association_type = ASSOC_OPEN;
	m_pConn->association.auth_type = AUTH_NONE;

	if (m_pConn->profile != NULL)
	{
		free(m_pConn->profile);
		m_pConn->profile = NULL;
	}

	return true;
}

bool ConfigConnAdaptTabWireless::setAssocAuthData()
{
	if (m_pAssociationType->currentText() == tr("WPA2-Enterprise"))
	{
		if (saveWPA2Enterprise() == false) return false;
	}
	else if(m_pAssociationType->currentText() == tr("WPA2-Personal (PSK)"))
	{
		if (saveWPA2PSK() == false) return false;
	}
	else if (m_pAssociationType->currentText() == tr("WPA-Enterprise"))
	{
		if (saveWPAEnterprise() == false) return false;
	}
	else if (m_pAssociationType->currentText() == tr("WPA-Personal (PSK)"))
	{
		if (saveWPAPSK() == false) return false;
	}
	else if (m_pAssociationType->currentText() == tr("Dynamic WEP 802.1X"))
	{
		if (saveWEPdot1X() == false) return false;
	}
	else if (m_pAssociationType->currentText() == tr("Static WEP"))
	{
		if (saveStaticWEP() == false) return false;
	}
	else if (m_pAssociationType->currentText() == tr("Open"))
	{
		if (saveOpen() == false) return false;
	}
	else
	{
		QMessageBox::critical(this, tr("Error"), tr("An unknown association/authentication type was selected!"));
		return false;
	}

	return true;
}

bool ConfigConnAdaptTabWireless::save()
{
	// Save SSID data
	if (setSSIDdata() == false) return false;

	// Set association/authentication data
	if (setAssocAuthData() == false) return false;

	if (m_pPSK->echoMode() == QLineEdit::Normal) slotShowHidePSK();

	return true;
}

void ConfigConnAdaptTabWireless::slotRescan()
{
	m_pRescan->setText(tr("Scanning"));
	m_pRescan->setEnabled(false);

	if (m_pSupplicant->startWirelessScan(m_AdapterName) == false)
	{
		QMessageBox::critical(this, tr("Scan Error"), tr("Unable to start a scan on this interface."));
		m_pRescan->setText(tr("Rescan"));
		m_pRescan->setEnabled(true);
	}

	m_Timer.setInterval(30000);  // Give it 30 seconds to time out on.
	m_Timer.start();

	m_bTimerConnected = true;

	Util::myConnect(&m_Timer, SIGNAL(timeout()), this, SLOT(slotScanTimeout()));
}

void ConfigConnAdaptTabWireless::slotAssocChanged()
{
	if (m_pAssociationType->currentText() == tr("WPA2-Enterprise"))
	{
		m_pStack->setCurrentIndex(PROFILE_PAGE);
	}
	else if(m_pAssociationType->currentText() == tr("WPA2-Personal (PSK)"))
	{
		m_pStack->setCurrentIndex(PSK_PAGE);
	}
	else if (m_pAssociationType->currentText() == tr("WPA-Enterprise"))
	{
		m_pStack->setCurrentIndex(PROFILE_PAGE);
	}
	else if (m_pAssociationType->currentText() == tr("WPA-Personal (PSK)"))
	{
		m_pStack->setCurrentIndex(PSK_PAGE);
	}
	else if (m_pAssociationType->currentText() == tr("Dynamic WEP 802.1X"))
	{
		m_pStack->setCurrentIndex(PROFILE_PAGE);
	}
	else if (m_pAssociationType->currentText() == tr("Static WEP"))
	{
		m_pStack->setCurrentIndex(STATIC_WEP_PAGE);
	}
	else if (m_pAssociationType->currentText() == tr("Open"))
	{
		m_pStack->setCurrentIndex(NO_AUTH_PAGE);
	}
	else
	{
		QMessageBox::critical(this, tr("Error"), tr("An unknown association/authentication type was selected!"));
	}
}

void ConfigConnAdaptTabWireless::slotScanComplete(const QString &scanInt)
{
	ssid_info_enum *pSSIDs = NULL;
	int i = 0;

	if (m_DeviceName != scanInt) return;

	if (m_bTimerConnected)
	{
		m_Timer.stop();
		Util::myDisconnect(&m_Timer, SIGNAL(timeout()), this, SLOT(slotScanTimeout()));
		m_bTimerConnected = false;
	}

	// We got a scan complete message, so request an update.
	if (m_pSupplicant->getBroadcastSSIDs(m_AdapterName, &pSSIDs) == true)
	{
		// Go through our list, and add the ones that aren't already there.
		while (pSSIDs[i].ssidname != NULL)
		{
			if ((pSSIDs[i].ssidname != NULL) && (strlen(pSSIDs[i].ssidname) > 0))
			{
				if (m_pBroadcastCombo->findText(QString(pSSIDs[i].ssidname)) < 0)
				{
					// We need to add it.
					m_pBroadcastCombo->addItem(QString(pSSIDs[i].ssidname), QVariant(pSSIDs[i].abil));
				}
			}

			i++;
		}
	}

	m_pRescan->setText(tr("Rescan"));
	m_pRescan->setEnabled(true);
}

void ConfigConnAdaptTabWireless::slotScanTimeout()
{
	m_Timer.stop();

	QMessageBox::information(this, tr("Scan Timeout"), tr("The attempt to rescan for wireless networks timed out.  Your SSID list could not be updated."));
	Util::myDisconnect(&m_Timer, SIGNAL(timeout()), this, SLOT(slotScanTimeout()));
	m_bTimerConnected = false;
	m_pRescan->setEnabled(true);
	m_pRescan->setText(tr("Rescan"));
}

void ConfigConnAdaptTabWireless::setLabelInvalid(QLabel *toEditLabel)
{
	QPalette *mypalette;

	if (toEditLabel == NULL) return;

	m_NormalColor = toEditLabel->palette().color(QPalette::WindowText);

	mypalette = new QPalette();

	mypalette->setColor(QPalette::WindowText, QColor(255, 0, 0));  // Set the color to red.
	toEditLabel->setPalette((*mypalette));

	delete mypalette;

	toEditLabel->setToolTip(tr("You cannot use this Connection until you select a valid Profile."));
	m_pProfile->setToolTip(tr("You cannot use this Connection until you select a valid Profile."));	
}

void ConfigConnAdaptTabWireless::setLabelValid(QLabel *toEditLabel)
{
	QPalette *mypalette;

	if (toEditLabel == NULL) return;

	mypalette = new QPalette();

	mypalette->setColor(QPalette::WindowText, m_NormalColor);

	toEditLabel->setPalette((*mypalette));

	delete mypalette;

	toEditLabel->setToolTip("");  // Clear the tool tip.
	m_pProfile->setToolTip("");
}

void ConfigConnAdaptTabWireless::slotProfileChanged(int newSelection)
{
	if (newSelection == 0)
	{
		setLabelInvalid(m_pWirelessProfileLabel);
	}
	else
	{
		setLabelValid(m_pWirelessProfileLabel);
	}
}

void ConfigConnAdaptTabWireless::slotChangeBitDepth(int selected)
{
	if (selected == 1)
	{
		m_pWEPKey->setValidator(new QRegExpValidator(QRegExp("^[A-Fa-f0-9]{26}$"), m_pWEPKey));

		if (m_pHexKeyLabel != NULL)
		{
			 m_pHexKeyLabel->setText(tr("Enter 26 characters 0-9 or A-F"));
		}
	}
	else
	{
		m_pWEPKey->setValidator(new QRegExpValidator(QRegExp("^[A-Fa-f0-9]{10}$"), m_pWEPKey));

		if (m_pHexKeyLabel != NULL)
		{
			m_pHexKeyLabel->setText(tr("Enter 10 characters 0-9 or A-F"));
		}
	}
}
