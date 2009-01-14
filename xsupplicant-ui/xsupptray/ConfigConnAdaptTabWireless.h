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

#ifndef _CONFIGCONNADAPTTABWIRELESS_H_
#define _CONFIGCONNADAPTTABWIRELESS_H_

#include <QWidget>

#include "xsupcalls.h"

class ConfigConnAdaptTabWireless : public QWidget
 {
     Q_OBJECT

 public:
	 ConfigConnAdaptTabWireless(QWidget *pRealWidget, Emitter *e, XSupCalls *pSupplicant, config_connection *pConn, QString adaptName, QWidget *parent);
	 ~ConfigConnAdaptTabWireless();

	 bool attach();
	 bool save();

signals:
	 void signalDataChanged();

private slots:
	 void slotDataChanged();		 
	 void slotShowHidePSK();
	 void slotHiddenToggled(bool);
	 void slotAssocChanged();
	 void slotRescan();
	 void slotScanComplete(const QString &);
	 void slotScanTimeout();
	 void slotProfileChanged(int);
	 void slotChangeBitDepth(int);
	 void adapterInserted();

 private:

	 enum {
		 PROFILE_PAGE,
		 PSK_PAGE,
		 STATIC_WEP_PAGE,
		 NO_AUTH_PAGE
	 };

	void updateWindow();
	void updateSSIDData();
	void updateAssocData();
	void clearFields();
	void populateSSIDs();

	// Set the window for different association/auth combinations.
	void setOpenNoAuth();
	void setOpenEAP();
	void setWPAPSK();
	void setWPA2PSK();
	void setWPAEAP();
	void setWPA2EAP();
	bool setSSIDdata();
	bool setAssocAuthData();
	bool saveWPA2Enterprise();
	bool saveWPA2PSK();
	bool saveWPAEnterprise();
	bool saveWPAPSK();
	bool saveWEPdot1X();
	bool saveStaticWEP();
	bool saveOpen();
	bool setKeyType();
	 void setLabelInvalid(QLabel *);
	 void setLabelValid(QLabel *);

	 config_connection *m_pConn;

	 QWidget *m_pParent;

	 QWidget *m_pRealWidget;

	 XSupCalls *m_pSupplicant;
	 Emitter *m_pEmitter;

	 QRadioButton *m_pBroadcastSSID;
	 QRadioButton *m_pHiddenSSID;
	 QComboBox *m_pBroadcastCombo;
	 QLineEdit *m_pHiddenName;
	 QComboBox *m_pAssociationType;
	 QComboBox *m_pProfile;
	 QLineEdit *m_pPSK;
	 QComboBox *m_pWEPLength;
	 QLineEdit *m_pWEPKey;
	 QStackedWidget *m_pStack;
	 QPushButton *m_pShowButton;
	 QPushButton *m_pRescan;
 	 QLabel *m_pWirelessProfileLabel;
	 QLabel *m_pHexKeyLabel;
	 QLabel *m_pKeyTypeLabel;
	 QComboBox *m_pKeyTypeCombo;

	 QString m_AdapterName;
	 QString m_DeviceName;

	 QTimer m_Timer;

 	 QColor m_NormalColor;

	 bool m_bTimerConnected;
	 bool m_bDataChanged;
	 bool m_bConnected;
};

#endif  // _CONFIGCONNADAPTTABWIRELESS_H_
