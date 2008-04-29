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

#ifndef _CONFIGWIDGETEDITTRUSTEDSERVERS_H_
#define _CONFIGWIDGETEDITTRUSTEDSERVERS_H_

#include "ConfigWidgetBase.h"
#include "TrustedRootCertsDlg.h"
#include "xsupcalls.h"
#include "NavPanel.h"

class ConfigWidgetEditTrustedServers : public ConfigWidgetBase
 {
     Q_OBJECT

 public:
	 ConfigWidgetEditTrustedServers(QWidget *pRealWidget, QString serverName, XSupCalls *xsup, NavPanel *pPanel, QWidget *parent);
	 ~ConfigWidgetEditTrustedServers();

	 bool attach();
	 bool save();
	 bool dataChanged();
	 bool newItem();
	 void discard();
	 void detach();
	 void getPageName(QString &);

private slots:
	 void slotDataChanged();
	 void slotBrowse();
	 void slotValidateCheckbox(int);
	 void slotServerRenamed(const QString &);
	 void slotServerSelected();
	 void slotServerCanceled();
	 void slotShowHelp();

 private:
	void updateWindow();
	void updateCertData();

	 QWidget *m_pParent;

	 XSupCalls *m_pSupplicant;

	 QWidget *m_pRealWidget;

	 TrustedRootCertsDlg *m_pServerPicker;

	 QString m_originalServername;
	 QString m_lastServername;

	 QLineEdit *m_pCNEdit;
	 QLineEdit *m_pServerNameEdit;
	 QCheckBox *m_pValidateServer;
	 QPushButton *m_pbuttonBrowse;
	 QLabel *m_pCertCNLabel;
	 QLabel *m_pCertDeptLabel;
	 QLabel *m_pCertCompanyLabel;
	 QLabel *m_pCertLocationLabel;
	 QLabel *m_pCertStateLabel;
	 QLabel *m_pCertOULabel;
	 QLabel *m_pCertDomainLabel;
	 QLabel *m_pCertPurposeLabel;

	 bool m_bChangedData;
	 bool m_bNewServer;
	 bool m_bServerRenamed;

	 NavPanel *m_pNavPanel;

	 config_trusted_server *m_pTrustedServer;
};

#endif // _CONFIGWIDGETEDITTRUSTEDSERVERS_H_

