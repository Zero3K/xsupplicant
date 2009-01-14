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

#ifndef _CONFIGCONNNETTAB_H_
#define _CONFIGCONNNETTAB_H_

#include "TabWidgetBase.h"
#include "xsupcalls.h"

class ConfigConnNetTab : public TabWidgetBase
 {
     Q_OBJECT

 public:
	 ConfigConnNetTab(QWidget *pRealWidget, XSupCalls *pSupplicant, config_connection *pConn, QWidget *parent);
	 ~ConfigConnNetTab();

	 bool attach();
	 bool save();

signals:
	 void signalDataChanged();
	 void signalChangeDHCP(bool);

public slots:
	 void slotDataChanged();		 

private slots:
	void slotDHCPtoggled(bool);

 private:
	 void updateWindow();

	 config_connection *m_pConn;

	 QWidget *m_pParent;

	 QWidget *m_pRealWidget;

	 QRadioButton *m_pDHCPRadioBtn;
	 QRadioButton *m_pStaticRadioBtn;
	 QCheckBox *m_pRenewDHCPCheckbox;
	 QLineEdit *m_pIPAddrEdit;
	 QLineEdit *m_pNetmaskEdit;
	 QLineEdit *m_pGWEdit;

	 XSupCalls *m_pSupplicant;

	 bool m_bDataChanged;
	 bool m_bConnected;
};

#endif  // _CONFIGCONNNETTAB_H_

