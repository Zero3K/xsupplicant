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

#ifndef _TRUSTEDROOTCERTSDLG_H_
#define _TRUSTEDROOTCERTSDLG_H_

#include <QWidget>
#include "xsupcalls.h"

class TrustedRootCertsDlg : public QWidget
{
  Q_OBJECT 

public:
  TrustedRootCertsDlg(XSupCalls &sup, QWidget *parent);
  virtual ~TrustedRootCertsDlg(void);
  void getCurrentCertificate(QString &certStoreType, QString &certLocation);

  bool attach();
  void show();

signals:
  void signalAccept();
  void signalCancel();

private:
  void updateWindow();
  void addRowsToCertTable();
  bool getCerts();

  QWidget *m_pRealWidget;
  QWidget *m_pParent;

  QPushButton *m_pOkButton;
  QPushButton *m_pCancelButton;
  QPushButton *m_pHelpButton;
  QTableWidget *m_pCertificateTable; 
  QPushButton *m_pImportButton;

  XSupCalls &m_supplicant;
  QString m_certStoreType;
  QString m_certLocation;
  cert_enum *m_pCertificates;
  cert_info m_certInfo;

  int m_CNCol;
  int m_issuedToCol;
  int m_issuedByCol;
  int m_expirationCol;
  int m_friendlyNameCol;
  int m_locationCol;

  private slots:
    void slotImport();

  public slots:
    void slotHelp();
};

#endif // _TRUSTEDROOTCERTSDLG_H_

