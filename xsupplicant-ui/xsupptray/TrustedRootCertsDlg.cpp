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

#include "FormLoader.h"
#include "TrustedRootCertsDlg.h"
#include "Util.h"
#include "helpbrowser.h"

TrustedRootCertsDlg::TrustedRootCertsDlg(XSupCalls &sup, QWidget *parent):
  m_pParent(parent), m_supplicant(sup), m_pCertificates(NULL)
{
  memset(&m_certInfo, 0x00, sizeof(m_certInfo));
  m_pRealWidget = NULL;
  m_pHelpButton = NULL;
  m_pCertificates = NULL;
}


TrustedRootCertsDlg::~TrustedRootCertsDlg(void)
{
  m_supplicant.freeEnumCertificates(&m_pCertificates);

	if (m_pHelpButton != NULL)
	{
		Util::myDisconnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotHelp()));
	}

	Util::myDisconnect(m_pCancelButton, SIGNAL(clicked()), this, SIGNAL(signalCancel()));
	Util::myDisconnect(m_pOkButton, SIGNAL(clicked()), this, SIGNAL(signalAccept()));
	Util::myDisconnect(m_pRealWidget, SIGNAL(rejected()), this, SIGNAL(signalCancel()));
	Util::myDisconnect(m_pCertificateTable, SIGNAL(cellDoubleClicked(int, int)), this, SIGNAL(signalAccept()));
	Util::myDisconnect(m_pImportButton, SIGNAL(clicked()), this, SLOT(slotImport()));

	if (m_pRealWidget != NULL) delete m_pRealWidget;
}

bool TrustedRootCertsDlg::attach()
{
	Qt::WindowFlags flags;

	m_pRealWidget = FormLoader::buildform("SelectTrustedServerDlg.ui");
	if (m_pRealWidget == NULL) 
	{
		QMessageBox::critical(this, tr("Form Load Error"), tr("Unable to load the 'SelectTrustedServerDlg.ui' form."));
		return false;
	}

	flags = m_pRealWidget->windowFlags();
	flags &= (~Qt::WindowContextHelpButtonHint);
	m_pRealWidget->setWindowFlags(flags);

	m_pCertificateTable = qFindChild<QTableWidget*>(m_pRealWidget, "certTableWidget");
	if (m_pCertificateTable == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QTableWidget named 'certTableWidget'."));
		return false;
	}

	m_pOkButton = qFindChild<QPushButton*>(m_pRealWidget, "okBtn");
	if (m_pOkButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QPushButton named 'okBtn'."));
		return false;
	}

	m_pCancelButton = qFindChild<QPushButton*>(m_pRealWidget, "cancelBtn");
	if (m_pCancelButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable the locate the QPushButton named 'cancelBtn'."));
		return false;
	}

	m_pImportButton = qFindChild<QPushButton*>(m_pRealWidget, "importBtn");
	if (m_pImportButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QPushButton named 'importBtn'."));
		return false;
	}

	m_pHelpButton = qFindChild<QPushButton*>(m_pRealWidget, "helpBtn");
	if (m_pHelpButton != NULL)
	{
		Util::myConnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotHelp()));
	}

	Util::myConnect(m_pCancelButton, SIGNAL(clicked()), this, SIGNAL(signalCancel()));
	Util::myConnect(m_pOkButton, SIGNAL(clicked()), this, SIGNAL(signalAccept()));
	Util::myConnect(m_pRealWidget, SIGNAL(rejected()), this, SIGNAL(signalCancel()));
	Util::myConnect(m_pCertificateTable, SIGNAL(cellDoubleClicked(int, int)), this, SIGNAL(signalAccept()));
	Util::myConnect(m_pImportButton, SIGNAL(clicked()), this, SLOT(slotImport()));

	m_issuedToCol = 0;
	m_issuedByCol = 1;
	m_CNCol = 2;
	m_expirationCol = 3;
	m_friendlyNameCol = 4;
	m_locationCol = 5;

	m_pCertificateTable->setColumnCount(6);  // Bump it up one to store the location data.  
	m_pCertificateTable->setColumnHidden(m_locationCol, true);  // Then hide the location data. ;)

	m_pCertificateTable->resizeColumnsToContents();
	m_pCertificateTable->horizontalHeader()->setStretchLastSection(true);

	updateWindow();

	return true;
}

void TrustedRootCertsDlg::updateWindow()
{
  getCerts();
  addRowsToCertTable();
}

//! addRowsToCertTable
/*!
  \brief Populates the certificates table using information from the supplicant

*/
void TrustedRootCertsDlg::addRowsToCertTable()
{
  int i = 0;
  int count = 0;
  bool sorting = false;

  if (m_pCertificates)
  {
    while (m_pCertificates[count].certname != NULL)
    {
      count++;
    }

    m_pCertificateTable->setRowCount(count);
    m_pCertificateTable->clearContents();
    m_pCertificateTable->setTextElideMode(Qt::ElideRight);

	sorting = m_pCertificateTable->isSortingEnabled();

	if (sorting)
	{
		m_pCertificateTable->setSortingEnabled(false);
	}

    // Only allow one to be selected at a time
    m_pCertificateTable->setSelectionMode(QAbstractItemView::SingleSelection);

    while (m_pCertificates[i].certname != NULL)
    {
      QTableWidgetItem *item = new QTableWidgetItem;
      item->setText(QString(m_pCertificates[i].certname)); 
      item->setFlags(item->flags() & ~Qt::ItemIsEditable);
      m_pCertificateTable->setItem(i, m_issuedToCol, item);

      QTableWidgetItem *issuer = new QTableWidgetItem;
      issuer->setText(QString(m_pCertificates[i].issuer)); 
      issuer->setFlags(issuer->flags() & ~Qt::ItemIsEditable);
      m_pCertificateTable->setItem(i, m_issuedByCol, issuer);

      item = new QTableWidgetItem;
      QDate d(m_pCertificates[i].year, m_pCertificates[i].month, m_pCertificates[i].day);
      QString date = d.toString("MM/dd/yyyy"); // tr need to change this for appropriate locales
      item->setText(date);
      item->setFlags(item->flags() & ~Qt::ItemIsEditable);
      m_pCertificateTable->setItem(i, m_expirationCol, item);

      item = new QTableWidgetItem;
      item->setText(QString(m_pCertificates[i].friendlyname));
      item->setFlags(item->flags() & ~Qt::ItemIsEditable);
      m_pCertificateTable->setItem(i, m_friendlyNameCol, item);

      item = new QTableWidgetItem;
	    item->setText(QString(m_pCertificates[i].commonname));
      item->setFlags(item->flags() & ~Qt::ItemIsEditable);
      m_pCertificateTable->setItem(i, m_CNCol, item);

	  item = new QTableWidgetItem;
	  item->setText(QString(m_pCertificates[i].location));
	  item->setFlags(item->flags() & ~Qt::ItemIsEditable);
	  m_pCertificateTable->setItem(i, m_locationCol, item);
	  
      i++; 
    }

	m_pCertificateTable->setSortingEnabled(sorting);
	m_pCertificateTable->sortByColumn(0, Qt::AscendingOrder);
  }
}

void TrustedRootCertsDlg::slotImport()
{
	QString result;
	char *path = NULL;
	int err = 0;

  result = QFileDialog::getOpenFileName(NULL, tr("Select a certificate to import"), "c:/", tr("DER Encoded Certificates (*.cer;*.der)"));

  if (result != "")
  {
#ifdef WINDOWS
	  result.replace(QString("/"), QString("\\"));
#endif

	  path = strdup(result.toAscii());
	  err = xsupgui_request_add_root_ca_certificate(path);

	  if (err != REQUEST_SUCCESS)
	  {
		  QMessageBox::critical(this, tr("Certificate Error"), tr("Unable to add the certificate to the certificate store.  Please be sure that it is a valid DER encoded certificate."));
	  }
	  else
	  {
		  QMessageBox::information(this, tr("Certificate Added"), tr("The certificate has been added to the certificate store."));
		  if (getCerts())
		  {
			  addRowsToCertTable();
		  }
	  }
  }
}

void TrustedRootCertsDlg::slotHelp()
{
  HelpBrowser::showPage("xsupphelp.html", "xsupservercert");
}

//! getCurrentCertificate
/*!
  \brief Get the currently selected certificate
  \param[out] certInfo - the certificate information - may be empty if it couldn't be read
*/
void TrustedRootCertsDlg::getCurrentCertificate(QString &certStoreType, QString &certLocation)
{
  certStoreType = "WINDOWS";

  m_pCertificateTable->setColumnHidden(m_locationCol, false);  // Need to unhide it to use it.

  QList <QTableWidgetItem *>items = m_pCertificateTable->selectedItems();

  if (items.count() == 0 || items.count() < 6)
  {
	  certLocation = "";
  }
  else
  {
    QTableWidgetItem *p = items.at(5); // column 5 is the location

	certLocation = p->text();
  }

  m_pCertificateTable->setColumnHidden(m_locationCol, true);  // Hide it again, just in case.
}

//! getCerts
/*!
  \brief Get the certificates
  Get the appropriate data for the screen
  \param[in] type - client, server, or both
*/
bool TrustedRootCertsDlg::getCerts()
{
  m_supplicant.freeEnumCertificates(&m_pCertificates);
 
  return m_supplicant.enumCertificates(&m_pCertificates);
}

void TrustedRootCertsDlg::show()
{
	m_pRealWidget->show();
}

