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

#include "stdafx.h"

#include "FormLoader.h"
#include "AboutDlg.h"
#include "xsupcalls.h"
#include "Util.h"
#include "TrayApp.h"

#include "version.h"
#include "buildnum.h"

//! Constructor
/*!
  \brief Sets up the fields   

  \note  We don't build the proxied form here, because we need to be able to
         return a failure status if the form can't be loaded from the disk.

  \param[in] parent
  \return nothing
*/
AboutWindow::AboutWindow(QWidget *parent)
     : QWidget(parent),
     m_supplicant(this)
{
	m_versionString    = VERSION".";
	m_versionString    += BUILDNUM;
	m_pRealForm        = NULL;
	m_pDialog          = NULL;
	m_pTitleImageLabel = NULL;
	m_pSupVersion      = NULL;
	m_pGUIVersion      = NULL;
	m_pbuttonClose     = NULL;

	m_postureVersionString = ((TrayApp *)parent)->m_pluginVersionString;
}


//! Destructor
/*!
  \brief Clears out whatever needs to be cleared out
  \return nothing
*/
AboutWindow::~AboutWindow()
{
	if (m_pRealForm != NULL) 
	{
		Util::myDisconnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));
		delete m_pRealForm;
	}
}

bool AboutWindow::create()
{
	QLabel *pTemp = NULL;

	m_pRealForm = FormLoader::buildform("AboutWindow.ui");

	if (m_pRealForm == NULL) return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pSupVersion = qFindChild<QLabel*>(m_pRealForm, "dataFieldEngineVersion");

	if (m_pSupVersion == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'About Dialog' did not contain the 'dataFieldEngineVersion' label.  The engine version will not be displayed properly."));
	}

	m_pGUIVersion = qFindChild<QLabel*>(m_pRealForm, "dataFieldGUIVersion");

	if (m_pGUIVersion == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'About Dialog' did not contain the 'dataFieldGUIVersion' label.  The GUI version will not be displayed properly."));
	}

	m_pLocale = qFindChild<QLabel*>(m_pRealForm, "currentLocale");

	m_pdataFieldPostureVersion = qFindChild<QLabel *>(m_pRealForm, "dataFieldPostureVersion");

	m_pdataFieldPlugins = qFindChild<QLabel*>(m_pRealForm, "dataFieldPlugins");

	if (m_pdataFieldPlugins == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'About Dialog' did not contain the 'dataFieldPlugins' label.  The plugins section of the About Dialog will be incorrect."));
	}

	m_pbuttonClose = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");

	// If m_pbuttonClose is NULL, then there isn't a close button.  We don't consider that to be a problem, so don't complain.
	if (m_pbuttonClose != NULL)
	{
		m_pbuttonClose->setText(tr("Close"));

	    QObject::connect(m_pbuttonClose, SIGNAL(clicked()),
		                  this, SIGNAL(close()));
	}

	// We need to attach to the various pieces of text in the form and put the text in so that linguist picks up the strings
	// as needing to be translated.  (It is okay to acquire a pointer here, and then overwrite it.  Deleting the pointer would
	// make a mess of the form, and we don't need to update this information later.)
	pTemp = qFindChild<QLabel*>(m_pRealForm, "headerProductInformation");
	if (pTemp != NULL) pTemp->setText(tr("Product Information"));

	pTemp = qFindChild<QLabel*>(m_pRealForm, "headerVersionInformation");
	if (pTemp != NULL) pTemp->setText(tr("Version Information"));

	pTemp = qFindChild<QLabel*>(m_pRealForm, "headerContactInformation");
	if (pTemp != NULL) pTemp->setText(tr("Contact Information"));

	pTemp = qFindChild<QLabel*>(m_pRealForm, "labelMoreInformation");
	if (pTemp != NULL) pTemp->setText(tr("For more information, please visit :"));

	pTemp = qFindChild<QLabel*>(m_pRealForm, "labelGUIVersion");
	if (pTemp != NULL) pTemp->setText(tr("GUI Version :"));

	pTemp = qFindChild<QLabel*>(m_pRealForm, "labelEngineVersion");
	if (pTemp != NULL) pTemp->setText(tr("Current Locale :"));

	setupWindow();

	// Then, populate some data.
	updateData();

	return true;
}

void AboutWindow::show()
{
	m_pRealForm->show();
	m_pRealForm->raise();
	m_pRealForm->activateWindow();
}

void AboutWindow::setupWindow()
{
	Qt::WindowFlags flags;

	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);
}

void AboutWindow::updateData()
{
  QString fullVersion;
  QString numberString;
  QString guiVersion;

  m_supplicant.getAndCheckSupplicantVersion(fullVersion, numberString, false);
  m_pSupVersion->setText(QString("%1").arg(numberString));

  if (m_pLocale != NULL) m_pLocale->setText(QLocale::system().name());

  m_pdataFieldPlugins->setText("");
  if(m_pdataFieldPostureVersion != NULL) {
	  m_pdataFieldPostureVersion->setText(QString(tr("No TNC")));
  }

  m_pGUIVersion->setText(tr("%1").arg(getGUIVersion()));
}

//! Setup the fields prior to displaying the page
/*!
  \brief Retrieves the data to display on the page.  Call this before displaying the page.
  \param[out] guiVersion - the version of the GUI
  \return nothing
  \todo Need to get the data from the supplicant for all of the fields that we need here
*/
QString &AboutWindow::getGUIVersion()
{
  return m_versionString;
}
