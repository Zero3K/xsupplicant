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

	if (m_pSupVersion == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'About Dialog' did not contain the 'dataFieldGUIVersion' label.  The GUI version will not be displayed properly."));
	}

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
	    QObject::connect(m_pbuttonClose, SIGNAL(clicked()),
		                  this, SIGNAL(close()));
	}

	setupWindow();

	// Then, populate some data.
	updateData();

	return true;
}

void AboutWindow::show()
{
	// This will cause the window to come to the front if it is already built.
	if (m_pRealForm->isVisible() == true) m_pRealForm->hide();

	m_pRealForm->show();
}

void AboutWindow::setupWindow()
{
	Qt::WindowFlags flags;

	flags = m_pRealForm->windowFlags();
	flags &= (~Qt::WindowContextHelpButtonHint);
	flags |= Qt::WindowMinimizeButtonHint;
  m_pRealForm->setWindowFlags(flags);
}

void AboutWindow::updateData()
{
  QString fullVersion;
  QString numberString;
  QString guiVersion;

  m_supplicant.getAndCheckSupplicantVersion(fullVersion, numberString, false);
  m_pSupVersion->setText(tr("%1").arg(numberString));

//#ifdef TNC
  m_pdataFieldPlugins->setText(tr("with Identity Engines Ignition Posture Module"));
  if(m_pdataFieldPostureVersion != NULL) {
	  m_pdataFieldPostureVersion->setText(m_postureVersionString);
  }
/*#else
  m_pdataFieldPlugins->setText("");
  if(m_pdataFieldPostureVersion != NULL) {
	  m_pdataFieldPostureVersion->setText(QString(tr("No TNC")));
  }
#endif*/

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
