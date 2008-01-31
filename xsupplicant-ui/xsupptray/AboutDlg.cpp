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
AboutDlg::AboutDlg(QWidget *parent)
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
	m_pClose           = NULL;
}


//! Destructor
/*!
  \brief Clears out whatever needs to be cleared out
  \return nothing
*/
AboutDlg::~AboutDlg()
{
	if (m_pRealForm != NULL) 
	{
		Util::myDisconnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));
		delete m_pRealForm;
	}
}

bool AboutDlg::create()
{
	m_pRealForm = FormLoader::buildform("AbtDlg.ui");

	if (m_pRealForm == NULL) return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SIGNAL(close()));

	// At this point, the form is loaded in to memory, but we need to locate a couple of fields that we want to be able to edit.
	m_pSupVersion = qFindChild<QLabel*>(m_pRealForm, "engVersionLabel");

	if (m_pSupVersion == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'About Dialog' did not contain the 'engVersionLabel' label.  The engine version will not be displayed properly."));
	}

	m_pGUIVersion = qFindChild<QLabel*>(m_pRealForm, "uiVersionLabel");

	if (m_pSupVersion == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'About Dialog' did not contain the 'uiVersionLabel' label.  The GUI version will not be displayed properly."));
	}

	m_pPlugInsLabel = qFindChild<QLabel*>(m_pRealForm, "pluginsLabel");

	if (m_pPlugInsLabel == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error!"), tr("The form loaded for the 'About Dialog' did not contain the 'pluginsLabel' label.  The plugins section of the About Dialog will be incorrect."));
	}

	m_pClose = qFindChild<QPushButton*>(m_pRealForm, "clsBtn");

	// If m_pClose is NULL, then there isn't a close button.  We don't consider that to be a problem, so don't complain.
	if (m_pClose != NULL)
	{
	    QObject::connect(m_pClose, SIGNAL(clicked()),
		                  this, SIGNAL(close()));
	}

	setupWindow();

	// Then, populate some data.
	updateData();

	return true;
}

void AboutDlg::show()
{
	// This will cause the window to come to the front if it is already built.
	if (m_pRealForm->isVisible() == true) m_pRealForm->hide();

	m_pRealForm->show();
}

void AboutDlg::setupWindow()
{
	Qt::WindowFlags flags;

	flags = m_pRealForm->windowFlags();
	flags &= (~Qt::WindowContextHelpButtonHint);
  m_pRealForm->setWindowFlags(flags);
}

void AboutDlg::updateData()
{
  QString fullVersion;
  QString numberString;
  QString guiVersion;

  m_supplicant.getAndCheckSupplicantVersion(fullVersion, numberString, false);
  m_pSupVersion->setText(tr("%1").arg(numberString));

#ifdef TNC
  m_pPlugInsLabel->setText(tr("with Identity Engines Ignition Posture Module"));
#else
  m_pPlugInsLabel->setText("");
#endif

  m_pGUIVersion->setText(tr("%1").arg(getGUIVersion()));
}

//! Setup the fields prior to displaying the page
/*!
  \brief Retrieves the data to display on the page.  Call this before displaying the page.
  \param[out] guiVersion - the version of the GUI
  \return nothing
  \todo Need to get the data from the supplicant for all of the fields that we need here
*/
QString &AboutDlg::getGUIVersion()
{
  return m_versionString;
}
