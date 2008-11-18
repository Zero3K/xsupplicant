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

#include "ConfigConnAdapterTab.h"
#include "Util.h"

ConfigConnAdapterTab::ConfigConnAdapterTab(QWidget *pRealWidget, Emitter *e, XSupCalls *pSupplicant, config_connection *pConn, QWidget *parent) :
	m_pRealWidget(pRealWidget), m_pSupplicant(pSupplicant), m_pConn(pConn), m_pParent(parent), m_pEmitter(e)
{
	m_bDataChanged       = false;
	m_bConnected         = false;
	m_pWirelessTab       = NULL;
	m_pWiredProfileLabel = NULL;
	m_pAdapterSelection  = NULL;
	m_pWidgetStack       = NULL;
	m_pWiredProfile      = NULL;

}

ConfigConnAdapterTab::~ConfigConnAdapterTab()
{
	if (m_bConnected == true)
	{
		Util::myDisconnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

		Util::myDisconnect(m_pAdapterSelection, SIGNAL(currentIndexChanged(int)), this, SLOT(adapterChanged(int)));

		Util::myDisconnect(m_pWiredProfile, SIGNAL(currentIndexChanged(int)), this, SLOT(slotProfileChanged(int)));

		Util::myDisconnect(m_pEmitter, SIGNAL(signalNewInterfaceInserted()), this, SLOT(adapterInserted()));
	}

	if (m_pWirelessTab != NULL)
	{
		delete m_pWirelessTab;
	}
}

void ConfigConnAdapterTab::slotDataChanged()
{
	m_bDataChanged = true;
}

void ConfigConnAdapterTab::populateProfiles()
{
	QComboBox *pWirelessProfile = NULL;
	QLabel *pWirelessProfileLabel = NULL;
	profile_enum *pProfiles = NULL;
	int i = 0;

	pWirelessProfile = qFindChild<QComboBox*>(m_pRealWidget, "dataComboWirelessProfile");
	if (pWirelessProfile == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox named 'dataComboWirelessProfile'."));
		return;
	}

	pWirelessProfileLabel = qFindChild<QLabel*>(m_pRealWidget, "labelComboWirelessProfile");

	if (m_pSupplicant->enumProfiles((CONFIG_LOAD_GLOBAL | CONFIG_LOAD_USER), &pProfiles, true) != true)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to enumerate profiles."));
		return;
	}

	pWirelessProfile->clear();
	m_pWiredProfile->clear();

	pWirelessProfile->addItem(" <None>  ");
	m_pWiredProfile->addItem(" <None>  ");

	while (pProfiles[i].name != NULL)
	{
		pWirelessProfile->addItem(pProfiles[i].name);
		m_pWiredProfile->addItem(pProfiles[i].name);
		i++;
	}

	if (m_pConn == NULL) return;

	if (m_pConn->profile != NULL)
	{
		i = pWirelessProfile->findText(m_pConn->profile);
		if (i < 0) i = 0;   // Set it to <None>
		pWirelessProfile->setCurrentIndex(i);

		i = m_pWiredProfile->findText(m_pConn->profile);
		if (i < 0) i = 0;   // Set it to <None>
		m_pWiredProfile->setCurrentIndex(i);

		if (i == 0)
		{
			setLabelInvalid(pWirelessProfileLabel);
			setLabelInvalid(m_pWiredProfileLabel);
		}
		else
		{
			setLabelValid(pWirelessProfileLabel);
			setLabelValid(m_pWiredProfileLabel);

			m_pWiredProfile->setToolTip(tr(""));
			pWirelessProfile->setToolTip(tr(""));
		}
	}
	else
	{
		pWirelessProfile->setCurrentIndex(0);
		m_pWiredProfile->setCurrentIndex(0);

		setLabelInvalid(pWirelessProfileLabel);
		setLabelInvalid(m_pWiredProfileLabel);

		m_pWiredProfile->setToolTip(tr("You cannot use this Connection until you select a valid Profile."));
		pWirelessProfile->setToolTip(tr("You cannot use this Connection until you select a valid Profile."));
	}

	m_pSupplicant->freeEnumProfile(&pProfiles);
}

void ConfigConnAdapterTab::setLabelInvalid(QLabel *toEditLabel)
{
	QPalette mypalette;

	if (toEditLabel == NULL) return;

	m_pNormalColor = toEditLabel->palette().color(QPalette::WindowText);

	mypalette.setColor(QPalette::WindowText, QColor(255, 0, 0));  // Set the color to red.
	toEditLabel->setPalette(mypalette);

	toEditLabel->setToolTip(tr("You cannot use this Connection until you select a valid Profile."));
	m_pWiredProfile->setToolTip(tr("You cannot use this Connection until you select a valid Profile."));	
}

void ConfigConnAdapterTab::setLabelValid(QLabel *toEditLabel)
{
	QPalette mypalette;

	if (toEditLabel == NULL) return;

	mypalette.setColor(QPalette::WindowText, m_pNormalColor);

	toEditLabel->setPalette(mypalette);

	toEditLabel->setToolTip("");  // Clear the tool tip.
	m_pWiredProfile->setToolTip("");
}

void ConfigConnAdapterTab::slotProfileChanged(int newSelection)
{
	emit signalDataChanged();

	if (newSelection == 0)
	{
		setLabelInvalid(m_pWiredProfileLabel);
	}
	else
	{
		setLabelValid(m_pWiredProfileLabel);
	}
}

bool ConfigConnAdapterTab::attach()
{
	m_pAdapterSelection = qFindChild<QComboBox*>(m_pRealWidget, "dataComboAdapters");
	if (m_pAdapterSelection == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox named 'dataComboAdapters'."));
		return false;
	}

	m_pWidgetStack = qFindChild<QStackedWidget*>(m_pRealWidget, "widgetStackAdapter");
	if (m_pWidgetStack == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QStackedWidget named 'widgetStackAdapter'."));
		return false;
	}

	m_pWiredProfile = qFindChild<QComboBox*>(m_pRealWidget, "dataComboWiredNetworkProfile");
	if (m_pWiredProfile == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("Unable to locate the QComboBox named 'dataComboWiredNetworkProfile'."));
		return false;
	}

	m_pWiredProfileLabel = qFindChild<QLabel*>(m_pRealWidget, "labelComboWiredNetworkProfile");

	updateWindow();
	populateProfiles();

	Util::myConnect(this, SIGNAL(signalDataChanged()), m_pParent, SIGNAL(signalDataChanged()));

	// The data changed signal is emitted from the adapterChanged() slot, so we don't need to double bind.
	Util::myConnect(m_pAdapterSelection, SIGNAL(currentIndexChanged(int)), this, SLOT(adapterChanged(int)));

	Util::myConnect(m_pWiredProfile, SIGNAL(currentIndexChanged(int)), this, SLOT(slotProfileChanged(int)));

	Util::myConnect(m_pEmitter, SIGNAL(signalNewInterfaceInserted()), this, SLOT(adapterInserted()));

	m_bConnected = true;

	return true;
}

void ConfigConnAdapterTab::updateWindow()
{
  int i = 0;
  int iswireless = 2; 
  int_config_enum *pConfigInterfaces = NULL;

  m_pAdapterSelection->clear();

  if ((m_pSupplicant->enumConfigInterfaces(&pConfigInterfaces, true)) && (pConfigInterfaces))
	{
		i = 0;
		while (pConfigInterfaces[i].desc != NULL)
		{
			if ((m_pConn != NULL) && (QString(pConfigInterfaces[i].desc) != QString(m_pConn->device)))
			{
				m_pAdapterSelection->addItem(pConfigInterfaces[i].desc, QVariant(pConfigInterfaces[i].is_wireless));
			}
			else if (m_pConn != NULL)
			{
				// This is the adapter we are using.
				m_pAdapterSelection->addItem(pConfigInterfaces[i].desc, QVariant(pConfigInterfaces[i].is_wireless));
				iswireless = pConfigInterfaces[i].is_wireless;
			}

			i++;
		}
	}

  if ((m_pConn != NULL) && (m_pConn->device != NULL))
  {
	  i = m_pAdapterSelection->findText(m_pConn->device);
  }
  else
  {
	  i = -1;
  }

  if (i < 0) i = 0;   // Make sure to pick the first one in the list, rather than make it blank.

  m_pAdapterSelection->setCurrentIndex(i);

	if (iswireless == 2)  // This is probably a new connection.
	{
		if (pConfigInterfaces[0].is_wireless == TRUE)
		{
			iswireless = TRUE;
		}
		else
		{
			iswireless = FALSE;
		}
	}

	if (iswireless == TRUE)
	{
		m_pWidgetStack->setCurrentIndex(WIRELESS_PAGE);
		setupWireless();
	}
	else
	{
		m_pWidgetStack->setCurrentIndex(WIRED_PAGE);
	}

	m_pSupplicant->freeEnumStaticInt(&pConfigInterfaces);
}

void ConfigConnAdapterTab::setupWireless()
{
	if (m_pWirelessTab != NULL)
	{
		delete m_pWirelessTab;
		m_pWirelessTab = NULL;
	}

	m_pWirelessTab = new ConfigConnAdaptTabWireless(m_pRealWidget, m_pEmitter, m_pSupplicant, m_pConn, m_pAdapterSelection->currentText(), this);
	if (m_pWirelessTab == NULL) 
	{
		QMessageBox::critical(this, tr("Memory Allocation Error"), tr("Unable to allocate memory to store wireless tab information."));
		return;
	}

	if (m_pWirelessTab->attach() == false)
	{
		QMessageBox::critical(this, tr("Wireless Tab Init Failure"), tr("Unable to initialize the wireless tab."));
		return;
	}
}

void ConfigConnAdapterTab::adapterChanged(int newAdapt)
{
	QVariant qv;

	emit signalDataChanged();

	qv = m_pAdapterSelection->itemData(newAdapt);
	if (qv.toInt() == TRUE)
	{
		// It is a wireless interface.
		m_pWidgetStack->setCurrentIndex(WIRELESS_PAGE);
		setupWireless();
	}
	else
	{
		// It is a wired interface.
		m_pWidgetStack->setCurrentIndex(WIRED_PAGE);
	}
}

bool ConfigConnAdapterTab::saveAdapter()
{
	if (m_pConn->device != NULL)
	{
		free(m_pConn->device);
		m_pConn->device = NULL;
	}

	if (m_pAdapterSelection->currentText() == "")  // err.. invalid..  (Should be impossible.. but..)
	{
		QMessageBox::critical(this, tr("Configuration Error"), tr("Please select a valid adapter from the drop down box."));
		return false;
	}

	m_pConn->device = _strdup(m_pAdapterSelection->currentText().toAscii());

	return true;
}

bool ConfigConnAdapterTab::saveWired()
{
	// Need to save the profile, and interface, and make sure everything else is clear.
	if (m_pConn->profile != NULL)
	{
		free(m_pConn->profile);
		m_pConn->profile = NULL;
	}

	if (m_pWiredProfile->currentIndex() > 0)  // Make sure they don't have <None> selected.
	{
		m_pConn->profile = _strdup(m_pWiredProfile->currentText().toAscii());
	}

	if (saveAdapter() == false) return false;

	// Now, make sure everything else is cleaned out.
	m_pSupplicant->freeConfigAssociation(&m_pConn->association);
	
	if (m_pConn->ssid != NULL)
	{
		free(m_pConn->ssid);
		m_pConn->ssid = NULL;
	}

	return true;
}

bool ConfigConnAdapterTab::save()
{
	if (m_pWidgetStack->currentIndex() == WIRED_PAGE)
	{
		return saveWired();
	}
	else
	{
		if (m_pWirelessTab == NULL)
		{
			QMessageBox::critical(this, tr("Programming Error"), tr("Somehow you managed to get the wireless widget to show without having the wireless object created.  Please report this!"));
			return false;
		}

		if (saveAdapter() == false) return false;

		return m_pWirelessTab->save();
	}

	return false;  // Shouldn't EVER get here!
}

void ConfigConnAdapterTab::adapterInserted()
{
	updateWindow();
}

