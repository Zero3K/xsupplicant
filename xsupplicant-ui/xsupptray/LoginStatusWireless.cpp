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

#include "LoginStatusWireless.h"
#include "Util.h"

LoginStatusWireless::LoginStatusWireless(bool fromConnect, QString inDevName, poss_conn_enum *pConnEnum, QWidget *proxy, QWidget *parent, Emitter *e)
{
	myParent = parent;
	myProxy = proxy;
	pConn = pConnEnum;
	devName = inDevName;
	m_pEmitter = e;
	m_connID = 255;

    m_pTNCStatusTextLabel = NULL;
    m_pTNCStatusImageText = NULL;
	m_pTNCStatusImagePic = NULL;

	Util::myConnect(m_pEmitter, SIGNAL(signalSignalStrength(int)), this, SLOT(slotSignalStrengthChanged(int)));
	Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotStateChange(const QString &, int, int, int, unsigned int)));
	Util::myConnect(m_pEmitter, SIGNAL(signalIPAddressSet()), this, SLOT(updateIPAddress()));
    Util::myConnect(m_pEmitter, SIGNAL(signalTNCUILoginWindowStatusUpdateEvent(unsigned int, unsigned int, unsigned int, unsigned int)), this, SLOT(updateTNCStatus(unsigned int, unsigned int, unsigned int, unsigned int)));


	updateWindow(true, fromConnect);
}

LoginStatusWireless::~LoginStatusWireless()
{
	Util::myDisconnect(m_pEmitter, SIGNAL(signalSignalStrength(int)), this, SLOT(slotSignalStrengthChanged(int)));	
	Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotStateChange(const QString &, int, int, int, unsigned int)));
	Util::myDisconnect(m_pEmitter, SIGNAL(signalIPAddressSet()), this, SLOT(updateIPAddress()));
    Util::myDisconnect(m_pEmitter, SIGNAL(signalTNCUILoginWindowStatusUpdateEvent(unsigned int, unsigned int, unsigned int, unsigned int)), this, SLOT(updateTNCStatus(unsigned int, unsigned int, unsigned int, unsigned int)));

	m_pEmitter = NULL;
}

// Don't care about updateAll.  It is just a place holder.
void LoginStatusWireless::updateWindow(bool updateAll, bool fromConnect)
{
	LoginStatus::updateWindow(updateAll, fromConnect);

	enableWirelessItems();

	if (m_pSSIDName != NULL) m_pSSIDName->setText(pConn->ssid);

	getEncryption();
	getAssociation();
}

void LoginStatusWireless::enableWirelessItems()
{
	QLabel *myLabel;

	if (m_pSignalImageLabel != NULL) m_pSignalImageLabel->setVisible(true);
	if (m_pSignalTextLabel != NULL) m_pSignalTextLabel->setVisible(true);

	if (m_pSecurityImageLabel != NULL) m_pSecurityImageLabel->setVisible(true);
	if (m_pSecurityTextLabel != NULL) m_pSecurityTextLabel->setVisible(true);

	if (m_pAssociationImageLabel != NULL) m_pAssociationImageLabel->setVisible(true);
	if (m_pAssociationTextLabel != NULL) m_pAssociationTextLabel->setVisible(true);

	if (m_pSSIDName != NULL) m_pSSIDName->setVisible(true);

	myLabel = qFindChild<QLabel*>(myProxy, "ssidLabel");
	if (myLabel != NULL) myLabel->setVisible(true);
}

//! getSignalStrength
/*!
  \brief Called to initially get the signal strength
  \return nothing
*/
void LoginStatusWireless::getSignalStrength()
{
  int signal = 0;
  bool bValue = true;
  QString temp;

  temp = pConn->dev_desc;
  bValue = m_supplicant.getSignalStrength(temp, devName, signal, m_bDisplayError);
  if (bValue)
  {
    setSignalStrength(signal);
  }
  else
  {
	  signal = 0;
	  setSignalStrength(signal);
  }
}

//! getSignalStrength
/*!
  \brief Set the signal strength
  \param[in] signal
  \return nothing
*/
void LoginStatusWireless::setSignalStrength(int signal)
{
  QString temp;

	if (m_pSignalImageLabel != NULL)
	{
		if (signal <= 0)
		{
		  temp = "signal_0.png";
		  setPixmapLabel(m_pSignalImageLabel, temp);
		}
		else if (signal > 0 && signal <= 25)
		{
		  temp = "signal_1.png";
		  setPixmapLabel(m_pSignalImageLabel, temp);
		}
		else if (signal > 25 && signal <= 50)
		{
		  temp = "signal_2.png";
		  setPixmapLabel(m_pSignalImageLabel, temp);
		}
		else if (signal > 50 && signal <= 75)
		{
		  temp = "signal_3.png";
		  setPixmapLabel(m_pSignalImageLabel, temp);
		}
		else
		{
		  temp = "signal_4.png";
		  setPixmapLabel(m_pSignalImageLabel, temp);
		}
	}

  if (signal < 0)
    signal = 0;
  if (signal > 100)
    signal = 100;

  if (m_pSignalTextLabel != NULL)  m_pSignalTextLabel->setText(QString("%1%").arg(signal));
}

//! getEncryption
/*!
  \brief Called initially to get the encryption type
  \return nothing
*/
bool LoginStatusWireless::getEncryption()
{
  QString encryptionValue;

  if (m_pSecurityTextLabel != NULL)
  {
	bool bValue = m_supplicant.getEncryption(devName, encryptionValue, m_bDisplayError);
	if (bValue)
	{
		m_pSecurityTextLabel->setText(encryptionValue);
	}
	else
	{
		m_pSecurityTextLabel->setText(tr("Unknown"));
	}

	return bValue;
  }

  return true;
}

//! getAssociation
/*!
  \brief Called initially to get the association type
  \return nothing
*/
bool LoginStatusWireless::getAssociation()
{
  QString text;
  QString temp;
  bool bValue = true;

  if (m_pAssociationTextLabel != NULL)
  {
	// Using the device name, get the association
    temp = pConn->dev_desc;
	bValue = m_supplicant.getAssociation(temp, devName, text, m_bDisplayError);
	if (bValue)
	{
		m_pAssociationTextLabel->setText(text);
	}
	else
	{
		m_pAssociationTextLabel->setText(tr("Unknown"));
	}

	return bValue;
  }

  return true;
}

void LoginStatusWireless::updateState()
{
	bool bValue;
	QString m_status;
	int m_PState;
	QString temp;

	temp = pConn->dev_desc;
	bValue = m_supplicant.getPhysicalState(temp, 
		devName, 
		m_status, 
		m_PState, 
		m_bDisplayError);

  if (bValue && m_PState == ASSOCIATED)
  {
	  getSignalStrength();
	  m_pSecurityImageLabel->setEnabled(true);
	  m_pAssociationImageLabel->setEnabled(true);
	  m_pSignalImageLabel->setEnabled(true);

	LoginStatus::updateState();
  }
  else
  {
	  setSignalStrength(0);
	  m_pSecurityImageLabel->setEnabled(false);
	  m_pAssociationImageLabel->setEnabled(false);
	  m_pSignalImageLabel->setEnabled(false);

	  if (bValue)
	  {
		m_pStatusLabel->setText(m_status);
	  }
	  else
	  {
		  m_pStatusLabel->setText(tr("Unknown"));
	  }
  }
}

void LoginStatusWireless::slotSignalStrengthChanged(int newstrength)
{
	setSignalStrength(newstrength);
}

void LoginStatusWireless::slotStateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid)
{
	QString m_state;

	if ((sm == IPC_STATEMACHINE_PHYSICAL) && (intName == devName))
	{
		m_supplicant.mapPhysicalState(newstate, m_state);

		m_pStatusLabel->setText(m_state);

		if (newstate == ASSOCIATED)
		{
		  if (oldstate != ASSOCIATED) getSignalStrength();

		  m_pSecurityImageLabel->setEnabled(true);
		  m_pAssociationImageLabel->setEnabled(true);
		  m_pSignalImageLabel->setEnabled(true);
		}
		else
		{
		  QTime t;
		  t.setHMS(0,0,0);
		  m_pClockTimer->stop();
		  setTime(t);

		  setSignalStrength(0);
		  m_pSecurityImageLabel->setEnabled(false);
		  m_pAssociationImageLabel->setEnabled(false);
		  m_pSignalImageLabel->setEnabled(false);
		}
	}

	if  ((sm == IPC_STATEMACHINE_8021X) && (intName == devName))
	{
		LoginStatus::slotStateChange(intName, sm, oldstate, newstate, tncconnectionid);
	}
}

