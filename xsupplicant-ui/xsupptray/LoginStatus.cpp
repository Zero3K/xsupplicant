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

#include "LoginStatus.h"
#include "FormLoader.h"
#include "Util.h"
#include "eap_types/tnc/tnc_compliance_options.h"


LoginStatus::LoginStatus(bool fromConnect, QString inDevName, poss_conn_enum *pConnEnum, QWidget *proxy, QWidget *parent, Emitter *e):QWidget(parent),
	myParent(parent), myProxy(proxy), m_supplicant(NULL), m_pEmitter(e), pConn(pConnEnum)
{
	devName = inDevName;
	m_timeauthed = 0;
	m_connID = 255;
	m_bDisplayError = false;

	sigsConnectHere = true;

	m_pSignalImageLabel = NULL;
	m_pSignalTextLabel = NULL;
	m_pSecurityImageLabel = NULL;
	m_pSecurityTextLabel = NULL;
	m_pAssociationImageLabel = NULL;
	m_pAssociationTextLabel = NULL;
	m_pSSIDName = NULL;
	m_pStatusLabel = NULL;

    m_pTNCStatusTextLabel = NULL;
    m_pTNCStatusImageText = NULL;
    m_pTNCStatusImagePic  = NULL;
    m_pTNCStatusButton    = NULL;
    m_TNCConnectionID     = -1;

	Util::myConnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotStateChange(const QString &, int, int, int, unsigned int)));
	Util::myConnect(m_pEmitter, SIGNAL(signalIPAddressSet()), this, SLOT(updateIPAddress()));
    Util::myConnect(m_pEmitter, SIGNAL(signalTNCUILoginWindowStatusUpdateEvent(unsigned int, unsigned int, unsigned int, unsigned int)), this, SLOT(updateTNCStatus(unsigned int, unsigned int, unsigned int, unsigned int)));
									   
	updateWindow(true, fromConnect);
	clearWirelessItems();  // If we used this constructor, then this is a wired interface.
}

LoginStatus::LoginStatus() : m_supplicant(NULL)
{
	m_timeauthed = 0;
	m_bDisplayError = false;
	sigsConnectHere = false;
	m_pEmitter = NULL;
}

LoginStatus::~LoginStatus()
{
	if (sigsConnectHere)
	{
		Util::myDisconnect(m_pEmitter, SIGNAL(signalStateChange(const QString &, int, int, int, unsigned int)), this, SLOT(slotStateChange(const QString &, int, int, int, unsigned int)));
		Util::myDisconnect(m_pEmitter, SIGNAL(signalIPAddressSet()), this, SLOT(updateIPAddress()));
		Util::myDisconnect(m_pEmitter, SIGNAL(signalTNCUILoginWindowStatusUpdateEvent(unsigned int, unsigned int, unsigned int, unsigned int)), this, SLOT(updateTNCStatus(unsigned int, unsigned int, unsigned int, unsigned int)));
        
        if(m_pTNCStatusButton != NULL) {
            Util::myDisconnect(m_pTNCStatusButton, SIGNAL(clicked(bool)), this, SLOT(sendTNCUIConnectionStatusRequest()));
        }
    }



	if (m_pClockTimer != NULL) 
	{
		m_pClockTimer->stop();
		Util::myDisconnect(m_pClockTimer, SIGNAL(timeout()), this, SLOT(slotShowTime()));

		delete m_pClockTimer;
		m_pClockTimer = NULL;
	}
}

// We don't care about updateAll right now.  It does nothing but act as a place holder.
void LoginStatus::updateWindow(bool updateAll, bool fromConnect)
{
	QLabel *myLabel = NULL;
	QString temp;

	myLabel = qFindChild<QLabel*>(myProxy, "dataFieldAdapterName");
	if (myLabel != NULL)
	{
	  temp = pConn->dev_desc;
	  myLabel->setText(Util::removePacketSchedulerFromName(temp));
	}

	m_pIpAddressTextBox = qFindChild<QLabel*>(myProxy, "dataFieldIPAddress");

	m_pSignalImageLabel = qFindChild<QLabel*>(myProxy, "iconSignalStrength");

	m_pSignalTextLabel = qFindChild<QLabel*>(myProxy, "dataFieldSignalStrength");

	m_pSecurityImageLabel = qFindChild<QLabel*>(myProxy, "iconEncryptionType");

	m_pSecurityTextLabel = qFindChild<QLabel*>(myProxy, "dataFieldEncryptionType");

	m_pAssociationImageLabel = qFindChild<QLabel*>(myProxy, "iconAssociationMode");

	m_pAssociationTextLabel = qFindChild<QLabel*>(myProxy, "dataFieldAssociationMode");

	m_pStatusLabel = qFindChild<QLabel*>(myProxy, "dataFieldStatus");

	m_pSSIDName = qFindChild<QLabel*>(myProxy, "dataFieldSSIDName");
	
	m_pTimeBox = qFindChild<QLabel*>(myProxy, "dataFieldConnectedTime");

	m_pTNCStatusTextLabel = qFindChild<QLabel*>(myProxy, "tncStatus");

	m_pTNCStatusImageText = qFindChild<QLabel*>(myProxy, "tncStatusIconText");

	m_pTNCStatusImagePic = qFindChild<QLabel*>(myProxy, "tncStatusIcon");

    m_pTNCStatusButton    = qFindChild<QPushButton *>(myProxy, "buttonTNCStatus");

    if(m_pTNCStatusImagePic != NULL)
    {
        m_pTNCStatusImagePic->hide();
    }

    if(m_pTNCStatusImageText != NULL)
    {
        m_pTNCStatusImageText->hide();
    }

    if(m_pTNCStatusTextLabel != NULL)
    {
        m_pTNCStatusTextLabel->setText(tr("Not Available"));
    }

    if(m_pTNCStatusButton != NULL) 
    {
        m_pTNCStatusButton->hide();
        Util::myConnect(m_pTNCStatusButton, SIGNAL(clicked(bool)), this, SLOT(sendTNCUIConnectionStatusRequest()));
    }

	if (m_pTimeBox != NULL)
	{
		m_pTimeBox->setText("00:00:00");
		m_pClockTimer = new QTimer(this);
		Util::myConnect(m_pClockTimer, SIGNAL(timeout()), this, SLOT(slotShowTime()));
		m_pClockTimer->stop();
	}

	if (fromConnect)
	{
		if (m_pIpAddressTextBox != NULL)
		{
			m_pIpAddressTextBox->setText("Updating. . . ");
		}
	}
	else
	{
		getIPAddress();
	}

	updateState();

	requestPostureState();
}

void LoginStatus::requestPostureState()
{
	unsigned int connID = 0;

	if (xsupgui_request_get_tnc_conn_id(devName.toAscii().data(), &connID) == REQUEST_SUCCESS)
	{
		m_connID = connID;

		// XXX The IMC ID below needs to be set dynamically.  This is okay for now, since we only load one IMC
		// but in the future it *WILL* cause us problems!  (This probably also doesn't belong here, since it is for
		// a proprietary IMC. ;)
		if (m_pEmitter != NULL)
		{
			m_pEmitter->sendTNCReply(0, connID, 25065, BATCH_TNC_STATE_CHANGE, false, 0);
		}
	}
}

void LoginStatus::updateIPAddress()
{
	getIPAddress();
}

//! getIPAddress
/*!
  \brief Get the IP address from the supplicant and display it
  \return nothing
*/
bool LoginStatus::getIPAddress()
{
  IPInfoClass ipInfo;

  if (m_pIpAddressTextBox != NULL)
  {
	bool bValue = m_supplicant.getIPInfo(devName, ipInfo, false);
	if (bValue)
	{
		if (ipInfo.getIPAddress() == "")
		{
			m_pIpAddressTextBox->setText(tr("Updating. . ."));
		}
		else
		{
			m_pIpAddressTextBox->setText(ipInfo.getIPAddress());
		}
	}
	else
	{
		m_pIpAddressTextBox->setText(tr("Updating. . ."));
	}

	return bValue;
  }
  
  return false;
}

void LoginStatus::clearWirelessItems()
{
	QLabel *myLabel;

	if (m_pSignalImageLabel != NULL) m_pSignalImageLabel->setVisible(false);
	if (m_pSignalTextLabel != NULL) m_pSignalTextLabel->setVisible(false);

	if (m_pSecurityImageLabel != NULL) m_pSecurityImageLabel->setVisible(false);
	if (m_pSecurityTextLabel != NULL) m_pSecurityTextLabel->setVisible(false);

	if (m_pAssociationImageLabel != NULL) m_pAssociationImageLabel->setVisible(false);
	if (m_pAssociationTextLabel != NULL) m_pAssociationTextLabel->setVisible(false);

	if (m_pSSIDName != NULL) m_pSSIDName->setVisible(false);

	myLabel = qFindChild<QLabel*>(myProxy, "labelSSID");
	if (myLabel != NULL) myLabel->setVisible(false);
}

//! getTime
/*!
  \brief Get the time from the supplicant and display it
  \return nothing
  \todo need to create a widget that will increment the time once it is displayed
  \todo is there a standard way to do this?
*/
bool LoginStatus::getTime()
{
  int days = 0;
  int hours = 0;
  int minutes = 0;
  int seconds = 0;
  QTime t;

  if  (m_pTimeBox == NULL)
  {
    return true;
  }

  // The only time I'm calling this is when we're supposed to be authenticated, therefore
  // regardless of the m_timeauthed, start the timer
  bool bValue = m_supplicant.getAuthTime(devName, m_timeauthed, m_bDisplayError);
  if (bValue)
  {
    long int tempTime = m_timeauthed;
    // Get days, hours, minutes and seconds the hard way - for now
    days = (int)(tempTime / (60*60*24));
    tempTime = tempTime % (60*60*24);
    hours = (int) (tempTime / (60*60));
    tempTime = tempTime % (60*60);
    minutes = (int) tempTime / 60;
    seconds = tempTime % 60;
    t.setHMS(hours, minutes, seconds);
    setTime(t);
    m_pClockTimer->start(1000);
  }
  else
  {
    t.setHMS(0,0,0);
    m_pClockTimer->stop();
    setTime(t);
  }
  return bValue;
}

void LoginStatus::setTime(QTime &time)
{
  m_time  = time;
  if (m_pTimeBox != NULL) m_pTimeBox->setText(m_time.toString(Qt::TextDate));
}

void LoginStatus::slotShowTime()
{
  m_time = m_time.addSecs(1);
  if (m_pTimeBox != NULL) m_pTimeBox->setText(m_time.toString(Qt::TextDate));
}

void LoginStatus::updateState()
{
	bool bValue;
	QString m_status;
	int m_XState;
	QString temp;

	temp = pConn->dev_desc;
	bValue = m_supplicant.get1xState(temp, 
      devName, 
      m_status,  // this is what we display on the status window
      m_XState, 
      m_bDisplayError);

	if (bValue == true)
	{
		// Process the 802.1X state.
		if (m_pStatusLabel != NULL) m_pStatusLabel->setText(m_status);

		if ((m_XState == AUTHENTICATED) || (m_XState == S_FORCE_AUTH))
		{
			getTime();
		}
	}
	else
	{
		m_pStatusLabel->setText("Unknown");
	}
}

void LoginStatus::slotStateChange(const QString &intName, int sm, int oldstate, int newstate, unsigned int tncconnectionid)
{
	QString m_state;

	// Make sure this is an interface we care about.  (If not, ignore it.)
	if (intName == devName)
	{
		if (sm == IPC_STATEMACHINE_8021X)
		{
			m_supplicant.map1XState(newstate, m_state);

			m_pStatusLabel->setText(m_state);

			if (((newstate == AUTHENTICATED) && (oldstate != AUTHENTICATED)) || 
				((newstate == S_FORCE_AUTH) && (oldstate != S_FORCE_AUTH)))
			{
				getIPAddress();
				getTime();
				requestPostureState();
			}
			else
			{
				if ((newstate == HELD) && (oldstate != HELD))
				{
					// Reset our posture state.
					requestPostureState();
				}

				if ((newstate != AUTHENTICATED) && (newstate != S_FORCE_AUTH))
				{
					if (m_pClockTimer->isActive())
					{
						QTime t;
						t.setHMS(0,0,0);
						m_pClockTimer->stop();
						setTime(t);
				
						// clear ip address here
						m_pIpAddressTextBox->clear();
					}
				}
				else
				{
					getTime();
				}
			}
		}
	}
}

void LoginStatus::setPixmapLabel(QLabel *label, QString &URLPath)
{
  // Create an array of these so I don't have to load them everytime.
  // When to load - 
  QPixmap *pixMap;

  pixMap = FormLoader::loadicon(URLPath);
  if (pixMap == NULL)
  {
	  label->clear();
  }
  else
  {
	  label->setPixmap((*pixMap));
  }

  delete pixMap;
}

//! updateTNCStatus
/*!
  \brief Update the login window with the current TNC state.
  \param[in] newState - The new TNC state.
  \return nothing
*/
void LoginStatus::updateTNCStatus(unsigned int imc, unsigned int connID, unsigned int oui, unsigned int newState)
{
	char *adaptName = NULL;
	bool bValue;
	QString m_status;
	int m_XState;
	QString temp;

    if((m_pTNCStatusTextLabel != NULL) && (m_pTNCStatusImageText != NULL) && (m_pTNCStatusImagePic != NULL) && (m_pTNCStatusButton != NULL))
    {
        if(m_connID == -1)
        {
		    adaptName = _strdup(devName.toAscii());
		    if (xsupgui_request_get_tnc_conn_id(adaptName, &connID) == REQUEST_SUCCESS)
		    {
			    m_connID = connID;
		    }
		    free(adaptName);
        }

        if(m_connID != connID)
        {
                return;
        }

        // Check the authentication state.
        // If it's "AUTHENTICATED" then we can ask the IMC for the posture state.
        // If it's "FAILED" we'll always report NA
        // If it's anything else, we won't update.
	temp = pConn->dev_desc;
	    bValue = m_supplicant.get1xState(temp, 
            devName, 
            m_status,  
            m_XState, 
            m_bDisplayError);

        if(bValue == true)
        {
            // If we're authenticated we'll update with the new state we received.
            if(m_XState != AUTHENTICATED)
            {
                // If we've failed, update to "NA"
                if(((m_XState == HELD) || (m_XState == S_FORCE_UNAUTH)))
                {
                    newState = 255;
                }
                else
                {
                    // Otherwise, we're not interested in updating the login window
                    return;
                }
            }
        }

/*
#define TNC_CONNECTION_STATE_ACCESS_ALLOWED 2
#define TNC_CONNECTION_STATE_ACCESS_ISOLATED 3
#define TNC_CONNECTION_STATE_ACCESS_NONE 4
*/
        switch(newState)
        {
            case 2:
            {
                //tnc_allowed.png
                m_pTNCStatusTextLabel->setText(tr("This connection is compliant."));
				m_pTNCStatusImageText->setText(tr("ALLOWED"));
				temp = "tnc_allowed.png";
				setPixmapLabel(m_pTNCStatusImagePic, temp);
				m_pTNCStatusImagePic->setHidden(false);

                m_pTNCStatusButton->setIcon(QIcon(QPixmap(FormLoader::iconpath() + "tnc_allowed.png")));
                m_pTNCStatusButton->setHidden(false);
            }break;

            case 3:
            {
                //tnc_isolated.png
                m_pTNCStatusTextLabel->setText(tr("This connection has been isolated."));
				m_pTNCStatusImageText->setText(tr("ISOLATED"));
				temp = "tnc_isolated.png";
				setPixmapLabel(m_pTNCStatusImagePic, temp);
				m_pTNCStatusImagePic->setHidden(false);

                m_pTNCStatusButton->setIcon(QIcon(QPixmap(FormLoader::iconpath() + "tnc_isolated.png")));
                m_pTNCStatusButton->setHidden(false);
            }break;

            case 4:
            {
                //tnc_none.png
                m_pTNCStatusTextLabel->setText(tr("This connection was not allowed on the network."));
				m_pTNCStatusImageText->setText(tr("NONE"));
				temp = "tnc_none.png";
				setPixmapLabel(m_pTNCStatusImagePic, temp);
				m_pTNCStatusImagePic->setHidden(false);

                m_pTNCStatusButton->setIcon(QIcon(QPixmap(FormLoader::iconpath() + "tnc_none.png")));
                m_pTNCStatusButton->setHidden(false);
            }break;

            default:
            {
                // We shouldn't get here, unless something's broken, or the TNC standard has been changed.
                m_pTNCStatusTextLabel->setText(tr("Not Available"));
				m_pTNCStatusImageText->setText(tr(""));
				m_pTNCStatusImagePic->setHidden(true);

                m_pTNCStatusButton->setIcon(QIcon(QPixmap("")));
                m_pTNCStatusButton->setHidden(true);
            }break;
        };

        if(m_pTNCStatusTextLabel->isHidden())
        {
            m_pTNCStatusTextLabel->show(); 
        }

		if (m_pTNCStatusImageText->isHidden())
		{
			m_pTNCStatusImageText->show();
		}

        if(m_pTNCStatusButton != NULL) {
            if(m_pTNCStatusButton->isHidden()) {
                m_pTNCStatusButton->show();
            }
        }

        // Keep track of the connection ID so we can tickle plugins with it, if necessary.
        m_TNCConnectionID = connID;
    }
}

void LoginStatus::sendTNCUIConnectionStatusRequest() 
{
    if(m_pEmitter != NULL) {
        m_pEmitter->sendTNCUIConnectionStatusRequest(m_TNCConnectionID);
    }
}