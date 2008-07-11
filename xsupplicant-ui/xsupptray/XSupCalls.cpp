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
#include "CharC.h"
#include "Emitter.h"
#include "xsupcalls.h"
#include "Util.h"

extern "C"
{
#include "xsupconfig.h"
#include "libxml/parser.h"
#include "libxsupgui/xsupgui_request.h"
#include "libxsupgui/xsupgui_xml_common.h"
#include "libxsupgui/xsupgui.h"
#include "ipc_events_index.h"
#include "libxsupgui/xsupgui_events.h"
#include "libxsupgui/xsupgui_events_state.h"
#include "xsupconfig_structs.h"
#include "xsupconfig.h"
#include "xsupconfig_defaults.h"
#include "libxsupgui/xsupgui_mac_utils.h"
#include "xsup_err.h"
#include "supdetect.h"
#include "eap_types/tnc/tnc_compliance_options.h"
}

#ifndef WINDOWS
#define _strdup strdup
#endif /* WINDOWS */

int XSupCalls::CONNECTION_DEFAULT_PRIORITY = DEFAULT_PRIORITY;
bool XSupCalls::m_bEventsConnected = false;

// parent used to display messages
XSupCalls::XSupCalls(QWidget *parent):
  m_message(parent)
{

}

//! Destructor
/*!
  \brief Make sure all data is freed
  \return Nothing
*/
XSupCalls::~XSupCalls(void)
{
}


//! connectXSupplicant()
/*!
  \brief Attempt to connect to the XSupplicant
  \param[in] bRetry - set to true if we are retrying the connection.   
  If true, we give a message that we will attempt to load it
  If false, we give a "giving up" message
  \return true/false
*/
bool XSupCalls::connectXSupplicant()
{
  int retcode = xsupgui_connect();
  if (retcode != 0)
  {
    return false;
  }

  // Now check for errors from the supplicant
  getAndDisplayErrors();

  return true;
}

//! disconnectXSupplicant()
/*!
  \brief Attempt to disconnect from the XSupplicant
  \param[in] bRetry - set to true if we are retrying the connection.   
  If true, we give a message that we will attempt to load it
  If false, we give a "giving up" message
  \return true/false
*/
void XSupCalls::disconnectXSupplicant()
{
  int retcode = 0;
  retcode = disconnectEventListener();

  retcode = xsupgui_disconnect();
  if (retcode != 0)
  {
    if (QThread::currentThread() == qApp->thread())
    {
      QMessageBox::critical(NULL, tr("Error"), 
        tr("Can't disconnect from xsupplicant."));
    }
  }
}

/*********************************************************/
// Create ... routines
/*********************************************************/
//! createNewConnection
/*!
  \brief Create and save a new connection
  \param[in/out] name - the name of the new connection - may change if duplicates found
  \param[in] defaultDevice - the device used to initially create the connection
  \return true/false
*/
bool XSupCalls::createNewConnection(QString &name, config_connection **newConnection)
{
  bool bValue = true;
  config_connection *pConfig = NULL;
  int i = 1;
  QString newName = name;
  QString deviceName;

  // Need to make sure this connection does not already exist
  // If it does, add a _1 _2 etc., to the name until a unique name is found
  do
  {
    bValue  = getConfigConnection(newName, &pConfig, false);
    if (bValue == true)
    {
      newName = QString ("%1_%2").arg(name).arg(i);
      i++;
    }

	freeConfigConnection(&pConfig);   // Free the memory so it won't leak.
	pConfig = NULL;
  }while (bValue);

  name = newName;

  if (!createNewConnectionDefaults(name, &pConfig) || !pConfig)
  {
    return false;
  }
  
  // Now save the new connection, after setting the connection name
  pConfig->name = Util::myNullStrdup(name.toAscii());
  pConfig->priority = CONNECTION_DEFAULT_PRIORITY;

  // Start with some defaults, so we can be sure the dialog is drawn properly.  (if the connection ends up being
  // wired, these settings will get removed anyway.)
  pConfig->association.association_type = ASSOC_WPA2;
  pConfig->association.auth_type = AUTH_EAP;

  (*newConnection) = pConfig;

  return true;
}

//! createNewTrustedServer
/*!
  \brief Create a new trusted server
  \param[in] name - the name of the new trusted server
  \return true/false
*/
bool XSupCalls::createNewTrustedServer(QString &name, config_trusted_server **pTServer)
{
  bool bValue = true;
  config_trusted_server *pConfig = NULL;
  QString newName = name;
  int i = 1;

  (*pTServer) = NULL;

  // Need to make sure this trusted server does not already exist
  do
  {
    bValue  = getConfigTrustedServer(newName, &pConfig, false);
    if (bValue == true)
    {
      this->freeConfigTrustedServer(&pConfig);
      newName = QString ("%1_%2").arg(name).arg(i);
      i++;
    }
  }while (bValue);

  name = newName;
  if (!createNewTrustedServerDefaults(name, &pConfig) || pConfig == NULL)
  {
    return false;
  }

  // Now save the new connection, after setting the connection name
  pConfig->name = Util::myNullStrdup(name.toAscii());
#ifdef WINDOWS
  char *p = "WINDOWS";
  pConfig->store_type = Util::myNullStrdup(p);
#else
  QMessageBox::critical(NULL, tr("Invalid Trusted Server Config"), tr("Need location for this OS."));
  pConfig->location = "WHOKNOWS";
#endif 

  (*pTServer) = pConfig;

  return true;
}

//! createNewProfile
/*!
  \brief Create and save a new profile
  \param[in] name - the name of the new profile
  \return true/false
*/
bool XSupCalls::createNewProfile(QString &name, config_profiles **m_pConfig)
{
  bool bValue = true;
  config_profiles *pConfig = NULL;
  QString newName = name;
  int i = 1;

  (*m_pConfig) = NULL;

  // Need to make sure this profile does not already exist
  do
  {
    bValue  = getConfigProfile(newName, &pConfig, false);
    if (bValue == true)
    {
      freeConfigProfile(&pConfig);
      newName = QString ("%1_%2").arg(name).arg(i);
      i++;
    }
  }while (bValue);

  name = newName;
  if ((!createNewProfileDefaults(name, &pConfig)) || (pConfig == NULL))
  {
    return false;
  }

  // New profiles default to EAP-PEAP 
  // Now save the new connection, after setting the connection name
  pConfig->name = Util::myNullStrdup(name.toAscii());

  (*m_pConfig) = pConfig;

  return true;
}

//! createNewInterface
/*!
  \brief Create and save a new interface
  \param[in] deviceName - the description of the interface (user-friendly name)
  \param[in] deviceDescription - the name of the new interface
  \param[in] mac - the mac address of the interface
  \return true - interface added, false - not added
*/
bool XSupCalls::createNewInterface(QString &name, QString &deviceDescription, QString &mac, 
                                   bool bWireless, bool /*bDisplayError*/)
{
  bool bValue = true;
  CharC macAddress(mac);
  config_interfaces *pConfig = NULL;
  QString newName = name;
  int i = 1;

  // Need to make sure this interface does not already exist
  do
  {
    bValue  = this->getConfigInterface(newName, &pConfig, false);
    if (bValue == true)
    {
      freeConfigInterface(&pConfig);
      newName = QString ("%1_%2").arg(name).arg(i);
      i++;
    }
  }while (bValue);
  name = newName;

  if (!this->createNewInterfaceDefaults(name, &pConfig))
  {
    return false;
  }

  // Now save the new interface, after device description
  pConfig->description = Util::myNullStrdup(deviceDescription.toAscii());

  // Convert the one format of mac address to the other one
  // mac is an array of 6 char's
  xsupgui_mac_utils_convert_mac(macAddress.charPtr(), (char *)pConfig->mac);
  if (bWireless)
  {
    pConfig->flags |= CONFIG_INTERFACE_IS_WIRELESS;
  }
  bValue = setConfigInterface(pConfig);
  this->freeConfigInterface(&pConfig);

  return bValue;
}

//! createNewConnectionDefaults
/*!
  \brief Create the defaults for a new connection
  \param[in] name - the connection name
  \param[in] pConfig - the configuration structure
  \return true/false
*/
bool XSupCalls::createNewConnectionDefaults(QString &name, config_connection **pConfig)
{
  bool bValue = true;
  Q_ASSERT(pConfig);

  int retval = xsupconfig_defaults_create_connection(pConfig);
  if ((retval != 0) || (pConfig == NULL))
  {
    QMessageBox::critical(NULL, tr("Status Warning"), 
      tr("Can't create new connection '%1'.").arg(name));
    bValue = false;
  }

  return bValue;
}

//! createNewTrustedServerDefaults
/*!
  \brief Create the defaults for a new trusted server
  \param[in] name - the server name
  \param[in] pConfig - the configuration structure
  \return true/false
*/
bool XSupCalls::createNewTrustedServerDefaults(QString &name, config_trusted_server **pConfig)
{
  bool bValue = true;
  Q_ASSERT(pConfig);

  int retval = xsupconfig_defaults_create_trusted_server(pConfig);
  if ((retval != 0) || (pConfig == NULL))
  {
    QMessageBox::critical(NULL, tr("Status Warning"), 
      tr("Can't create new trusted server '%1'").arg(name));
    bValue = false;
  }

  return bValue;
}

//! createNewProfileDefaults
/*!
  \brief Create the defaults for a new profile
  \param[in] name - the profile name
  \param[in] pConfig - the configuration structure
  \return true/false
*/
bool XSupCalls::createNewProfileDefaults(QString &name, config_profiles **pConfig)
{
  bool bValue = true;
  Q_ASSERT(pConfig);

  int retval = xsupconfig_defaults_create_profile(pConfig);
  if ((retval != 0) || (pConfig == NULL))
  {
    QMessageBox::critical(NULL, tr("Status Warning"), 
			      tr("Can't create new profile '%1'").arg(name));
    bValue = false;
  }
  return bValue;
}

//! createNewInterfaceDefaults
/*!
  \brief Create the defaults for a new interface
  \param[in] name - the interface name
  \param[in] pConfig - the configuration structure
  \return true/false
*/
bool XSupCalls::createNewInterfaceDefaults(QString &name, config_interfaces **pConfig)
{
  Q_ASSERT(pConfig);
  bool bValue = true;

  int retval = xsupconfig_defaults_create_interface(pConfig);
  if ((retval != 0) || (pConfig == NULL))
  {
    QMessageBox::critical(NULL, tr("Status Warning"), 
      tr("Can't create new interface '%1'")
      .arg(name));
    bValue = false;
  }
  return bValue;
}

/*********************************************************/
// Get ... routines
/*********************************************************/
/** 
 \brief Given a profile configuration, get the password.
 *
 *  @param[in] prof - the profile
 *  @param[out] innerUser The user name for the inner (tunnel) protocol for the profile
 *  @param[out] password   The password for the passed in profile
 *  \retval XENONE on success
 **/
void XSupCalls::getUserAndPasswordFromProfile(config_profiles *prof, QString &innerUser, QString &password)
{
  Q_ASSERT(prof);
  innerUser = "";
  password = "";
  char *p = NULL;

  config_get_pwd(prof->method, &p);
  if (p)
  {
    password = p;
    delete p;
  }
  if (prof->method->method_num == EAP_TYPE_MD5)
  {
    innerUser = prof->identity;
  }
  else
  {
    config_get_user(prof->method, &p);
    if (p)
    {
      innerUser = p;
      delete p;
    }
  }
}

//! getConfigConnectionName
/*!
  \brief Get the name of the connection configuration used to connect to this device
  \param[in] deviceDescription - for displaying to the user
  \param[in] deviceName - the device for which we want signal strength
  \param[out] connName - the name of the connection configuration that was used to authenticate
  \return true - there was a connection in use /false - there wasn't a connection in use
*/
bool XSupCalls::getConfigConnectionName(QString &deviceDescription, 
                                        QString &deviceName, 
                                        QString &connName,
                                        bool bDisplayError)
{
  bool bValue = true;
  CharC d(deviceName);
  char *pName = NULL;

  int retval = xsupgui_request_get_conn_name_from_int(d.charPtr(), &pName);
  if (retval != 0)
  {
    if (retval != IPC_ERROR_NO_CONNECTION) // this means that there is no connection in use
    {
      if (bDisplayError)
      {
	QMessageBox::critical(NULL, tr("Status Warning"), 
              tr("Can't get the name of the connection used to connect to device '%1'.\n" 
              "This means that the device isn't using a connection.\n").arg(deviceDescription));
      }
    }
    bValue = false;
  }
  else if (pName)
  {
    connName = pName;
    free (pName);
  }
  else
  {
    bValue = false;
  }

  return bValue;
}

//! getSignalStrength
/*!
  \brief Get the signal strength for the wireless adapter
  \param[in] deviceName - the device for which we want signal strength
  \param[out] retVal - the percentage
  \return true/false
*/
bool XSupCalls::getSignalStrength(QString &deviceDesc, QString &deviceName, int &signal, bool bDisplayError)
{
  bool bValue = true;
  CharC d(deviceName);
  int retval;

  retval = xsupgui_request_get_signal_strength_percent(d.charPtr(), &signal);
  if (retval != 0)
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Status Warning"), 
            tr("Can't get signal strength for device '%1'")
            .arg(deviceDesc));
    }
    bValue = false;
	}
  return bValue;
}

//! getAssociation
/*!
  \brief Get the device association (live)
  \param[in] deviceDesc - for displaying to the user
  \param[in] deviceName - the device for which we want signal strength
  \param[out] value - the association
  \return true/false
*/
bool XSupCalls::getAssociation(QString &deviceDesc, QString &deviceName, QString &value, bool bDisplayError)
{
  bool bValue = true;
  QString text;
  CharC d(deviceName);
  int assocType;

  int retval = xsupgui_request_get_association_type(d.charPtr(), &assocType);
  if (retval != 0)
  {
    bValue = false;
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Status Warning"), 
          tr("Can't get assocation type for device '%1'.")
          .arg(deviceDesc));
    }
    bValue = false;
  }
	switch (assocType)
	{
    case ASSOC_TYPE_OPEN:
      value = tr("Open");
      break;

    case ASSOC_TYPE_SHARED:
      value = tr("Shared");
      break;

    case ASSOC_TYPE_LEAP:
      value = tr("Shared");
      break;

    case ASSOC_TYPE_WPA1:
      value = tr("WPA");
      break;

    case ASSOC_TYPE_WPA2:
      value = tr("WPA2");
      break;

  	default:
    case ASSOC_TYPE_UNKNOWN:
      value = tr("Unknown");
      break;

  }
  return bValue;
}

//! getSSID
/*!
  \brief Get the SSID for the device
  \param[in] deviceDesc - for displaying to the user
  \param[in] deviceName - the device for which we want signal strength
  \param[out] ssidString - the SSID (live) which is associated with this device
  \param[in] bDisplayError
  \return true/false
*/
bool XSupCalls::getSSID(QString &deviceDesc, QString &device, QString &ssidString, bool bDisplayError)
{
  char *ssid;
  CharC d(device);

  int retval = xsupgui_request_get_ssid(d.charPtr(), &ssid);
	if (retval == REQUEST_SUCCESS)
  {
    ssidString = ssid;
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Status Warning"), 
          tr("Can't get the SSID for device '%1'.").arg(deviceDesc));
    }
    ssidString = "";
    return false;
  }
}

//! getLiveInterfaceData()
/*!
 * @param[in] intName The name of the interface
 * @param[out] intdesc   The interface description tied to the OS specific interface name.
 * @param[out] mac   The string representation of the MAC address for the interface.
 *                   (Suitable for inclusion in the configuration file structures.)
 * @param[out] iswireless   TRUE or FALSE indicating if the interface named is wireless.
 * @return true/false - true if it is a new interface, false if it is already bound
 */
bool XSupCalls::getLiveInterfaceData(QString &intName, QString &description, 
    QString &mac, bool &bWireless, bool bDisplayError)
{
  bool bValue = false;
  char *pDescription  = NULL;
  char *pMac = NULL;
  int wireless = 0;

  bWireless = false;

  int retval = xsupgui_request_get_os_specific_int_data(intName.toAscii().data(), &pDescription, &pMac, &wireless);
  // If we get an error, it should signify that the interface is already bound
  // thus no action need occur
  if (retval)
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Status Warning"), 
          tr("Can't get OS specific information about adapter '%1'.")
          .arg(description));
    }

    bValue = false;
  }
  else
  {
    if (pDescription)
    {
      description = pDescription;
      free (pDescription);
    }

    if (pMac)
    {
      mac = pMac;
      free (pMac);
    }

    if (wireless)
    {
      bWireless = true;
    }

    bValue = true;
  }
  return bValue;
}

//! enumAndSortConnections
/*!
  \brief Get the list of connections from the configuration file
  \param[in] sortType - how to sort the connections upon return
  \param[out] pConn - the list of connections
  \param[in] bDisplayMessage - whether to display the error messages

  \return true/false
*/
bool XSupCalls::enumAndSortConnections(conn_enum **pSortedConns, bool bDisplayMessage)
{
  Q_ASSERT(pSortedConns);
  bool bValue = true;
  conn_enum *pConn = NULL;
  int retval = 0;

  retval = xsupgui_request_enum_connections(&pConn);
  if ((retval != REQUEST_SUCCESS) || (pConn == NULL))
  {
    if (bDisplayMessage)
    {
      QMessageBox::critical(NULL, tr("Get Connections Error"), 
        tr("Can't get connections."));
    }
  	bValue = false;
  }
  else
  {
    sortConnections(pConn, pSortedConns);
  }
  
  if (pConn != NULL) freeEnumConnections(&pConn);

  return bValue;
}

//! enumAndSortPossibleConnections
/*!
  \brief Get the list of "possible" connections from the configuration file
  \param[out] pConn - the list of connections
  \param[in] bDisplayMessage - whether to display the error messages

  \return true/false
*/
bool XSupCalls::enumAndSortPossibleConnections(poss_conn_enum **pSortedConn, bool bDisplayMessage)
{
  bool bValue = true;
  Q_ASSERT(pSortedConn);
  poss_conn_enum *pConn = NULL;
  int retval = 0;

  retval = xsupgui_request_enum_possible_connections(&pConn);
  if (retval == REQUEST_SUCCESS && pConn)
  {
    sortPossibleConnections(pConn, pSortedConn);
  }
  else
  {
    if (bDisplayMessage)
    {
      QMessageBox::critical(NULL, tr("Get Connections Error"), 
        tr("Can't get connections."));
    }
		bValue = false;
	}
  this->freeEnumPossibleConnections(&pConn);
  return bValue;
}

//! sortPossibleConnections
/*!
   \brief Sorts the connections by NAME
   \return nothing
   \todo Optimize this using qStableSort or qSort - will have to put the data into a class with iterators to do so
*/
void XSupCalls::sortPossibleConnections(poss_conn_enum *pConns, poss_conn_enum **pSortedConns)
{
  Q_ASSERT(pSortedConns);
  QList <int> connList;
  int count = 0;
  connList.clear();
  if (pConns == NULL)
  {
    return;
  }
  poss_conn_enum *pSConns = NULL; // use this for convenience rather than dereferencing the pointer-to-pointer

  while (pConns[count].name != NULL)
  {
    count++; 
  }
  int connIndex = 0;
  int index = 0;
  QString currentName;
  QString newName;
  bool bAdded = false;
  while (pConns[connIndex].name != NULL)
  {
    newName = pConns[connIndex].name;
    // Check the name of each entry
    // If the current one is less than the previous one, insert the index before
    for (index = 0; index < connList.count(); index++)
    {
      bAdded = false;
      currentName = pConns[connList.at(index)].name;
      if (newName.compare(currentName, Qt::CaseInsensitive) < 0)
      {
        // insert before previous
        connList.insert(index, connIndex);
        bAdded = true;
        break;
      }
    }
    // otherwise - add at the end
    if (!bAdded)
    {
      connList.append(connIndex);
    }
    connIndex++; // ends up with the total count
  }

  // Allocate and nullify all of the memory for the connections
  int size = sizeof(poss_conn_enum) * (connList.count() + 1);
  pSConns = (poss_conn_enum *)malloc(size);
  memset(pSConns, 0, size);
  index = 0;
  // shuffle the connections into priority order and put them back into the sorted enum array
  for (int i = 0; i < connList.count(); i++)
  { 
    // This is the index of the element in the original array
    index = connList.at(i);
    // Now copy the data into the new structure except for strings
    pSConns[i].auth_type = pConns[index].auth_type;
    pSConns[i].dev_desc = Util::myNullStrdup(pConns[index].dev_desc);
    pSConns[i].encryption = pConns[index].encryption;
    pSConns[i].flags = pConns[index].flags;
    pSConns[i].name = Util::myNullStrdup(pConns[index].name);
    pSConns[i].priority = pConns[index].priority;
    pSConns[i].ssid = Util::myNullStrdup(pConns[index].ssid);
  }
  // Debug code
  (*pSortedConns) = pSConns;
}

//! sortConnections
/*!
   \brief Sorts the connections into PRIORITY
   \return nothing
   \todo Optimize this using qStableSort or qSort - will have to put the data into a class with iterators to do so
*/
void XSupCalls::sortConnections(conn_enum *pConns, conn_enum **pSortedConns)
{
  Q_ASSERT(pSortedConns);
  QList <int> connList;
  int count = 0;
  connList.clear();
  if (pConns == NULL)
  {
    return;
  }

  conn_enum *pSConns = NULL;

  connList.clear();

  while (pConns[count].name != NULL)
  {
    count++; 
  }

  int connIndex = 0;
  int index = 0;
  int nextPriority = 0;

  while (pConns[connIndex].name != NULL)
  {
    int newPriority = pConns[connIndex].priority;

    if (newPriority == XSupCalls::CONNECTION_DEFAULT_PRIORITY)
    {
      connList.append(connIndex);
    }
    else
    {
      // Check the priority of each entry
      // If the current one is less, insert before
      bool bAdded = false;

      for (index = 0; index < connList.count(); index++)
      {
        nextPriority = pConns[connList.at(index)].priority;
        if (newPriority <= nextPriority)
        {
          // insert before previous
          connList.insert(index, connIndex);
          bAdded = true;
          break;
        }
      }

      // Not added - add at the end of the previous list and before the default priority items
      if (!bAdded)
      {
        connList.append(connIndex);
      }
    }

    connIndex++; // ends up with the total count
  }

  int size = sizeof(conn_enum) * (connIndex + 1);
  pSConns = (conn_enum *)malloc(size);
  memset(pSConns, 0, size);

  index = 0;

  // shuffle the connections into priority order and put them back into the enum array
  for (int i = 0; i < connIndex; i++)
  { 
    index = connList.at(i);
    memcpy(&pSConns[i], &pConns[index], sizeof(conn_enum));
    pSConns[i].name = Util::myNullStrdup(pConns[index].name);
    pSConns[i].ssid = Util::myNullStrdup(pConns[index].ssid);
    pSConns[i].dev_desc = Util::myNullStrdup(pConns[index].dev_desc);
  }
#ifdef _DEBUG
  // Debug code
  QString oldNames;
  QString oldSsids;
  QString oldDesc;
  QString newNames;
  QString newSsids;
  QString newDesc;
  for (int i = 0; i < connList.count(); i++)
  {
    newNames.append(pSConns[i].name);
    newSsids.append(pSConns[i].ssid);
    newDesc.append(pSConns[i].dev_desc);
    oldNames.append(pConns[i].name);
    oldSsids.append(pConns[i].ssid);
    oldDesc.append(pConns[i].dev_desc);
  }
//  QMessageBox::information(NULL, "Sort By Priority", tr("Before names %1\nssids %2\ndescr %3\nAfter names %4\nssids %5\ndescr %6")
  //    .arg(oldNames).arg(oldSsids).arg(oldDesc).arg(newNames).arg(newSsids).arg(newDesc));
#endif
  // end debug code
  (*pSortedConns) = pSConns;
}

//! getBroadcastSSIDs
/*!
  \brief Gets the device name and then calls the other getBroadcastSSIDs()
  \param[in] deviceDescription - the description (not the name) of the interface
  \param[out] pssids - a pointer to a pointer of ssid we get back
  \return true/false
*/
bool XSupCalls::getBroadcastSSIDs(QString &deviceDescription, ssid_info_enum **pssids)
{
  bool bcode = true;
  Q_ASSERT(pssids);
  QString deviceName;

  if (getDeviceName(deviceDescription, deviceName, false))
  {
    bcode = getBroadcastSSIDs(deviceDescription, deviceName, pssids);
  }
  else
  {
	  return false;
  }

  return bcode;
}

//! getBroadcastSSIDs
/*!
  \brief Retrieves the list of ssids for the specified adapter
  \param[in] deviceDescription - the user readable name
  \param[in] deviceName - the computer readable name
  \param[out] pssids - a pointer to a pointer of ssid we get back
  \return true/false
*/
bool XSupCalls::getBroadcastSSIDs(QString &deviceDescription, QString &deviceName, ssid_info_enum **pssids)
{
  CharC d(deviceName);
  Q_ASSERT(pssids);

  int retval = xsupgui_request_enum_ssids(d.charPtr(), pssids);
  if (retval == REQUEST_SUCCESS && *pssids)
	{
		return true;
	}
  else
  {
    QMessageBox::critical(NULL, tr("Get SSIDs Error"), 
      tr("Can't get SSIDs for device %1\n")
      .arg(deviceDescription));
		return false;
	}
}

//! enumProfiles
/*!
  \brief Retrieves the list of profiles from the supplicant configuration file
  \param[out] pProfiles - a pointer to a pointer of profile_enums
  \return true/false
*/
bool XSupCalls::enumProfiles(profile_enum **pProfiles, bool bDisplayError)
{
  Q_ASSERT(pProfiles);

  int retval = xsupgui_request_enum_profiles(pProfiles);
  if (retval == REQUEST_SUCCESS && *pProfiles)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Profiles Error"), 
        tr("Can't get profiles."));
    }
		return false;
	}
}

//! getConfigProfile
/*!
  \brief Retrieves the list of profiles from the supplicant configuration file
  \param[out] pProfiles - a pointer to a pointer of profile_enums
  \return true/false
*/
bool XSupCalls::getConfigProfile(QString &profileName, config_profiles **pConfig, bool bDisplayError)
{
  Q_ASSERT(pConfig);
  CharC pName(profileName);

  *pConfig = NULL;

  int retval = xsupgui_request_get_profile_config(pName.charPtr(), pConfig);
  if (retval == REQUEST_SUCCESS && *pConfig)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Profiles Error"), 
        tr("Can't get profile configuration for profile '%1'.").arg(profileName));
    }
		return false;
	}
}

//! enumTrustedServers
/*!
  \brief Retrieves the list of trusted servers from the supplicant configuration file
  \param[out] pServers - a pointer to a pointer of trusted_servers_enum
  \return true/false
*/
bool XSupCalls::enumTrustedServers(trusted_servers_enum **pServers, bool bDisplayError)
{
  Q_ASSERT(pServers);

  int retval = xsupgui_request_enum_trusted_servers(pServers);
  if (retval == REQUEST_SUCCESS && *pServers)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Servers Error"), 
        tr("Can't enumerate trusted servers"));
    }
    return false;
	}
}

//! enumCertificates
/*!
  \brief Retrieves the list of root ca certificates on this workstation
  \param[out] pCertificates - a pointer to a pointer of cert_enum
  \param[in] bDisplayError - set to true if we want to display from here, the error message, if there is one
  \return true/false
*/
bool XSupCalls::enumCertificates(cert_enum **pCertificates, bool bDisplayError)
{
  Q_ASSERT(pCertificates);

  int retval = xsupgui_request_enum_root_ca_certs(pCertificates);
  if (retval == REQUEST_SUCCESS && *pCertificates)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Certificates Error"), 
        tr("Can't enumerate Root CA Certificates."));
    }
    return false;
	}
}

//! enumCertificates
/*!
  \brief Retrieves the list of root ca certificates on this workstation
  \param[in] certName - the name of the certificate from which to return information
  \param[out] certInfo - must already be allocated memory
  \param[in] bDisplayError - set to true if we want to display from here, the error message, if there is one
  \return true/false
*/
bool XSupCalls::getCertInfo(QString &storetype, QString &location, cert_info **certInfo, bool bDisplayError)
{
  if (location.isEmpty())
    return false;

  int retval = xsupgui_request_ca_certificate_info(storetype.toAscii().data(), location.toAscii().data(), certInfo);
  if (retval == REQUEST_SUCCESS)
	{
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Certificates Error"), 
        tr("Can't get certificate information for storetype %1 and location '%2'.").arg(storetype).arg(location));
    }
    return false;
	}
}

//! getConfigConnection
/*!
  \brief Retrieves a specific connection configuration
  \param[in] connection - the connection name
  \param[out] pConfig - a pointer to the configuratio connection information
  \return true/false
*/
bool XSupCalls::getConfigConnection(QString &connection, config_connection **pConfig, bool bDisplayError)
{
  Q_ASSERT(pConfig);
  CharC conn(connection);
  *pConfig = NULL;

  if (connection.isEmpty())
  {
    Q_ASSERT(!connection.isEmpty());
    return false;
  }

  int retval = xsupgui_request_get_connection_config(conn.charPtr(), pConfig);
  if (retval == REQUEST_SUCCESS && *pConfig)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Connections Config Error"), 
        tr("Can't get connection configuration for connection '%1'").arg(connection));
    }
		return false;
	}
}

//! getConfigTrustedServer
/*!
  \brief Retrieves a specific server's configuration
  \param[in] server - the server name
  \param[out] pConfig - a pointer to the configuration server information
  \return true/false
*/
bool XSupCalls::getConfigTrustedServer(QString &server, config_trusted_server **pConfig, bool bDisplayError)
{
  Q_ASSERT(pConfig);
  CharC srvr(server);
  *pConfig = NULL;

  int retval = xsupgui_request_get_trusted_server_config(srvr.charPtr(), pConfig);
  if (retval == REQUEST_SUCCESS && *pConfig)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Connections Config Error"), 
        tr("Can't get connection configuration for trusted server '%1'.").arg(server));
    }
		return false;
	}
}

//! getConnectionInformation
/*!
  \brief Retrieves a partial set of configuration information from the configuration file
  \param[in] connectionName - the name of the connection
  \param[out] userNameString - the user name for the connection
  \param[out] passwordString - the password for the connection
  \return true/false
*/
bool XSupCalls::getConnectionInformation(QString &connectionName, int &authType, QString &userNameString, QString &passwordString, bool bDisplayError)
{
  bool bValue = true;
  char *username = NULL;
  char *password = NULL;
  CharC c(connectionName);

  int retval = xsupgui_request_get_connection_upw(c.charPtr(), &username, &password, &authType);
  if (retval)
  {
    if(bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Status Warning"), 
        tr("Can't get connection information for connection '%1'").arg(connectionName));
    }
    bValue = false;
  }
  else
  {
	  switch (authType)
	  {

	  case AUTH_NONE:
	  case AUTH_EAP:
      userNameString = username;
      passwordString = password;
      break;

	  case AUTH_PSK:
      userNameString = "";
      passwordString = password;
      break;

	  default:
      bValue = false;
		  break;
    }

	  free(username);
	  free(password);
	} 

  return bValue;
}

//! getDefaultSettings()
/*!
  \brief Retrieves the default global settings
  \param[out] p - a pointer to the config_globals
  \return true/false
  \todo not coded - just stubbed in
*/
bool XSupCalls::getDefaultSettings(config_globals **pGlobals)
{
  Q_ASSERT(pGlobals);
  initialize_config_globals(pGlobals);
  return true;
}

//! getAuthTime
/*!
  \brief Retrieves the authentication time
  \param[in] deviceName - the name of the device for which we want connection time
  \param[out] timeauthed - the time, in seconds, that this connection has been connected
  \return true/false
*/
bool XSupCalls::getAuthTime(QString &deviceName, long int &timeauthed, bool bDisplayError)
{
  CharC d(deviceName);

  int retval = xsupgui_request_get_seconds_authenticated(d.charPtr(), &timeauthed);
  if (retval == REQUEST_SUCCESS)
  {
    return true;
  }
  else
  {
    // No message
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Error Getting Time"), 
        tr("Can't retrieve the authenticated time."));
    }
    return false;
	}
}

//! getIPInfo
/*!
  \brief Retrieves the IP address for a specific device
  \param[in] deviceDescription - the description of the device for which we want the IP address
  \param[out] outInfo - the IP Address information
  \return true/false
*/
bool XSupCalls::getIPInfo(QString &deviceDescription, IPInfoClass &outInfo, bool bDisplayError)
{
  ipinfo_type *info = NULL; 
  CharC d(deviceDescription);

  int retval = xsupgui_request_get_ip_info(d.charPtr(), &info);
  if (retval == REQUEST_SUCCESS)
  {
    outInfo.setInfo(info);

	xsupgui_request_free_ip_info(&info);
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Error getting device info"),
        tr("An error occurred while gettting the IP info for device '%1'.").arg(deviceDescription));
    }

	if (info != NULL) xsupgui_request_free_ip_info(&info);

    return false;
  }
}

//! getDeviceName
/*!
  \brief Retrieves the XSupplicant device name from the user-readable device description
  \param[in] deviceDescription - the user-readable device description
  \param[out] deviceName - the name that the XSupplicant needs for the device
  \return true/false
*/
bool XSupCalls::getDeviceName(const QString &deviceDescription, QString &deviceName, bool bDisplayError)
{
  QString text;
  char *pDeviceName = NULL;
  CharC d(deviceDescription);

  // Using the device description - get the device name
  int retval = xsupgui_request_get_devname(d.charPtr(), &pDeviceName);
	if (retval != REQUEST_SUCCESS)
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get device info"),
        tr("An error occurred while getting the device name for device '%1'\n%2\n%3\n%4\n%5\n%6\n\n")
        .arg(deviceDescription)
        .arg(tr("This has multiple causes:"))
        .arg(tr("1. Your network card is disabled."))
        .arg(tr("2. Your configuration file (*.conf) is incorrectly formatted."))
        .arg(tr("3. A device with the associated <MAC> address isn't available on this computer."))
        .arg(tr("Select another connection or fix the problem before proceeding.")));
    }
    return false;
	}

  deviceName = pDeviceName;
  free(pDeviceName);
  pDeviceName = NULL;

  return true;
}

//! getDeviceDescription
/*!
  \brief Retrieves the XSupplicant device description from the OS specific device name
  \param[in] deviceName - the name that the XSupplicant needs for the device
  \param[out] deviceDescription - the user-readable device description

  \return true/false
*/
bool XSupCalls::getDeviceDescription(const QString &deviceName, QString &deviceDescription, bool bDisplayError)
{
  QString text;
  char *pDeviceDescription = NULL;
  CharC d(deviceName);

  // Using the device description - get the device name
  int retval = xsupgui_request_get_devdesc(d.charPtr(), &pDeviceDescription);
	if (retval != REQUEST_SUCCESS)
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get device info"),
        tr("An error occurred while getting the device description for device '%1'\n%2\n%3\n%4\n%5\n%6\n\n")
        .arg(deviceDescription)
        .arg(tr("This has multiple causes:"))
        .arg(tr("1. Your network card is disabled."))
        .arg(tr("2. Your configuration file (*.conf) is incorrectly formatted."))
        .arg(tr("3. A device with the associated <MAC> address isn't available on this computer."))
        .arg(tr("Select another connection or fix the problem before proceeding.")));
    }
    return false;
	}

  deviceDescription = pDeviceDescription;

  free(pDeviceDescription);
  pDeviceDescription = NULL;

  return true;
}

//! getEncryption
/*!
  \brief Gets the encryption being used for this device (live)
  \param[in] device - the device that will be disassociated
  \param[out] encryptionType - the type of encryption currently being used
  \note What if the device is a wired device?  What happens then?
  \return true/false
*/
bool XSupCalls::getEncryption(QString &device, QString &encryptionType, bool bDisplayError)
{
  bool bValue = true;
  CharC d(device);
  int keyType = 0;

  int retval = xsupgui_request_get_pairwise_key_type(d.charPtr(), &keyType);
  if (retval)
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Pairwise Key Type"),
          tr("An error occurred while getting the encryption type for device '%1'.\n\n").arg(device));
    }
    bValue = false;
  }
  else
  {
	  switch (keyType)   // keyType contains the value for the encryption method we are using.
	  {
	    case CIPHER_NONE:
        encryptionType = tr("NONE");
	      break;

      case CIPHER_WEP40:
#ifdef WINDOWS
		  encryptionType = tr("WEP");  // Windows doesn't let us tell between WEP40 & WEP104.
#else
        encryptionType = tr("WEP40");
#endif
        break;

      case CIPHER_TKIP:
        encryptionType = tr("TKIP");
        break;

      case CIPHER_WRAP:
        // Shouldn't ever get this!
        encryptionType = tr("WRAP");
        break;

      case CIPHER_CCMP:
        encryptionType = tr("CCMP");
        break;

      case CIPHER_WEP104:
#ifdef WINDOWS
		  encryptionType = tr("WEP");  // Windows doesn't let us tell between WEP40 & WEP104.
#else
        encryptionType = tr("WEP104");
#endif
        break;

      default:
        encryptionType = tr("Unknown");
	      break;
    }
	}

  return bValue;
}


//! getPhysicalState
/*!
  \brief Gets the state of the physical state machine
  \param[in] deviceDescription - a readable string for the error message
  \param[in] deviceName - the device for which information will be retrieved
  \param[out] status - the user-readable status of the connection 
  \param[out] state - the numeric value of the status
  \param[in] bDisplayError - whether or not to display the error
  \note What happens if a wired connection is passed in here? What if the device is not using 802.1X?
  \return true/false
*/
bool XSupCalls::getPhysicalState(QString &deviceDescription, 
                                 QString &deviceName, 
                                 QString &status, 
                                 int &state,
                                 bool bDisplayError)
{
  bool bValue = true;
  CharC d(deviceName);

  int retval = xsupgui_request_get_physical_state(d.charPtr(), &state);
  if (retval)
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Error getting physical device state"),
          tr("An error was returned while getting the physical state for device '%1'.").arg(deviceDescription));
    }
    bValue = false;
  }

  mapPhysicalState(state, status);
  return bValue;
}

//! mapPhysicalState
/*!
  \brief Maps the physical state number to a string
  \param[in] state - the physical state
  \param[out] status - the user-readable state
*/
void XSupCalls::mapPhysicalState(int state, QString &status)
{
  switch (state)
  {
    case WIRELESS_UNKNOWN_STATE:
      status = tr("Unknown State");
	    break;

    case WIRELESS_UNASSOCIATED:
	    status = tr("Wireless is not associated");
	    break;

    case WIRELESS_ASSOCIATED:
	    status  = tr("Wireless is associated");
	    break;

    case WIRELESS_ACTIVE_SCAN:
	    status = tr("Scanning for wireless networks...");
	    break;

    case WIRELESS_ASSOCIATING:
	    status = tr("Attempting to associate");
	    break;

    case WIRELESS_ASSOCIATION_TIMEOUT_S:
	    status = tr("Wireless association attempt failed");
	    break;

    case WIRELESS_PORT_DOWN:
	    status = tr("The interface is down");
	    break;

    case WIRELESS_NO_ENC_ASSOCIATION:
	    status = tr("Associated (No Encryption)");
	    break;

    case WIRELESS_INT_RESTART:
	    status = tr("The interface is being restarted");
	    break;

    case WIRELESS_INT_STOPPED:
	    status = tr("The interface has been stopped");
	    break;

    case WIRELESS_INT_HELD:
	    status = tr("The interface is waiting..");
	    break;

    case 255:
	    status = tr("No information available");
	    break;

    default:
	    status = tr("Unknown state value %1.").arg(state);
	    break;
  }
}

//! get1xState
/*!
  \brief Gets the 802.1X state of the device
  \param[in] deviceDescription - a readable string for the error message
  \param[in] device - the device for which information will be retrieved
  \param[out] status - the user-readable status of the connection 
  \param[out] state - the numeric value of the status
  \param[in] bDisplayError - whether or not to display the error
  \note What happens if a wired connection is passed in here? What if the device is not using 802.1X?
  \return true/false
*/
bool XSupCalls::get1xState(QString &deviceDescription, 
                           QString &deviceName, 
                           QString &status, 
                           int &state, 
                           bool bDisplayError)
{
  bool bValue = true;
  CharC d(deviceName);
  int retval = xsupgui_request_get_1x_state(d.charPtr(), &state);
  if (retval)
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Error getting 802.1X state"),
        tr("An error was returned while getting the 802.1X state for device '%1'.\n").arg(deviceDescription));
    }
    bValue = false;
  }
  else
  {
    map1XState(state, status);
  }
  return bValue;
}

//! map1XState
/*!
  \brief Maps the 802.1X state number to a string
  \param[in] state - the 802.1X state
  \param[out] status - the user-readable state
*/
void XSupCalls::map1XState(int state, QString &status)
{
  switch (state)
  {
    case LOGOFF:
      status = tr("Logging off the network");
      break;

    case DISCONNECTED:
      status = tr("Disconnected");
      break;

    case CONNECTING:
      status = tr("Connecting");
      break;

    case ACQUIRED:
      status = tr("Acquired");
      break;

    case AUTHENTICATING:
      status = tr("Authenticating");
      break;

    case HELD:
      status = tr("Authentication Failed");
      break;

    case AUTHENTICATED:
      status = tr("Authenticated with 802.1X");
      break;

    case RESTART:
      status = tr("Restarting the authentication");
      break;

    case S_FORCE_AUTH:
      status = tr("Connected");
      break;

    default:
    case S_FORCE_UNAUTH:
      status = tr("Unauthenticated");
      break;

  }
}


//! enumConfigInterfaces (adapters)
/*!
  \brief Retrieves the list of interfaces (adapters) from the configuration file
  \param[out] pInterfaces - a pointer to a pointer of int_enum
  \return true/false
*/
bool XSupCalls::enumConfigInterfaces(int_config_enum **pInterfaceData, bool bDisplayError)
{
  Q_ASSERT(pInterfaceData);
  int retval = 0;
	
  retval = xsupgui_request_enum_ints_config(pInterfaceData);
  if (retval == REQUEST_SUCCESS && *pInterfaceData)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Enumerate Interfaces (adapters) Error"), 
        tr("No interfaces(Linux)/adapters(Windows) defined in the configuration file."));
    }
		return false;
	}
}

//! enumLiveInterfaces (adapters)
/*!
  \brief Retrieves the list of active interfaces (adapters) 
  \param[out] pInterfaces - a pointer to a pointer of int_enum
  \return true/false
*/
bool XSupCalls::enumLiveInterfaces(int_enum **pInterfaceData, bool bDisplayError)
{
  Q_ASSERT(pInterfaceData);

  int retval = xsupgui_request_enum_live_ints(pInterfaceData);
  if (retval == REQUEST_SUCCESS && *pInterfaceData)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Live Interfaces Error"), 
        tr("Can't get the list of interfaces.\n"));
    }
	}
  return false;
}

//! getConfigInterface 
/*!
  \brief Retrieves a specific interface configuration
  \param[in] name - the interface name
  \param[out] pInterface - a pointer to a pointer of config_interfaces
  \param[in] bDisplayError 
  \return true/false
*/
bool XSupCalls::getConfigInterface(QString &interfaceName, config_interfaces **pInterfaceData, bool bDisplayError)
{
  Q_ASSERT(pInterfaceData);

  int retval = 0;
  CharC i(interfaceName);

  retval = xsupgui_request_get_interface_config(i.charPtr(), pInterfaceData);

  if (retval == REQUEST_SUCCESS && *pInterfaceData)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get interface configuration error"), 
        tr("Can't get the configuration data for interface '%1'.").arg(interfaceName));
    }
		return false;
	}
}


//! getConfigGlobals
/*!
  \brief Retrieves the list of interfaces (adapters) from the supplicant
  \param[out] globals - a pointer to a pointer of config_globals
  \return true/false
*/
bool XSupCalls::getConfigGlobals(config_globals **pGlobals, bool bDisplayError)
{
  Q_ASSERT(pGlobals);

  int retval = xsupgui_request_get_globals_config(pGlobals);
  if (retval == REQUEST_SUCCESS && *pGlobals)
  {
    return true;
  }
  else
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Get Globals Error"),
        tr("Can't get advanced/global settings."));
    }
		return false;
	}
}

/*********************************************************/
// Set ... routines
/*********************************************************/
//! setConfigGlobals
/*!
  \brief Retrieves the list of interfaces (adapters) from the supplicant
  \param[out] globals - a pointer to a pointer of config_globals
  \return true/false
*/
bool XSupCalls::setConfigGlobals(config_globals *pGlobals)
{
  Q_ASSERT(pGlobals);

	int retval = xsupgui_request_set_globals_config(pGlobals);
  if (retval == REQUEST_SUCCESS)
  {
    return true;
  }
  else
  {
    QMessageBox::critical(NULL, tr("Set Globals Error"), 
      tr("Can't set advanced/global settings.\n"));
		return false;
	}
}

//! applyPriorities()
/*!
  \brief Applies the priorities for these connections
  \param[in] pConns - the connections
  \return true/false
*/
bool XSupCalls::applyPriorities(conn_enum *pConns)
{
  Q_ASSERT(pConns);
  config_connection *pConfig = NULL;
  int i = 0;
  QString temp;

  // Must first read the entire configuration
  if (pConns)
  {
    while (pConns[i].name)
    {
      temp = pConns[i].name;
      if (!getConfigConnection(temp, &pConfig))
      {
        continue; // no message necessary - already shown in above call
      }
      pConfig->priority = pConns[i].priority;
      setConfigConnection(pConfig);
      freeConfigConnection(&pConfig);
      i++;
    }
    // Now saves it to the configuration file
    this->writeConfig();
  }

  return true;
}

//! setConfigConnection
/*!
  \brief Sets the connection configuration
  \param[in] pConfig - the configuration to save
  \return true/false
*/
bool XSupCalls::setConfigConnection(config_connection *pConfig)
{
  Q_ASSERT(pConfig);
  bool bValue = false;

  int retval = xsupgui_request_set_connection_config(pConfig);

  if (retval == REQUEST_SUCCESS)
  {
    bValue = true;
  }
  else
  {
    QMessageBox::critical(NULL, tr("Set connection configuration"),
      tr("An error occurred while setting the connection configuration for connection '%1'.").arg(pConfig->name));
  }

  return bValue;
}

//! setConnection
/*!
  \brief Sets the connection for the specified device
  \param[in] deviceName - the device to which we will connect the connection information
  \param[in] connectionName - the name of the connection from the config to be used to connect the device
  \return true/false
  \todo get the new error and then the list of connections
*/
bool XSupCalls::setConnection(QString &deviceName, QString &connectionName)
{
  bool bValue = false;
  CharC d(deviceName);
  CharC c(connectionName);

  int retval = xsupgui_request_set_connection(d.charPtr(), c.charPtr());
  if (retval == REQUEST_SUCCESS)
  {
    bValue = true;
  }
  else
  {
    if (retval == IPC_ERROR_NEW_ERRORS_IN_QUEUE)
    {
      getAndDisplayErrors();
    }
    else
    {
      QMessageBox::critical(NULL, tr("Set connection info"),
        tr("An error occurred while setting the connection information for connection '%1' and device '%2'.\n")
        .arg(connectionName).arg(deviceName));
    }
  }
  return bValue;
}

//! getAndDisplayErrors()
/*!
  \brief Gets the list of errors from the supplicant and displays them
*/
void XSupCalls::getAndDisplayErrors()
{
  int i = 0;
  QString errors;
  error_messages *msgs = NULL;

  int retval = xsupgui_request_get_error_msgs(&msgs);
  if (retval == REQUEST_SUCCESS)
  {
    if (msgs && msgs[0].errmsgs)
    {
      // If we have at least one message, display it here
      while (msgs[i].errmsgs != NULL)
      {
        errors += QString ("- %1\n").arg(msgs[i].errmsgs);
        i++;
      }

      // This box needs to be modeless - I have to create my own dialog box to go modeless
      QMessageBox::critical(NULL, tr("XSupplicant Error Summary"),
        tr("The following errors were returned from XSupplicant while starting up or attempting to connect.\n%1")
        .arg(errors));
    }
  }
  else
  {
    QMessageBox::critical(NULL, tr("Get Error Message error"),
      tr("An error occurred while checking for errors from the XSupplicant."));
  }

  xsupgui_request_free_error_msgs(&msgs);
}

//! setConfigTrustedServer
/*!
  \brief Sets the trusted server configuration
  \param[in] pConfig - the configuration to save
  \return true/false
*/
bool XSupCalls::setConfigTrustedServer(config_trusted_server *pConfig)
{
  Q_ASSERT(pConfig);
  bool bValue = false;

  int retval = xsupgui_request_set_trusted_server_config(pConfig);
  if (retval == REQUEST_SUCCESS)
  {
    bValue = true;
  }
  else
  {
    QMessageBox::critical(NULL, tr("Set trusted server configuration"),
      tr("An error occurred while setting the trusted server configuration for server '%1'.\n")
      .arg(pConfig->name));
  }
  return bValue;
}

//! setConfigProfile
/*!
  \brief Sets the profile configuration
  \param[in] pConfig - the configuration to save
  \return true/false
*/
bool XSupCalls::setConfigProfile(config_profiles *pConfig)
{
  Q_ASSERT(pConfig);
  bool bValue = false;

  int retval = xsupgui_request_set_profile_config(pConfig);
  if (retval == REQUEST_SUCCESS)
  {
    bValue = true;
  }
  else
  {
    QMessageBox::critical(NULL, tr("Set profile configuration"),
      tr("An error occurred while setting the connection configuration for profile '%1'.")
      .arg(pConfig->name));
  }
  return bValue;
}

//! setConfigInterface
/*!
  \brief Sets the interface configuration
  \param[in] pConfig - the configuration to save
  \return true/false
*/
bool XSupCalls::setConfigInterface(config_interfaces *pConfig)
{
  Q_ASSERT(pConfig);
  bool bValue = false;
  int retval = xsupgui_request_set_interface_config(pConfig);
  if (retval == REQUEST_SUCCESS)
  {
    bValue = true;
  }
  else
  {
    QMessageBox::critical(NULL, tr("Set interface configuration"),
      tr("An error occurred while setting the interface configuration for interface '%1'.").arg(pConfig->description));
  }
  return bValue;
}

//! setUserNameAndPassword
/*!
  \brief Sets the user name and password into the connection block for use later to connect to a device
  \param[in] connectionName - the name of the connection
  \param[in] userNameString - the user name for the connection
  \param[in] passwordString - the password for the connection
  \param[in] authType - the authentication type
  \return true/false
*/
bool XSupCalls::setUserNameAndPassword(const QString &connectionName, const QString &userName, 
                                       const QString &password, int authType)
{
  CharC connName(connectionName);
  CharC uName(userName);
  CharC pass(password); 
  char *pPassword = NULL;
  char *pUser = NULL;
  int	retval = REQUEST_SUCCESS;

  if (authType != AUTH_NONE)
  {
    if (!userName.isEmpty())
    {
      pUser = uName.charPtr();
    }
    if (!password.isEmpty())
    {
      pPassword = pass.charPtr();
    }
    retval = xsupgui_request_set_connection_upw(connName.charPtr(), pUser, pPassword);
  }

  if (retval == REQUEST_SUCCESS)
  {
    return true;
  }
  else if (retval == IPC_ERROR_INVALID_PROF_NAME)
  {
    QMessageBox::critical(NULL, tr("Set connection info"),
      tr("Unable to locate the profile for this connection.  Please verify that you have a valid profile defined for connection '%1'.")
      .arg(connectionName));

	  return false;
  }
  else
  {
    QMessageBox::critical(NULL, tr("Set connection info"),
      tr("An error occurred while setting the user name and password for connection '%1'.")
      .arg(connectionName));

    return false;
	}
}

//! setPasswordIntoProfile
/*!
  \brief Sets the password into the Profile structure
  \param[in] prof - the profile
  \param[in] password - the password to be set into the profile
  \todo Have Chris review this code
*/
void XSupCalls::setPasswordIntoProfile(config_profiles *prof, const QString &password)
{
  Q_ASSERT(prof);

  int retval = config_change_pwd(prof->method, password.toAscii().data());
  if (retval != XENONE)
  {
    QMessageBox::critical(NULL, tr("Set password"),
				    tr("An error occurred while setting the tunnel password for profile '%1'.\n").arg(prof->name));
  }
}

//! setUserNameIntoProfile
/*!
  \brief Sets the password into the Profile structure
  \param[in] prof - the profile
  \param[in] password - the password to be set into the profile
  \todo Have Chris review this code
*/
void XSupCalls::setUserNameIntoProfile(config_profiles *prof, const QString &userName)
{
  Q_ASSERT(prof);

  if (prof->method->method_num == EAP_TYPE_MD5)
  {
    Util::myFree(&prof->identity);
    prof->identity = Util::myNullStrdup(userName.toAscii());
  }
  else
  {
    int retval = config_set_user(prof->method, userName.toAscii().data());
    if (retval != XENONE)
    {
      QMessageBox::critical(NULL, tr("Set user name"),
        tr("An error occurred while setting the tunnel user name for profile '%1'.").arg(prof->name));
    }
  }
}

//! logoffWired
/*!
  \brief Logs off a wired connection.
  \param[in] device - the device that will be disassociated
  \return true/false
*/
bool XSupCalls::logoffWired(QString &device, QString &description)
{
  int retval;

  retval = xsupgui_request_logoff(device.toAscii().data());
  if (retval != REQUEST_SUCCESS)
  {
    QMessageBox::critical(NULL, tr("Disconnect Wired"),
      tr("An error occurred while logging off device '%1'.")
      .arg(description));

    return false;
	}
  return true;
}

//! disassociateWireless
/*!
  \brief Disassociates a wireless devices from the current connection
  \param[in] device - the device that will be disassociated
  \note What happens if a wired connection is passed in here? Should this be checked.
  \return true/false
*/
bool XSupCalls::disassociateWireless(QString &device, QString &description)
{
  int retval;

  retval = xsupgui_request_set_disassociate(device.toAscii().data(), 0);
  if (retval != REQUEST_SUCCESS)
  {
    QMessageBox::critical(NULL, tr("Disconnect Wireless"),
      tr("An error occurred while disassociating device '%1'.\n").arg(description));
    return false;
	}
  return true;
}

//! pauseWireless
/*!
  \brief Pauses (not sure what this means) the wireless device
  \param[in] device - the device that will be disassociated
  \note What does this really do and why would we use it?
  \return true/false
*/
bool XSupCalls::pauseWireless(QString &device, QString &description)
{
  int retval;

  retval = xsupgui_request_stop(device.toAscii().data());
  if (retval != REQUEST_SUCCESS)
  {
    QMessageBox::critical(NULL, tr("XSupplicant Pause Wireless Error"),
      tr("An error occurred while attempting to 'pause' device '%1'.\n").arg(description));

    return false;
	}
  return true;
}


//! connectEventListener
/*!
  \brief Connects the pipe to listen for events from the XSupplicant
  \return true/false
*/
bool XSupCalls::connectEventListener(bool bDisplayMessage)
{
  if (!m_bEventsConnected)
  {
    int retval = xsupgui_connect_event_listener();
    if (retval != REQUEST_SUCCESS)
    {
      if (bDisplayMessage)
      {
	QMessageBox::critical(NULL, tr("XSupplicant Event System Error"),
          tr("An error occurred while attempting to connect to the XSupplicant Event system\n"));
      }
      return false;
	  }
  }
  m_bEventsConnected = true;
  return true;
}

//! disconnectEventListener
/*!
  \brief Connects the pipe to listen for events from the XSupplicant
  \return true/false
  \todo How to kill the threads that are using this event_listener?
*/
bool XSupCalls::disconnectEventListener()
{
  if (m_bEventsConnected)
  {
    // Kill the threads that are waiting on this event listener
    //
    int retval = xsupgui_disconnect_event_listener();
    if (retval != REQUEST_SUCCESS)
    {
      if (QThread::currentThread() == qApp->thread())
      {
	QMessageBox::critical(NULL, tr("XSupplicant Event Listener Error"),
          tr("An error occurred while attempting to disconnect from the XSupplicant Event system."
          "This usually means handle couldn't be closed\n"));
        return false;
	    }
    }
  }
  m_bEventsConnected = false;
  return true;
}

//! waitForEvents
/*!
  \brief Blocks until an event fires Connects the pipe to listen for events from the XSupplicant
  \param[in] e - the signal emitter object
  \return true/false
  \todo set the cur_debug_level - what should this be set to?  Should this be passed in?
  \todo What other events should this be listening to?
*/
bool XSupCalls::waitForEvents(Emitter &e)
{
  int eventType = 0;
  int retval = 0;
  bool bContinue = true;
  do
  {
    retval = xsupgui_process(&eventType); 
    if (retval != REQUEST_SUCCESS)
    {
      QString errorText = m_message.getMessageString(retval);
      QString text = tr("Error %1 error occurred while listening for events. API: xsupgui_process - %2")
        .arg(retval).arg(errorText);
      e.sendUIMessage(text); 
	    xsupgui_free_event_doc();
    }
    else
    {
      bContinue = processEvent(e, eventType);
  		// Clean up the event memory
	  	// *DO NOT REMOVE THIS IT WILL CLOG THE IPC!* 
		  xsupgui_free_event_doc(); 
    }
    
  }while(eventType >= -1 && bContinue);

   QString text = tr("waitForEvents() exited.");
   e.sendUIMessage(text); 

  // -1 is a parser error
  if (eventType < -1)
  {
    return false;
  }
  return true;
}

//! processEvent
/*!
  \brief Processes the events coming from xsupgui_process()
  \param[in] e - the signal emitter object
  \param[in] eventCode - the top-level event code
  \return true - continue the wait loop, false - exit the wait loop upon return
*/
bool XSupCalls::processEvent(Emitter &e, int eventCode)
{
  char *logline = NULL;
  char *ints = NULL;
  QString text;
  int ccode = 0;
  int ecode = 0;
  bool bCode = true;
  int sm, oldstate, newstate;
  unsigned int tncconnectionid = 0xFFFFFFFF;
  QString temp;

  /*
  text = QString(tr("Event %1")).arg(eventCode);
  e.sendUIMessage(text); 
  */

	switch (eventCode)
	{
    case IPC_EVENT_LOG:
	    // Process a log message.
	    ccode = xsupgui_events_generate_log_string(&ints, &logline);
		if (ccode == REQUEST_SUCCESS)
		{
	        e.sendLogMessage(logline); 
	    }
	   else
	    {
		    text = tr("Can't process an IPC_EVENT_LOG event.  Error: %1").arg(ccode);
		    e.sendUIMessage(text);
		}

	    Util::myFree(&ints);
	    Util::myFree(&logline);			
	    break;

	  case IPC_EVENT_ERROR:
	    // Process an error message.
        // This also needs to throw up an error window in addition to logging it
        ccode = xsupgui_events_get_error(&ecode, &logline);
        if (ccode == 0)
        {
			switch (ecode)
			{
			case IPC_EVENT_ERROR_SUPPLICANT_SHUTDOWN:
			    // We already have a process for notifying the user that the supplicant
			    // shut down.  So, mute this error message.
				break;

			case IPC_EVENT_ERROR_IES_DONT_MATCH:
				// We want to change what this error says.  So trap it here.
				text = QString(tr("There was a problem connecting to this network.  Please try again.  If this problem persists, please talk to your network administrator."));
				e.sendSupWarningEvent(text);
				break;

			default:
			    text = QString(tr("Error : '%1'")).arg(logline);
			    e.sendSupErrorEvent(text);
				break;
			}
        }
        break; 


	  case IPC_EVENT_STATEMACHINE:
		  if (xsupgui_events_get_state_change(&ints, &sm, &oldstate, &newstate, &tncconnectionid) >= 0)
		  {
			  // The state change message was valid.
			  e.sendStateChange(QString(ints), sm, oldstate, newstate, tncconnectionid);
			  
			  free(ints);
			  ints = NULL;
		  }
		  // Otherwise ignore it. :-/
		  break;
    
    case IPC_EVENT_SCAN_COMPLETE:
	  if (xsupgui_events_get_scan_complete_interface(&ints) == REQUEST_SUCCESS)
	  {
		  e.sendScanComplete(QString(ints));
	  }
	  else
	  {
		  e.sendUIMessage(tr("Got a wireless scan complete message from an unknown interface."));
	  }
      break;

	  case IPC_EVENT_REQUEST_PWD:
      {
    	  char *connname = NULL;
        char *eapmethod = NULL;
        char *chalstr = NULL;

		// Process a password request event.
		ccode = xsupgui_events_get_passwd_challenge(&connname, &eapmethod, &chalstr);
        if (ccode == 0)
        {
          e.sendRequestPassword(QString(connname), QString(eapmethod), QString(chalstr));
			    free(connname);
  		    free(eapmethod);
	  	    free(chalstr);
        }
        else
        {
          text = tr("Can get the password challenge for an IPC_EVENT_REQUEST_PWD event.  Error: %1").arg(eventCode);
          e.sendUIMessage(text);
        }
		break;
      }

    case IPC_EVENT_UI:
      {
        QString desc;
      	int uievent = 0;
        char *value = NULL;
        char *interfaces = NULL;
    		int sspercent = 0;

	      ccode = xsupgui_events_get_ui_event(&uievent, &interfaces, &value);
	      if (ccode == 0)
	      {
          switch (uievent)
          {
		        case IPC_EVENT_UI_IP_ADDRESS_SET:
					e.sendIPAddressSet();
			        break;

            case IPC_EVENT_ERROR_CANT_RENEW_DHCP: 
					e.sendIPAddressSet();
			        break;

			case IPC_EVENT_UI_AUTH_TIMEOUT:
			  temp = interfaces;
				e.sendAuthTimeout(temp);
				break;

            case IPC_EVENT_ERROR_SUPPLICANT_SHUTDOWN: 
              e.sendXSupplicantShutDownMessage();
              bCode = false;
              break;

            case IPC_EVENT_SIGNAL_STRENGTH:
		      sspercent = atoi(value);
  		      e.sendSignalStrength(sspercent);
              break;

            case IPC_EVENT_INTERFACE_INSERTED:
              e.sendInterfaceInsertedEvent(value);
              break;

			case IPC_EVENT_INTERFACE_REMOVED:
				e.sendInterfaceRemovedEvent(value);
				break;

			case IPC_EVENT_BAD_PSK:
			  temp = value;
				e.sendBadPSK(temp);
				break;

			case IPC_EVENT_UI_LINK_UP:
				e.sendLinkUpEvent(value);
				break;

			case IPC_EVENT_UI_LINK_DOWN:
				e.sendLinkDownEvent(value);
				break;

			case IPC_EVENT_UI_INT_CTRL_CHANGED:
				sspercent = atoi(value);

				if (sspercent == 1)
				{
					e.sendInterfaceControl(true);
				}
				else
				{
					e.sendInterfaceControl(false);
				}
				break;

			case IPC_EVENT_UI_TROUBLETICKET_ERROR:
				e.sendTroubleTicketError();
				break;

			case IPC_EVENT_UI_TROUBLETICKET_DONE:
				e.sendTroubleTicketDone();
				break;

			case IPC_EVENT_UI_NEED_UPW:
				temp = value;
				e.sendRequestUPW(temp);
				break;

			case IPC_EVENT_UI_POST_CONNECT_TIMEOUT:
				temp = value;
				e.sendPostConnectTimeout(temp);
				break;

			case IPC_EVENT_UI_CONNECTION_DISCONNECT:
				temp = value;
				e.sendConnectionDisconnected(temp);
				break;

			case IPC_EVENT_PSK_SUCCESS:
				temp = value;
				e.sendPSKSuccess(temp);
				break;

            default:
            if (getUIEventString(uievent, desc))
            {
              text = QString ("%1").arg(desc);
              e.sendUIMessage(text); 
            }
            break;
          }

            //free (value);    // XXX Fix later. (Freeing here causes the request to get interface data in LoginMainDlg/slotInterfaceInserted to be NULL.
		    free(interfaces);  
	    }
	    else
	    {
          text = tr("Couldn't parse UI event!\n");
          e.sendUIMessage(text);
	    }
        break;
      }


	  case IPC_EVENT_TNC_UI:
      {
        uint32_t oui = 0;
        uint32_t notification = 0;
		    if ((ccode = xsupgui_events_get_tnc_ui_event(&oui, &notification)) == 0)
		    {
          e.sendTNCUIEvent(oui, notification);
		    }
        else
        {
          text = tr("Can process an IPC_EVENT_TNC_UI event.  Error: %1").arg(ccode);
          e.sendUIMessage(text);
        }
			  break;
      }

	  case IPC_EVENT_TNC_UI_REQUEST:
      {
        uint32_t imc = 0, connID = 0, oui = 0, request = 0;
		    if ((ccode = xsupgui_events_get_tnc_ui_request_event(&imc, &connID, &oui, &request)) == 0)
		    {
          e.sendTNCUIRequestEvent(imc, connID, oui, request);
		    }
        else
        {
          text = tr("Can't process an IPC_EVENT_TNC_UI_REQUEST event.  Error: %1").arg(ccode);
          e.sendUIMessage(text);
        }
			  break;
      }

	  case IPC_EVENT_TNC_UI_BATCH_REQUEST:
      {
        uint32_t imc = 0; // TNC object making call - GUI stores and passes back only
        uint32_t connID = 0; // TNC connection id - GUI stores and passes back only
        uint32_t oui = 0; // Vendor ID from IMC - GUI stores and passes back only
        uint32_t batchType = 0;  // This IS significant: currently defined types are: 
        tnc_msg_batch *pTNCMessages = NULL;
		    if ((ccode = xsupgui_events_get_tnc_ui_batch_request_event(&imc, 
          &connID, &oui, &batchType, &pTNCMessages)) == 0 
          && oui == ID_ENGINES_OUI) 
        {
			QString eventNum = QString("The UI got a TNC remediation event: %1  (ConnID : %2,  IMC ID : %3)\n").arg(batchType).arg(connID).arg(imc);
			e.sendUIMessage(eventNum);

          switch (batchType)
          {
            case BATCH_OUT_OF_COMPLIANCE:
			  {
				e.sendUIMessage(tr("Notifying listeners that a TNC IMC has detected a compliance issue."));
				e.sendTNCUIComplianceFailureBatchEvent(imc, connID, oui, batchType, pTNCMessages);
			  }
			  break;
            case BATCH_COMPLIANCE_REPORT:
                {
                    e.sendUIMessage(tr("Notifying listeners about a TNC IMC compliance report."));
                    e.sendTNCUIComplianceReportBatchEvent(imc, connID, oui, batchType, pTNCMessages);
                }
                break;
            case BATCH_REMEDIATION_REQUESTED:
              {
			    e.sendUIMessage(tr("Notifying listeners that remediation has been requested by a TNC IMC."));
                e.sendTNCUIRemediationRequestedBatchEvent(imc, connID, oui, batchType, pTNCMessages);
              }
              break;
			case BATCH_REMEDIATION_WILL_BEGIN:
			  {
			    e.sendUIMessage(tr("Notifying listeners that remediation will begin."));
				e.sendTNCUIRemediationWillBeginBatchEvent(imc, connID, oui, batchType, pTNCMessages);
			  }
			  break;
            case BATCH_REMEDIATION_ITEM_STARTED:
              {
                e.sendUIMessage(tr("Notifying listeners that an item has begun remediation."));
                e.sendTNCUIRemediationStatusItemStartedEvent(imc, connID, oui, batchType, pTNCMessages);
              }
              break;
            case BATCH_REMEDIATION_ITEM_SUCCESS:
              {
                e.sendUIMessage(tr("Notifying listeners that an item has successful remediated."));
                e.sendTNCUIRemediationStatusItemSuccessEvent(imc, connID, oui, batchType, pTNCMessages);
              }
              break;
            case BATCH_REMEDIATION_ITEM_FAILURE:
              {
                e.sendUIMessage(tr("Notifying listeners that an item has failed remediation."));
                e.sendTNCUIRemediationStatusItemFailureEvent(imc, connID, oui, batchType, pTNCMessages);
              }
              break;
            case BATCH_REMEDIATION_WILL_END:
              {
				e.sendUIMessage(tr("Notifying listeners that remediation will end."));
                e.sendTNCUIRemediationWillEndBatchEvent(imc, connID, oui, batchType, pTNCMessages);
              }
			  break;
            case BATCH_TNC_STATE_CHANGE:
                {
					e.sendUIMessage(tr("Notifying listeners of a TNC state change.  (New State: %1)").arg(pTNCMessages[0].msgid));

					if (pTNCMessages != NULL)
					{
						e.sendTNCUILoginWindowStatusUpdateEvent(imc, connID, oui, pTNCMessages[0].msgid);
					}
                }
                break;
            case BATCH_REMEDIATION_EVENT:
                {
				    e.sendUIMessage(tr("Notifying listeners of a remediation event."));
                    e.sendTNCUIRemediationEventBatchEvent(imc, connID, oui, batchType, pTNCMessages);
                }break;
			case BATCH_TNC_CONNECTION_PURGE_EVENT:
				{
					e.sendUIMessage(tr("Notifying listeners of a TNC connection purge event."));
					e.sendTNCUIPurgeConnectionBatchEvent(imc, connID, oui, batchType, pTNCMessages);
				}break;
            default: // do nothing
              break;
          }

//		  xsupgui_events_free_tnc_msg_batch_data(&pTNCMessages);
        }
        else
        {
          text = tr("Can't process an IPC_EVENT_TNC_UI_REQUEST event.  Error: %1").arg(ccode);
          e.sendUIMessage(text);
        }
		    break;
      }

      // get this when the pipe is broken and most likely, the supplicant has died
    case IPC_EVENT_COM_BROKEN: 
      e.sendXSupplicantShutDownMessage();
      bCode = false; // end the wait loop
      break;

    default:
      text = QString(tr("Unknown event received: %1\n")).arg(eventCode);
      e.sendUIMessage(text); 
	    break;

	}
  return bCode;
}

//! TNCReply
/*!
  \brief Replies to the TNC remediation request
  \param[out] uiEvent - the event received
  \param[out] connID - the connection to send the signal to
  \param[out] desc - the description of the event
  \return true/false - display the message or not
*/
bool XSupCalls::TNCReply(uint32_t imc, uint32_t connID, uint32_t oui, uint32_t request, bool bDisplayError, int answer)
{
	// Tell the IMC that the user has requested remediation
  int retval = xsupgui_request_answer_tnc_ui_request(imc, connID, oui, request, answer);
  if (retval)
  {
    if (bDisplayError)
    {
      QMessageBox::critical(NULL, tr("Remediation Response Error"), 
        tr("Got an error telling the XSupplicant to fix the remediation issues issues."));
    }
    return false;
  }
  return true;
}

//! getUIEventString
/*!
  \brief Gets the UI string for the specified UI Event
  \param[in] uiEvent - the event received
  \param[out] desc - the description of the event
  \return true/false - display the message or not
*/
bool XSupCalls::getUIEventString(int uiEvent, QString &desc)
{
  bool bValue = true;
	switch (uiEvent)
	{
	case IPC_EVENT_UI_IP_ADDRESS_SET:
		desc = tr("An interface has had it's IP address set!");
		bValue = false; // I already ask XSupplicant for this information
		break;

  case IPC_EVENT_INTERFACE_INSERTED:
		desc = tr("An interface (adapter) was inserted!");
    bValue = true; // I want to know about this one and act upon it
    break;

  case IPC_EVENT_INTERFACE_REMOVED:
    desc = tr("An interface has been removed.");
    bValue = false; // I don't care about this right now
    break;

  case IPC_EVENT_SIGNAL_STRENGTH:
    desc = tr("An interface's signal strength is being updated.");
    bValue = false; // I already ask XSupplicant for this information
    break;

  case IPC_EVENT_UI_GOING_TO_SLEEP:
	  bValue = false;
	  break;

  case IPC_EVENT_UI_SLEEP_CANCELLED:
	  bValue = false;
	  break;

  case IPC_EVENT_UI_WAKING_UP:
	  bValue = false;
	  break;

	default:
		desc = tr("An unknown XSupplicant UI event occurred '%1'").arg(uiEvent);
		break;
	}
  return bValue;
}


// Test code
void XSupCalls::sendPStatus(Emitter &e)
{
  QString newStateStr;
  static int newstate = 0;
  mapPhysicalState(newstate, newStateStr);
  e.sendStateMessageToScreen(IPC_STATEMACHINE_PHYSICAL, newstate, newStateStr);
  newstate++;
}

// Test code
void XSupCalls::sendXStatus(Emitter &e)
{
  static int newstate = 0;
  QString newStateStr;
  map1XState(newstate, newStateStr);
  e.sendStateMessageToScreen(IPC_STATEMACHINE_8021X, newstate, newStateStr);
  newstate++;
}


//! startWirelessScan
/*!
  \brief Starts scanning for wireless SSIDs
  \param[in] device - the device with which to scan
  \return true/false
*/
bool XSupCalls::startWirelessScan(QString &deviceDescription)
{
  QString deviceName;

  bool bval = getDeviceName(deviceDescription, deviceName, true);
  if (!bval)
    return false;

  int retval = xsupgui_request_wireless_scan(deviceName.toAscii().data(), FALSE);
  if (retval == REQUEST_SUCCESS)
  {
    return true;
  }
  else
  {
    QMessageBox::critical(NULL, tr("Scan for Wireless Access Points"), 
      tr("Can't start a scan for wireless access points on adapter '%1'.").arg(deviceDescription));
		return false;
  }
}

/*********************************************************/
// Delete ... routines
/*********************************************************/
//! deleteConnection
/*!
  \brief Delete a connection configuration
  \param[in] name - the name of the object to delete
  \param[in] bAsk - whether to ask if they want to attempt to disconnect
  \param[out] bDisconnect - if the user has selected to disconnect from this connection - caller needs to take action to disconnect
*/
bool XSupCalls::deleteConnectionConfig(QString &name)
{
  int retval = xsupgui_request_delete_connection_config(name.toAscii().data());
  if (retval == REQUEST_SUCCESS)
  {
    writeConfig();
    return true;
  }
  else
  {
    if (retval == IPC_ERROR_CANT_DEL_CONN_IN_USE)
    {
      QMessageBox::critical(NULL, tr("Can't delete"), tr("You cannot delete this connection because it is still in use.\nPlease disconnect from the network, and try again."));
		return false;
	}
    else
    {
		if (retval == IPC_ERROR_INVALID_CONN_NAME) return true;  // This means the configuration wasn't written yet.

		QMessageBox::critical(NULL, tr("Error Deleting Connection"), 
        tr("Can't delete connection '%1' from the configuration file.")
        .arg(name));
    }
		return false;
  }
}

//! deleteProfile
/*!
  \brief Deletes a profile
  \param[in] p - the name of the object
*/
bool XSupCalls::deleteProfileConfig(QString &name)
{  
  int retval = REQUEST_SUCCESS;

  retval = xsupgui_request_delete_profile_config(name.toAscii().data(), 0);

  if (retval == REQUEST_SUCCESS)
  {
	  writeConfig();
	  return true;
  }

  if (retval == IPC_ERROR_STILL_IN_USE)
  {
    QMessageBox::critical(NULL, tr("Delete a Profile"),
		  tr("The profile '%1' is still in use by one or more connections.  Please remove it from any connections and try again.").arg(name));
	return false;
  }
  else
  {
	  if (retval == IPC_ERROR_INVALID_PROF_NAME) return true;  // This means the profile wasn't written yet.  (Which means it was deleted. ;)

	  QMessageBox::critical(NULL, tr("Delete a Profile"), 
        tr("Can't delete profile '%1'from the configuration file.\n").arg(name));
		  return false;
  }

  return false;  // Should be impossible.
}

//! deleteTrustedServerConfig
/*!
  \brief Delete a trusted server from the configuration file
  \param[in] p - the name of the object
*/
bool XSupCalls::deleteTrustedServerConfig(QString &name)
{
  CharC n(name);
  int retval = REQUEST_SUCCESS;

  retval = xsupgui_request_delete_trusted_server_config(n.charPtr(), 0);
  if (retval == REQUEST_SUCCESS)
  {
    return writeConfig(); // now save it to the configuration file
  }
  else if (retval == IPC_ERROR_STILL_IN_USE)
  {
    QMessageBox::critical(NULL, tr("Delete a Trusted Server"),
		  tr("Can't delete trusted server '%1' because it is still in use by one or more profiles.").arg(name));
	  return false;
  }
  else
  {
	  if (retval == IPC_ERROR_INVALID_TRUSTED_SVR) return true;  // Means the trusted server wasn't written yet.

	  QMessageBox::critical(NULL, tr("Delete a Trusted Server"), 
      tr("Can't delete trusted server '%1'from the configuration file.\n").arg(name));
  return false;
  }

  return false;  // Should be impossible.
}



/*********************************************************/
// Memory freeing routines
/*********************************************************/
//! freeEnumConn
/*!
  \brief Free the list
  \param[in] p - a pointer to a pointer of conn_enum
*/
void XSupCalls::freeEnumConnections(conn_enum **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_conn_enum(p);
}

//! freeEnumConn
/*!
  \brief Free the list
  \param[in] p - a pointer to a pointer of conn_enum
*/
void XSupCalls::freeEnumPossibleConnections(poss_conn_enum **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_poss_conn_enum(p);
}

//! freeEnumProfile
/*!
  \brief Free the list
  \param[in] p - a pointer to a pointer of profile_enum
*/
void XSupCalls::freeEnumProfile(profile_enum **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_profile_enum(p);
}

//! freeEnumServer
/*!
  \brief Free the list
  \param[in] p - a pointer to a pointer of trusted_servers_enum
*/
void XSupCalls::freeEnumTrustedServer(trusted_servers_enum **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_trusted_servers_enum(p);
}

//! freeGlobals
/*!
  \brief Free the list
  \param[in] globals - a pointer to a pointer of int_enum
  \todo Need a free function in the supplicant
*/
void XSupCalls::freeEnumLiveInt(int_enum **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_int_enum(p);
}

//! freeConfigIntEnums
/*!
  \brief Free the list
  \param[in] p - a pointer to be freed
  \todo Need a free function in the supplicant
*/
void XSupCalls::freeEnumStaticInt(int_config_enum **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_int_config_enum(p);
}

//! freeConfigGlobals
/*!
  \brief Free the list
  \param[in] globals - a pointer to a pointer of config_globals1
*/
void XSupCalls::freeConfigGlobals(config_globals **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_config_globals(p);
}

//! freeEnumSSID
/*!
  \brief Free the ssid enums
  \param[in] pssids - the block to free
*/
void XSupCalls::freeEnumSSID(ssid_info_enum **p)
{
  Q_ASSERT(p);
	xsupgui_request_free_ssid_enum(p);
}

//! freeEnumServer
/*!
  \brief Free the list
  \param[in] p - a pointer to a pointer of trusted_servers_enum
*/
void XSupCalls::freeEnumCertificates(cert_enum **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_cert_enum(p);
}
//! freeConfigProfile
/*!
  \brief Free the configuration block
  \param[in] p - a pointer to a pointer of config_profiles
*/
void XSupCalls::freeConfigProfile(config_profiles **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_profile_config(p);
}

//! freeCertInfo
/*!
  \brief Free the memory associated with a configuration block
  \param[in] p - a pointer to a pointer of config_connection - this doesn't free the memory allocated for the cert_info - 
*/
void XSupCalls::freeCertInfo(cert_info **certInfo)
{
	xsupgui_request_free_cert_info(certInfo);
}

//! freeConfigConnection
/*!
  \brief Free the configuration block
  \param[in] p - a pointer to a pointer of config_connection
*/
void XSupCalls::freeConfigConnection(config_connection **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_connection_config(p);
}

//! freeConfigTrustedServer
/*!
  \brief Free the configuration block
  \param[in] p - a pointer to a pointer of config_trusted_server
*/
void XSupCalls::freeConfigTrustedServer(config_trusted_server **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_trusted_server_config(p);
}


//! freeConfigInterface
/*!
  \brief Free the configuration block
  \param[in] p - a pointer to a pointer of config_interfaces
*/
void XSupCalls::freeConfigInterface(config_interfaces **p)
{
  Q_ASSERT(p);
  xsupgui_request_free_interface_config(p);
}

//! writeConfig
/*!
  \brief Writes the configuration from the supplicant to the configuration file
  \note If debugging - writes the file to a testconfig.conf
  \note if release - writes the file to the actual in-use file
  \todo Link up the help button here
*/
bool XSupCalls::writeConfig()
{
  int retval = 0;
  QMessageBox::StandardButton b = QMessageBox::Yes;
  QString tempFile = QString("%1/%2").arg(QApplication::applicationDirPath()).arg("testconfig.conf");

  switch (b)
  {
    case QMessageBox::Cancel:
      return false;

    case QMessageBox::No:
    {
      tempFile = QString("%1/%2").arg(QApplication::applicationDirPath()).arg("testconfig.conf");
      CharC n(tempFile);
      retval = xsupgui_request_write_config(n.charPtr());
      break;
    }

    case QMessageBox::Yes:
    {
      retval = xsupgui_request_write_config(NULL);
      break;
    }
    
  default:
    return false;
  }
  if (retval == REQUEST_SUCCESS)
  {
    return true;
  }
  else
  {
    QMessageBox::critical(NULL, tr("Write Configuration"), 
      tr("Can't write the supplicant configuration file.\n"));
  return false;
  }
}

bool XSupCalls::getAndCheckSupplicantVersion(QString &fullVersion, QString &numberString, bool bDisplay)
{
  char *pVersion = NULL;
  bool bValue = true;

  int retval = xsupgui_request_version_string(&pVersion);
  if (retval)
  {
    if (bDisplay)
    {
      QMessageBox::critical(NULL, 
        tr("XSupplicant Version Info"), 
        tr("The XSupplicant version information could not be read. You cannot proceed."));
    }
    fullVersion = tr("Unknown");
    numberString = tr("Unknown");
    bValue = false;
  }
  else
  {
    // Pull off the number only
    fullVersion = pVersion;
    numberString = fullVersion.remove("XSupplicant ");
    //bValue = checkSupplicantVersion(numberString);
	bValue = true;

	free(pVersion);
  }
  return bValue;
}

/*
 *  \brief Check the supplicant version and print appropriate messages
 *
 *  @param[in] retVal - if it was not read corrrect, comes in as non-zero
 *  @param[in] numberString - the number portion of the version
 *
 **/
bool XSupCalls::checkSupplicantVersion(QString &numberString)
{
  bool bValue = true;

  // Pull the XSupplicant off the version string
  QString temp = numberString.right(numberString.length() - QString("XSupplicant ").length());
  QStringList versionInfo = temp.split(".");
  if (versionInfo.size() != 4)
  {
    QMessageBox::critical(NULL, 
      tr("XSupplicant Version Info"), 
      tr("The XSupplicant version information could not be parsed. The version string is invalid: %1\nYou cannot proceed.")
      .arg(numberString));
    bValue = false;
  }

  return true;
}



/**
 *  sendPing()
 *  \brief Pings the supplicant and, if anything but a REQUEST_SUCCESS is received, returns an error
 *
 *  \reutns true or false
 **/
bool XSupCalls::sendPing()
{
	int err = xsupgui_request_ping();

  if (err != REQUEST_SUCCESS)
  {
    return false;
  }
  return true;
}

/**
 *  getTunnelNames()
 *  \brief Gets the outer (phase1) and inner (phase2) - if any - protocol names
 *  \param [in] pMethod - the outer eap method structure
 *  \param [out] outer - the outer tunnel name
 *  \param [out] inner - the inner tunnel name
 *  \returns nothing
 **/
void XSupCalls::getTunnelNames(config_eap_method *pMethod, QString &outer, QString &inner)
{
  inner = "None";
  outer = "";
  switch (pMethod->method_num)
  {
    case EAP_TYPE_MD5:
    {
      outer = "EAP-MD5";
      break;
    }
    case EAP_TYPE_GTC: 
    {
      outer = "EAP-GTC";
      break;
    }
    case EAP_TYPE_LEAP:
    {
      outer = "EAP-LEAP";
      break;
    }

	  case EAP_TYPE_AKA:
    {
      outer = "EAP-AKA";
		  break;
    }

	  case EAP_TYPE_SIM:
    {
      outer = "EAP-SIM";
      break;
    }

    case EAP_TYPE_OTP:
    {
      outer = "EAP-OTP";
      break;
    }

    case EAP_TYPE_TLS:
    {
      outer = "EAP-TLS";
      break;
    }

    case EAP_TYPE_TTLS: //! This method has an inner-protocol as well
    {
      outer = "EAP-TTLS";
      // Does have inner - need to enable the tab and populate it
      config_eap_ttls *p = (config_eap_ttls *)pMethod->method_data;
      if (p)
      {
        getInnerTunnelName(p->phase2_type, p->phase2_data, inner);
      }
      break;
    }

    case EAP_TYPE_PEAP: //! This method has an inner-protocol as well
    {
      outer = "EAP-PEAP";
      // Does have inner - need to enable the tab and populate it
      // Need to check all of these pointers
      config_eap_peap *p = (config_eap_peap *)pMethod->method_data;
      if (p && p->phase2)
      {
        getInnerTunnelName(p->phase2->method_num, p->phase2->method_data, inner);
      }
      break;
    }

    case EAP_TYPE_MSCHAPV2:
    {
      outer = "EAP-MSCHAPv2";
      break;
    }
 	  case EAP_TYPE_FAST:
    {
      outer = "EAP-FAST";
      config_eap_fast *p = (config_eap_fast*)pMethod->method_data;
      if (p && p->phase2)
      {
        getInnerTunnelName(p->phase2->method_num, p->phase2->method_data, inner);
      }
	    break;
    }
    default:
    {
      outer = "Unknown";
      break;
    }
  }
}

void XSupCalls::getInnerTunnelName(int innerMethod, void *pMethodData, QString &inner)
{
  switch (innerMethod)
  {
  case EAP_TYPE_MSCHAPV2:
    inner = tr("EAP-MSCHAPv2");
    break;
  case EAP_TYPE_GTC:
    inner = tr("EAP-GTC");
    break;
  case TTLS_PHASE2_PAP:
    inner = tr("PAP");
    break;
  case TTLS_PHASE2_CHAP:
    inner = tr("CHAP");
    break;
  case TTLS_PHASE2_MSCHAP:
    inner = tr("MSCHAP");
    break;
  case TTLS_PHASE2_MSCHAPV2:
    inner = tr("MSCHAPv2");
    break;
  case TTLS_PHASE2_EAP:
    {
      config_eap_method *pMethod = (config_eap_method *)pMethodData;
      if ( pMethod && pMethod->method_num == EAP_TYPE_MD5)
      {
        inner = tr("EAP-MD5");
      }
      else
      {
        inner = tr("Invalid");
      }
    }
    break;
  default:
    inner = tr("Unknown");
      break;
  }
}

void XSupCalls::deleteConfigEapMethod(config_eap_method **p)
{
  Q_ASSERT(p);
  delete_config_eap_method(p);
}

/**
 *  connectToSupplicant()
 *  \brief Loads (if necesary) and connects to the XSupplicant
 *  \returns true/false
 **/
bool XSupCalls::connectToSupplicant()
{
  // Make sure we can load the supplicant - if not - don't go on
  disconnectXSupplicant();
  return connectXSupplicant();
}

//! checkProfileUse
/*!
   \brief Checks to see if this profile is being used in any of the connections.
   Asks the user if they want to proceed or not.
   \return true/false
*//*
bool XSupCalls::checkProfileUse(QString &profileToDelete)
{
  bool bValue = true;
  int i = 0;
  config_connection *pConfig  = NULL;
  conn_enum *pConns = NULL;
  bValue = enumAndSortConnections(&pConns, false);
  // If can't read them or no connections - OK to delete
  if (!bValue || pConns == NULL)
  {
    return true;
  }
  
  while(pConns[i].name)
  {
    if (getConfigConnection(QString(pConns[i].name), &pConfig, false))
    {
      if (profileToDelete == pConfig->profile)
      {
        m_message.DisplayMessage( m_message.ERROR_TYPE, tr("Can't Delete Object"),
          tr("Because profile '%1' is used in connection '%2' it can't be deleted.  Before you can delete this profile, you will have to use another profile in connection '%2' (and any other connections that use this profile).")
          .arg(profileToDelete)
          .arg(pConfig->name));
        bValue = false;
        break;
      }
    }
    i++;
  }
  this->freeEnumConnections(&pConns);
  return bValue;
}*/

//! checkServerUse
/*!
   \brief Checks to see if this server is being used in any of the profiles
   Asks the user if they want to proceed or not.
   \return true/false
*/
/*
bool XSupCalls::checkServerUse(QString &serverToDelete)
{
  bool bValue = true;
  config_profiles *pProfile = NULL;
  profile_enum *pProfiles;
  bValue = enumProfiles(&pProfiles, false);
  int i = 0;
  // If there aren't any - proceed
  if (!bValue || pProfiles == NULL)
  {
    return true;
  }
  while(pProfiles[i].name)
  {
    if (getConfigProfile(QString(pProfiles[i].name), &pProfile, false))
    {
      // Need to switch on EAP methods here - probably put this into a separate function
      if (isServerUsedInProfile(pProfile, serverToDelete))
      {
        m_message.DisplayMessage( m_message.ERROR_TYPE, tr("Can't Delete Object"),
          tr("Because server '%1' is used in profile '%2' it can't be deleted.  Before you can delete this profile, you will have to use another server in profile '%2' (and any other profiles that use this server).")
          .arg(serverToDelete)
          .arg(pProfile->name));
        bValue = false;
        break;
      }
    }
    i++;
  }
  this->freeEnumProfile(&pProfiles);
  return bValue;
}
*/

bool XSupCalls::isServerUsedInProfile(config_profiles *pProfile, QString &server)
{
  bool bFound = false;
  switch (pProfile->method->method_num)
  {
    case EAP_TYPE_MD5:
      break;

    case EAP_TYPE_GTC: // not supported with version 1
      break;

    case EAP_TYPE_LEAP:
      break;

	  case EAP_TYPE_AKA:
		  break;

	  case EAP_TYPE_SIM:
      break;

    case EAP_TYPE_OTP:
      break;

    case EAP_TYPE_TLS:
      {
        config_eap_tls *p = (config_eap_tls *)pProfile->method->method_data;
        if (server == p->trusted_server)
        {
          bFound = true;
        }
      }
      // No inner
      break;

    case EAP_TYPE_TTLS: //! This method has an inner-protocol as well
      {
        config_eap_ttls *p = (config_eap_ttls *)pProfile->method->method_data;
        if (server == p->trusted_server)
        {
          bFound= true;
        }
      }
      break;

    case EAP_TYPE_PEAP: //! This method has an inner-protocol as well
      {
        config_eap_peap *p = (config_eap_peap *)pProfile->method->method_data;
        if (server == p->trusted_server)
        {
          bFound = true;
        }
      }
      break;

    case EAP_TYPE_MSCHAPV2:
      break;

 	  case EAP_TYPE_FAST:
	    break;

    default:
      break;
  }
  return bFound;
}


//! isOnlyInstance
/*!
   \brief Checks to see if this executable is the only one running
   \param[in] executableName (without the .exe on Windows)
   \return true/false
*/
bool XSupCalls::isOnlyInstance(char *exeName)
{

#ifdef WINDOWS
  QString fullName = QString ("%1.exe").arg(exeName);
  CharC c = fullName;
  if (supdetect_numinstances(c.charPtr()) >= 2)
  {
    return false;
  }
#else
#warning FIX!
  /*
  if (supdetect_numinstance(exeName) >= 2)
  {
    return false;
  }
  */
#endif
  return true;
}

//! updateAdapters
/*!
   \brief Lists the live adapters, and adds those that are not bound into the configuration file
   \param [in] bDisplayError
   \return true/false
*/
bool XSupCalls::updateAdapters(bool bDisplayError)
{
  bool bAdded = false; 
  int_enum *liveInts;
  QString deviceDescription;
  QString deviceName;
  QString mac;
  bool bWireless = false;
  int i = 0;

  do
  {
    if (!m_adapterMutex.tryLock())
    {
      i++;
      continue;
    }

    bool bValue = enumLiveInterfaces(&liveInts, bDisplayError);
    if ((!bValue) || (liveInts == NULL))
    {
      return false;
    }

    while (liveInts[i].name)
    {
      deviceName = liveInts[i].name;

      // If we can get the liveInterfaceData then it means it isn't in the config file
      // Therefore, add it 
      if (getLiveInterfaceData(deviceName, deviceDescription, mac, bWireless, bDisplayError) == true)
      {
        bAdded |= createNewInterface(deviceName, deviceDescription, mac, bWireless, bDisplayError);
      }
      i++;
    }

    // If we found a new interface, make sure we save the config file.
    if (bAdded)
    {
      writeConfig();
    }

    freeEnumLiveInt(&liveInts);
    m_adapterMutex.unlock();
    i = 11;
  }while(i < 10);

  return false;
}

//! isLiveAdapters
/*!
   \brief Checks the list to see if the config interface is in the live interface list
   \param [in] liveInts
   \param [in] configInterfaceName
   \return true/false
*/
bool XSupCalls::isLiveInterface(const int_enum *pLiveInts, const char *pConfigInterfaceName)
{
  int i = 0;
  if (!pLiveInts || !pConfigInterfaceName)
  {
    return false;
  }
  while (pLiveInts[i].name)
  {
    if (strcmp(pLiveInts[i].desc, pConfigInterfaceName) == 0)
    {
      return true;
    }
    i++;
  }
  return false;
}


//! networkDisconnect
/*!
   \brief Disconnects the specific device 
   \param [in] deviceName - not user readable
   \param [in] deviceDescription - user readable
   \param [in] bWireless - true or false
   \return true/false
*/
bool XSupCalls::networkDisconnect(QString &deviceName, QString &deviceDescription, bool bWireless)
{
  bool bValue = true;
  CharC d(deviceName);

  // Call the supplicant and request that the logon be aborted
  if (bWireless)
  {
    bValue = disassociateWireless(deviceName, deviceDescription);

	// Lock the connection in a disconnected state so that we don't change to something else.
	xsupgui_request_set_connection_lock(d.charPtr(), TRUE);
  }
  else
  {
	  bValue = logoffWired(deviceName, deviceDescription);
  }

  // Unbind the connection so that the user can delete or change the config.
  if (bValue == true)
  {
	  if (xsupgui_request_unbind_connection(d.charPtr()) != REQUEST_SUCCESS)
		  bValue = false;
  }

  return bValue;
}

//! connectionDisconnect
/*!
   \brief If the connection is being used by the supplicant, disconnect it
   \param [in] connectionName
   \return true/false
*/
bool XSupCalls::connectionDisconnect(QString &connectionName)
{
  QString usedConnection;
  QString deviceDescription;
  QString deviceName;
  bool bWireless = false;

  // Need to get the connection configuration
  config_connection *pConnConfig = NULL;
  getConfigConnection(connectionName, &pConnConfig, true);
  if (!pConnConfig)
  {
    return false; // this shouldn't ever happen
  } 

  deviceDescription = pConnConfig->device;

  // Get the readable device description 
  getDeviceName(deviceDescription, deviceName);

  // See if the connection is being used
  // If it is (which it should be since we are making this call)
  // Then call networkDisconnect on the device, if it is being used
  if (getConfigConnectionName(deviceDescription, 
                              deviceName,  
                              usedConnection))
  {
    if (usedConnection == connectionName)
    {
      if (pConnConfig->ssid && *pConnConfig->ssid)
      {
        bWireless = true;
      }
      return networkDisconnect(deviceName, deviceDescription, bWireless);
    }
    else
    {
      return true; // not being used - nothing to disconnects
    }
  }
  return false;
}

//! renameConnection
/*!
   \brief Renames a connection
   \param [in] oldName
   \param [in] newName
   \return true/false
*/
bool XSupCalls::renameConnection(QString &oldName, QString &newName)
{
  int retval = xsupgui_request_rename_connection(oldName.toAscii().data(), newName.toAscii().data());
  if (retval != REQUEST_SUCCESS)
  {
    QMessageBox::critical(NULL, tr("Can't Rename Connection"),
      tr("Old name: %1\nNew name: %2").arg(oldName).arg(newName));
    return false;
  }
  return true;
}

//! renameProfile
/*!
   \brief Renames a profile
   \param [in] oldName
   \param [in] newName
   \return true/false
*/
bool XSupCalls::renameProfile(QString &oldName, QString &newName)
{
  int retval = xsupgui_request_rename_profile(oldName.toAscii().data(), newName.toAscii().data());
  if (retval != REQUEST_SUCCESS)
  {
    QMessageBox::critical(NULL, tr("Can't Rename Profile"),
      tr("Old name: %1\nNew name: %2").arg(oldName).arg(newName));
    return false;
  }
  return true;
}
//! renameTrustedServer
/*!
   \brief Renames a trusted server
   \param [in] oldName
   \param [in] newName
   \return true/false
*/
bool XSupCalls::renameTrustedServer(QString &oldName, QString &newName)
{
  int retval = xsupgui_request_rename_trusted_server(oldName.toAscii().data(), newName.toAscii().data());
  if (retval != REQUEST_SUCCESS)
  {
    QMessageBox::critical(NULL, tr("Can't Rename Trusted Server"),
      tr("Old name: %1\nNew name: %2").arg(oldName).arg(newName));
    return false;
  }
  return true;
}
    
// The following code came from xsupconfig.c - need to get the password from these structures
// It was setting the password, these routines now get the password
// I would propose that we move this code to the supplicant
/**
 *  \brief Get a password based on the phase 2 information for TTLS.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[out] password   The existig password for the EAP type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int XSupCalls::config_get_ttls_pwd(struct config_eap_method *meth, char **pPassword)
{
	struct config_eap_ttls *ttls = NULL;
  *pPassword = NULL;
	ttls = (struct config_eap_ttls *)meth->method_data;
	if (ttls == NULL) return -1;

	if (ttls->phase2_data == NULL) return -1;

	switch (ttls->phase2_type)
	{
	  case TTLS_PHASE2_PAP:
	  case TTLS_PHASE2_CHAP:
	  case TTLS_PHASE2_MSCHAP:
	  case TTLS_PHASE2_MSCHAPV2:
  	  *pPassword = Util::myNullStrdup(((struct config_pwd_only *)(ttls->phase2_data))->password);
		  break;

	  case TTLS_PHASE2_EAP:
		  return config_get_pwd((struct config_eap_method *)ttls->phase2_data, pPassword);
		  break;

	  default:
	    QMessageBox::critical(NULL, tr("Error Getting Password")
        ,tr("Invalid EAP method requested: %1\n(config_get_ttls_pwd)")
        .arg(meth->method_num));
		  break;
	}

	return 0; // XENONE;
}

/**
 *  \brief Change a password based on the EAP method structure.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[out] password   The password for the EAP type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
 int XSupCalls::config_get_pwd(struct config_eap_method *meth, char **pPassword)
{
  *pPassword = NULL;
	switch (meth->method_num)
	{
	case EAP_TYPE_MD5:
	case EAP_TYPE_LEAP:
	case EAP_TYPE_GTC:
    *pPassword = Util::myNullStrdup(((struct config_pwd_only *)(meth->method_data))->password);
		break;

	case EAP_TYPE_TLS:
	  *pPassword = Util::myNullStrdup(((struct config_eap_tls *)(meth->method_data))->user_key_pass);
		break;

	case EAP_TYPE_SIM:
	  *pPassword = Util::myNullStrdup(((struct config_eap_sim *)(meth->method_data))->password);
		break;

	case EAP_TYPE_AKA:
 		*pPassword = Util::myNullStrdup(((struct config_eap_aka *)(meth->method_data))->password);
		break;

	case EAP_TYPE_MSCHAPV2:
    *pPassword = Util::myNullStrdup(((struct config_eap_mschapv2 *)(meth->method_data))->password);
		break;

	case EAP_TYPE_PEAP:
		return config_get_pwd(((struct config_eap_peap *)(meth->method_data))->phase2, pPassword);
		break;

	case EAP_TYPE_TTLS:
		//printf("Changing TTLS password.\n");
		return config_get_ttls_pwd(meth, pPassword);
		break;

	case EAP_TYPE_FAST:
		return config_get_pwd(((struct config_eap_fast *)(meth->method_data))->phase2, pPassword);
		break;

	default:
	  QMessageBox::critical(NULL, tr("Error Getting Password")
      ,tr("Invalid EAP method requested: %1\n(config_get_pwd)")
      .arg(meth->method_num));
		break;
	}

	return 0; //XENONE;
}

/**
 *  \brief Get an inner-user name based on the phase 2 information for TTLS.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[out] username   The existing username for the EAP type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int XSupCalls::config_get_ttls_user(struct config_eap_method *meth, char **pUser)
{
	struct config_eap_ttls *ttls;
  *pUser = NULL;

	ttls = (struct config_eap_ttls *)meth->method_data;
	if (ttls == NULL) return -1;

	switch (ttls->phase2_type)
	{
	  case TTLS_PHASE2_PAP:
	  case TTLS_PHASE2_CHAP:
	  case TTLS_PHASE2_MSCHAP:
	  case TTLS_PHASE2_MSCHAPV2:
      *pUser = Util::myNullStrdup(ttls->inner_id);
		  break;

	  case TTLS_PHASE2_EAP:
		  return config_get_user((struct config_eap_method *)ttls->phase2_data, pUser);
		  break;

	  default:
	    QMessageBox::critical(NULL, tr("Error Getting TTLS User")
        ,tr("Invalid EAP method requested: %1\n(config_get_ttls_user)")
        .arg(ttls->phase2_type));
		  break;
	}

	return 0; // XENONE;
}

/**
 *  \brief Get a user name based on the EAP method structure.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[out] password   The password for the EAP type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int XSupCalls::config_get_user(struct config_eap_method *meth, char **pUser)
{
  *pUser = NULL;
  int retval = 0;
	switch (meth->method_num)
	{
	case EAP_TYPE_MD5:
	case EAP_TYPE_LEAP:
	case EAP_TYPE_GTC:
	case EAP_TYPE_TLS:
	case EAP_TYPE_MSCHAPV2:
		break;

	case EAP_TYPE_SIM:
    *pUser = Util::myNullStrdup(((struct config_eap_sim *)(meth->method_data))->username);
		break;

	case EAP_TYPE_AKA:
    *pUser = Util::myNullStrdup(((struct config_eap_aka *)(meth->method_data))->username);
		break;

	case EAP_TYPE_PEAP:
		//retval = config_get_peap_user(((struct config_eap_peap *)(meth->method_data))->phase2, pUser);
    retval = config_get_peap_user(meth, pUser);
		break;

	case EAP_TYPE_TTLS:
		retval = config_get_ttls_user(meth, pUser);
		break;

	case EAP_TYPE_FAST:
		retval = config_get_user(((struct config_eap_fast *)(meth->method_data))->phase2, pUser);
		break;

	default:
	  QMessageBox::critical(NULL, tr("Error Getting User")
      ,tr("Invalid EAP method requested: %1\n(config_get_user)")
      .arg(meth->method_num));
		break;
	}

	return retval; //XENONE;
}

/**
 *  \brief Set an inner-user name based on the phase 2 information for TTLS.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[in] username   The existing username for the EAP type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int XSupCalls::config_set_ttls_user(struct config_eap_method *meth, char *pUser)
{
  int retval = 0;
	struct config_eap_ttls *ttls;

	ttls = (struct config_eap_ttls *)meth->method_data;
	if (ttls == NULL) return -1;

	switch (ttls->phase2_type)
	{
	  case TTLS_PHASE2_PAP:
	  case TTLS_PHASE2_CHAP:
	  case TTLS_PHASE2_MSCHAP:
	  case TTLS_PHASE2_MSCHAPV2:
      Util::myFree(&ttls->inner_id);
      ttls->inner_id = Util::myNullStrdup(pUser);
		  break;

	  case TTLS_PHASE2_EAP:
		  retval = config_set_user((struct config_eap_method *)ttls->phase2_data, pUser);
		  break;

	  default:
	    QMessageBox::critical(NULL, tr("Error Getting Password")
        ,tr("Invalid EAP method requested: %1\n(config_set_ttls_user)")
        .arg(meth->method_num));
		  break;
	}

	return retval; // XENONE;
}

/**
 *  \brief Set an inner-user name based on the phase 2 information for TTLS.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[in] username   The existing username for the EAP type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int XSupCalls::config_set_peap_user(struct config_eap_method *meth, char *pUser)
{
  int retval = 0;
	struct config_eap_peap *peap = (struct config_eap_peap *)meth->method_data;
	if (peap == NULL) return -1;

  Util::myFree(&peap->identity);
  peap->identity = Util::myNullStrdup(pUser);

	return retval; // XENONE;
}

/**
 *  \brief Set an inner-user name based on the phase 2 information for TTLS.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[in] username   The existing username for the EAP type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int XSupCalls::config_get_peap_user(struct config_eap_method *meth, char **pUser)
{
  int retval = 0;
  *pUser = NULL;
	struct config_eap_peap *peap = (struct config_eap_peap *)meth->method_data;
	if (peap == NULL) return -1;

  *pUser = Util::myNullStrdup(peap->identity);

	return retval; // XENONE;
}

/**
 *  \brief Change a user name based on the EAP method structure.
 *
 *  @param[in] meth   A structure that contains a pointer to EAP method
 *                    specific configuration data, in addition to a 
 *                    numeric value that indicates the EAP type it points
 *                    to.
 *  @param[out] password   The password for the EAP type defined by 'meth'.
 *
 *  \retval XENONE on success
 **/
int XSupCalls::config_set_user(struct config_eap_method *meth, char *pUser)
{
  int retval = 0;
	switch (meth->method_num)
	{
	case EAP_TYPE_MD5:
	case EAP_TYPE_LEAP:
	case EAP_TYPE_GTC:
	case EAP_TYPE_TLS:
	case EAP_TYPE_MSCHAPV2:
		break;

	case EAP_TYPE_SIM:
    Util::myFree(&((struct config_eap_sim *)(meth->method_data))->username);
    ((struct config_eap_sim *)(meth->method_data))->username = Util::myNullStrdup(pUser);
		break;

	case EAP_TYPE_AKA:
    Util::myFree(&((struct config_eap_aka *)(meth->method_data))->username);
    ((struct config_eap_aka *)(meth->method_data))->username = Util::myNullStrdup(pUser);
		break;

	case EAP_TYPE_PEAP:
		retval = config_set_peap_user(meth, pUser);
		break;

	case EAP_TYPE_TTLS:
		retval = config_set_ttls_user(meth, pUser);
		break;

	case EAP_TYPE_FAST:
		retval = config_set_user(((struct config_eap_fast *)(meth->method_data))->phase2, pUser);
		break;

	default:
	  QMessageBox::critical(NULL,  tr("Error Getting Password")
      ,tr("Invalid EAP method requested: %1\n(config_set_user)")
      .arg(meth->method_num));
		break;
	}

	return retval; //XENONE;
}

/**
 * \brief Delete the EAP configuration specified by 'method'.
 *
 * @param[in] method   A double dereferenced pointer to the area in 
 *                     memory that contains the configuration information
 *                     about an EAP method.
 **/
void XSupCalls::freeConfigEAPMethod(struct config_eap_method **method)
{
	delete_config_eap_method(method);
}

void XSupCalls::freeConfigAssociation(struct config_association *p)
{
	int i = 0;
	struct config_association *myassoc = NULL;

	myassoc = p;

	for (i=0; i<5; i++)
	{
		if (myassoc->keys[i] != NULL)
		{
			free(myassoc->keys[i]);
			// No need to NULL it here, it will get taken care of in the memset below.
		}
	}

	if (myassoc->psk != NULL)
	{
		free(myassoc->psk);
	}

	if (myassoc->psk_hex != NULL)
	{
		free(myassoc->psk_hex);
	}

	memset((struct config_association *)myassoc, 0x00, sizeof(struct config_association));
}

/**
 * \brief Ask the supplicant to create a troubleticket named filename.
 *
 * @param[in] filename   The name of the (zip) file to create.
 * @param[in] scratchdir A temporary scratch directory where log files can be created.
 * @param[in] overwrite A flag indicating whether the file should be overwritten if it already exists.
 **/
int XSupCalls::createTroubleTicket(char *filename, char *scratchdir, int overwrite)
{
	return xsupgui_request_create_trouble_ticket_file(filename, scratchdir, overwrite);
}


