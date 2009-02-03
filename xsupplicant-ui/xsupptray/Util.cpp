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
#include <QtGui>
#include <qstring.h>
#include "Util.h"

bool Util::myConnect(const QObject *from, const char *signal, const QObject *to, const char *slot)
{
  if (!connect(from, signal, to, slot))
  {
    QString text = QString (tr("QT connect() API failed\nFrom class: %1\n\tSIGNAL: '%2\nTo class: %3\n\tSLOT: '%4'\n"))
      .arg(from->metaObject()->className())
      .arg(signal)
      .arg(to->metaObject()->className())
      .arg(slot);

    // This doesn't work if we are not in the main GUI thread
    // How can I check to see if we are in the GUI thread?
    if (QThread::currentThread() == qApp->thread())
    {
      QMessageBox::critical(NULL, tr("Run-time coding API Error"), text);
    }
    else
    {
      // Display a message to the user outside of the gui thread?
      qDebug(text.toAscii());
    }
    return false;
  }
  return true;
}

bool Util::myDisconnect(const QObject *from, const char *signal, const QObject *to, const char *slot)
{
  if (!disconnect(from, signal, to, slot))
  {
    QString text = QString (tr("QT disconnect() API failed\nFrom class: %1\n\tSLOT: '%2\nTo class: %3\n\tSIGNAL: '%4'\n"))
      .arg(from->metaObject()->className())
      .arg(signal)
      .arg(to->metaObject()->className())
      .arg(slot);
    QMessageBox::critical(NULL, tr("Run-time coding API Error"), text);
    return false;
  }
  return true;
}

QPushButton *Util::createButton(const QString &text, QObject *thisPtr, const char *slot, const QString &toolTip)
{
    QPushButton *item = new QPushButton(text);
    Util::myConnect(item, SIGNAL(clicked()), thisPtr, slot);
    item->setToolTip(toolTip);
    return item;
}

QRadioButton *Util::createRadioButton(const QString &text, QObject *thisPtr, const char *slot, const QString &toolTip)
{
    QRadioButton *item = new QRadioButton(text);
    Util::myConnect(item, SIGNAL(clicked()), thisPtr, slot);
    item->setToolTip(toolTip);
    return item;
}

QComboBox *Util::createComboBox(const QString &whatsThis)
{
    QComboBox * item = new QComboBox();
    item->setWhatsThis(whatsThis);
    item->setToolTip(whatsThis);
    return item;
}

QLineEdit *Util::createLineEdit(const QString &text, const QString &whatsThis)
{
    QLineEdit *item = new QLineEdit(text);
    item->setWhatsThis(whatsThis);
    item->setToolTip(whatsThis);
    return item;
}

QTextEdit *Util::createTextEdit(const QString &text, const QString &whatsThis)
{
    QTextEdit *item = new QTextEdit(text);
    item->setWhatsThis(whatsThis);
    item->setToolTip(whatsThis);
    return item;
}

QListWidget *Util::createListWidget(const QString &whatsThis)
{
    QListWidget *item = new QListWidget();
    item->setWhatsThis(whatsThis);
    item->setToolTip(whatsThis);
    return item;
}

QCheckBox *Util::createCheckBox(const QString &text, const QString &whatsThis)
{
    QCheckBox *item = new QCheckBox(text);
    item->setWhatsThis(whatsThis);
    item->setToolTip(whatsThis);
    return item;
}

QRadioButton *Util::createRadioButton(const QString &text, const QString &whatsThis)
{
    QRadioButton *item = new QRadioButton(text);
    item->setWhatsThis(whatsThis);
    item->setToolTip(whatsThis);
    return item;
}

QLabel *Util::createLabel(const QString &text, const QString &whatsThis)
{
    QLabel *item = new QLabel(text);
    item->setWhatsThis(whatsThis);
    item->setToolTip(whatsThis);
    return item;
}

void Util::setWidgetWidth(QWidget *pWidget, char *text)
{
    QFontMetrics f = pWidget->fontMetrics();
    int width = f.width(text);
    pWidget->setSizePolicy(QSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed));
    pWidget->setFixedWidth(width);
}

//! isValidIPAddress
/*!
  \brief validates that each element of the address is between 1 - 255
  \param[in] b  - not used
  \return Nothing
*/
bool Util::isValidIPAddress(QString &ipaddr)
{
  int ipAddress[4];
  int i = 0;
  bool ok = false;
  QStringList ipAddressList = ipaddr.split(".", QString::KeepEmptyParts);
  i = ipAddressList.count();
  if (ipAddressList.count() < 4)
  {
    return false;
  }

  for (i = 0; i < 4; i++)
  {
    ipAddress[i] = ipAddressList[i].toInt(&ok);
    if (!ok)
    {
      return false;
    }
  }

  // If they are all 0's then leave it
  if (ipAddress[0] == 0 &&  ipAddress[1] == 0 && ipAddress[2] == 0 && ipAddress[3] == 0)
  {
    return true;
  }

  for (i = 0; i < 4; i++)
  {
    if (ipAddress[i] < 1 || ipAddress[i] > 255)
    {
      return false;
    }
  }
  return true;
}


void Util::myFree(char **p)
{
  if (p && (*p))  
  {
    free((*p));
  }
  (*p)=NULL;
}

void Util::myFree(void **p)
{
  if (p && (*p))
  {
    free((*p));
  }
  (*p)=NULL;
}
//! createPixmapLabel
/*!
   \brief Opens the help file
   A function to create a QPixmap object
   \param [in] URLPath - the path of the file
   \return nothing
   \note (none)
*/
QLabel *Util::createPixmapLabel(QString &URLPath) // , int height, int width)
{
  QPixmap pixMap;
  QLabel *pLabel = new QLabel();
  if (pixMap.load(URLPath))
  {
//    QPixmap scaledPixMap = pixMap.scaled(width, height,Qt::IgnoreAspectRatio);
    pLabel->setPixmap(pixMap); // scaledPixMap);
  }
  return pLabel;
}

QString Util::removePacketSchedulerFromName(char *fullName)
{
  // Remove the stuff after the '-' to show to the user
  // Add the full name in the data
  QString partialName = fullName;
  int pos = partialName.indexOf(" - Packet Scheduler Miniport", 0);
  if (pos >= 0)
  {
    partialName.truncate(pos);
  }
  return partialName;
}

QString Util::removePacketSchedulerFromName(const QString &fullName)
{
  // Remove the stuff after the '-' to show to the user
  // Add the full name in the data
  QString partialName = fullName;
  int pos = partialName.indexOf(" - Packet Scheduler Miniport", 0);
  if (pos >= 0)
  {
    partialName.truncate(pos);
  }
  return partialName;
}

//! myStrdup()
/*!
   \brief If the pointer is NULL or points to a Null string, return a null pointer.
   \param [in] p
   \return char * (null if string or pointer is null)
   \note (none)
*/
char *Util::myNullStrdup(const char *p)
{
  if (p && *p)
  {
    return _strdup(p);
  }
  else
  {
    return NULL;
  }
}
 
void Util::useBackslash(char *str)
{
	unsigned int i;

	for (i=0; i<strlen(str); i++)
	{
		if (str[i] == '/')
		{
			str[i] = '\\';
		}
	}
}

Util::ConnectionStatus Util::getConnectionStatusFromPhysicalState(int state)
{
	Util::ConnectionStatus connStatus;
	switch (state)
	{
		case WIRELESS_UNKNOWN_STATE:
		case WIRELESS_UNASSOCIATED:
		case WIRELESS_ACTIVE_SCAN:
		case WIRELESS_PORT_DOWN:
		case WIRELESS_INT_STOPPED:
		case WIRELESS_INT_HELD:
		case WIRELESS_INT_RESTART:
			connStatus = Util::status_idle;
			break;

		case WIRELESS_ASSOCIATING:
		case WIRELESS_ASSOCIATION_TIMEOUT_S:
			connStatus = Util::status_connecting;
			break;

		case WIRELESS_NO_ENC_ASSOCIATION:
			connStatus = Util::status_connected;
			break;

		case WIRELESS_ASSOCIATED:
			connStatus = Util::status_connected;
			break;

		default:
			connStatus = Util::status_unknown;
			break;
	}
	return connStatus;
}

Util::ConnectionStatus Util::getConnectionStatusFromDot1XState(int state)
{
	Util::ConnectionStatus connStatus;
	
	switch (state)
	{
		case LOGOFF:
		case DISCONNECTED:
		case S_FORCE_UNAUTH:
			connStatus = Util::status_idle;
			break;

		case CONNECTING:
		case ACQUIRED:
		case AUTHENTICATING:
		case RESTART:
			connStatus = Util::status_connecting;
			break;

		case HELD:
			connStatus = Util::status_authFailed;
			break;

		case AUTHENTICATED:
		case S_FORCE_AUTH:
			connStatus = Util::status_connected;
			break;

		default:
			connStatus = Util::status_unknown;  // This should be impossible!
			break;
	}
	return connStatus;
}

QString Util::getConnectionTextFromConnectionState(Util::ConnectionStatus state)
{
	QString text = QWidget::tr("Unknown");
	switch (state)
	{
		case Util::status_unknown:
			text = QWidget::tr("Unknown");
			break;
		case Util::status_idle:
			text = QWidget::tr("Idle");
			break;
		case Util::status_connecting:
			text = QWidget::tr("Connecting...");
			break;
		case Util::status_connected:
			text = QWidget::tr("Connected");
			break;	
		case Util::status_authFailed:
			text = QWidget::tr("Authentication Failed");
			break;					
	}
	return text;
}

bool Util::isIPAddrValid(QString addr)
{
	if ((addr == "0.0.0.0") || (addr == "255.255.255.255")) return false;

	return true;
}

unsigned int Util::ipToInt(QString addr, unsigned int failure)
{
	QRegExp regex("^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)");
	unsigned int result = 0, temp = 0;
	bool ok;

	regex.indexIn(addr);
	if (regex.exactMatch(addr) == false) return failure;   // return all Fs, so that any tests done fail.

	result = regex.cap(1).toInt(&ok);
	if (!ok) return failure;
	result = result << 24;

	temp = regex.cap(2).toInt(&ok);
	if (!ok) return failure;
	result |= (temp << 16);

	temp = regex.cap(3).toInt(&ok);
	if (!ok) return failure;
	result |= (temp << 8);

	temp = regex.cap(4).toInt(&ok);
	if (!ok) return failure;
	result |= temp;

	return result;
}

bool Util::isNetmaskValid(QString netmask)
{
	uint32_t addr = 0;
	bool ones = true;
	int i = 0;
	int x = 0;

	if (netmask == "") return false;

	addr = ipToInt(netmask, 0);
	if (addr == 0) return false;

	if ((addr & 0x80000000) != 0x80000000)
	{
		// Our first bit isn't 1, this mask is invalid.
		return false;
	}

	for (i=31; i>=0; i--)
	{
		x = 0;
		x = (1 << i);
		if ((x & addr) == x)
		{
			if (ones != true) return false;   // We got an "out of place" 1.
		}
		else
		{
			if (ones == true)
			{
				ones = false;   // From here on out, everything should be a 0.
			}
		}
	}

	return true;
}

bool Util::isGWinSubnet(QString addr, QString netmask, QString gateway)
{
	uint32_t addr_n = 0, netmask_n = 0, gateway_n = 0;
	uint32_t addr_net_part = 0;
	uint32_t gw_net_part = 0;

	if ((addr == "") || (netmask == "") || (gateway == "")) return FALSE;

	addr_n = ipToInt(addr, 0);
	netmask_n = ipToInt(netmask, 0);
	gateway_n = ipToInt(gateway, 0);

	if ((addr_n == 0) || (netmask_n == 0) || (gateway_n == 0)) return FALSE;

	addr_net_part = addr_n & netmask_n;
	gw_net_part = gateway_n & netmask_n;

	if (addr_net_part != gw_net_part) return false;  // They are in different subnets.

	return true;
}

bool Util::ipIsBroadcast(QString addr, QString netmask)
{
	uint32_t addr_n = 0, netmask_n = 0;
	uint32_t addr_host_part = 0;

	if ((addr == "") || (netmask == "")) return false;

	addr_n = ipToInt(addr, 0);
	netmask_n = ipToInt(netmask, 0);

	if ((addr_n == 0) || (netmask_n == 0)) return false;

	netmask_n = ~netmask_n;
	addr_host_part = addr_n & netmask_n;

	if ((addr_host_part == 0) || (addr_host_part == netmask_n)) return true;

	return false;
}


