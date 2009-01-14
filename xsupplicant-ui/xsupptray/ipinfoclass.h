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

#ifndef _IPINFOCLASS_H_
#define _IPINFOCLASS_H_

extern "C" 
{
#include "libxml/parser.h"
#include "libxsupgui/xsupgui_request.h"
#include "libxsupgui/xsupgui_xml_common.h"
#include "libxsupgui/xsupgui.h"
#include "ipc_events_index.h"
#include "libxsupgui/xsupgui_events.h"
#include "libxsupgui/xsupgui_events_state.h"
}

#include <QtGui>

//!\class IpInfoClass
/*!\brief Class to hold the IP information
*/
class IPInfoClass: QObject
{
private:
  QString m_ipAddress;
	QString m_gateway;
	QString m_mask;
	QString m_dns1;
	QString m_dns2;
	QString m_dns3;
public:
  const QString &getIPAddress() {return m_ipAddress;}
  const QString &getGateway() {return m_gateway;}
  const QString &getMask() {return m_mask;}
  const QString &getDNS1() {return m_dns1;}
  const QString &getDNS2() {return m_dns2;}
  const QString &getDNS3() {return m_dns3;}

  void setInfo(ipinfo_type *info);

  void setIPAddress(char *value) {m_ipAddress = value;}
  void setGateway(char *value) {m_gateway = value;}
  void setMask(char *value) {m_mask = value;}
  void setDNS1(char *value) {m_dns1 = value;}
  void setDNS2(char *value) {m_dns2 = value;}
  void setDNS3(char *value) {m_dns3 = value;}
};

#endif  // _IPINFOCLASS_H_
