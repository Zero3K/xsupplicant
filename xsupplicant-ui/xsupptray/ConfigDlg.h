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

#ifndef _CONFIGDLG_H_
#define _CONFIGDLG_H_

#include <QWidget>

#include "xsupcalls.h"
#include "NavPanel.h"
#include "ConfigInfo.h"
#include "UIPlugins.h"

class ConfigDlg : public QWidget
 {
     Q_OBJECT

 public:
  ConfigDlg(XSupCalls &sup, Emitter *e, QWidget *parent);
  ~ConfigDlg();

  bool create();
  void show();

signals:
  void close();
  void navItemSelected(int, const QString &);

 private:
	 void enumData();

	 Emitter *m_pEmitter;

	 XSupCalls &m_supplicant;

	 QWidget *m_pRealForm;

	 NavPanel *m_pNavPanel;
	 ConfigInfo *m_pConfigInfo;

	 // Enumerate this stuff in the root object, since it will be used by most of the children.  (This avoids excessive I/O.)
	 conn_enum *m_pConns;
	 profile_enum *m_pProfs;
	 trusted_servers_enum *m_pTrustedServers;

	 UIPlugins *m_pPlugins;
  	 UICallbacks uiCallbacks;
};

#endif  // _CONFIGDLG_H_
