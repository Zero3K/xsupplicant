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

#include "interfacectrl.h"

InterfaceCtrl::InterfaceCtrl(bool takingCtrl, Emitter *pEmitter, XSupCalls *pSupplicant, QWidget *parent)
	: QDialog(parent)
{
	Qt::WindowFlags flags;

	flags = windowFlags();
	flags &= (~Qt::WindowContextHelpButtonHint);

	setWindowFlags(flags);
	
	m_pSupplicant = pSupplicant;
	m_pEmitter = pEmitter;
	xsupCtrl = takingCtrl;

	setWindowTitle(tr("Interface Control"));

	if (takingCtrl)
	{
		m_pText = new QLabel(tr("Please wait. . .  XSupplicant is taking control of your interfaces. . ."));
	}
	else
	{
		m_pText = new QLabel(tr("Please wait. . .  Windows is taking control of your interfaces. . ."));
	}

	m_pLayout = new QVBoxLayout(this);
	m_pLayout->addWidget(m_pText);

	setLayout(m_pLayout);
}

InterfaceCtrl::~InterfaceCtrl()
{
	delete m_pLayout;
	delete m_pText;
}

bool InterfaceCtrl::updateSupplicant()
{
	config_globals *globals = NULL;
	bool retVal = true;

	if (m_pSupplicant->getConfigGlobals(&globals, false) == false)
	{
		QMessageBox::critical(this, tr("Communication Error"), tr("Unable to get configuration data from the supplicant engine!"));
		return false;
	}

	if (xsupCtrl == true)
	{
		UNSET_FLAG(globals->flags, CONFIG_GLOBALS_NO_INT_CTRL);
	}
	else
	{
		SET_FLAG(globals->flags, CONFIG_GLOBALS_NO_INT_CTRL);
	}

	if (m_pSupplicant->setConfigGlobals(globals) == false)
	{
		QMessageBox::critical(this, tr("Communication Error"), tr("Unable to set configuration data to the supplicant engine!"));
		retVal = false;
	}

	m_pSupplicant->freeConfigGlobals(&globals);
	m_pSupplicant->writeConfig(CONFIG_LOAD_GLOBAL);

	return retVal;
}

