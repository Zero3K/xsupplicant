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
	m_pSupplicant->writeConfig();

	return retVal;
}

