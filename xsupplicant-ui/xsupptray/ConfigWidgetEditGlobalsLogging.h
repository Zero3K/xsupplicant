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

#ifndef _CONFIGWIDGETEDITGLOBALSLOGGING_H_
#define _CONFIGWIDGETEDITGLOBALSLOGGING_H_

#include "ConfigWidgetBase.h"
#include "ViewLogDlg.h"
#include "xsupcalls.h"

class ConfigWidgetEditGlobalsLogging : public ConfigWidgetBase
 {
     Q_OBJECT

 public:
	 ConfigWidgetEditGlobalsLogging(QWidget *pRealWidget, XSupCalls *xsup, QWidget *parent);
	 ~ConfigWidgetEditGlobalsLogging();

	 bool attach();
	 bool save();
	 bool dataChanged();
	 void discard();
	 void getPageName(QString &);

 public slots:
	 void cleanupuiWindowViewLogs();

 private slots:
	 void slotDataChanged();
	 void loggingStateChanged(int);
	 void browseButtonClicked();
	 void viewLogButtonClicked();
	 void slotShowHelp();
	 void slotRollLogsClicked(int);

 private:
	 enum {
		 LOGGING_NORMAL,
		 LOGGING_VERBOSE,
		 LOGGING_DEBUG
	 };

	 enum {
		 DEBUG_NORMAL = BIT(0),
		 DEBUG_VERBOSE = BIT(25)
	 };

	#define DEBUG_ALL            0x7fffffff   // Enable ALL debug flags.

	 void updateWindow();
	 void setEnabled(bool);

	bool m_bSettingsChanged;

	config_globals *m_pGlobals;

	QWidget *m_pRealWidget;
	QWidget *m_pParent;

	uiWindowViewLogs *m_pViewLogDialog;

	XSupCalls *m_pSupplicant;

	// Stuff that can be edited on the form.
	QCheckBox *m_pEnableLogging;
	QPushButton *m_pBrowseButton;
	QPushButton *m_pViewLogButton;
	QCheckBox *m_pFriendlyWarnings;
	QLineEdit *m_pLogDirectory;
	QComboBox *m_pLogLevel;

	QSpinBox *m_pLogsToKeep;
	QSpinBox *m_pRollAtSize;
	QCheckBox *m_pRollBySize;
};

#endif  // _CONFIGWIDGETEDITGLOBALSLOGGING_H_

