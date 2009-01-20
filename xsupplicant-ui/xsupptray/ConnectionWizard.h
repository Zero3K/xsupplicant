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

#ifndef _CONNECTIONWIZARD_H_
#define _CONNECTIONWIZARD_H_

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QStackedWidget>
#include <QStack>
#include "ConnectionWizardData.h"

class WizardPage;
class Emitter;

class ConnectionWizard : public QWidget
{
	Q_OBJECT
	
public:
	ConnectionWizard(QString adaptName, QWidget *parent, QWidget *parentWindow, Emitter *e);
	~ConnectionWizard(void);
	bool create(void);
	
	// set up to create a new connection, with defaults
	void init(void);
	
	// edit an existing connection
	void edit(const ConnectionWizardData &);
	
	// prompt for only 802.1X info, as all other info is provided in Wizard Data passed in
	void editDot1XInfo(const ConnectionWizardData &);
	
	void show(void);
	
	typedef enum {
		pageNoPage=-1,
		pageNetworkType=0,
		pageWiredSecurity,
		pageWirelessNetwork,
		pageWirelessInfo,
		pageIPOptions,
		pageStaticIP,
		pageDot1XProtocol,
		pageDot1XInnerProtocol,
		pageDot1XCert,
		pageDot1XUserCert,
		pageSCReader,
		pageFastInnerProtocol,
		pageAuthOptions,
		pageFinishPage,
		pageLastPage,
	} wizardPages;
	
signals:
	void cancelled(void);
	void finished(bool, const QString &, const QString &); // whether successful, the name of connection created, and the interface that should be used (if provided)
	
private:
	bool initUI(void);
	bool loadPages(void);
	void gotoPage(wizardPages newPageIdx);
	void finishWizard(void);
	bool saveConnectionData(QString *);
	wizardPages getNextPage(void);
	
private slots:
	void gotoNextPage(void);
	void gotoPrevPage(void);
	void cancelWizard(void);
	
private:
	QWidget *m_pParent;
	QWidget *m_pParentWindow;
	QWidget *m_pRealForm;
	QPushButton *m_pCancelButton;
	QPushButton *m_pBackButton;
	QPushButton *m_pNextButton;
	QLabel *m_pHeaderLabel;
	QStackedWidget *m_pStackedWidget;
	
	WizardPage *m_wizardPages[pageLastPage];
	ConnectionWizardData m_connData;
	Emitter *m_pEmitter;
	
	QStack<wizardPages> m_wizardHistory;
	wizardPages m_currentPage;
	bool m_dot1Xmode;
	bool m_editMode; // whether editing an existing connection
	QString m_originalConnName;
	QString m_originalProfileName;
	QString m_originalServerName;
	QString m_adapterName;
};
#endif