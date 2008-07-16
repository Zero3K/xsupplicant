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

#ifndef _PREFERREDCONNECTIONS_H_
#define _PREFERREDCONNECTIONS_H_

#include "xsupcalls.h"

class QLabel;
class QPushButton;
class QFileInfo;
class QListWidget;

class PreferredConnections:public QWidget
{
	Q_OBJECT
public:
	PreferredConnections(XSupCalls &supplicant, QWidget *parent, QWidget *parentWindow);
	~PreferredConnections();
	bool attach();
	void show();

signals:
	void close();

private slots:
    void slotMoveLeft();
    void slotMoveRight();
    void slotMoveUp();
    void slotMoveDown();
    void slotClose();
    void slotEnableButtons();
	void slotPreferredSelected(QListWidgetItem *);
	void slotAvailableSelected(QListWidgetItem *);
    void slotHelp();
    
private:
	void hookupSignalsAndSlots();
	void updateLists();
	void setupWindow();
	void moveItems(QListWidget *from, QListWidget *to);
	
private:
	QString m_connection;
	conn_enum *m_pConns;
	XSupCalls &m_supplicant;
	MessageClass m_message;

	//! GUI variables
	QWidget *m_pRealForm;
	QWidget *m_pParentWindow;
	QListWidget *m_pAvailableList;
	QListWidget *m_pPreferredList;
	QPushButton *m_pLeftButton;
	QPushButton *m_pRightButton;
	QPushButton *m_pUpButton;
	QPushButton *m_pDownButton;
	QPushButton *m_pCloseButton;
	QPushButton *m_pHelpButton;
};

#endif  // _PREFERREDCONNECTIONS_H_

