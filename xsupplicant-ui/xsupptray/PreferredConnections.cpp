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

#ifdef WINDOWS
#include <direct.h>
#endif

#include "PreferredConnections.h"
#include "Util.h"
#include "FormLoader.h"
#include "helpbrowser.h"
#include "XSupWrapper.h"

//! Constructor
/*!
  \param[in] pConns - the list of connections we are working with (this is now sorted by priority)
  \param[in] supplicant - the suppplicant object
  \param[in] parent is the parent widget
  \return Nothing
*/
PreferredConnections::PreferredConnections(XSupCalls *supplicant, QWidget *parent, QWidget *parentWindow)
     : QWidget(parent), m_psupplicant(supplicant), m_pParentWindow(parentWindow)
 {
  m_pAvailableList = NULL;
  m_pPreferredList = NULL;
  m_pLeftButton = NULL;
  m_pRightButton = NULL;
  m_pUpButton = NULL;
  m_pDownButton = NULL;
  m_pCloseButton = NULL;
  m_pHelpButton = NULL;
  m_pRealForm = NULL;
  m_pConns = NULL;
 }

//! Destructor
/*!
  \return Nothing
*/
 PreferredConnections::~PreferredConnections()
{
	if (m_pConns != NULL) {
		xsupgui_request_free_conn_enum(&m_pConns);
		m_pConns = NULL;
	}
	
	if (m_pAvailableList != NULL)
	{
		Util::myDisconnect(m_pAvailableList, SIGNAL(itemSelectionChanged()), this, 
			SLOT(slotEnableButtons()));
		Util::myDisconnect(m_pAvailableList, SIGNAL(itemClicked(QListWidgetItem *)), this,
			SLOT(slotAvailableSelected(QListWidgetItem *)));
	}

	if (m_pPreferredList != NULL)
	{
		Util::myDisconnect(m_pPreferredList, SIGNAL(itemSelectionChanged()), this, 
			SLOT(slotEnableButtons()));
		Util::myDisconnect(m_pPreferredList, SIGNAL(itemClicked(QListWidgetItem *)), this,
			SLOT(slotPreferredSelected(QListWidgetItem *)));
	}

	if (m_pLeftButton != NULL)
		Util::myDisconnect(m_pLeftButton, SIGNAL(clicked()), this, SLOT(slotMoveLeft()));

	if (m_pRightButton != NULL)
		Util::myDisconnect(m_pRightButton, SIGNAL(clicked()), this, SLOT(slotMoveRight()));

	if (m_pUpButton != NULL)
		Util::myDisconnect(m_pUpButton, SIGNAL(clicked()), this, SLOT(slotMoveUp()));
	
	if (m_pDownButton != NULL)
		Util::myDisconnect(m_pDownButton, SIGNAL(clicked()), this, SLOT(slotMoveDown()));

	if (m_pCloseButton != NULL)
		Util::myDisconnect(m_pCloseButton, SIGNAL(clicked()), this, SLOT(slotClose()));

	if (m_pHelpButton != NULL)
		Util::myDisconnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotHelp()));

	if (m_pRealForm != NULL)
		delete m_pRealForm;
}

 void PreferredConnections::show()
 {
	 if (m_pRealForm != NULL) 
		m_pRealForm->show();
 }

 bool PreferredConnections::attach()
 {
	m_pRealForm = FormLoader::buildform("WirelessPriorityWindow.ui", m_pParentWindow);

	if (m_pRealForm == NULL) 
		return false;

	// If the user hits the "X" button in the title bar, close us out gracefully.
	Util::myConnect(m_pRealForm, SIGNAL(rejected()), this, SLOT(slotClose()));

	m_pAvailableList = qFindChild<QListWidget*>(m_pRealForm, "dataFrameAvailableConnections");
	if (m_pAvailableList == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form is missing the 'dataFrameAvailableConnections' QListWidget!"));
		return false;
	}

	m_pPreferredList = qFindChild<QListWidget*>(m_pRealForm, "dataFramePreferredConnections");
	if (m_pPreferredList == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form is missing the 'dataFramePreferredConnections' QListWidget!"));
		return false;
	}

	m_pLeftButton = qFindChild<QPushButton*>(m_pRealForm, "buttonLeft");
	if (m_pLeftButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form is missing the 'buttonLeft' QPushButton!"));
		return false;
	}

	m_pRightButton = qFindChild<QPushButton*>(m_pRealForm, "buttonRight");
	if (m_pRightButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form is missing the 'buttonRight' QPushButton!"));
		return false;
	}

	m_pUpButton = qFindChild<QPushButton*>(m_pRealForm, "buttonUp");
	if (m_pUpButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form is missing the 'buttonUp' QPushButton!"));
		return false;
	}

	m_pDownButton = qFindChild<QPushButton*>(m_pRealForm, "buttonDown");
	if (m_pDownButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form is missing the 'buttonDown' QPushButton!"));
		return false;
	}

	m_pCloseButton = qFindChild<QPushButton*>(m_pRealForm, "buttonClose");
	if (m_pCloseButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form is missing the 'buttonClose' QPushButton!"));
		return false;
	}

	m_pHelpButton = qFindChild<QPushButton*>(m_pRealForm, "buttonHelp");
	if (m_pHelpButton == NULL)
	{
		QMessageBox::critical(this, tr("Form Design Error"), tr("The form is missing the 'buttonHelp' QPushButton!"));
		return false;
	}

	setupWindow();
	hookupSignalsAndSlots();
	updateLists();
	slotEnableButtons(); // initialize button states

	return true;
 }

 void PreferredConnections::setupWindow()
{
	Qt::WindowFlags flags;

	flags = m_pRealForm->windowFlags();
	flags &= ~Qt::WindowContextHelpButtonHint;
	flags &= ~Qt::WindowMinimizeButtonHint;
	m_pRealForm->setWindowFlags(flags);
}

//! hookupSignalsAndSlots
/*!
 \brief Hooks up all the signals between the various components
  \return Nothing
*/
 void PreferredConnections::hookupSignalsAndSlots()
{
  // hookup the available list selection to the left and right arrows enablement
  // hookup the preferred list selection to the left and right arrows enablement
  // hookup the preferred list selection to the up and down arrows enablement
  Util::myConnect(m_pAvailableList, SIGNAL(itemSelectionChanged()), this, 
    SLOT(slotEnableButtons()));
  Util::myConnect(m_pAvailableList, SIGNAL(itemClicked(QListWidgetItem *)), this,
	  SLOT(slotAvailableSelected(QListWidgetItem *)));
  
  Util::myConnect(m_pPreferredList, SIGNAL(itemSelectionChanged()), this, 
    SLOT(slotEnableButtons()));
  Util::myConnect(m_pPreferredList, SIGNAL(itemClicked(QListWidgetItem *)), this,
	  SLOT(slotPreferredSelected(QListWidgetItem *)));

	if (m_pLeftButton != NULL)
		Util::myConnect(m_pLeftButton, SIGNAL(clicked()), this, SLOT(slotMoveLeft()));
	
	if (m_pRightButton != NULL)
		Util::myConnect(m_pRightButton, SIGNAL(clicked()), this, SLOT(slotMoveRight()));
	
	if (m_pUpButton != NULL)
		Util::myConnect(m_pUpButton, SIGNAL(clicked()), this, SLOT(slotMoveUp()));
  
	if (m_pDownButton != NULL)
		Util::myConnect(m_pDownButton, SIGNAL(clicked()), this, SLOT(slotMoveDown()));

	if (m_pCloseButton != NULL)
		Util::myConnect(m_pCloseButton, SIGNAL(clicked()), this, SLOT(slotClose()));
		
	if (m_pHelpButton != NULL)
		Util::myConnect(m_pHelpButton, SIGNAL(clicked()), this, SLOT(slotHelp()));
}

//! slotMoveLeft
/*!
  \brief Move a connection from preferred to available - set the priority to DEFAULT_PRIORITY
  \param[in] from - the list from which we are moving data
  \param[in] to - the list to which we are moving data
  \return Nothing
*/
void PreferredConnections::slotMoveLeft()
{
	moveItems(m_pPreferredList, m_pAvailableList);
}

//! slotMoveRight
/*!
  \brief Move a connection from available to preferred - set the priority to 0xfd
  \return Nothing
*/
void PreferredConnections::slotMoveRight()
{  
	moveItems(m_pAvailableList, m_pPreferredList);
}

//! moveItems
/*!
  \brief Move a connection from one list to another
  \param[in] from - the list from which we are moving data
  \param[in] to - the list to which we are moving data
  \return Nothing
*/
void PreferredConnections::moveItems(QListWidget *from, QListWidget *to)
{
  // Get the selection from the preferred list and move it to the available list
  int row = -1;
  QList<QListWidgetItem *> items = from->selectedItems();
  QListWidgetItem *q = NULL;

  for (int i = 0; i < items.size(); i++)
  {
    row = from->row(items[i]);
    q = from->takeItem(row);
	to->addItem(q);
  }

  from->clearSelection();
  to->clearSelection();

  to->setCurrentRow(0);
}


//! slotMoveUp
/*!
  \brief Move a list of connections up in the list - increase their priority
  \return Nothing
*/
void PreferredConnections::slotMoveUp()
{
  // Get the list of selected items
  QList<QListWidgetItem *> items = m_pPreferredList->selectedItems();
  QListWidgetItem *p = NULL;
  int insertRow = 0;

  // Get the top selected row
  if (items.size() == 0)
    return;

  int row = m_pPreferredList->row(items[0]);
  // Make sure there is somewhere to move them
  // If the top row is already the top row, there is nothing to do
  if (row == 0)
    return;

  // now move them up - need to find the row just before the row selected and move above this row.
  // Move the items - make sure they move
  insertRow = row;
  for (int i = 0; i < items.size(); i++) 
  {
    insertRow--;
    p = new QListWidgetItem(items[i]->text());
    m_pPreferredList->insertItem(insertRow, p);
  }

  // Then delete the old items
  // Will this work?  Need to see.
  for (int i=0; i < items.size(); i++)
  {
    int row = m_pPreferredList->row(items[i]);
    p = m_pPreferredList->takeItem(row);
    delete p;
  }
  m_pPreferredList->setCurrentRow(insertRow);
}

//! slotMoveDown
/*!
  \brief Move a list of connections up in the list - decrease their priority
  \return Nothing
*/
void PreferredConnections::slotMoveDown()
{
  // Get the list of selected items
  QList<QListWidgetItem *> items = m_pPreferredList->selectedItems();
  QListWidgetItem *p = NULL;
  int insertRow = 0;

  // First, see if they've selected anything
  int count = items.size();
  if (count == 0)
    return;


  // Get the last row selected
  int row = m_pPreferredList->row(items[count-1]);

  // Make sure there is somewhere to move them
  // If the top row is already the top row, there is nothing to do
  // Row is zero-based, so must add one
  if (row+1 == m_pPreferredList->count())
    return;

  // now move them up - need to find the row just before the row selected and move above this row.
  // Move the items - make sure they move
  insertRow = row + 1;
  for (int i = 0; i < items.size(); i++) 
  {
    insertRow++;
    p = new QListWidgetItem(items[i]->text());
    m_pPreferredList->insertItem(insertRow, p);
  }

  // Then delete the old items
  // Will this work?  Need to see.
  for (int i=0; i < items.size(); i++)
  {
    int row = m_pPreferredList->row(items[i]);
    p = m_pPreferredList->takeItem(row);
    delete p;
  }
  m_pPreferredList->setCurrentRow(insertRow-1);
}

//! slotEnableUpDownButtons
/*!
  \brief Enable the up down buttons when an entry in the preferred list is selected
  \param[in] row - the row that was selected
  \return Nothing
*/
void PreferredConnections::slotEnableButtons()
{
  int totalCount = m_pPreferredList->count();
  int selectionCount = m_pPreferredList->selectedItems().count();
  if (selectionCount > 0)
  {
    if (!m_pPreferredList->isItemSelected(m_pPreferredList->item(0))) // if first in the list is selected - don't enable up
    {
      m_pUpButton->setEnabled(true);
    }
    else
    {
      m_pUpButton->setEnabled(false);
    }

    // If we have more than 1 selected and the last one isn't selected, enable the down button
    if (totalCount > 1 && !m_pPreferredList->isItemSelected(m_pPreferredList->item(totalCount-1))) // if last in the list - don't enable down
    {
      m_pDownButton->setEnabled(true);
    }
    else
    {
      m_pDownButton->setEnabled(false);
    }
    m_pLeftButton->setEnabled(true);
  }
  else
  {
    m_pUpButton->setEnabled(false);
    m_pDownButton->setEnabled(false);
    m_pLeftButton->setEnabled(false);
  }
  if (m_pAvailableList->selectedItems().count() > 0)
  {
    m_pRightButton->setEnabled(true);
  }
  else
  {
    m_pRightButton->setEnabled(false);
  }
}

//! updateLists
/*!
  \brief Update the lists
  \return Nothing
*/
void PreferredConnections::updateLists()
{
	int i = 0;
	int retval = 0;
	bool success = false;
	config_connection *pConn = NULL;
	bool volatileConn = false;

	if (m_pAvailableList != NULL)
		m_pAvailableList->clear();
	
	if (m_pPreferredList != NULL)
		m_pPreferredList->clear();

	if (m_pConns != NULL) {
		xsupgui_request_free_conn_enum(&m_pConns);
		m_pConns = NULL;
	}
		
	retval = xsupgui_request_enum_connections((CONFIG_LOAD_GLOBAL | CONFIG_LOAD_USER), &m_pConns);
	
	// if no connections then nothing to populate lists with
	if (retval != REQUEST_SUCCESS || m_pConns == NULL)
		return;

	while (m_pConns[i].name != NULL)
	{
		if (m_pConns[i].ssid != NULL && QString(m_pConns[i].ssid).isEmpty() == false)
		{
			success = XSupWrapper::getConfigConnection(m_pConns[i].config_type, QString(m_pConns[i].name), &pConn);
			
			if (success == true && pConn != NULL && ((pConn->flags & CONFIG_VOLATILE_CONN) == CONFIG_VOLATILE_CONN))
				volatileConn = true;
				
			if (pConn != NULL)
			{
				XSupWrapper::freeConfigConnection(&pConn);
				pConn = NULL;
			}
			
			// don't show volatile connections in this list	
			if (volatileConn == false)
			{
				QListWidgetItem *pItem = new QListWidgetItem(m_pConns[i].name);
				
				if (pItem != NULL)
				{
					if (m_pConns[i].priority >= XSupCalls::CONNECTION_DEFAULT_PRIORITY)
					{
						// Available list goes here
						if (m_pAvailableList != NULL)
							m_pAvailableList->addItem(pItem);
					}
					else
					{
						// List is already prioritized
						if (m_pPreferredList != NULL)
							m_pPreferredList->addItem(pItem);
					}
				}
			}
		}
		i++;
	}
}

//! slotClose
/*!
  \brief Appply the data to the supplicant but don't write out to file
  \return Nothing
  \note Here is what I need to do
  1. Go through the m_pConns
  2. Search in the preferred connections list to see if that entry is there
  3. If so, change the priority based on position 1 = 1, 2 = 2, 3 = 3, 4 = 4, etc.
  4. For all of the ones not found, change the priority to the default (255)
*/
void PreferredConnections::slotClose()
{ 
	// nothing to do
	if (m_pConns == NULL)
		return;
   	
	int listIndex = 0;

    for (listIndex = 0; listIndex < m_pPreferredList->count(); listIndex++)
    {
		// Match up the m_pConns list
		int connIndex = 0;
		while (m_pConns[connIndex].name != NULL)
		{
			if (m_pPreferredList->item(listIndex)->text() == m_pConns[connIndex].name)
			{
				int priority;
				
				if (listIndex < XSupCalls::CONNECTION_DEFAULT_PRIORITY)
					priority = listIndex + 1; // not zero-based
				else // If we have 255 or more connections, this could happen
					priority = XSupCalls::CONNECTION_DEFAULT_PRIORITY - 1;

				m_pConns[connIndex].priority = priority;
				break;
			}
        
			connIndex++;
		}
	}

	m_psupplicant->applyPriorities(m_pConns);
	emit close();
}

void PreferredConnections::slotAvailableSelected(QListWidgetItem *)
{
	m_pPreferredList->clearSelection();
}

void PreferredConnections::slotPreferredSelected(QListWidgetItem *)
{
	m_pAvailableList->clearSelection();
}

//! slotHelp
/*!
  \brief Calls the help for this page
  \return nothing
  \todo Emplement this
*/
void PreferredConnections::slotHelp()
{
	HelpWindow::showPage("xsupphelp.html", "xsupsetconnpriorities");
}


