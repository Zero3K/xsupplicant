/**
* This portion of the XSupplicant User Interface is Copyright 2009 The Open1X Group.
* The Open1X Group offers this file under the GPL version 2 license.
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
**/  

#ifndef _TABLEIMAGEDELEGATE_H_
#define _TABLEIMAGEDELEGATE_H_

#include <QItemDelegate>

class TableImageDelegate:public QItemDelegate 
{
	Q_OBJECT 

public: 
	TableImageDelegate(QWidget * parent = 0):QItemDelegate(parent)
	{
	} 

	void paint(QPainter * painter, const QStyleOptionViewItem & option,
		const QModelIndex & index) const;

	QSize sizeHint(const QStyleOptionViewItem & option,
		const QModelIndex & index) const;
};



#endif				// _TABLEIMAGEDELEGATE_H_

