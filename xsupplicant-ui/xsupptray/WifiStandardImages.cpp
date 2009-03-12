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
    
#include "stdafx.h"
#include "WifiStandardImages.h"
#include "FormLoader.h"
    WifiStandardImages::WifiStandardImages() 
{
	m_modes = 0;
} WifiStandardImages::WifiStandardImages(unsigned char modes) 
{
	m_modes = modes;
} void WifiStandardImages::paint(QPainter * painter, const QRect & rect,
				    const QPalette &) const const 
{
	unsigned char modes = m_modes;
	unsigned int xpoint, ypoint;
	painter->save();
	QString labelFileName = "802_11_";
	if ((modes & WIRELESS_MODE_A) != 0)
		labelFileName.append("a");
	if ((modes & WIRELESS_MODE_B) != 0)
		labelFileName.append("b");
	if ((modes & WIRELESS_MODE_G) != 0)
		labelFileName.append("g");
	if ((modes & WIRELESS_MODE_N) != 0)
		labelFileName.append("n");
	labelFileName.append(".png");
	QImage myImage(FormLoader::iconpath() + labelFileName);
	xpoint = rect.x() + ((rect.width() - myImage.rect().width()) / 2);
	ypoint = rect.y() + ((rect.height() - myImage.rect().height()) / 2);
	painter->drawImage(QPoint(xpoint, ypoint), myImage, myImage.rect());
	
//      painter->drawText(rect, Qt::AlignHCenter, QString("%1").arg(m_modes), 0);
	    painter->restore();
}

QSize WifiStandardImages::sizeHint() constconst 
{
	
	    // The images are all 68x16.
	    return QSize(68, 16);
}


