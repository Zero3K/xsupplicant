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

#include <QApplication>
#include <QDir>

#include "stdafx.h"

#include "FormLoader.h"

FormLoader::FormLoader()
{
}

FormLoader::~FormLoader()
{
}

QWidget *FormLoader::buildform(QString formname, QWidget * parent /* = NULL */ )
{
	QUiLoader loader;	// Used to load the .ui file to generate the form.
	QString shortpath = skinpath();
	QString fullpath = shortpath + formname;
	QWidget *m_pForm = NULL;

	QFile file(fullpath);

	if (file.open(QFile::ReadOnly) != true)
		return false;	// We couldn't load the UI file.

	QDir mydir(shortpath);

	loader.setWorkingDirectory(mydir);
	m_pForm = loader.load(&file, parent);

	file.close();

	return m_pForm;
}

QPixmap *FormLoader::loadicon(QString iconname)
{
	QString path = iconpath() + iconname;
	QPixmap *p = NULL;

	p = new QPixmap(path);

	return p;
}

QString FormLoader::skinpath()
{
#ifdef __APPLE__
        return QString("/Library/Application Support/XSupplicant") + QString("/Skins/Default/");
#else
	return QApplication::applicationDirPath() + QString("/Skins/Default/");
#endif // __APPLE__
}

QString FormLoader::iconpath()
{
	return QString(skinpath() + QString("icons/"));
}
