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
#ifndef XSUPPLICANT_UI_PLUGINS_H
#define XSUPPLICANT_UI_PLUGINS_H

#include <QWidget>
#include "xsupcalls.h"
#include "PluginWidget.h"
#include "Emitter.h"
#include "stdafx.h"

#ifdef WIN32
#include <windows.h>
#endif

#define PLUGIN_TYPE_UNKNOWN        0
#define PLUGIN_TYPE_PROFILE_TAB    1
#define PLUGIN_TYPE_CONNECTION_TAB 2
#define PLUGIN_TYPE_STARTUP        3

#define PLUGIN_DESTROY_FAILURE    -5
#define PLUGIN_INIT_FAILURE       -4
#define PLUGIN_LOAD_FAILURE       -3
#define PLUGIN_ACTION_UNKNOWN     -2
#define PLUGIN_ACTION_FAILURE     -1
#define PLUGIN_ACTION_SUCCESS      0
#define PLUGIN_INIT_SUCCESS        1
#define PLUGIN_ALREADY_INITIALIZED 2
#define PLUGIN_LOAD_SUCCESS        3
#define PLUGIN_DESTROY_SUCCESS     4


class UIPlugins : public QObject
{
	Q_OBJECT

private:
protected:
	PluginWidget *plugin; // The widget for this plugin

	int type;
	int index;         // The index of this plugin's widget (for those that can be added/removed from parents)
	bool initialized;  // Is the plugin's widget object instantiated?
	bool loaded;       // Is the DLL loaded?
	config_profiles *m_pProfile; // The configuration profile
	Emitter *m_pEmitter;         // The signal emitter from our parent.
	XSupCalls *m_pSupplicant;
#ifdef WIN32
	HINSTANCE hdll;
#endif // WIN32
public:
	UIPlugins *next;

	UIPlugins();
	UIPlugins(Emitter *pEmitter, XSupCalls *pSupplicant);
	~UIPlugins();
	int loadPlugin(char *location);
	void unloadPlugin();
	void setType(int newType);
	int getType();
	bool isType(int pluginType);
	int addToParent(QWidget *parent);
	int removeFromParent(QWidget *parent);
	bool isInitialized();
	bool isLoaded();
	int instantiateWidget();
	int destroyWidget();
	void setProfile(config_profiles *pProfile);
	virtual void setEmitter(Emitter *pEmitter);
	virtual void setCallbacks(UICallbacks uiCallbacks);
	QString getPluginVersionString();
	void updateEngineVersionString(QString m_newVersion);
	bool save();
	void show();
	QString getWidgetName();
	void showHelp();
#ifdef WIN32
	HINSTANCE getPlugin();
#endif //WIN32
};

#endif // XSUPPLICANT_UI_PLUGINS_H
