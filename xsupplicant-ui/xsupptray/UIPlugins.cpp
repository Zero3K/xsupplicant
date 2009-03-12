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

#include "UIPlugins.h"
#include "PluginWidget.h"
#include <QWidget>
#include "stdafx.h"

#ifdef WIN32
#include <tchar.h>
#endif				// WIN32

UIPlugins::UIPlugins()
{
	UIPlugins(NULL, NULL);
}

UIPlugins::UIPlugins(Emitter * pEmitter, XSupCalls * pSupplicant)
{
	next = NULL;

#ifdef WINDOWS
	hdll = NULL;
#endif

	initialized = false;
	loaded = false;
	type = PLUGIN_TYPE_UNKNOWN;
	plugin = NULL;
	m_pProfile = NULL;
	m_pEmitter = pEmitter;
	m_pSupplicant = pSupplicant;
	index = -1;
}

UIPlugins::~UIPlugins()
{
	if (this->plugin != NULL) {
		this->destroyWidget();
	}

	this->unloadPlugin();
}

int UIPlugins::loadPlugin(char *location)
{
#ifdef WIN32
	hdll = LoadLibraryA(location);	// Probably need to change this to LoadLibraryW later on.

	//DWORD error = GetLastError();

	if (hdll == NULL)
		return PLUGIN_LOAD_FAILURE;
#endif				//WIN32

	loaded = true;

	if (m_pEmitter != NULL) {
		m_pEmitter->sendPluginLoaded(this);
	}

	return PLUGIN_LOAD_SUCCESS;
}

void UIPlugins::unloadPlugin()
{
	if (m_pEmitter != NULL) {
		m_pEmitter->sendPluginUnloading(this);
	}
#ifdef WIN32
	FreeLibrary(hdll);
	hdll = NULL;
#endif
}

#ifdef WIN32
HINSTANCE UIPlugins::getPlugin()
{
	return hdll;
}
#endif

void UIPlugins::setType(int newType)
{
	type = newType;
}

int UIPlugins::getType()
{
	return type;
}

bool UIPlugins::isType(int pluginType)
{
	if (pluginType == type) {
		return true;
	}

	return false;
}

int UIPlugins::addToParent(QWidget * pParent)
{

	if (isInitialized()) {
		if (plugin != NULL) {
			plugin->setParent(pParent);
			return PLUGIN_ACTION_SUCCESS;
		}
	}

/*	switch(type)
	{
	case PLUGIN_TYPE_PROFILE_TAB:
		{
			if(this->isInitialized())
			{
				if(plugin != NULL)
				{
					// We pass a -1 as the index so we will get appended to the tab list.
					index = ((ConfigProfileTabs *)pParent)->insertTab(-1, plugin, "Compliance");

					plugin->setParent(pParent);

					return PLUGIN_ACTION_SUCCESS;
				}
			}
			return PLUGIN_ACTION_FAILURE;
		}break;
	default:
			return PLUGIN_ACTION_UNKNOWN;
	}*/

	return PLUGIN_ACTION_FAILURE;
}

int UIPlugins::removeFromParent(QWidget * pParent)
{
	// XXX Is this function still needed?
	pParent = pParent;	// Silence the compiler.
	/*if(isInitialized())
	   {
	   if(plugin != NULL)
	   {
	   plugin->setParent(pParent);
	   }
	   } */

/*
	switch(type)
	{
	case PLUGIN_TYPE_PROFILE_TAB:
		{
			// An index of -1 indicates that we're not loaded into a parent...
			// If we're loaded, remove us from the parent.
			if(index != -1)
			{
				((ConfigProfileTabs *)pParent)->removeTab(index);

				//plugin->setParent(NULL);

				index = -1;

				return PLUGIN_ACTION_SUCCESS;
			}

			return PLUGIN_ACTION_FAILURE;
		}break;
	default:
		return PLUGIN_ACTION_UNKNOWN;
	};
*/

	return PLUGIN_ACTION_FAILURE;
}

bool UIPlugins::isInitialized()
{
	return initialized;
}

bool UIPlugins::isLoaded()
{
	return loaded;
}

int UIPlugins::instantiateWidget()
{
	QString engineVersion;

#ifdef WIN32
	typedef void *(*funcPtr) ();
	funcPtr CreatePluginWidgetObject;

	// Create the function pointer needed to instantiate the object.
	CreatePluginWidgetObject =
	    (funcPtr) (GetProcAddress(hdll, "CreatePluginWidgetObject"));

	if (CreatePluginWidgetObject != NULL) {
		//Instantiate the class object from the DLL                     
		plugin = (PluginWidget *) CreatePluginWidgetObject();

		if (plugin != NULL) {
			initialized = true;

			plugin->setEmitter(m_pEmitter);

			if (m_pEmitter != NULL) {
				m_pEmitter->sendPluginObjectInstantiated(this);
			}

			return PLUGIN_INIT_SUCCESS;
		}
	}
#endif				// WIN32

	return PLUGIN_INIT_FAILURE;
}

void UIPlugins::updateEngineVersionString(QString m_newVersion)
{
	if (plugin != NULL)
		plugin->setEngineVersionString(m_newVersion);
}

int UIPlugins::destroyWidget()
{
	if (plugin != NULL) {
		delete plugin;

		plugin = NULL;

		initialized = false;

		return PLUGIN_DESTROY_SUCCESS;
	}

	return PLUGIN_DESTROY_FAILURE;
}

void UIPlugins::setProfile(config_profiles * pProfile)
{
	m_pProfile = pProfile;

	if (isInitialized() == true) {
		// Now send a copy to the DLL
		if (plugin != NULL) {
			plugin->setProfile(m_pProfile);
		}
	}
}

bool UIPlugins::save()
{
	if (isInitialized()) {
		return plugin->save();
	}

	return false;
}

void UIPlugins::setEmitter(Emitter * pEmitter)
{
	m_pEmitter = pEmitter;

	if (initialized) {
		plugin->setEmitter(m_pEmitter);
	}
}

void UIPlugins::setCallbacks(UICallbacks uiCallbacks)
{
	if (initialized) {
		plugin->setCallbacks(uiCallbacks);
	}
}

QString UIPlugins::getPluginVersionString()
{
	if (initialized) {
		return plugin->getPluginVersionString();
	}

	return QString("Not Initialized");
}

void UIPlugins::show()
{
	if (plugin != NULL) {
		plugin->show();
	}
}

QString UIPlugins::getWidgetName()
{
	if (plugin != NULL) {
		return plugin->getWidgetName();
	}

	return QString("");
}

void UIPlugins::showHelp()
{
	if (plugin != NULL) {
		plugin->showHelp();
	}
}
