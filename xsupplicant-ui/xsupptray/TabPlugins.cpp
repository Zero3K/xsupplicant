#include "stdafx.h"

#include "TabPlugins.h"
#include "PluginWidget.h"

#include <QWidget>
#include <QTabWidget>


TabPlugins::TabPlugins()
{
	index = -1;
}

TabPlugins::~TabPlugins()
{
}

int TabPlugins::addToParent(QWidget *pParent)
{
	if(this->isInitialized())
	{
		if(plugin != NULL)
		{
			// We pass a -1 as the index so we will get appended to the tab list.
#if 0
			index = ((ConfigProfileTabs *)pParent)->insertTab(-1, plugin, "Compliance");

			plugin->setParent(pParent);
#endif
			return PLUGIN_ACTION_SUCCESS;
		}
	} 

	return PLUGIN_ACTION_FAILURE;
}

void TabPlugins::removeFromParent(QWidget *pParent)
{
	// An index of -1 indicates that we're not loaded into a parent...
	// If we're loaded, remove us from the parent.
	if(index != -1)
	{
		((QTabWidget *)pParent)->removeTab(index);

		plugin->setParent(NULL);

		index = -1;
	}
}

void TabPlugins::setProfile(config_profiles *pProfile)
{
	// Initialize our own profile...
	UIPlugins::setProfile(pProfile);

	if(isInitialized()== true)
	{
		// Now send a copy to the DLL
		if(plugin != NULL)
		{
			plugin->setProfile(m_pProfile);
		}
	}
}

// This function is over-ridden so we can do a late constructor call to the plugin.
int TabPlugins::instantiateWidget()
{
	if(UIPlugins::instantiateWidget() == PLUGIN_INIT_SUCCESS)
	{
		return PLUGIN_INIT_SUCCESS;
	}

	return PLUGIN_INIT_FAILURE;
}
