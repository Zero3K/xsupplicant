#ifndef XSUPPLICANT_UI_PROFILE_CONFIG_PLUGIN_H
#define XSUPPLICANT_UI_PROFILE_CONFIG_PLUGIN_H

#include "UIPlugins.h"

class TabPlugins:public UIPlugins {
 private:
 protected:
	//TabWidgetBase *widget;
	int index;		// Index of this tab in its parent object.
 public:
	 TabPlugins();
	~TabPlugins();
	int addToParent(QWidget * pParent);
	void removeFromParent(QWidget * pParent);
	void setProfile(config_profiles * pProfile);
	int instantiateWidget();
};

#endif				//XSUPPLICANT_UI_PROFILE_COFIG_PLUGIN_H
