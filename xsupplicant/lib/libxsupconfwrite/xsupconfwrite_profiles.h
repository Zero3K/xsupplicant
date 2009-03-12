/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/
#ifndef __XSUPCONFWRITE_PROFILES_H__
#define __XSUPCONFWRITE_PROFILES_H__

xmlNodePtr xsupconfwrite_profiles_create_tree(struct config_profiles *, uint8_t,
					      char, char);
xmlNodePtr xsupconfwrite_profile_create_tree(struct config_profiles *, uint8_t,
					     char);

#endif				// __XSUPCONFWRITE_PROFILES_H__
