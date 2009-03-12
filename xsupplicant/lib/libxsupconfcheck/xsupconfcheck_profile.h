/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfcheck_profile.h,v 1.2 2007/09/24 02:12:20 galimorerpg Exp $
 * $Date: 2007/09/24 02:12:20 $
 **/
#ifndef __XSUPCONFCHECK_PROFILE_H__
#define __XSUPCONFCHECK_PROFILE_H__

int xsupconfcheck_profile_check(struct config_profiles *, int);
int xsupconfcheck_profile_check_eap_method(struct config_eap_method *,
					   config_profiles *, int);

#endif				// __XSUPCONFCHECK_PROFILE_H__
