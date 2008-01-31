/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 * $Id: xsupconfwrite_managed_networks.h,v 1.2 2007/09/24 02:12:22 galimorerpg Exp $
 * $Date: 2007/09/24 02:12:22 $
 **/

#ifndef __XSUPCONFWRITE_MANAGED_NETWORKS_H__
#define __XSUPCONFWRITE_MANAGED_NETWORKS_H__

xmlNodePtr xsupconfwrite_managed_networks_create_tree(struct config_managed_networks *, char);
xmlNodePtr xsupconfwrite_managed_network_create_tree(struct config_managed_networks *, char);

#endif // __XSUPCONFWRITE_MANAGED_NETWORKS_H__






