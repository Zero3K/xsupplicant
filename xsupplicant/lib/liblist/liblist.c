/**
 * A generic linked list library.
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \file liblist.c
 *
 * \author chris@open1x.org
 *
 * $Id: liblist.c,v 1.3 2007/10/22 03:29:06 galimorerpg Exp $
 * $Date: 2007/10/22 03:29:06 $
 **/

#include <stdio.h>

#include "liblist.h"

/**
 * \brief Add a node to the head of the list.  If the list is empty, then it will be created.
 *
 * @param[in,out] addtolist   The list that we want to add a node to.
 * @param[in] newnode   The node that we want to add to the list.
 **/
void liblist_add_to_head(genlist **addtolist, genlist *newnode)
{
	newnode->next = (*addtolist);
	(*addtolist) = newnode;
}

/**
 * \brief Add a node to the end of the list.
 *
 * @param[in,out] addtolist   The list that we want to add a node to.
 * @param[in] newnode   The node that we want to add to the end of the list.
 **/
void liblist_add_to_tail(genlist **addtolist, genlist *newnode)
{
	genlist *cur = NULL;

	if ((*addtolist) == NULL)
	{
		(*addtolist) = newnode;
		return;
	}

	cur = (*addtolist);

	while (cur->next != NULL) cur = cur->next;

	cur->next = newnode;
}

/**
 * \brief Delete a child node.
 *
 * @param[in,out] parent   The parent node whose child we want to delete.
 * @param[in] delfunc   The function to call to properly delete the child node.
 **/
void liblist_delete_child_node(genlist *parent, node_delete_func delfunc)
{
	genlist *cur = NULL;

	if (parent->next == NULL) return;  // Do nothing.

	cur = parent->next->next;

	(*delfunc)((void **)&parent->next);

	parent->next = cur;
}

/**
 * \brief Delete a list.
 *
 * @param[in,out] list   The list that we want to delete.
 * @param[in] delfunc   The function to call to properly delete each node in the list.
 **/
void liblist_delete_list(genlist **list, node_delete_func delfunc)
{
	genlist *cur = NULL, *next = NULL;

	cur = (*list);

	while (cur != NULL)
	{
		next = cur;
		cur = cur->next;

		(*delfunc)((void **)&next);
	}

	(*list) = NULL;
}
