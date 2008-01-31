/**
 *
 * Licensed under a dual GPL/BSD license.  (See LICENSE file for more info.)
 *
 * \author chris@open1x.org
 *
 **/

#ifndef __LIBLIST_H__
#define __LIBLIST_H__

typedef struct _genlist_struct {
	struct _genlist_struct *next;
} genlist;

typedef void (*node_delete_func)(void **node);

void liblist_add_to_head(genlist **addtolist, genlist *newnode);
void liblist_add_to_tail(genlist **addtolist, genlist *newnode);
void liblist_delete_child_node(genlist *parent, node_delete_func delfunc);
void liblist_delete_list(genlist **list, node_delete_func delfunc);


#endif // __LIBLIST_H__






