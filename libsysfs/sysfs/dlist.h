/*
 * dlist.h
 *
 * Copyright (C) 2003 Eric J Bohm
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */
#ifndef _DLIST_H_
#define _DLIST_H_

/* Double linked list header.
   
* navigate your list with DLIST_PREV and DLIST_NEXT.  These are macros
* so function call overhead is minimized.

* Supports perl style push, pop, shift, unshift list semantics.

* You allocate the data and give dlist the pointer.  If your data is
* complex set the dlist->del_func to a an appropriate delete using
* dlist_new_with_delete.  Your delete function must match 
(void * )(del(void *)
*Otherwise dlist will just use free.

* NOTE: The small amount of pain involved in doing that allows us to
* avoid copy in copy out semantics.

* Dlist uses an internal mark pointer to keep track of where you are
* in the list.

* insert and delete take a directional parameter. Where direction
* corresponds to the direction in which you want the list to go.
* true direction corresponded to progressing forward in the last
* false to regressing in the list.
* so a dlist_insert(yourlist,item,1) will insert it after the mark
* so a dlist_insert(yourlist,item,0) will insert it before the mark
* any insert will move the mark to the new node regardless of the direction.

* Just use the dlist_(insert|delete)_(before|after) macros if you do not want
* to think about it.
*/

#include <stddef.h>

typedef struct dl_node {
  struct dl_node *prev;
  struct dl_node *next;
  void *data;
} DL_node;

typedef struct dlist {
  DL_node *marker;
  unsigned long count;
  size_t data_size;
  void (*del_func)(void *);
  DL_node headnode;
  DL_node *head;
} Dlist;

Dlist *dlist_new(size_t datasize);
Dlist *dlist_new_with_delete(size_t datasize,void (*del_func)(void*));
void *_dlist_mark_move(Dlist *list,int direction);
void *dlist_mark(Dlist *);
void dlist_start(Dlist *);
void dlist_end(Dlist *);
void dlist_move(struct dlist *source, struct dlist *dest, struct dl_node *target,int direction);
void *dlist_insert(Dlist *,void *,int) ;

void *dlist_insert_sorted(struct dlist *list, void *new_elem, int (*sorter)(void *, void *));

void dlist_delete(Dlist *,int);

void dlist_push(Dlist *,void *);

void dlist_unshift(Dlist *,void *);
void dlist_unshift_sorted(Dlist *,void *,int (*sorter)(void *, void *));

void *dlist_pop(Dlist *);

void *dlist_shift(Dlist *);

void dlist_destroy(Dlist *);

int _dlist_merge(struct dlist *listsource, struct dlist *listdest, unsigned int passcount, int (*compare)(void *, void *));

void *dlist_find_custom(struct dlist *list, void *target, int (*comp)(void *, void *));

void dlist_sort_custom(struct dlist *list, int (*compare)(void *, void *));


void _dlist_swap(struct dlist *list, struct dl_node *a, struct dl_node *b);

void dlist_transform(struct dlist *list, void (*node_operation)(void *));


/* 
 * _dlist_remove is for internal use only
 * _dlist_mark_move is for internal use only
 */
void *_dlist_remove(struct dlist *,struct dl_node *,int );
void *_dlist_insert_dlnode(struct dlist *list,struct dl_node *new_node,int direction);

#define dlist_prev(A) _dlist_mark_move((A),0)
#define dlist_next(A) _dlist_mark_move((A),1)

#define dlist_insert_before(A,B) dlist_insert((A),(B),0)
#define dlist_insert_after(A,B) dlist_insert((A),(B),1)

#define dlist_delete_before(A) dlist_delete((A),0)
#define dlist_delete_after(A) dlist_delete((A),1)

/**
 * provide for loop header which iterates the mark from start to end
 * list: the dlist pointer, use dlist_mark(list) to get iterator
 */
#define dlist_for_each(list) \
	for(dlist_start(list),dlist_next(list); \
		(list)->marker!=(list)->head;dlist_next(list))

/**
 * provide for loop header which iterates the mark from end to start
 * list: the dlist pointer, use dlist_mark(list) to get iterator
 */
#define dlist_for_each_rev(list) \
	for(dlist_end(list),dlist_prev(list); \
		(list)->marker!=(list)->head;dlist_prev(list))

/**
 * provide for loop header which iterates through the list without moving mark
 * list: the dlist_pointer
 * iterator: dl_node pointer to iterate
 */
#define dlist_for_each_nomark(list,iterator) \
	for((iterator)=(list)->head->next; (iterator)!=(list)->head; \
		(iterator)=(iterator)->next)

/**
 * provide for loop header which iterates through the list without moving mark
 * in reverse
 * list: the dlist_pointer
 * iterator: dl_node pointer to iterate
 */
#define dlist_for_each_nomark_rev(list,iterator) \
	for((iterator)=(list)->head->prev; (iterator)!=(list)->head; \
		(iterator)=(iterator)->prev)
/**
 * provide for loop header which iterates through the list providing a
 * data iterator
 * list: the dlist pointer
 * data_iterator: the pointer of type datatype to iterate
 * datatype:  actual type of the contents in the dl_node->data
 */

#define dlist_for_each_data(list,data_iterator,datatype) \
	for(dlist_start(list), (data_iterator)=(datatype *) dlist_next(list); \
	(list)->marker!=(list)->head;(data_iterator)=(datatype *) dlist_next(list))

/**
 * provide for loop header which iterates through the list providing a
 * data iterator in reverse
 * list: the dlist pointer
 * data_iterator: the pointer of type datatype to iterate
 * datatype:  actual type of the contents in the dl_node->data
 */
#define dlist_for_each_data_rev(list,data_iterator,datatype) \
	for(dlist_end(list), (data_iterator)=(datatype *) dlist_prev(list); \
	(list)->marker!=(list)->head;(data_iterator)=(datatype *) dlist_prev(list))

/**
 * provide for loop header which iterates through the list providing a
 * data iterator without moving the mark
 * list: the dlist pointer
 * iterator: the dl_node pointer to iterate
 * data_iterator: the pointer of type datatype to iterate
 * datatype:  actual type of the contents in the dl_node->data
 */

#define dlist_for_each_data_nomark(list,iterator,data_iterator,datatype) \
	for((iterator)=(list)->head->next, (data_iterator)=(datatype *) (iterator)->data; \
	(iterator)!=(list)->head;(iterator)=(iterator)->next,(data_iterator)=(datatype *) (iterator))

/**
 * provide for loop header which iterates through the list providing a
 * data iterator in reverse without moving the mark
 * list: the dlist pointer
 * iterator: the dl_node pointer to iterate
 * data_iterator: the pointer of type datatype to iterate
 * datatype:  actual type of the contents in the dl_node->data
 */
#define dlist_for_each_data_nomark_rev(list,iterator, data_iterator,datatype) \
	for((iterator)=(list)->head->prev, (data_iterator)=(datatype *) (iterator)->data; \
	(iterator)!=(list)->head;(iterator)=(iterator)->prev,(data_iterator)=(datatype *) (iterator))

#endif /* _DLIST_H_ */
