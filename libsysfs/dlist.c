/*
 * dlist.c
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 021110307 USA
 *
 */


/* Double linked list implementation.

 * You allocate the data and give dlist the pointer.
 * If your data is complex set the dlist->del_func to a an appropriate
 * delete function.  Otherwise dlist will just use free.

*/
#include "dlist.h"

/*
 * Return pointer to node at marker.
 * else null if no nodes.
 */

inline void *dlist_mark(Dlist *list)
{
  if(list->marker!=NULL)
    return(list->marker->data);
  else
    return(NULL);
}

/* 
 * Set marker to start.
 */

inline void dlist_start(Dlist *list)
{
  list->marker=list->head;
}

/* 
 * Set marker to end.
 */

inline void dlist_end(Dlist *list)
{
  list->marker=list->head;
}

/* internal use function
 * quickie inline to consolidate the marker movement logic
 * in one place
 *
 * when direction true it moves marker after 
 * when direction false it moves marker before.
 * return pointer to data at new marker
 * if nowhere to move the marker in desired direction return null 
 */
inline void *_dlist_mark_move(Dlist *list,int direction)
{
  if(direction)
    {
      if( list->marker && list->marker->next!=NULL)
	list->marker=list->marker->next;
      else
	return(NULL);
    }
  else
    {
      if( list->marker && list->marker->prev!=NULL)
	list->marker=list->marker->prev;
      else
	return(NULL);
    }
  if(list->marker!=list->head)
    return(list->marker->data);
  else
    return(NULL);
}

/*
 * Create new linked list to store nodes of datasize.
 * return null if list cannot be created.
 */
Dlist *dlist_new(size_t datasize)
{
  Dlist *list=NULL;
  if((list=malloc(sizeof(Dlist))))
    {
      list->marker=NULL;
      list->count=0L;
      list->data_size=datasize;
      list->del_func=free;
      list->head=&(list->headnode);
      list->head->prev=NULL;
      list->head->next=NULL;
      list->head->data=NULL;
    }
  return(list);
}

/*
 * Create new linked list to store nodes of datasize set list
 * data node delete function to the passed in del_func
 * return null if list cannot be created.
 */
Dlist *dlist_new_with_delete(size_t datasize,void (*del_func)(void*))
{
  Dlist *list=NULL;
  list=dlist_new(datasize);
  if(list!=NULL)
    list->del_func=del_func;
  return(list);
}


/*
 * remove marker node from list
 * call data_delete function on data if registered.
 * otherwise call free.
 * when direction true it moves marker after 
 * when direction false it moves marker before.
 * free marker node
 * return nothing.
 */
void dlist_delete(Dlist *list,int direction)
{
  if((list->marker != list->head)&&(list->marker!=NULL)) 
    {
      DL_node *corpse;
      corpse=list->marker;
      _dlist_mark_move(list,direction);
      if(list->head->next==corpse)
	list->head->next=corpse->next;
      if(list->head->prev==corpse)
	list->head->prev=corpse->prev;
      if(corpse->prev!=NULL) //should be impossible
	corpse->prev->next=corpse->next;
      if(corpse->next!=NULL) //should be impossible
	corpse->next->prev=corpse->prev;
      list->del_func(corpse->data);
      list->count--;
      free(corpse);
    }
}

/*
 * Insert node containing data at marker.
 * If direction true it inserts after.
 * If direction false it inserts before.
 * move marker to inserted node
 * return pointer to inserted node
 */
void *dlist_insert(Dlist *list,void *data,int direction)
{
  DL_node *new_node=NULL;
  if(list==NULL || data==NULL)
    return(NULL);
  if(list->marker==NULL) //in case the marker ends up unset
    list->marker=list->head;
  if((new_node=malloc(sizeof(DL_node))))
    {
      new_node->data=data;
      new_node->prev=NULL;
      new_node->next=NULL;
      list->count++;
      if(list->head->next==NULL) //no l
	{
	  list->head->next=list->head->prev=new_node;
	  new_node->prev=list->head;
	  new_node->next=list->head;
	}
      else if(direction)
	{
	  new_node->next=list->marker->next;
	  new_node->prev=list->marker;
	  list->marker->next->prev=new_node;
	  list->marker->next=new_node;
	}
      else
	{
	  new_node->prev=list->marker->prev;
	  new_node->next=list->marker;
	  list->marker->prev->next=new_node;
	  list->marker->prev=new_node;
	}
	list->marker=new_node;
    }
  else
    {
      return(NULL);
    }
  return(list->marker->data);
}

/* internal use only
 * Insert dl_node  at marker.
 * If direction true it inserts after.
 * If direction false it inserts before.
 * move marker to inserted node
 * return pointer to inserted node
 */
void *_dlist_insert_dlnode(struct dlist *list,struct dl_node *new_node,int direction)
{
  if(list==NULL || new_node==NULL)
    return(NULL);
  if(list->marker==NULL) //in case the marker ends up unset
    list->marker=list->head;
  list->count++;
  if(list->head->next==NULL) 
    {
      list->head->next=list->head->prev=new_node;
      new_node->prev=list->head;
      new_node->next=list->head;
    }
  else if(direction)
    {
      new_node->next=list->marker->next;
      new_node->prev=list->marker;
      list->marker->next->prev=new_node;
      list->marker->next=new_node;
    }
  else
    {
      new_node->prev=list->marker->prev;
      new_node->next=list->marker;
      list->marker->prev->next=new_node;
      list->marker->prev=new_node;
    }
  list->marker=new_node;
  return(list->marker);
}



/* 
 * Remove DL_node from list without deallocating data.
 * if marker == killme .
 *  when direction true it moves marker after 
 *  when direction false it moves marker before.
 * to previous if there is no next.
 */
void *_dlist_remove(Dlist *list,DL_node *killme,int direction)
{
  if(killme!=NULL)
    {
      void *killer_data=killme->data;
      // take care of head and marker pointers.
      if(list->marker==killme)
	_dlist_mark_move(list,direction);
      if(killme ==list->head->next)
	list->head->next=killme->next;
      if(killme==list->head->prev)  
	list->head->prev=killme->prev;
      // remove from list
      if(killme->prev !=NULL)
	killme->prev->next=killme->next;
      if(killme->next !=NULL)
	killme->next->prev=killme->prev;
      list->count--;
      free(killme);
      return(killer_data);
    }
  else
    return (NULL);
}

/* 
 * move dl_node from source to dest
 * if marker == target .
 *  when direction true it moves marker after 
 *  when direction false it moves marker before.
 * to previous if there is no next.
 */
void dlist_move(struct dlist *source, struct dlist *dest, struct dl_node *target,int direction)
{

  if(target!=NULL)
    {
      if(target==source->head)
	{
	  //not even going to try
	}
      else
	{
	  // take care of head and marker pointers.
	  if(source->marker==target)
	    _dlist_mark_move(source,direction);
	  if(target ==source->head->next)
	    source->head->next=target->next;
	  if(target==source->head->prev)  
	    source->head->prev=target->prev;
	  // remove from list
	  if(source->count==1)
	    {
	      target->prev=NULL;
	      target->next=NULL;
	      source->head->next=NULL;
	      source->head->prev=NULL;
	    }
	  else
	    {
	      if(target->prev !=NULL)
		target->prev->next=target->next;
	      if(target->next !=NULL)
		target->next->prev=target->prev;
	      target->prev=NULL;
	      target->next=NULL;
	    }
	  source->count--;
	  _dlist_insert_dlnode(dest,target,direction);
	}
    }
}


/*
 * Insert node containing data after end.
 */
void dlist_push(Dlist *list,void *data)
{
  list->marker=list->head->prev;
  dlist_insert(list,data,1);
}

/*
 * Insert node containing data at start.
 */

void dlist_unshift(Dlist *list,void *data)

{
  list->marker=list->head->next;
  dlist_insert(list,data,0);
}

void dlist_unshift_sorted(Dlist *list, void *data, 
			int (*sorter)(void *new_elem, void *old_elem))
{
	if (list->count == 0)
		dlist_unshift(list, data);
	else {
		list->marker=list->head->next;
		dlist_insert_sorted(list, data, sorter);
	}
}

/* 
 * Remove end node from list.
 * Return pointer to data in removed node.
 * Null if no nodes.
 */

void *dlist_pop(Dlist *list)
{
  return(_dlist_remove(list,list->head->prev,0));
}

/* 
 * Remove start node from list.
 * Return pointer to data in removed node.
 * Null if no nodes.
 */

void *dlist_shift(Dlist *list)
{
  return(_dlist_remove(list,list->head->next,1));
}


/* 
 * destroy the list freeing all memory
 */


void dlist_destroy(Dlist *list)
{
  if(list !=NULL)
    {
      dlist_start(list);
      dlist_next(list);
      while (dlist_mark(list)) {
	      dlist_delete(list,1);
      }
      free(list);
    }
}

/**
 *  Return void pointer to list_data element matching comp function criteria
 *  else null
 *  Does not move the marker.
 */

void *dlist_find_custom(struct dlist *list, void *target, int (*comp)(void *, void *))
{
	/* test the comp function on each node */
	struct dl_node *nodepointer;
	dlist_for_each_nomark(list,nodepointer)
		if(comp(target,nodepointer->data))
			return(nodepointer->data);
	return(NULL);
}

/**
 * Apply the node_operation function to each data node in the list
 */
void dlist_transform(struct dlist *list, void (*node_operation)(void *))
{
	struct dl_node *nodepointer;
	dlist_for_each_nomark(list,nodepointer)
		node_operation(nodepointer->data);
}

/**
 * insert new into list in sorted order
 * sorter function in form int sorter(new,ith)
 *       must return 1 for when new should go before ith
 *       else 0
 * return pointer to inserted node
 * NOTE: assumes list is already sorted
 */
void *dlist_insert_sorted(struct dlist *list, void *new, int (*sorter)(void *, void *))
{
	for(dlist_start(list),dlist_next(list); \
		list->marker!=list->head && !sorter(new,list->marker->data);dlist_next(list));
	return(dlist_insert_before(list,new));
}

/*
 * NOTE: internal use only
 */
int _dlist_merge(struct dlist *listsource, struct dlist *listdest, unsigned int passcount, int (*compare)(void *, void *))
{

  struct dl_node *l1head;
  struct dl_node *l2head;
  struct dl_node *target;
  unsigned int l1count=0;
  unsigned int l2count=0;
  unsigned int mergecount=0;
  while(listsource->count>0)
    {
      l1head=listsource->head->next;
      l2head=l1head;
      while((l1count<passcount)&&(l2head!=listsource->head))
	{
	  l2head=l2head->next;
	  l1count++;
	}
      // so now we have two lists to merge
      
      if(l2head==listsource->head)
	{// l2count
	  l2count=0;
	}
      else
	{
	  l2count=passcount;
	}
      while(l1count>0 || l2count>0)
	{
	  mergecount++;
	  if((l2count>0)&&(l1count>0))
	    {
	      // we have things to merge
	      int result=compare(l1head->data,l2head->data);
	      if(result>0)
		{
		  // move from l2
		  target=l2head;
		  l2head=l2head->next;
		  dlist_move(listsource,listdest,target,1);
		  l2count--;
		  if(l2head==listsource->head)
		    l2count=0;
		}
	      else
		{
		  // move from l1
		  target=l1head;
		  l1head=l1head->next;
		  dlist_move(listsource,listdest,target,1);
		  l1count--;
		}
	    }
	  else if(l1count>0)
	    {
	      // only have l1 to work with
	      while(l1count>0)
		{
		  target=l1head;
		  l1head=l1head->next;
		  dlist_move(listsource,listdest,target,1);
		  l1count--;
		}
	    }
	  else if(l2count>0)
	    {
	      // only have l2 to work with
	      while(l2count>0)
		{
		  if(l2head==listsource->head)
		    {
		      l2count=0;
		    }
		  else
		    {
		      target=l2head;
		      l2head=l2head->next;
		      dlist_move(listsource,listdest,target,1);
		      l2count--;
		    }
		}
	    }
	  else
	    { //nothing left and this should be unreachable
	    }
	}  
    }
  return(mergecount);
}

/**
 * mergesort the list based on compare
 * compare function in form int sorter(void * a,void * b)
 *       must return >0 for a after b
 *       must return <0 for a before b
 *       else 0

 * NOTE: mergesort changes the mark pointer
 */
void dlist_sort_custom(struct dlist *list, int (*compare)(void *, void *))
{

  dlist_start(list);
  struct dlist *listsource, *listdest, *swap;
  struct dlist *templist = dlist_new(list->data_size);
  unsigned int passcount = 1;
  unsigned int mergecount = 1;
  // do nothing if there isn't anything to sort
  listsource = list;
  listdest = templist;
  if(listsource->count<2)
    { //nothing to do
      return;
    }
  else
    {
      while(mergecount>0)
	{
	  mergecount=_dlist_merge(listsource, listdest, passcount, compare);
	  if(mergecount>1)
	    {
	      passcount=passcount*2;
	      //start new pass
	      swap=listsource;
	      listsource=listdest;
	      listdest=swap;
	    }
	}
    }
  // now put the input list pointers right
  // list pointers = newlist pointers
  // including the forward and next nodes prev and back pointers
  if(list->count==0)
    {//copy
      list->marker = listdest->marker;
      list->count = listdest->count;
      list->data_size = listdest->data_size;
      list->del_func = listdest->del_func;
      list->head->prev = listdest->head->prev;
      list->head->next = listdest->head->next;
      list->head->data = listdest->head->data;
      list->head->next->prev=list->head;
      list->head->prev->next=list->head;
      templist->head->next=NULL;
      templist->head->prev=NULL;
      templist->count=0;
    }
  else
    {// no need to copy
      
    }

  dlist_destroy(templist);
}



/* internal use function
   swaps elements a and b
   No sense in juggling node pointers when we can just swap the data pointers
*/

void _dlist_swap(struct dlist *list, struct dl_node *a, struct dl_node *b)
{

  void *swap=a->data;
  a->data=b->data;
  b->data=swap;
  
}
  
