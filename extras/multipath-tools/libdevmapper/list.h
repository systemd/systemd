/*
 * Copyright (C) 2001 Sistina Software
 *
 * This file is released under the LGPL.
 */

#ifndef _LVM_LIST_H
#define _LVM_LIST_H

#include <assert.h>

struct list {
	struct list *n, *p;
};

#define LIST_INIT(name)	struct list name = { &(name), &(name) }

static inline void list_init(struct list *head)
{
	head->n = head->p = head;
}

static inline void list_add(struct list *head, struct list *elem)
{
	assert(head->n);

	elem->n = head;
	elem->p = head->p;

	head->p->n = elem;
	head->p = elem;
}

static inline void list_add_h(struct list *head, struct list *elem)
{
	assert(head->n);

	elem->n = head->n;
	elem->p = head;

	head->n->p = elem;
	head->n = elem;
}

static inline void list_del(struct list *elem)
{
	elem->n->p = elem->p;
	elem->p->n = elem->n;
}

static inline int list_empty(struct list *head)
{
	return head->n == head;
}

static inline int list_end(struct list *head, struct list *elem)
{
	return elem->n == head;
}

static inline struct list *list_next(struct list *head, struct list *elem)
{
	return (list_end(head, elem) ? NULL : elem->n);
}

#define list_iterate(v, head) \
	for (v = (head)->n; v != head; v = v->n)

#define list_uniterate(v, head, start) \
	for (v = (start)->p; v != head; v = v->p)

#define list_iterate_safe(v, t, head) \
	for (v = (head)->n, t = v->n; v != head; v = t, t = v->n)

static inline unsigned int list_size(const struct list *head)
{
	unsigned int s = 0;
	const struct list *v;

	list_iterate(v, head)
	    s++;

	return s;
}

#define list_item(v, t) \
    ((t *)((uintptr_t)(v) - (uintptr_t)&((t *) 0)->list))

#define list_struct_base(v, t, h) \
    ((t *)((uintptr_t)(v) - (uintptr_t)&((t *) 0)->h))

/* Given a known element in a known structure, locate another */
#define struct_field(v, t, e, f) \
    (((t *)((uintptr_t)(v) - (uintptr_t)&((t *) 0)->e))->f)

/* Given a known element in a known structure, locate the list head */
#define list_head(v, t, e) struct_field(v, t, e, list)

#endif
