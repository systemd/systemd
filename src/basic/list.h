/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* The head of the linked list. Use this in the structure that shall
 * contain the head of the linked list */
#define LIST_HEAD(t,name)                                               \
        t *name

/* The pointers in the linked list's items. Use this in the item structure */
#define LIST_FIELDS(t,name)                                             \
        t *name##_next, *name##_prev

/* Initialize the list's head */
#define LIST_HEAD_INIT(head)                                            \
        do {                                                            \
                (head) = NULL;                                          \
        } while (false)

/* Initialize a list item */
#define LIST_INIT(name,item)                                            \
        do {                                                            \
                typeof(*(item)) *_item = (item);                        \
                assert(_item);                                          \
                _item->name##_prev = _item->name##_next = NULL;         \
        } while (false)

/* Prepend an item to the list */
#define LIST_PREPEND(name,head,item)                                    \
        ({                                                              \
                typeof(*(head)) **_head = &(head), *_item = (item);     \
                assert(_item);                                          \
                if ((_item->name##_next = *_head))                      \
                        _item->name##_next->name##_prev = _item;        \
                _item->name##_prev = NULL;                              \
                *_head = _item;                                         \
                _item;                                                  \
        })

/* Append an item to the list */
#define LIST_APPEND(name,head,item)                                     \
        ({                                                              \
                typeof(*(head)) **_hhead = &(head), *_tail;             \
                _tail = LIST_FIND_TAIL(name, *_hhead);                  \
                LIST_INSERT_AFTER(name, *_hhead, _tail, item);          \
        })

/* Remove an item from the list */
#define LIST_REMOVE(name,head,item)                                     \
        ({                                                              \
                typeof(*(head)) **_head = &(head), *_item = (item);     \
                assert(_item);                                          \
                if (_item->name##_next)                                 \
                        _item->name##_next->name##_prev = _item->name##_prev; \
                if (_item->name##_prev)                                 \
                        _item->name##_prev->name##_next = _item->name##_next; \
                else {                                                  \
                        assert(*_head == _item);                        \
                        *_head = _item->name##_next;                    \
                }                                                       \
                _item->name##_next = _item->name##_prev = NULL;         \
                _item;                                                  \
        })

/* Find the head of the list */
#define LIST_FIND_HEAD(name,item)                                       \
        ({                                                              \
                typeof(*(item)) *_item = (item);                        \
                while (_item && _item->name##_prev)                     \
                        _item = _item->name##_prev;                     \
                _item;                                                  \
        })

/* Find the tail of the list */
#define LIST_FIND_TAIL(name,item)                                       \
        ({                                                              \
                typeof(*(item)) *_item = (item);                        \
                while (_item && _item->name##_next)                     \
                        _item = _item->name##_next;                     \
                _item;                                                  \
        })

/* Insert an item after another one (a = where, b = what) */
#define LIST_INSERT_AFTER(name,head,a,b)                                \
        ({                                                              \
                typeof(*(head)) **_head = &(head), *_a = (a), *_b = (b); \
                assert(_b);                                             \
                if (!_a) {                                              \
                        if ((_b->name##_next = *_head))                 \
                                _b->name##_next->name##_prev = _b;      \
                        _b->name##_prev = NULL;                         \
                        *_head = _b;                                    \
                } else {                                                \
                        if ((_b->name##_next = _a->name##_next))        \
                                _b->name##_next->name##_prev = _b;      \
                        _b->name##_prev = _a;                           \
                        _a->name##_next = _b;                           \
                }                                                       \
                _b;                                                     \
        })

/* Insert an item before another one (a = where, b = what) */
#define LIST_INSERT_BEFORE(name,head,a,b)                               \
        ({                                                              \
                typeof(*(head)) **_head = &(head), *_a = (a), *_b = (b); \
                assert(_b);                                             \
                if (!_a) {                                              \
                        if (!*_head) {                                  \
                                _b->name##_next = NULL;                 \
                                _b->name##_prev = NULL;                 \
                                *_head = _b;                            \
                        } else {                                        \
                                typeof(*(head)) *_tail = (head);        \
                                while (_tail->name##_next)              \
                                        _tail = _tail->name##_next;     \
                                _b->name##_next = NULL;                 \
                                _b->name##_prev = _tail;                \
                                _tail->name##_next = _b;                \
                        }                                               \
                } else {                                                \
                        if ((_b->name##_prev = _a->name##_prev))        \
                                _b->name##_prev->name##_next = _b;      \
                        else                                            \
                                *_head = _b;                            \
                        _b->name##_next = _a;                           \
                        _a->name##_prev = _b;                           \
                }                                                       \
                _b;                                                     \
        })

#define LIST_JUST_US(name, item)                                        \
        ({                                                              \
                typeof(*(item)) *_item = (item);                        \
                !(_item)->name##_prev && !(_item)->name##_next;         \
        })

/* The type of the iterator 'i' is automatically determined by the type of 'head', and declared in the
 * loop. Hence, do not declare the same variable in the outer scope. Sometimes, we set 'head' through
 * hashmap_get(). In that case, you need to explicitly cast the result. */
#define LIST_FOREACH_WITH_NEXT(name,i,n,head)                           \
        for (typeof(*(head)) *n, *i = (head); i && (n = i->name##_next, true); i = n)

#define LIST_FOREACH(name,i,head)                                       \
        LIST_FOREACH_WITH_NEXT(name, i, UNIQ_T(n, UNIQ), head)

#define _LIST_FOREACH_WITH_PREV(name,i,p,start)                         \
        for (typeof(*(start)) *p, *i = (start); i && (p = i->name##_prev, true); i = p)

#define LIST_FOREACH_BACKWARDS(name,i,start)                            \
        _LIST_FOREACH_WITH_PREV(name, i, UNIQ_T(p, UNIQ), start)

/* Iterate through all the members of the list p is included in, but skip over p */
#define LIST_FOREACH_OTHERS(name,i,p)                                   \
        for (typeof(*(p)) *_p = (p), *i = ({                            \
                                typeof(*_p) *_j = _p;                   \
                                while (_j && _j->name##_prev)           \
                                        _j = _j->name##_prev;           \
                                if (_j == _p)                           \
                                        _j = _p->name##_next;           \
                                _j;                                     \
                        });                                             \
             i;                                                         \
             i = i->name##_next == _p ? _p->name##_next : i->name##_next)

/* Loop starting from p->next until p->prev. p can be adjusted meanwhile. */
#define LIST_LOOP_BUT_ONE(name,i,head,p)                                \
        for (typeof(*(p)) *i = (p)->name##_next ? (p)->name##_next : (head); \
             i != (p);                                                  \
             i = i->name##_next ? i->name##_next : (head))

/* Join two lists tail to head: a->b, c->d to a->b->c->d and de-initialise second list */
#define LIST_JOIN(name,a,b)                                             \
        ({                                                              \
                assert(b);                                              \
                if (!(a))                                               \
                        (a) = (b);                                      \
                else {                                                  \
                        typeof(*(a)) *_head = (b), *_tail;              \
                        _tail = LIST_FIND_TAIL(name, (a));              \
                        _tail->name##_next = _head;                     \
                        _head->name##_prev = _tail;                     \
                }                                                       \
                (b) = NULL;                                             \
                a;                                                      \
        })

#define LIST_POP(name, a)                                               \
        ({                                                              \
                typeof(a)* _a = &(a);                                   \
                typeof(a) _p = *_a;                                     \
                if (_p)                                                 \
                        LIST_REMOVE(name, *_a, _p);                     \
                _p;                                                     \
        })

#define LIST_CLEAR(name, head, free_func)       \
        _LIST_CLEAR(name, head, free_func, UNIQ_T(elem, UNIQ))

/* Clear the list, destroying each element with free_func */
#define _LIST_CLEAR(name, head, free_func, elem)        \
        ({                                              \
                typeof(head) elem;                      \
                while ((elem = LIST_POP(name, head)))   \
                        free_func(elem);                \
                head;                                   \
        })
