/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foolisthfoo
#define foolisthfoo

/* The head of the linked list. Use this in the structure that shall
 * contain the head of the linked list */
#define LIST_HEAD(t,name)                                               \
    t *name

/* The pointers in the linked list's items. Use this in the item structure */
#define LIST_FIELDS(t)                                                  \
    t *next, *prev

/* Initialize the list's head */
#define LIST_HEAD_INIT(t,item)                                          \
        do {                                                            \
                (item) = (t*) NULL; }                                   \
        while(false)

/* Initialize a list item */
#define LIST_INIT(t,item)                                               \
        do {                                                            \
                t *_item = (item);                                      \
                assert(_item);                                          \
                _item->prev = _item->next = NULL;                       \
        } while(false)

/* Prepend an item to the list */
#define LIST_PREPEND(t,head,item)                                       \
        do {                                                            \
                t **_head = &(head), *_item = (item);                   \
                assert(_item);                                          \
                if ((_item->next = *_head))                             \
                        _item->next->prev = _item;                      \
                _item->prev = NULL;                                     \
                *_head = _item;                                         \
        } while(false)

/* Remove an item from the list */
#define LIST_REMOVE(t,head,item)                                        \
        do {                                                            \
                t **_head = &(head), *_item = (item);                   \
                assert(_item);                                          \
                if (_item->next)                                        \
                        _item->next->prev = _item->prev;                \
                if (_item->prev)                                        \
                        _item->prev->next = _item->next;                \
                else {                                                  \
                        assert(*_head == _item);                        \
                        *_head = _item->next;                           \
                }                                                       \
                _item->next = _item->prev = NULL;                       \
        } while(false)

/* Find the head of the list */
#define LIST_FIND_HEAD(t,item,head)                                     \
        do {                                                            \
                t **_head = (head), *_item = (item);                    \
                *_head = _item;                                         \
                assert(_head);                                          \
                while ((*_head)->prev)                                  \
                        *_head = (*_head)->prev;                        \
        } while (false)

/* Insert an item after another one (a = where, b = what) */
#define LIST_INSERT_AFTER(t,head,a,b)                                   \
        do {                                                            \
                t **_head = &(head), *_a = (a), *_b = (b);              \
                assert(_b);                                             \
                if (!_a) {                                              \
                        if ((_b->next = *_head))                        \
                                _b->next->prev = _b;                    \
                        _b->prev = NULL;                                \
                        *_head = _b;                                    \
                } else {                                                \
                        if ((_b->next = _a->next))                      \
                                _b->next->prev = _b;                    \
                        _b->prev = _a;                                  \
                        _a->next = _b;                                  \
                }                                                       \
        } while(false)

#define LIST_FOREACH(i,head)                                            \
        for (i = (head); i; i = i->next)

#define LIST_FOREACH_SAFE(i,n,head)                                     \
        for (i = (head); i && ((n = i->next), 1); i = n)

#endif
