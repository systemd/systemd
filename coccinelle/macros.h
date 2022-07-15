/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Collected macros from our systemd codebase to make the cocci semantic
 * parser happy. Inspired by the original cocci macros file
 * /usr/lib64/coccinelle/standard.h (including the YACFE_* symbols)
 */

// General
#define PTR_TO_PID(x)

// src/basic/macro.h
#define _printf_(a, b) __attribute__((__format__(printf, a, b)))
#define _alloc_(...) __attribute__((__alloc_size__(__VA_ARGS__)))
#define _sentinel_ __attribute__((__sentinel__))
#define _section_(x) __attribute__((__section__(x)))
#define _used_ __attribute__((__used__))
#define _unused_ __attribute__((__unused__))
#define _destructor_ __attribute__((__destructor__))
#define _pure_ __attribute__((__pure__))
#define _const_ __attribute__((__const__))
#define _deprecated_ __attribute__((__deprecated__))
#define _packed_ __attribute__((__packed__))
#define _malloc_ __attribute__((__malloc__))
#define _weak_ __attribute__((__weak__))
#define _likely_(x) (__builtin_expect(!!(x), 1))
#define _unlikely_(x) (__builtin_expect(!!(x), 0))
#define _public_ __attribute__((__visibility__("default")))
#define _hidden_ __attribute__((__visibility__("hidden")))
#define _weakref_(x) __attribute__((__weakref__(#x)))
#define _align_(x) __attribute__((__aligned__(x)))
#define _alignas_(x) __attribute__((__aligned__(__alignof(x))))
#define _alignptr_ __attribute__((__aligned__(sizeof(void*))))
#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _fallthrough_
#define _noreturn_ __attribute__((__noreturn__))
#define thread_local __thread

#define ELEMENTSOF(x)                                                   \
        (__builtin_choose_expr(                                         \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                               \
                VOID_0))

// src/basic/umask-util.h
#define _cleanup_umask_
#define RUN_WITH_UMASK(mask)                                            \
        for (_cleanup_umask_ mode_t _saved_umask_ = umask(mask) | S_IFMT; \
             FLAGS_SET(_saved_umask_, S_IFMT);                          \
             _saved_umask_ &= 0777)

// src/basic/hashmap.h
#define _IDX_ITERATOR_FIRST (UINT_MAX - 1)
#define HASHMAP_FOREACH(e, h) YACFE_ITERATOR
#define ORDERED_HASHMAP_FOREACH(e, h) YACFE_ITERATOR
#define HASHMAP_FOREACH_KEY(e, k, h) YACFE_ITERATOR
#define ORDERED_HASHMAP_FOREACH_KEY(e, k, h) YACFE_ITERATOR

// src/basic/list.h
#define LIST_HEAD(t,name)                                               \
        t *name
#define LIST_FIELDS(t,name)                                             \
        t *name##_next, *name##_prev
#define LIST_HEAD_INIT(head)                                            \
        do {                                                            \
                (head) = NULL;                                          \
        } while (false)
#define LIST_INIT(name,item)                                            \
        do {                                                            \
                typeof(*(item)) *_item = (item);                        \
                assert(_item);                                          \
                _item->name##_prev = _item->name##_next = NULL;         \
        } while (false)
#define LIST_PREPEND(name,head,item)                                    \
        do {                                                            \
                typeof(*(head)) **_head = &(head), *_item = (item);     \
                assert(_item);                                          \
                if ((_item->name##_next = *_head))                      \
                        _item->name##_next->name##_prev = _item;        \
                _item->name##_prev = NULL;                              \
                *_head = _item;                                         \
        } while (false)
#define LIST_APPEND(name,head,item)                                     \
        do {                                                            \
                typeof(*(head)) **_hhead = &(head), *_tail;             \
                LIST_FIND_TAIL(name, *_hhead, _tail);                   \
                LIST_INSERT_AFTER(name, *_hhead, _tail, item);          \
        } while (false)
#define LIST_REMOVE(name,head,item)                                     \
        do {                                                            \
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
        } while (false)
#define LIST_FIND_HEAD(name,item,head)                                  \
        do {                                                            \
                typeof(*(item)) *_item = (item);                        \
                if (!_item)                                             \
                        (head) = NULL;                                  \
                else {                                                  \
                        while (_item->name##_prev)                      \
                                _item = _item->name##_prev;             \
                        (head) = _item;                                 \
                }                                                       \
        } while (false)
#define LIST_FIND_TAIL(name,item,tail)                                  \
        do {                                                            \
                typeof(*(item)) *_item = (item);                        \
                if (!_item)                                             \
                        (tail) = NULL;                                  \
                else {                                                  \
                        while (_item->name##_next)                      \
                                _item = _item->name##_next;             \
                        (tail) = _item;                                 \
                }                                                       \
        } while (false)
#define LIST_INSERT_AFTER(name,head,a,b)                                \
        do {                                                            \
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
        } while (false)
#define LIST_INSERT_BEFORE(name,head,a,b)                               \
        do {                                                            \
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
        } while (false)

#define LIST_JUST_US(name,item)                                         \
        (!(item)->name##_prev && !(item)->name##_next)
#define LIST_FOREACH(name,i,head)                                       \
        for ((i) = (head); (i); (i) = (i)->name##_next)
#define LIST_FOREACH_SAFE(name,i,n,head)                                \
        for ((i) = (head); (i) && (((n) = (i)->name##_next), 1); (i) = (n))
#define LIST_FOREACH_BEFORE(name,i,p)                                   \
        for ((i) = (p)->name##_prev; (i); (i) = (i)->name##_prev)
#define LIST_FOREACH_AFTER(name,i,p)                                    \
        for ((i) = (p)->name##_next; (i); (i) = (i)->name##_next)
#define LIST_FOREACH_OTHERS(name,i,p)                                   \
        for (({                                                         \
                (i) = (p);                                              \
                while ((i) && (i)->name##_prev)                         \
                        (i) = (i)->name##_prev;                         \
                if ((i) == (p))                                         \
                        (i) = (p)->name##_next;                         \
             });                                                        \
             (i);                                                       \
             (i) = (i)->name##_next == (p) ? (p)->name##_next : (i)->name##_next)
#define LIST_LOOP_BUT_ONE(name,i,head,p)                                \
        for ((i) = (p)->name##_next ? (p)->name##_next : (head);        \
             (i) != (p);                                                \
             (i) = (i)->name##_next ? (i)->name##_next : (head))

#define LIST_JOIN(name,a,b)                                             \
        do {                                                            \
                assert(b);                                              \
                if (!(a))                                               \
                        (a) = (b);                                      \
                else {                                                  \
                        typeof(*(a)) *_head = (b), *_tail;              \
                        LIST_FIND_TAIL(name, (a), _tail);               \
                        _tail->name##_next = _head;                     \
                        _head->name##_prev = _tail;                     \
                }                                                       \
                (b) = NULL;                                             \
        } while (false)

// src/basic/strv.h
#define STRV_FOREACH(s, l) YACFE_ITERATOR
#define STRV_FOREACH_BACKWARDS(s, l) YACFE_ITERATOR
#define STRV_FOREACH_PAIR(x, y, l) YACFE_ITERATOR

// src/basic/socket-util.h
#define CMSG_BUFFER_TYPE(size)                                          \
        union {                                                         \
                struct cmsghdr cmsghdr;                                 \
                uint8_t buf[size];                                      \
                uint8_t align_check[(size) >= CMSG_SPACE(0) &&          \
                                    (size) == CMSG_ALIGN(size) ? 1 : -1]; \
        }

// src/libsystemd/sd-device/device-util.h
#define FOREACH_DEVICE_PROPERTY(device, key, value) YACFE_ITERATOR
#define FOREACH_DEVICE_TAG(device, tag) YACFE_ITERATOR
#define FOREACH_DEVICE_CURRENT_TAG(device, tag) YACFE_ITERATOR
#define FOREACH_DEVICE_SYSATTR(device, attr) YACFE_ITERATOR
#define FOREACH_DEVICE_DEVLINK(device, devlink) YACFE_ITERATOR
#define FOREACH_DEVICE(enumerator, device) YACFE_ITERATOR
#define FOREACH_SUBSYSTEM(enumerator, device) YACFE_ITERATOR

// src/basic/dirent-util.h
#define FOREACH_DIRENT(de, d, on_error) YACFE_ITERATOR
#define FOREACH_DIRENT_ALL(de, d, on_error) YACFE_ITERATOR
