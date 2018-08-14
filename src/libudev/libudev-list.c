/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "libudev-private.h"
#include "string-util.h"

/**
 * SECTION:libudev-list
 * @short_description: list operation
 *
 * Libudev list operations.
 */

/**
 * udev_list_entry:
 *
 * Opaque object representing one entry in a list. An entry contains
 * a name, and optionally a value.
 */
struct udev_list_entry {
        struct udev_list *list;
        char *name;
        char *value;
        int num;
};

void udev_list_entry_free(struct udev_list_entry *entry) {
        if (!entry)
                return;

        if (entry->list && entry->name)
                (void) hashmap_remove(entry->list->entries, entry->name);

        free(entry->name);
        free(entry->value);
        free(entry);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_list_entry*, udev_list_entry_free);

void udev_list_init(struct udev_list *list, bool unique) {
        assert(list);

        *list = (struct udev_list) {
                .unique = unique,
        };
}

int udev_list_entry_add(struct udev_list *list, const char *name, const char *value, struct udev_list_entry **ret) {
        _cleanup_(udev_list_entry_freep) struct udev_list_entry *entry = NULL;
        _cleanup_free_ char *n = NULL, *v = NULL;
        int r;

        assert(list);
        assert(name);

        if (list->unique) {
                entry = hashmap_get(list->entries, name);
                if (entry) {
                        r = free_and_strdup(&entry->value, value);
                        if (r < 0)
                                return r;

                        if (ret)
                                *ret = entry;

                        TAKE_PTR(entry);
                        return 0;
                }
        }

        n = strdup(name);
        if (!n)
                return -ENOMEM;

        if (value) {
                v = strdup(value);
                if (!v)
                        return -ENOMEM;
        }

        entry = new(struct udev_list_entry, 1);
        if (!entry)
                return -ENOMEM;

        *entry = (struct udev_list_entry) {
                .list = list,
                .name = TAKE_PTR(n),
                .value = TAKE_PTR(v),
        };

        r = hashmap_ensure_allocated(&list->entries, list->unique ? &string_hash_ops : NULL);
        if (r < 0)
                return r;

        r = hashmap_put(list->entries, entry->name, entry);
        if (r < 0)
                return r;

        if (ret)
                *ret = entry;

        TAKE_PTR(entry);
        return 0;
}

void udev_list_cleanup(struct udev_list *list) {
        struct udev_list_entry *entry;

        if (!list)
                return;

        list->iterator = ITERATOR_FIRST;

        while ((entry = hashmap_first(list->entries)))
                udev_list_entry_free(entry);

        list->entries = hashmap_free(list->entries);
}

struct udev_list_entry *udev_list_get_entry(struct udev_list *list) {
        struct udev_list_entry *next;

        assert(list);

        list->iterator = ITERATOR_FIRST;

        if (hashmap_iterate(list->entries, &list->iterator, (void**) &next, NULL))
                return next;

        return NULL;
}

/**
 * udev_list_entry_get_next:
 * @list_entry: current entry
 *
 * Get the next entry from the list.
 *
 * Returns: udev_list_entry, #NULL if no more entries are available.
 */
_public_ struct udev_list_entry *udev_list_entry_get_next(struct udev_list_entry *entry) {
        struct udev_list_entry *next;

        assert_return(entry, NULL);
        assert_return(entry->list, NULL);

        if (hashmap_iterate(entry->list->entries, &entry->list->iterator, (void**) &next, NULL))
                return next;

        return NULL;
}

/**
 * udev_list_entry_get_by_name:
 * @list_entry: current entry
 * @name: name string to match
 *
 * Lookup an entry in the list with a certain name.
 *
 * Returns: udev_list_entry, #NULL if no matching entry is found.
 */
_public_ struct udev_list_entry *udev_list_entry_get_by_name(struct udev_list_entry *entry, const char *name) {
        assert_return(name, NULL);
        assert_return(entry, NULL);
        assert_return(entry->list, NULL);

        if (!entry->list->unique)
                return NULL;

        return hashmap_get(entry->list->entries, name);
}

/**
 * udev_list_entry_get_name:
 * @list_entry: current entry
 *
 * Get the name of a list entry.
 *
 * Returns: the name string of this entry.
 */
_public_ const char *udev_list_entry_get_name(struct udev_list_entry *entry) {
        assert_return(entry, NULL);

        return entry->name;
}

/**
 * udev_list_entry_get_value:
 * @list_entry: current entry
 *
 * Get the value of list entry.
 *
 * Returns: the value string of this entry.
 */
_public_ const char *udev_list_entry_get_value(struct udev_list_entry *entry) {
        assert_return(entry, NULL);

        return entry->value;
}

int udev_list_entry_get_num(struct udev_list_entry *entry) {
        assert_return(entry, -EINVAL);

        return entry->num;
}

int udev_list_entry_set_num(struct udev_list_entry *entry, int num) {
        assert_return(entry, -EINVAL);

        entry->num = num;

        return 0;
}
