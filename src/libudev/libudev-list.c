/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "libudev-list-internal.h"
#include "list.h"
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
 * contains a name, and optionally a value.
 */
struct udev_list_entry {
        struct udev_list *list;
        char *name;
        char *value;

        LIST_FIELDS(struct udev_list_entry, entries);
};

struct udev_list {
        Hashmap *unique_entries;
        LIST_HEAD(struct udev_list_entry, entries);
        bool unique:1;
        bool uptodate:1;
};

static struct udev_list_entry* udev_list_entry_free(struct udev_list_entry *entry) {
        if (!entry)
                return NULL;

        if (entry->list) {
                if (entry->list->unique && entry->name)
                        hashmap_remove(entry->list->unique_entries, entry->name);

                if (!entry->list->unique || entry->list->uptodate)
                        LIST_REMOVE(entries, entry->list->entries, entry);
        }

        free(entry->name);
        free(entry->value);

        return mfree(entry);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_list_entry*, udev_list_entry_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                udev_list_entry_hash_ops,
                char, string_hash_func, string_compare_func,
                struct udev_list_entry, udev_list_entry_free);

struct udev_list* udev_list_new(bool unique) {
        struct udev_list *list;

        list = new(struct udev_list, 1);
        if (!list)
                return NULL;

        *list = (struct udev_list) {
                .unique = unique,
        };

        return list;
}

struct udev_list_entry* udev_list_entry_add(struct udev_list *list, const char *name, const char *value) {
        _cleanup_(udev_list_entry_freep) struct udev_list_entry *entry = NULL;

        assert(list);
        assert(name);

        entry = new0(struct udev_list_entry, 1);
        if (!entry)
                return NULL;

        if (strdup_to(&entry->name, name) < 0)
                return NULL;

        if (strdup_to(&entry->value, value) < 0)
                return NULL;

        if (list->unique) {
                udev_list_entry_free(hashmap_get(list->unique_entries, entry->name));

                if (hashmap_ensure_put(&list->unique_entries, &udev_list_entry_hash_ops, entry->name, entry) < 0)
                        return NULL;

                list->uptodate = false;
        } else
                LIST_APPEND(entries, list->entries, entry);

        entry->list = list;

        return TAKE_PTR(entry);
}

void udev_list_cleanup(struct udev_list *list) {
        if (!list)
                return;

        if (list->unique) {
                list->uptodate = false;
                hashmap_clear(list->unique_entries);
        } else
                LIST_FOREACH(entries, i, list->entries)
                        udev_list_entry_free(i);
}

struct udev_list* udev_list_free(struct udev_list *list) {
        if (!list)
                return NULL;

        udev_list_cleanup(list);
        hashmap_free(list->unique_entries);

        return mfree(list);
}

struct udev_list_entry* udev_list_get_entry(struct udev_list *list) {
        if (!list)
                return NULL;

        if (list->unique && !list->uptodate) {
                size_t n;

                LIST_HEAD_INIT(list->entries);

                n = hashmap_size(list->unique_entries);
                if (n == 0)
                        ;
                else if (n == 1)
                        LIST_PREPEND(entries, list->entries, hashmap_first(list->unique_entries));
                else {
                        _cleanup_free_ struct udev_list_entry **buf = NULL;

                        if (hashmap_dump_sorted(list->unique_entries, (void***) &buf, /* ret_n = */ NULL) < 0)
                                return NULL;

                        for (size_t j = n; j > 0; j--)
                                LIST_PREPEND(entries, list->entries, buf[j-1]);
                }

                list->uptodate = true;
        }

        return list->entries;
}

/**
 * udev_list_entry_get_next:
 * @list_entry: current entry
 *
 * Get the next entry from the list.
 *
 * Returns: udev_list_entry, #NULL if no more entries are available.
 */
_public_ struct udev_list_entry* udev_list_entry_get_next(struct udev_list_entry *list_entry) {
        if (!list_entry)
                return NULL;
        if (list_entry->list->unique && !list_entry->list->uptodate)
                return NULL;
        return list_entry->entries_next;
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
_public_ struct udev_list_entry* udev_list_entry_get_by_name(struct udev_list_entry *list_entry, const char *name) {
        if (!list_entry)
                return NULL;
        if (!list_entry->list->unique || !list_entry->list->uptodate)
                return NULL;
        return hashmap_get(list_entry->list->unique_entries, name);
}

/**
 * udev_list_entry_get_name:
 * @list_entry: current entry
 *
 * Get the name of a list entry.
 *
 * Returns: the name string of this entry.
 */
_public_ const char* udev_list_entry_get_name(struct udev_list_entry *list_entry) {
        if (!list_entry)
                return NULL;
        return list_entry->name;
}

/**
 * udev_list_entry_get_value:
 * @list_entry: current entry
 *
 * Get the value of list entry.
 *
 * Returns: the value string of this entry.
 */
_public_ const char* udev_list_entry_get_value(struct udev_list_entry *list_entry) {
        if (!list_entry)
                return NULL;
        return list_entry->value;
}
