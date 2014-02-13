/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "libudev.h"
#include "libudev-private.h"

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
        struct udev_list_node node;
        struct udev_list *list;
        char *name;
        char *value;
        int num;
};

/* the list's head points to itself if empty */
void udev_list_node_init(struct udev_list_node *list)
{
        list->next = list;
        list->prev = list;
}

int udev_list_node_is_empty(struct udev_list_node *list)
{
        return list->next == list;
}

static void udev_list_node_insert_between(struct udev_list_node *new,
                                          struct udev_list_node *prev,
                                          struct udev_list_node *next)
{
        next->prev = new;
        new->next = next;
        new->prev = prev;
        prev->next = new;
}

void udev_list_node_append(struct udev_list_node *new, struct udev_list_node *list)
{
        udev_list_node_insert_between(new, list->prev, list);
}

void udev_list_node_remove(struct udev_list_node *entry)
{
        struct udev_list_node *prev = entry->prev;
        struct udev_list_node *next = entry->next;

        next->prev = prev;
        prev->next = next;

        entry->prev = NULL;
        entry->next = NULL;
}

/* return list entry which embeds this node */
static inline struct udev_list_entry *list_node_to_entry(struct udev_list_node *node)
{
        return container_of(node, struct udev_list_entry, node);
}

void udev_list_init(struct udev *udev, struct udev_list *list, bool unique)
{
        memzero(list, sizeof(struct udev_list));
        list->udev = udev;
        list->unique = unique;
        udev_list_node_init(&list->node);
}

/* insert entry into a list as the last element  */
static void udev_list_entry_append(struct udev_list_entry *new, struct udev_list *list)
{
        /* inserting before the list head make the node the last node in the list */
        udev_list_node_insert_between(&new->node, list->node.prev, &list->node);
        new->list = list;
}

/* insert entry into a list, before a given existing entry */
static void udev_list_entry_insert_before(struct udev_list_entry *new, struct udev_list_entry *entry)
{
        udev_list_node_insert_between(&new->node, entry->node.prev, &entry->node);
        new->list = entry->list;
}

/* binary search in sorted array */
static int list_search(struct udev_list *list, const char *name)
{
        unsigned int first, last;

        first = 0;
        last = list->entries_cur;
        while (first < last) {
                unsigned int i;
                int cmp;

                i = (first + last)/2;
                cmp = strcmp(name, list->entries[i]->name);
                if (cmp < 0)
                        last = i;
                else if (cmp > 0)
                        first = i+1;
                else
                        return i;
        }

        /* not found, return negative insertion-index+1 */
        return -(first+1);
}

struct udev_list_entry *udev_list_entry_add(struct udev_list *list, const char *name, const char *value)
{
        struct udev_list_entry *entry;
        int i = 0;

        if (list->unique) {
                /* lookup existing name or insertion-index */
                i = list_search(list, name);
                if (i >= 0) {
                        entry = list->entries[i];

                        free(entry->value);
                        if (value == NULL) {
                                entry->value = NULL;
                                return entry;
                        }
                        entry->value = strdup(value);
                        if (entry->value == NULL)
                                return NULL;
                        return entry;
                }
        }

        /* add new name */
        entry = new0(struct udev_list_entry, 1);
        if (entry == NULL)
                return NULL;
        entry->name = strdup(name);
        if (entry->name == NULL) {
                free(entry);
                return NULL;
        }
        if (value != NULL) {
                entry->value = strdup(value);
                if (entry->value == NULL) {
                        free(entry->name);
                        free(entry);
                        return NULL;
                }
        }

        if (list->unique) {
                /* allocate or enlarge sorted array if needed */
                if (list->entries_cur >= list->entries_max) {
                        struct udev_list_entry **entries;
                        unsigned int add;

                        add = list->entries_max;
                        if (add < 1)
                                add = 64;
                        entries = realloc(list->entries, (list->entries_max + add) * sizeof(struct udev_list_entry *));
                        if (entries == NULL) {
                                free(entry->name);
                                free(entry->value);
                                free(entry);
                                return NULL;
                        }
                        list->entries = entries;
                        list->entries_max += add;
                }

                /* the negative i returned the insertion index */
                i = (-i)-1;

                /* insert into sorted list */
                if ((unsigned int)i < list->entries_cur)
                        udev_list_entry_insert_before(entry, list->entries[i]);
                else
                        udev_list_entry_append(entry, list);

                /* insert into sorted array */
                memmove(&list->entries[i+1], &list->entries[i],
                        (list->entries_cur - i) * sizeof(struct udev_list_entry *));
                list->entries[i] = entry;
                list->entries_cur++;
        } else {
                udev_list_entry_append(entry, list);
        }

        return entry;
}

void udev_list_entry_delete(struct udev_list_entry *entry)
{
        if (entry->list->entries != NULL) {
                int i;
                struct udev_list *list = entry->list;

                /* remove entry from sorted array */
                i = list_search(list, entry->name);
                if (i >= 0) {
                        memmove(&list->entries[i], &list->entries[i+1],
                                ((list->entries_cur-1) - i) * sizeof(struct udev_list_entry *));
                        list->entries_cur--;
                }
        }

        udev_list_node_remove(&entry->node);
        free(entry->name);
        free(entry->value);
        free(entry);
}

void udev_list_cleanup(struct udev_list *list)
{
        struct udev_list_entry *entry_loop;
        struct udev_list_entry *entry_tmp;

        free(list->entries);
        list->entries = NULL;
        list->entries_cur = 0;
        list->entries_max = 0;
        udev_list_entry_foreach_safe(entry_loop, entry_tmp, udev_list_get_entry(list))
                udev_list_entry_delete(entry_loop);
}

struct udev_list_entry *udev_list_get_entry(struct udev_list *list)
{
        if (udev_list_node_is_empty(&list->node))
                return NULL;
        return list_node_to_entry(list->node.next);
}

/**
 * udev_list_entry_get_next:
 * @list_entry: current entry
 *
 * Get the next entry from the list.
 *
 * Returns: udev_list_entry, #NULL if no more entries are available.
 */
_public_ struct udev_list_entry *udev_list_entry_get_next(struct udev_list_entry *list_entry)
{
        struct udev_list_node *next;

        if (list_entry == NULL)
                return NULL;
        next = list_entry->node.next;
        /* empty list or no more entries */
        if (next == &list_entry->list->node)
                return NULL;
        return list_node_to_entry(next);
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
_public_ struct udev_list_entry *udev_list_entry_get_by_name(struct udev_list_entry *list_entry, const char *name)
{
        int i;

        if (list_entry == NULL)
                return NULL;

        if (!list_entry->list->unique)
                return NULL;

        i = list_search(list_entry->list, name);
        if (i < 0)
                return NULL;
        return list_entry->list->entries[i];
}

/**
 * udev_list_entry_get_name:
 * @list_entry: current entry
 *
 * Get the name of a list entry.
 *
 * Returns: the name string of this entry.
 */
_public_ const char *udev_list_entry_get_name(struct udev_list_entry *list_entry)
{
        if (list_entry == NULL)
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
_public_ const char *udev_list_entry_get_value(struct udev_list_entry *list_entry)
{
        if (list_entry == NULL)
                return NULL;
        return list_entry->value;
}

int udev_list_entry_get_num(struct udev_list_entry *list_entry)
{
        if (list_entry == NULL)
                return -EINVAL;
        return list_entry->num;
}

void udev_list_entry_set_num(struct udev_list_entry *list_entry, int num)
{
        if (list_entry == NULL)
                return;
        list_entry->num = num;
}
