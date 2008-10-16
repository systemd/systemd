/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "libudev.h"
#include "libudev-private.h"

struct udev_list_entry {
	struct udev *udev;
	struct udev_list_node node;
	struct udev_list_node *list;
	char *name;
	char *value;
	int flag;
};

/* list head point to itself if empty */
void udev_list_init(struct udev_list_node *list)
{
	list->next = list;
	list->prev = list;
}

static int list_is_empty(struct udev_list_node *list)
{
	return list->next == list;
}

static void list_node_insert_between(struct udev_list_node *new,
				     struct udev_list_node *prev,
				     struct udev_list_node *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static void list_node_remove(struct udev_list_node *entry)
{
	struct udev_list_node *prev = entry->prev;
	struct udev_list_node *next = entry->next;

	next->prev = prev;
	prev->next = next;

	entry->prev = NULL;
	entry->next = NULL;
}

/* return list entry which embeds this node */
static struct udev_list_entry *list_node_to_entry(struct udev_list_node *node)
{
	char *list;

	list = (char *)node;
	list -= offsetof(struct udev_list_entry, node);
	return (struct udev_list_entry *)list;
}

/* insert entry into a list as the last element  */
static void list_entry_append(struct udev_list_entry *new, struct udev_list_node *list)
{
	/* inserting before the list head make the node the last node in the list */
	list_node_insert_between(&new->node, list->prev, list);
	new->list = list;
}

/* insert entry into a list, before a given existing entry */
static void list_entry_insert_before(struct udev_list_entry *new, struct udev_list_entry *entry)
{
	list_node_insert_between(&new->node, entry->node.prev, &entry->node);
	new->list = entry->list;
}

struct udev_list_entry *udev_list_entry_add(struct udev *udev, struct udev_list_node *list,
					    const char *name, const char *value,
					    int unique, int sort)
{
	struct udev_list_entry *entry_loop = NULL;
	struct udev_list_entry *entry_new;

	if (unique)
		udev_list_entry_foreach(entry_loop, udev_list_get_entry(list)) {
			if (strcmp(entry_loop->name, name) == 0) {
				info(udev, "'%s' is already in the list\n", name);
				free(entry_loop->value);
				if (value == NULL) {
					entry_loop->value = NULL;
					info(udev, "'%s' value unset\n", name);
					return entry_loop;
				}
				entry_loop->value = strdup(value);
				if (entry_loop->value == NULL)
					return NULL;
				info(udev, "'%s' value replaced with '%s'\n", name, value);
				return entry_loop;
			}
		}

	if (sort)
		udev_list_entry_foreach(entry_loop, udev_list_get_entry(list)) {
			if (strcmp(entry_loop->name, name) > 0)
				break;
		}

	entry_new = malloc(sizeof(struct udev_list_entry));
	if (entry_new == NULL)
		return NULL;
	memset(entry_new, 0x00, sizeof(struct udev_list_entry));
	entry_new->udev = udev;
	entry_new->name = strdup(name);
	if (entry_new->name == NULL) {
		free(entry_new);
		return NULL;
	}
	if (value != NULL) {
		entry_new->value = strdup(value);
		if (entry_new->value == NULL) {
			free(entry_new->name);
			free(entry_new);
			return NULL;
		}
	}
	if (entry_loop != NULL)
		list_entry_insert_before(entry_new, entry_loop);
	else
		list_entry_append(entry_new, list);
	info(udev, "'%s=%s' added\n", entry_new->name, entry_new->value);
	return entry_new;
}

void udev_list_entry_remove(struct udev_list_entry *entry)
{
	list_node_remove(&entry->node);
	free(entry->name);
	free(entry->value);
	free(entry);
}

void udev_list_cleanup(struct udev *udev, struct udev_list_node *list)
{
	struct udev_list_entry *entry_loop;
	struct udev_list_entry *entry_tmp;

	list_entry_foreach_safe(entry_loop, entry_tmp, udev_list_get_entry(list))
		udev_list_entry_remove(entry_loop);
}

void udev_list_entry_move_to_end(struct udev_list_entry *list_entry)
{
	list_node_remove(&list_entry->node);
	list_node_insert_between(&list_entry->node, list_entry->list->prev, list_entry->list);
}

struct udev_list_entry *udev_list_get_entry(struct udev_list_node *list)
{
	if (list_is_empty(list))
		return NULL;
	return list_node_to_entry(list->next);
}

struct udev_list_entry *udev_list_entry_get_next(struct udev_list_entry *list_entry)
{
	struct udev_list_node *next;

	if (list_entry == NULL)
		return NULL;
	next = list_entry->node.next;
	/* empty list or no more entries */
	if (next == list_entry->list)
		return NULL;
	return list_node_to_entry(next);
}

struct udev_list_entry *udev_list_entry_get_by_name(struct udev_list_entry *list_entry, const char *name)
{
	struct udev_list_entry *entry;

	udev_list_entry_foreach(entry, list_entry) {
		if (strcmp(udev_list_entry_get_name(entry), name) == 0) {
			dbg(entry->udev, "found '%s=%s'\n", entry->name, entry->value);
			return entry;
		}
	}
	return NULL;
}

const char *udev_list_entry_get_name(struct udev_list_entry *list_entry)
{
	if (list_entry == NULL)
		return NULL;
	return list_entry->name;
}

const char *udev_list_entry_get_value(struct udev_list_entry *list_entry)
{
	if (list_entry == NULL)
		return NULL;
	return list_entry->value;
}

extern int udev_list_entry_get_flag(struct udev_list_entry *list_entry)
{
	if (list_entry == NULL)
		return -EINVAL;
	return list_entry->flag;
}

extern void udev_list_entry_set_flag(struct udev_list_entry *list_entry, int flag)
{
	if (list_entry == NULL)
		return;
	list_entry->flag = flag;
}
