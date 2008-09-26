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

struct udev_list {
	struct udev *udev;
	struct list_node node;
	struct list_node *list;
	char *name;
	char *value;
};

static struct udev_list *node_to_entry(struct list_node *node)
{
	char *list;

	list = (char *)node;
	list -= offsetof(struct udev_list, node);
	return (struct udev_list *)list;
}

void list_init(struct list_node *list)
{
	list->next = list;
	list->prev = list;
}

static int list_empty(struct list_node *list)
{
	return list->next == list;
}

#if 0
static void list_add(struct list_node *new, struct list_node *list)
{
	struct list_node *next = list->next;

	next->prev = new;
	new->next = next;
	new->prev = list;
	list->next = new;
}
#endif

static void list_add_to_end(struct list_node *new, struct list_node *list)
{
	struct list_node *prev = list->prev;

	list->prev = new;
	new->next = list;
	new->prev = prev;
	prev->next = new;
}

static void list_del(struct list_node *entry)
{
	struct list_node *prev = entry->prev;
	struct list_node *next = entry->next;

	next->prev = prev;
	prev->next = next;
}

#define list_for_each_entry(pos, list) \
	for (pos = node_to_entry((list)->next); \
	     &pos->node != (list); \
	     pos = node_to_entry(pos->node.next))

#define list_for_each_entry_safe(pos, tmp, list) \
	for (pos = node_to_entry((list)->next), \
	     tmp = node_to_entry(pos->node.next); \
	     &pos->node != (list); \
	     pos = tmp, tmp = node_to_entry(tmp->node.next))

struct udev_list *list_insert_entry(struct udev *udev, struct list_node *list,
				    const char *name, const char *value, int sort)
{
	struct udev_list *list_loop;
	struct udev_list *list_new;

	/* avoid duplicate entries */
	list_for_each_entry(list_loop, list) {
		if (strcmp(list_loop->name, name) == 0) {
			dbg(udev, "'%s' is already in the list\n", name);
			return list_loop;
		}
	}

	if (sort) {
		list_for_each_entry(list_loop, list) {
			if (strcmp(list_loop->name, name) > 0)
				break;
		}
	}

	list_new = malloc(sizeof(struct udev_list));
	if (list_new == NULL)
		return NULL;
	memset(list_new, 0x00, sizeof(struct udev_list));
	list_new->udev = udev;
	list_new->list = list;
	list_new->name = strdup(name);
	if (list_new->name == NULL) {
		free(list_new);
		return NULL;
	}
	if (value != NULL) {
		list_new->value = strdup(value);
		if (list_new->value == NULL) {
			free(list_new);
			return NULL;
		}
	}
	dbg(udev, "adding '%s=%s'\n", list_new->name, list_new->value);
	list_add_to_end(&list_new->node, &list_loop->node);
	return list_new;
}

void list_move_entry_to_end(struct udev_list *list_entry, struct list_node *list)
{
	list_del(&list_entry->node);
	list_add_to_end(&list_entry->node, list);
}

void list_cleanup(struct udev *udev, struct list_node *list)
{
	struct udev_list *list_loop;
	struct udev_list *list_tmp;

	list_for_each_entry_safe(list_loop, list_tmp, list) {
		list_del(&list_loop->node);
		free(list_loop->name);
		free(list_loop->value);
		free(list_loop);
	}
}

struct udev_list *list_get_entry(struct list_node *list)
{
	if (list_empty(list))
		return NULL;
	return node_to_entry(list->next);
}

struct udev_list *udev_list_entry_get_next(struct udev_list *list_entry)
{
	struct list_node *next;

	next = list_entry->node.next;
	/* empty list or no more emtries */
	if (next == list_entry->list)
		return NULL;
	return node_to_entry(next);
}

const char *udev_list_entry_get_name(struct udev_list *list_entry)
{
	if (list_entry == NULL)
		return NULL;
	return list_entry->name;
}

const char *udev_list_entry_get_value(struct udev_list *list_entry)
{
	if (list_entry == NULL)
		return NULL;
	return list_entry->value;
}
