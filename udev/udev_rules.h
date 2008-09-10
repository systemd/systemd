/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef UDEV_RULES_H
#define UDEV_RULES_H

#include "udev.h"

#define PAIRS_MAX		5

enum key_operation {
	KEY_OP_UNSET,
	KEY_OP_MATCH,
	KEY_OP_NOMATCH,
	KEY_OP_ADD,
	KEY_OP_ASSIGN,
	KEY_OP_ASSIGN_FINAL,
};

struct key {
	enum key_operation operation;
	size_t val_off;
};

struct key_pair {
	struct key key;
	size_t key_name_off;
};

struct key_pairs {
	int count;
	struct key_pair keys[PAIRS_MAX];
};

enum import_type {
	IMPORT_UNSET,
	IMPORT_PROGRAM,
	IMPORT_FILE,
	IMPORT_PARENT,
};

enum escape_type {
	ESCAPE_UNSET,
	ESCAPE_NONE,
	ESCAPE_REPLACE,
};

struct udev_rule {
	struct key action;
	struct key devpath;
	struct key kernel;
	struct key subsystem;
	struct key driver;
	struct key_pairs attr;

	struct key kernels;
	struct key subsystems;
	struct key drivers;
	struct key_pairs attrs;

	struct key_pairs env;
	struct key program;
	struct key result;
	struct key import;
	enum import_type import_type;
	struct key test;
	mode_t test_mode_mask;
	struct key run;
	struct key wait_for;
	struct key label;
	struct key goto_label;

	struct key name;
	struct key symlink;
	struct key symlink_match;
	struct key owner;
	struct key group;
	struct key mode;
	enum escape_type string_escape;

	unsigned int link_priority;
	int event_timeout;
	unsigned int partitions;
	unsigned int last_rule:1,
		     run_ignore_error:1,
		     ignore_device:1,
		     ignore_remove:1;

	size_t bufsize;
	char buf[];
};

struct udev_rules {
	struct udev *udev;
	char *buf;
	size_t bufsize;
	int resolve_names;
};

struct udev_rules_iter {
	struct udev_rules *rules;
	size_t current;
};

extern int udev_rules_init(struct udev *udev, struct udev_rules *rules, int resolve_names);
extern void udev_rules_cleanup(struct udev_rules *rules);

extern void udev_rules_iter_init(struct udev_rules_iter *iter, struct udev_rules *rules);
extern struct udev_rule *udev_rules_iter_next(struct udev_rules_iter *iter);
extern struct udev_rule *udev_rules_iter_label(struct udev_rules_iter *iter, const char *label);

extern int udev_rules_get_name(struct udev_rules *rules, struct udevice *udev);
extern int udev_rules_get_run(struct udev_rules *rules, struct udevice *udev);
extern int udev_rules_run(struct udevice *udev);

extern void udev_rules_apply_format(struct udevice *udev, char *string, size_t maxsize);

#endif
