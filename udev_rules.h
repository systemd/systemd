/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef UDEV_RULES_H
#define UDEV_RULES_H

#include "udev.h"
#include "list.h"

#define PAIRS_MAX		5
#define RULESFILE_SUFFIX	".rules"

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
	struct key run;
	struct key wait_for_sysfs;
	struct key label;
	struct key goto_label;

	struct key name;
	struct key symlink;
	struct key owner;
	struct key group;
	mode_t mode;
	enum key_operation mode_operation;

	unsigned int partitions;
	unsigned int last_rule:1,
		     ignore_device:1,
		     ignore_remove:1;

	size_t bufsize;
	char buf[];
};

struct udev_rules {
	char *buf;
	size_t bufsize;
	size_t current;
	int resolve_names;
};

extern int udev_rules_init(struct udev_rules *rules, int resolve_names);
extern void udev_rules_cleanup(struct udev_rules *rules);

extern void udev_rules_iter_init(struct udev_rules *rules);
extern struct udev_rule *udev_rules_iter_next(struct udev_rules *rules);
extern struct udev_rule *udev_rules_iter_label(struct udev_rules *rules, const char *label);

extern int udev_rules_get_name(struct udev_rules *rules, struct udevice *udev);
extern int udev_rules_get_run(struct udev_rules *rules, struct udevice *udev);

extern void udev_rules_apply_format(struct udevice *udev, char *string, size_t maxsize);

#endif
