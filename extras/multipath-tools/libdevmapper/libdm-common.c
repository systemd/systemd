/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the LGPL.
 */

#include "libdm-targets.h"
#include "libdm-common.h"
#include "list.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <linux/dm-ioctl.h>
#include <linux/kdev_t.h>

#define DEV_DIR "/dev/"

static char _dm_dir[PATH_MAX] = DEV_DIR DM_DIR;

static int _verbose = 0;

/*
 * Library users can provide their own logging
 * function.
 */
static void _default_log(int level, const char *file, int line,
			 const char *f, ...)
{
	va_list ap;

	if (level > _LOG_WARN && !_verbose)
		return;

	va_start(ap, f);

	if (level < _LOG_WARN)
		vfprintf(stderr, f, ap);
	else
		vprintf(f, ap);

	va_end(ap);

	if (level < _LOG_WARN)
		fprintf(stderr, "\n");
	else
		fprintf(stdout, "\n");
}

dm_log_fn _log = _default_log;

void dm_log_init(dm_log_fn fn)
{
	_log = fn;
}

void dm_log_init_verbose(int level)
{
	_verbose = level;
}

static void _build_dev_path(char *buffer, size_t len, const char *dev_name)
{
	/* If there's a /, assume caller knows what they're doing */
	if (strchr(dev_name, '/'))
		snprintf(buffer, len, "%s", dev_name);
	else
		snprintf(buffer, len, "%s/%s", _dm_dir, dev_name);
}

int dm_get_library_version(char *version, size_t size)
{
	strncpy(version, DM_LIB_VERSION, size);
	return 1;
}

struct dm_task *dm_task_create(int type)
{
	struct dm_task *dmt = malloc(sizeof(*dmt));

	if (!dm_check_version())
		return NULL;

	if (!dmt) {
		log_error("dm_task_create: malloc(%d) failed", sizeof(*dmt));
		return NULL;
	}

	memset(dmt, 0, sizeof(*dmt));

	dmt->type = type;
	dmt->minor = -1;
	dmt->major = -1;

	return dmt;
}

int dm_task_set_name(struct dm_task *dmt, const char *name)
{
	char *pos;
	char path[PATH_MAX];
	struct stat st1, st2;

	if (dmt->dev_name) {
		free(dmt->dev_name);
		dmt->dev_name = NULL;
	}

	/* If path was supplied, remove it if it points to the same device
	 * as its last component.
	 */
	if ((pos = strrchr(name, '/'))) {
		snprintf(path, sizeof(path), "%s/%s", _dm_dir, pos + 1);

		if (stat(name, &st1) || stat(path, &st2) ||
		    !(st1.st_dev == st2.st_dev)) {
			log_error("dm_task_set_name: Device %s not found",
				  name);
			return 0;
		}

		name = pos + 1;
	}

	if (!(dmt->dev_name = strdup(name))) {
		log_error("dm_task_set_name: strdup(%s) failed", name);
		return 0;
	}

	return 1;
}

int dm_task_set_uuid(struct dm_task *dmt, const char *uuid)
{
	if (dmt->uuid) {
		free(dmt->uuid);
		dmt->uuid = NULL;
	}

	if (!(dmt->uuid = strdup(uuid))) {
		log_error("dm_task_set_uuid: strdup(%s) failed", uuid);
		return 0;
	}

	return 1;
}

int dm_task_set_major(struct dm_task *dmt, int major)
{
	dmt->major = major;
	log_debug("Setting major: %d", dmt->major);

	return 1;
}

int dm_task_set_minor(struct dm_task *dmt, int minor)
{
	dmt->minor = minor;
	log_debug("Setting minor: %d", dmt->minor);

	return 1;
}

int dm_task_add_target(struct dm_task *dmt, uint64_t start, uint64_t size,
		       const char *ttype, const char *params)
{
	struct target *t = create_target(start, size, ttype, params);

	if (!t)
		return 0;

	if (!dmt->head)
		dmt->head = dmt->tail = t;
	else {
		dmt->tail->next = t;
		dmt->tail = t;
	}

	return 1;
}

static int _add_dev_node(const char *dev_name, uint32_t major, uint32_t minor)
{
	char path[PATH_MAX];
	struct stat info;
	dev_t dev = MKDEV(major, minor);

	_build_dev_path(path, sizeof(path), dev_name);

	if (stat(path, &info) >= 0) {
		if (!S_ISBLK(info.st_mode)) {
			log_error("A non-block device file at '%s' "
				  "is already present", path);
			return 0;
		}

		if (info.st_rdev == dev)
			return 1;

		if (unlink(path) < 0) {
			log_error("Unable to unlink device node for '%s'",
				  dev_name);
			return 0;
		}
	}

	if (mknod(path, S_IFBLK | S_IRUSR | S_IWUSR | S_IRGRP, dev) < 0) {
		log_error("Unable to make device node for '%s'", dev_name);
		return 0;
	}

	return 1;
}

static int _rename_dev_node(const char *old_name, const char *new_name)
{
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	struct stat info;

	_build_dev_path(oldpath, sizeof(oldpath), old_name);
	_build_dev_path(newpath, sizeof(newpath), new_name);

	if (stat(newpath, &info) == 0) {
		if (!S_ISBLK(info.st_mode)) {
			log_error("A non-block device file at '%s' "
				  "is already present", newpath);
			return 0;
		}

		if (unlink(newpath) < 0) {
			if (errno == EPERM) {
				/* devfs, entry has already been renamed */
				return 1;
			}
			log_error("Unable to unlink device node for '%s'",
				  new_name);
			return 0;
		}
	}

	if (rename(oldpath, newpath) < 0) {
		log_error("Unable to rename device node from '%s' to '%s'",
			  old_name, new_name);
		return 0;
	}

	return 1;
}

static int _rm_dev_node(const char *dev_name)
{
	char path[PATH_MAX];
	struct stat info;

	_build_dev_path(path, sizeof(path), dev_name);

	if (stat(path, &info) < 0)
		return 1;

	if (unlink(path) < 0) {
		log_error("Unable to unlink device node for '%s'", dev_name);
		return 0;
	}

	return 1;
}

typedef enum {
	NODE_ADD,
	NODE_DEL,
	NODE_RENAME
} node_op_t;

static int _do_node_op(node_op_t type, const char *dev_name, uint32_t major,
		       uint32_t minor, const char *old_name)
{
	switch (type) {
	case NODE_ADD:
		return _add_dev_node(dev_name, major, minor);
	case NODE_DEL:
		return _rm_dev_node(dev_name);
	case NODE_RENAME:
		return _rename_dev_node(old_name, dev_name);
	}

	return 1;
}

static LIST_INIT(_node_ops);

struct node_op_parms {
	struct list list;
	node_op_t type;
	char *dev_name;
	uint32_t major;
	uint32_t minor;
	char *old_name;
	char names[0];
};

static void _store_str(char **pos, char **ptr, const char *str)
{
	strcpy(*pos, str);
	*ptr = *pos;
	*pos += strlen(*ptr) + 1;
}

static int _stack_node_op(node_op_t type, const char *dev_name, uint32_t major,
			  uint32_t minor, const char *old_name)
{
	struct node_op_parms *nop;
	size_t len = strlen(dev_name) + strlen(old_name) + 2;
	char *pos;

	if (!(nop = malloc(sizeof(*nop) + len))) {
		log_error("Insufficient memory to stack mknod operation");
		return 0;
	}

	pos = nop->names;
	nop->type = type;
	nop->major = major;
	nop->minor = minor;

	_store_str(&pos, &nop->dev_name, dev_name);
	_store_str(&pos, &nop->old_name, old_name);

	list_add(&_node_ops, &nop->list);

	return 1;
}

static void _pop_node_ops(void)
{
	struct list *noph, *nopht;
	struct node_op_parms *nop;

	list_iterate_safe(noph, nopht, &_node_ops) {
		nop = list_item(noph, struct node_op_parms);
		_do_node_op(nop->type, nop->dev_name, nop->major, nop->minor,
			    nop->old_name);
		list_del(&nop->list);
		free(nop);
	}
}

int add_dev_node(const char *dev_name, uint32_t major, uint32_t minor)
{
	return _stack_node_op(NODE_ADD, dev_name, major, minor, "");
}

int rename_dev_node(const char *old_name, const char *new_name)
{
	return _stack_node_op(NODE_RENAME, new_name, 0, 0, old_name);
}

int rm_dev_node(const char *dev_name)
{
	return _stack_node_op(NODE_DEL, dev_name, 0, 0, "");
}

void update_devs(void)
{
	_pop_node_ops();
}

int dm_set_dev_dir(const char *dir)
{
	snprintf(_dm_dir, sizeof(_dm_dir), "%s%s", dir, DM_DIR);
	return 1;
}

const char *dm_dir(void)
{
	return _dm_dir;
}
