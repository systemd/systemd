/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2008 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef _UDEV_H_
#define _UDEV_H_

#include <sys/types.h>
#include <sys/param.h>
#include <signal.h>

#include "libudev.h"
#include "libudev-private.h"

#define DEFAULT_FAKE_PARTITIONS_COUNT		15
#define UDEV_EVENT_TIMEOUT			180

#define UDEV_CTRL_SOCK_PATH			"@/org/kernel/udev/udevd"

struct udev_event {
	struct udev *udev;
	struct udev_device *dev;
	struct udev_device *dev_parent;
	char *name;
	char *tmp_node;
	char *program_result;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	struct udev_list_node run_list;
	unsigned int group_final:1;
	unsigned int owner_final:1;
	unsigned int mode_final:1;
	unsigned int name_final:1;
	unsigned int devlink_final:1;
	unsigned int run_final:1;
	unsigned int ignore_device:1;
	unsigned int inotify_watch:1;
};

struct udev_watch {
	struct udev_list_node node;
	int handle;
	char *name;
};

/* udev-rules.c */
struct udev_rules;
struct udev_rules *udev_rules_new(struct udev *udev, int resolve_names);
void udev_rules_unref(struct udev_rules *rules);
int udev_rules_apply_to_event(struct udev_rules *rules, struct udev_event *event);

/* udev-event.c */
struct udev_event *udev_event_new(struct udev_device *dev);
void udev_event_unref(struct udev_event *event);
int udev_event_execute_rules(struct udev_event *event, struct udev_rules *rules);
int udev_event_execute_run(struct udev_event *event, const sigset_t *sigset);
size_t udev_event_apply_format(struct udev_event *event, const char *src, char *dest, size_t size);
int udev_event_apply_subsys_kernel(struct udev_event *event, const char *string,
				   char *result, size_t maxsize, int read_value);

/* udev-watch.c */
int udev_watch_init(struct udev *udev);
void udev_watch_restore(struct udev *udev);
void udev_watch_begin(struct udev *udev, struct udev_device *dev);
void udev_watch_end(struct udev *udev, struct udev_device *dev);
struct udev_device *udev_watch_lookup(struct udev *udev, int wd);

/* udev-node.c */
int udev_node_mknod(struct udev_device *dev, const char *file, dev_t devnum, mode_t mode, uid_t uid, gid_t gid);
int udev_node_add(struct udev_device *dev, mode_t mode, uid_t uid, gid_t gid);
int udev_node_remove(struct udev_device *dev);
void udev_node_update_old_links(struct udev_device *dev, struct udev_device *dev_old);

/* udevadm commands */
int udevadm_monitor(struct udev *udev, int argc, char *argv[]);
int udevadm_info(struct udev *udev, int argc, char *argv[]);
int udevadm_control(struct udev *udev, int argc, char *argv[]);
int udevadm_trigger(struct udev *udev, int argc, char *argv[]);
int udevadm_settle(struct udev *udev, int argc, char *argv[]);
int udevadm_test(struct udev *udev, int argc, char *argv[]);
#endif
