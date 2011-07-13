/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2010 Kay Sievers <kay.sievers@vrfy.org>
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

#define UDEV_CTRL_SOCK_PATH			"@/org/kernel/udev/udevd"

struct udev_event {
	struct udev *udev;
	struct udev_device *dev;
	struct udev_device *dev_parent;
	struct udev_device *dev_db;
	char *name;
	char *tmp_node;
	char *program_result;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	struct udev_list_node run_list;
	int exec_delay;
	unsigned long long birth_usec;
	unsigned long long timeout_usec;
	int fd_signal;
	bool sigterm;
	bool inotify_watch;
	bool inotify_watch_final;
	bool group_final;
	bool owner_final;
	bool mode_set;
	bool mode_final;
	bool name_final;
	bool devlink_final;
	bool run_final;
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
int udev_rules_apply_to_event(struct udev_rules *rules, struct udev_event *event, const sigset_t *sigmask);
void udev_rules_apply_static_dev_perms(struct udev_rules *rules);

/* udev-event.c */
struct udev_event *udev_event_new(struct udev_device *dev);
void udev_event_unref(struct udev_event *event);
size_t udev_event_apply_format(struct udev_event *event, const char *src, char *dest, size_t size);
int udev_event_apply_subsys_kernel(struct udev_event *event, const char *string,
				   char *result, size_t maxsize, int read_value);
int udev_event_spawn(struct udev_event *event,
		     const char *cmd, char **envp, const sigset_t *sigmask,
		     char *result, size_t ressize);
int udev_event_execute_rules(struct udev_event *event, struct udev_rules *rules, const sigset_t *sigset);
int udev_event_execute_run(struct udev_event *event, const sigset_t *sigset);

/* udev-watch.c */
int udev_watch_init(struct udev *udev);
void udev_watch_restore(struct udev *udev);
void udev_watch_begin(struct udev *udev, struct udev_device *dev);
void udev_watch_end(struct udev *udev, struct udev_device *dev);
struct udev_device *udev_watch_lookup(struct udev *udev, int wd);

/* udev-node.c */
int udev_node_mknod(struct udev_device *dev, const char *file, mode_t mode, uid_t uid, gid_t gid);
int udev_node_add(struct udev_device *dev, mode_t mode, uid_t uid, gid_t gid);
int udev_node_remove(struct udev_device *dev);
void udev_node_update_old_links(struct udev_device *dev, struct udev_device *dev_old);

/* udev-ctrl.c */
struct udev_ctrl;
struct udev_ctrl *udev_ctrl_new_from_socket(struct udev *udev, const char *socket_path);
struct udev_ctrl *udev_ctrl_new_from_socket_fd(struct udev *udev, const char *socket_path, int fd);
int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl);
struct udev_ctrl *udev_ctrl_ref(struct udev_ctrl *uctrl);
struct udev_ctrl *udev_ctrl_unref(struct udev_ctrl *uctrl);
struct udev *udev_ctrl_get_udev(struct udev_ctrl *uctrl);
int udev_ctrl_get_fd(struct udev_ctrl *uctrl);
int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority, int timeout);
int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_reload_rules(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_ping(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_exit(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key, int timeout);
int udev_ctrl_send_set_children_max(struct udev_ctrl *uctrl, int count, int timeout);
struct udev_ctrl_connection;
struct udev_ctrl_connection *udev_ctrl_get_connection(struct udev_ctrl *uctrl);
struct udev_ctrl_connection *udev_ctrl_connection_ref(struct udev_ctrl_connection *conn);
struct udev_ctrl_connection *udev_ctrl_connection_unref(struct udev_ctrl_connection *conn);
struct udev_ctrl_msg;
struct udev_ctrl_msg *udev_ctrl_receive_msg(struct udev_ctrl_connection *conn);
struct udev_ctrl_msg *udev_ctrl_msg_ref(struct udev_ctrl_msg *ctrl_msg);
struct udev_ctrl_msg *udev_ctrl_msg_unref(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_set_log_level(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_stop_exec_queue(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_start_exec_queue(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_reload_rules(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_ping(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_exit(struct udev_ctrl_msg *ctrl_msg);
const char *udev_ctrl_get_set_env(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_set_children_max(struct udev_ctrl_msg *ctrl_msg);

/* udevadm commands */
struct udevadm_cmd {
	const char *name;
	int (*cmd)(struct udev *udev, int argc, char *argv[]);
	const char *help;
	int debug;
};
extern const struct udevadm_cmd udevadm_monitor;
extern const struct udevadm_cmd udevadm_info;
extern const struct udevadm_cmd udevadm_control;
extern const struct udevadm_cmd udevadm_trigger;
extern const struct udevadm_cmd udevadm_settle;
extern const struct udevadm_cmd udevadm_test;
#endif
