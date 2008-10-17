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

#include "udev-sysdeps.h"
#include "lib/libudev.h"
#include "lib/libudev-private.h"

#define ALLOWED_CHARS				"#+-.:=@_"
#define ALLOWED_CHARS_FILE			ALLOWED_CHARS "/"
#define ALLOWED_CHARS_INPUT			ALLOWED_CHARS_FILE " $%?,"

#define DEFAULT_PARTITIONS_COUNT		15
#define UDEV_EVENT_TIMEOUT			180

/* linux/include/linux/kobject.h */
#define UEVENT_BUFFER_SIZE			2048
#define UEVENT_NUM_ENVP				32

#define UDEV_CTRL_SOCK_PATH			"@" UDEV_PREFIX "/org/kernel/udev/udevd"

#define UDEV_MAX(a,b) ((a) > (b) ? (a) : (b))

/* pipes */
#define READ_END				0
#define WRITE_END				1

struct udev_rules;

static inline void logging_init(const char *program_name)
{
	openlog(program_name, LOG_PID | LOG_CONS, LOG_DAEMON);
}

static inline void logging_msg(struct udev *udev, int priority,
			  const char *file, int line, const char *fn,
			  const char *format, va_list args)
{
	vsyslog(priority, format, args);
}

static inline void logging_close(void)
{
	closelog();
}

/* udev-event.c */
struct udev_event {
	struct udev *udev;
	struct udev_device *dev;
	struct udev_device *dev_parent;
	int devlink_final;
	int owner_final;
	int group_final;
	int mode_final;
	char tmp_node[UTIL_PATH_SIZE];
	char program_result[UTIL_PATH_SIZE];
	int run_final;

	char name[UTIL_PATH_SIZE];
	mode_t mode;
	char owner[UTIL_NAME_SIZE];
	char group[UTIL_NAME_SIZE];
	struct udev_list_node run_list;
	int ignore_device;
	int test;

	struct udev_list_node node;
	pid_t pid;
	int exitstatus;
	time_t queue_time;
};
extern struct udev_event *udev_event_new(struct udev_device *dev);
extern void udev_event_unref(struct udev_event *event);
extern int udev_event_run(struct udev_event *event, struct udev_rules *rules);

/* udev-node.c */
extern int udev_node_mknod(struct udev_device *dev, const char *file, dev_t devnum, mode_t mode, uid_t uid, gid_t gid);
extern int udev_node_add(struct udev_device *dev, mode_t mode, const char *owner, const char *group, int test);
extern int udev_node_remove(struct udev_device *dev, int test);
extern void udev_node_update_old_links(struct udev_device *dev, struct udev_device *dev_old, int test);

/* udev-util.c */
extern int create_path(struct udev *udev, const char *path);
extern int delete_path(struct udev *udev, const char *path);
extern int unlink_secure(struct udev *udev, const char *filename);
extern uid_t lookup_user(struct udev *udev, const char *user);
extern gid_t lookup_group(struct udev *udev, const char *group);

/* udev_utils_file.c */
extern int file_map(const char *filename, char **buf, size_t *bufsize);
extern void file_unmap(void *buf, size_t bufsize);
extern size_t buf_get_line(const char *buf, size_t buflen, size_t cur);

/* udev-selinux.c */
#ifndef USE_SELINUX
static inline void selinux_init(struct udev *udev) {}
static inline void selinux_exit(struct udev *udev) {}
static inline void udev_selinux_lsetfilecon(struct udev *udev, const char *file, unsigned int mode) {}
static inline void udev_selinux_setfscreatecon(struct udev *udev, const char *file, unsigned int mode) {}
static inline void udev_selinux_resetfscreatecon(struct udev *udev) {}
#else
extern void selinux_init(struct udev *udev);
extern void selinux_exit(struct udev *udev);
extern void udev_selinux_lsetfilecon(struct udev *udev, const char *file, unsigned int mode);
extern void udev_selinux_setfscreatecon(struct udev *udev, const char *file, unsigned int mode);
extern void udev_selinux_resetfscreatecon(struct udev *udev);
#endif

/* udevadm commands */
extern int udevadm_monitor(struct udev *udev, int argc, char *argv[]);
extern int udevadm_info(struct udev *udev, int argc, char *argv[]);
extern int udevadm_control(struct udev *udev, int argc, char *argv[]);
extern int udevadm_trigger(struct udev *udev, int argc, char *argv[]);
extern int udevadm_settle(struct udev *udev, int argc, char *argv[]);
extern int udevadm_test(struct udev *udev, int argc, char *argv[]);
#endif
