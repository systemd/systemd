/*
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2003-2006 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef _UDEV_H_
#define _UDEV_H_

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>

#include "list.h"
#include "udev_sysdeps.h"
#define LIBUDEV_I_KNOW_THE_API_IS_SUBJECT_TO_CHANGE 1
#include "lib/libudev.h"
#include "lib/libudev-private.h"

#define COMMENT_CHARACTER			'#'
#define LINE_SIZE				512
#define PATH_SIZE				512
#define NAME_SIZE				256
#define VALUE_SIZE				128

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

struct sysfs_device {
	struct list_head node;			/* for device cache */
	struct sysfs_device *parent;		/* already cached parent*/
	char devpath[PATH_SIZE];
	char subsystem[NAME_SIZE];		/* $class, $bus, drivers, module */
	char kernel[NAME_SIZE];			/* device instance name */
	char kernel_number[NAME_SIZE];
	char driver[NAME_SIZE];			/* device driver name */
};

struct udevice {
	struct udev *udev;

	/* device event */
	struct sysfs_device *dev;		/* points to dev_local by default */
	struct sysfs_device dev_local;
	struct sysfs_device *dev_parent;	/* current parent device used for matching */
	char action[NAME_SIZE];
	char *devpath_old;

	/* node */
	char name[PATH_SIZE];
	struct list_head symlink_list;
	int symlink_final;
	char owner[NAME_SIZE];
	int owner_final;
	char group[NAME_SIZE];
	int group_final;
	mode_t mode;
	int mode_final;
	dev_t devt;

	/* event processing */
	struct list_head run_list;
	int run_final;
	struct list_head env_list;
	char tmp_node[PATH_SIZE];
	int partitions;
	int ignore_device;
	int ignore_remove;
	char program_result[PATH_SIZE];
	int link_priority;
	int event_timeout;
	int test_run;
};

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

/* udev_device.c */
extern struct udevice *udev_device_init(struct udev *udev);
extern void udev_device_cleanup(struct udevice *udevice);
extern dev_t udev_device_get_devt(struct udevice *udevice);

/* udev_device_event.c */
extern int udev_device_event(struct udev_rules *rules, struct udevice *udevice);

/* udev_sysfs.c */
extern int sysfs_init(void);
extern void sysfs_cleanup(void);
extern void sysfs_device_set_values(struct udev *udev,
				    struct sysfs_device *dev, const char *devpath,
				    const char *subsystem, const char *driver);
extern struct sysfs_device *sysfs_device_get(struct udev *udev, const char *devpath);
extern struct sysfs_device *sysfs_device_get_parent(struct udev *udev, struct sysfs_device *dev);
extern struct sysfs_device *sysfs_device_get_parent_with_subsystem(struct udev *udev, struct sysfs_device *dev, const char *subsystem);
extern char *sysfs_attr_get_value(struct udev *udev, const char *devpath, const char *attr_name);
extern int sysfs_resolve_link(struct udev *udev, char *path, size_t size);
extern int sysfs_lookup_devpath_by_subsys_id(struct udev *udev, char *devpath, size_t len, const char *subsystem, const char *id);

/* udev_node.c */
extern int udev_node_mknod(struct udevice *udevice, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid);
extern void udev_node_update_symlinks(struct udevice *udevice, struct udevice *udev_old);
extern int udev_node_add(struct udevice *udevice);
extern int udev_node_remove(struct udevice *udevice);

/* udev_db.c */
extern int udev_db_add_device(struct udevice *udevice);
extern int udev_db_delete_device(struct udevice *udevice);
extern int udev_db_rename(struct udev *udev, const char *devpath_old, const char *devpath);
extern int udev_db_get_device(struct udevice *udevice, const char *devpath);
extern int udev_db_get_devices_by_name(struct udev *udev, const char *name, struct list_head *name_list);
extern int udev_db_get_all_entries(struct udev *udevconst, struct list_head *name_list);

/* udev_utils.c */
struct name_entry {
	struct list_head node;
	char name[PATH_SIZE];
	unsigned int ignore_error:1;
};

extern int log_priority(const char *priority);
extern struct name_entry *name_list_add(struct udev *udev, struct list_head *name_list, const char *name, int sort);
extern struct name_entry *name_list_key_add(struct udev *udev, struct list_head *name_list, const char *key, const char *value);
extern int name_list_key_remove(struct udev *udev, struct list_head *name_list, const char *key);
extern void name_list_cleanup(struct udev *udev, struct list_head *name_list);
extern int add_matching_files(struct udev *udev, struct list_head *name_list, const char *dirname, const char *suffix);
extern uid_t lookup_user(struct udev *udev, const char *user);
extern gid_t lookup_group(struct udev *udev, const char *group);

/* udev_utils_string.c */
extern int string_is_true(const char *str);
extern void remove_trailing_chars(char *path, char c);
extern size_t path_encode(char *s, size_t len);
extern size_t path_decode(char *s);
extern int utf8_encoded_valid_unichar(const char *str);
extern int replace_chars(char *str, const char *white);

/* udev_utils_file.c */
extern int create_path(struct udev *udev, const char *path);
extern int delete_path(struct udev *udev, const char *path);
extern int unlink_secure(struct udev *udev, const char *filename);
extern int file_map(const char *filename, char **buf, size_t *bufsize);
extern void file_unmap(void *buf, size_t bufsize);
extern size_t buf_get_line(const char *buf, size_t buflen, size_t cur);

/* udevadm commands */
extern int udevadm_monitor(struct udev *udev, int argc, char *argv[]);
extern int udevadm_info(struct udev *udev, int argc, char *argv[]);
extern int udevadm_control(struct udev *udev, int argc, char *argv[]);
extern int udevadm_trigger(struct udev *udev, int argc, char *argv[]);
extern int udevadm_settle(struct udev *udev, int argc, char *argv[]);
extern int udevadm_test(struct udev *udev, int argc, char *argv[]);

#endif
