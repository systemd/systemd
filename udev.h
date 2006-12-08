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

#include <sys/types.h>
#include <sys/param.h>

#include "list.h"
#include "logging.h"
#include "udev_sysdeps.h"
#include "udev_version.h"

#define COMMENT_CHARACTER			'#'
#define PATH_TO_NAME_CHAR			'@'
#define LINE_SIZE				512
#define PATH_SIZE				512
#define NAME_SIZE				128
#define VALUE_SIZE				128

#define DEFAULT_PARTITIONS_COUNT		15
#define UDEV_ALARM_TIMEOUT			180

#define UDEV_MAX(a,b) ((a) > (b) ? (a) : (b))

/* pipes */
#define READ_END				0
#define WRITE_END				1

#define DB_DIR					".udev/db"

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
	/* device event */
	struct sysfs_device *dev;		/* points to dev_local by default */
	struct sysfs_device dev_local;
	struct sysfs_device *dev_parent;	/* current parent device used for matching */
	char action[NAME_SIZE];

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
	int test_run;
};

/* udev_config.c */
extern char udev_root[PATH_SIZE];
extern char udev_config_filename[PATH_SIZE];
extern char udev_rules_dir[PATH_SIZE];
extern int udev_log_priority;
extern int udev_run;
extern void udev_config_init(void);

/* udev_device.c */
extern struct udevice *udev_device_init(void);
extern void udev_device_cleanup(struct udevice *udev);
extern int udev_device_event(struct udev_rules *rules, struct udevice *udev);
extern dev_t udev_device_get_devt(struct udevice *udev);

/* udev_sysfs.c */
extern char sysfs_path[PATH_SIZE];
extern int sysfs_init(void);
extern void sysfs_cleanup(void);
extern void sysfs_device_set_values(struct sysfs_device *dev, const char *devpath,
				    const char *subsystem, const char *driver);
extern struct sysfs_device *sysfs_device_get(const char *devpath);
extern struct sysfs_device *sysfs_device_get_parent(struct sysfs_device *dev);
extern struct sysfs_device *sysfs_device_get_parent_with_subsystem(struct sysfs_device *dev, const char *subsystem);
extern char *sysfs_attr_get_value(const char *devpath, const char *attr_name);
extern int sysfs_resolve_link(char *path, size_t size);

/* udev_node.c */
extern int udev_node_mknod(struct udevice *udev, const char *file, dev_t devt, mode_t mode, uid_t uid, gid_t gid);
extern int udev_node_add(struct udevice *udev, struct udevice *udev_old);
extern void udev_node_remove_symlinks(struct udevice *udev);
extern int udev_node_remove(struct udevice *udev);

/* udev_db.c */
extern int udev_db_add_device(struct udevice *dev);
extern int udev_db_delete_device(struct udevice *dev);
extern int udev_db_get_device(struct udevice *udev, const char *devpath);
extern int udev_db_lookup_name(const char *name, char *devpath, size_t len);
extern int udev_db_get_all_entries(struct list_head *name_list);

/* udev_utils.c */
struct name_entry {
	struct list_head node;
	char name[PATH_SIZE];
};
extern int log_priority(const char *priority);
extern char *name_list_add(struct list_head *name_list, const char *name, int sort);
extern char *name_list_key_add(struct list_head *name_list, const char *key, const char *value);
extern void name_list_cleanup(struct list_head *name_list);
extern int add_matching_files(struct list_head *name_list, const char *dirname, const char *suffix);
extern uid_t lookup_user(const char *user);
extern gid_t lookup_group(const char *group);

/* udev_utils_string.c */
extern int string_is_true(const char *str);
extern void remove_trailing_chars(char *path, char c);
extern int utf8_encoded_valid_unichar(const char *str);
extern int replace_untrusted_chars(char *str);

/* udev_utils_file.c */
extern int create_path(const char *path);
extern int delete_path(const char *path);
extern int file_map(const char *filename, char **buf, size_t *bufsize);
extern void file_unmap(void *buf, size_t bufsize);
extern int unlink_secure(const char *filename);
extern size_t buf_get_line(const char *buf, size_t buflen, size_t cur);

/* udev_utils_run.c */
extern int pass_env_to_socket(const char *name, const char *devpath, const char *action);
extern int run_program(const char *command, const char *subsystem,
		       char *result, size_t ressize, size_t *reslen, int log);

#endif
