/*
 * udevdb header file
 */
#ifndef _UDEVDB_H_
#define _UDEVDB_H_

#include "namedev.h"
#include "udev.h"

#define BUS_DB		"/home/stekloff/src/udev-0.2/busdb.tdb"
#define CLASS_DB	"/home/stekloff/src/udev-0.2/classdb.tdb"
#define NAME_DB		"/home/stekloff/src/udev-0.2/namedb.tdb"

#define PATH_SIZE	256

#define UDEVDB_DEL	"#"

struct udevice {
	char name[NAME_SIZE];
	char sysfs_path[PATH_SIZE];
	char class_dev_name[NAME_SIZE];
	char class_name[NAME_SIZE];
	char bus_id[NAME_SIZE];
	char bus_name[NAME_SIZE];
	char driver[NAME_SIZE];
	char type;
	int major;
	int minor;
	int mode;
};

/* Function Prototypes */
extern int udevdb_delete_udevice(const char *name);
extern int udevdb_add_udevice(const struct udevice *dev);
extern struct udevice *udevdb_get_udevice(const char *name);
extern struct udevice *udevdb_get_udevice_by_bus(const char *bus, 
							const char *id);
extern struct udevice *udevdb_get_udevice_by_class(const char *cls,
							const char *cls_dev);

#endif /* _UDEVDB_H_ */
