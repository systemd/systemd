/*
 * udevdb header file
 */
#ifndef _UDEVDB_H_
#define _UDEVDB_H_

#define UDEV_DB		"udevdb.tdb" 

#define PATH_SIZE	256

#define UDEVDB_DEL	"#"

/* Udevdb initialization flags */
#define UDEVDB_DEFAULT	0	/* Defaults database to use file */
#define UDEVDB_INTERNAL	1	/* Don't store db on disk, use in memory */

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
extern void udevdb_exit(void);
extern int udevdb_init(int init_flag);
extern int udevdb_delete_udevice(const char *name);
extern int udevdb_add_udevice(const struct udevice *dev);
extern struct udevice *udevdb_get_udevice(const char *name);
extern struct udevice *udevdb_get_udevice_by_bus(const char *bus, 
							const char *id);
extern struct udevice *udevdb_get_udevice_by_class(const char *cls,
							const char *cls_dev);

#endif /* _UDEVDB_H_ */
