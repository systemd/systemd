/*
 * udevdb header file
 */
#ifndef _UDEVDB_H_
#define _UDEVDB_H_

/* Udevdb initialization flags */
#define UDEVDB_DEFAULT	0	/* Defaults database to use file */
#define UDEVDB_INTERNAL	1	/* Don't store db on disk, use in memory */

/* Function Prototypes */
extern void udevdb_exit(void);
extern int udevdb_init(int init_flag);

extern int udevdb_add_dev(const char *path, const struct udevice *dev);
extern struct udevice *udevdb_get_dev(const char *path);
extern int udevdb_delete_dev(const char *path);

#endif /* _UDEVDB_H_ */
