#ifndef UDEV_DBUS_H
#define UDEV_DBUS_H


#ifdef USE_DBUS

extern void sysbus_connect(void);
extern void sysbus_disconnect(void);
extern void sysbus_send_create(struct udevice *dev, const char *path);
extern void sysbus_send_remove(const char* name, const char *path);
 
#else

static inline void sysbus_connect(void) { }
static inline void sysbus_disconnect(void) { }
static inline void sysbus_send_create(struct udevice *dev, const char *path) { }
static inline void sysbus_send_remove(const char* name, const char *path) { }

#endif /* USE_DBUS */



#endif
