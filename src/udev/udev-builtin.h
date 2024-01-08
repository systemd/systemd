/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>

#include "sd-device.h"
#include "sd-netlink.h"

#include "macro.h"
#include "udev-event.h"

typedef enum UdevBuiltinCommand {
#if HAVE_BLKID
        UDEV_BUILTIN_BLKID,
#endif
        UDEV_BUILTIN_BTRFS,
        UDEV_BUILTIN_HWDB,
        UDEV_BUILTIN_INPUT_ID,
        UDEV_BUILTIN_KEYBOARD,
#if HAVE_KMOD
        UDEV_BUILTIN_KMOD,
#endif
        UDEV_BUILTIN_NET_DRIVER,
        UDEV_BUILTIN_NET_ID,
        UDEV_BUILTIN_NET_LINK,
        UDEV_BUILTIN_PATH_ID,
        UDEV_BUILTIN_USB_ID,
#if HAVE_ACL
        UDEV_BUILTIN_UACCESS,
#endif
        _UDEV_BUILTIN_MAX,
        _UDEV_BUILTIN_INVALID = -EINVAL,
} UdevBuiltinCommand;

typedef struct UdevBuiltin {
        const char *name;
        int (*cmd)(UdevEvent *event, int argc, char *argv[], bool test);
        const char *help;
        int (*init)(void);
        void (*exit)(void);
        bool (*should_reload)(void);
        bool run_once;
} UdevBuiltin;

#define UDEV_BUILTIN_CMD_TO_PTR(u)                 \
        ({                                         \
                UdevBuiltinCommand _u = (u);       \
                _u < 0 ? NULL : (void*)(intptr_t) (_u + 1);     \
        })

#define PTR_TO_UDEV_BUILTIN_CMD(p)                 \
        ({                                         \
                void *_p = (p);                    \
                _p && (intptr_t)(_p) <= _UDEV_BUILTIN_MAX ? \
                        (UdevBuiltinCommand)((intptr_t)_p - 1) : _UDEV_BUILTIN_INVALID; \
        })

#if HAVE_BLKID
extern const UdevBuiltin udev_builtin_blkid;
#endif
extern const UdevBuiltin udev_builtin_btrfs;
extern const UdevBuiltin udev_builtin_hwdb;
extern const UdevBuiltin udev_builtin_input_id;
extern const UdevBuiltin udev_builtin_keyboard;
#if HAVE_KMOD
extern const UdevBuiltin udev_builtin_kmod;
#endif
extern const UdevBuiltin udev_builtin_net_driver;
extern const UdevBuiltin udev_builtin_net_id;
extern const UdevBuiltin udev_builtin_net_setup_link;
extern const UdevBuiltin udev_builtin_path_id;
extern const UdevBuiltin udev_builtin_usb_id;
#if HAVE_ACL
extern const UdevBuiltin udev_builtin_uaccess;
#endif

void udev_builtin_init(void);
void udev_builtin_exit(void);
UdevBuiltinCommand udev_builtin_lookup(const char *command);
const char *udev_builtin_name(UdevBuiltinCommand cmd);
bool udev_builtin_run_once(UdevBuiltinCommand cmd);
int udev_builtin_run(UdevEvent *event, UdevBuiltinCommand cmd, const char *command, bool test);
void udev_builtin_list(void);
bool udev_builtin_should_reload(void);
int udev_builtin_add_property(sd_device *dev, bool test, const char *key, const char *val);
int udev_builtin_add_propertyf(sd_device *dev, bool test, const char *key, const char *valf, ...) _printf_(4, 5);
int udev_builtin_import_property(sd_device *dev, sd_device *src, bool test, const char *key);
int udev_builtin_hwdb_lookup(sd_device *dev, const char *prefix, const char *modalias,
                             const char *filter, bool test);
