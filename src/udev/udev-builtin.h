/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>

#include "sd-device.h"
#include "sd-netlink.h"

#include "macro.h"
#include "udev-def.h"
#include "udev-event.h"

typedef struct UdevBuiltin {
        const char *name;
        int (*cmd)(UdevEvent *event, int argc, char *argv[]);
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
#if HAVE_ACL
extern const UdevBuiltin udev_builtin_uaccess;
#endif
extern const UdevBuiltin udev_builtin_usb_id;

void udev_builtin_init(void);
void udev_builtin_exit(void);
UdevBuiltinCommand udev_builtin_lookup(const char *command);
const char* udev_builtin_name(UdevBuiltinCommand cmd);
bool udev_builtin_run_once(UdevBuiltinCommand cmd);
int udev_builtin_run(UdevEvent *event, UdevBuiltinCommand cmd, const char *command);
void udev_builtin_list(void);
UdevReloadFlags udev_builtin_should_reload(void);
void udev_builtin_reload(UdevReloadFlags flags);
int udev_builtin_add_property(UdevEvent *event, const char *key, const char *val);
int udev_builtin_add_propertyf(UdevEvent *event, const char *key, const char *valf, ...) _printf_(3, 4);
int udev_builtin_import_property(UdevEvent *event, const char *key);
int udev_builtin_hwdb_lookup(UdevEvent *event, const char *prefix, const char *modalias, const char *filter);
