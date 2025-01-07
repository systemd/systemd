/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <errno.h>

#include "env-util.h"

#define UDEV_NAME_SIZE   512
#define UDEV_PATH_SIZE  1024
#define UDEV_LINE_SIZE 16384

typedef enum EventMode {
        EVENT_UDEV_WORKER,
        EVENT_UDEVADM_TEST,
        EVENT_UDEVADM_TEST_BUILTIN,
        EVENT_TEST_RULE_RUNNER,
        EVENT_TEST_SPAWN,
        _EVENT_MODE_MAX,
        _EVENT_MODE_INVALID = -EINVAL,
} EventMode;

typedef enum UdevRuleEscapeType {
        ESCAPE_UNSET,
        ESCAPE_NONE,    /* OPTIONS="string_escape=none" */
        ESCAPE_REPLACE, /* OPTIONS="string_escape=replace" */
        _ESCAPE_TYPE_MAX,
        _ESCAPE_TYPE_INVALID = -EINVAL,
} UdevRuleEscapeType;

typedef enum ResolveNameTiming {
        RESOLVE_NAME_NEVER,
        RESOLVE_NAME_LATE,
        RESOLVE_NAME_EARLY,
        _RESOLVE_NAME_TIMING_MAX,
        _RESOLVE_NAME_TIMING_INVALID = -EINVAL,
} ResolveNameTiming;

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
#if HAVE_ACL
        UDEV_BUILTIN_UACCESS,
#endif
        UDEV_BUILTIN_USB_ID,
        _UDEV_BUILTIN_MAX,
        _UDEV_BUILTIN_INVALID = -EINVAL,
} UdevBuiltinCommand;

typedef enum UdevReloadFlags {
#if HAVE_BLKID
        UDEV_RELOAD_BUILTIN_BLKID    = 1u << UDEV_BUILTIN_BLKID,
#endif
        UDEV_RELOAD_BUILTIN_BTRFS    = 1u << UDEV_BUILTIN_BTRFS,
        UDEV_RELOAD_BUILTIN_HWDB     = 1u << UDEV_BUILTIN_HWDB,
        UDEV_RELOAD_BUILTIN_INPUT_ID = 1u << UDEV_BUILTIN_INPUT_ID,
        UDEV_RELOAD_BUILTIN_KEYBOARD = 1u << UDEV_BUILTIN_KEYBOARD,
#if HAVE_KMOD
        UDEV_RELOAD_BUILTIN_KMOD     = 1u << UDEV_BUILTIN_KMOD,
#endif
        UDEV_RELOAD_BUILTIN_DRIVER   = 1u << UDEV_BUILTIN_NET_DRIVER,
        UDEV_RELOAD_BUILTIN_NET_ID   = 1u << UDEV_BUILTIN_NET_ID,
        UDEV_RELOAD_BUILTIN_NET_LINK = 1u << UDEV_BUILTIN_NET_LINK,
        UDEV_RELOAD_BUILTIN_PATH_ID  = 1u << UDEV_BUILTIN_PATH_ID,
#if HAVE_ACL
        UDEV_RELOAD_BUILTIN_UACCESS  = 1u << UDEV_BUILTIN_UACCESS,
#endif
        UDEV_RELOAD_BUILTIN_USB_ID   = 1u << UDEV_BUILTIN_USB_ID,
        UDEV_RELOAD_KILL_WORKERS     = 1u << (_UDEV_BUILTIN_MAX + 0),
        UDEV_RELOAD_RULES            = 1u << (_UDEV_BUILTIN_MAX + 1),
} UdevReloadFlags;

/* udev properties are conceptually close to environment variables. Let's validate names, values, and
 * assignments in the same way. */
#define udev_property_name_is_valid(x)       env_name_is_valid(x)
#define udev_property_value_is_valid(x)      env_value_is_valid(x)
#define udev_property_assignment_is_valid(x) env_assignment_is_valid(x)
