/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>

#include "bitfield.h"
#include "device-private.h"
#include "device-util.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"

static const UdevBuiltin *const builtins[_UDEV_BUILTIN_MAX] = {
#if HAVE_BLKID
        [UDEV_BUILTIN_BLKID] = &udev_builtin_blkid,
#endif
        [UDEV_BUILTIN_BTRFS] = &udev_builtin_btrfs,
        [UDEV_BUILTIN_HWDB] = &udev_builtin_hwdb,
        [UDEV_BUILTIN_INPUT_ID] = &udev_builtin_input_id,
        [UDEV_BUILTIN_KEYBOARD] = &udev_builtin_keyboard,
#if HAVE_KMOD
        [UDEV_BUILTIN_KMOD] = &udev_builtin_kmod,
#endif
        [UDEV_BUILTIN_NET_DRIVER] = &udev_builtin_net_driver,
        [UDEV_BUILTIN_NET_ID] = &udev_builtin_net_id,
        [UDEV_BUILTIN_NET_LINK] = &udev_builtin_net_setup_link,
        [UDEV_BUILTIN_PATH_ID] = &udev_builtin_path_id,
#if HAVE_ACL
        [UDEV_BUILTIN_UACCESS] = &udev_builtin_uaccess,
#endif
        [UDEV_BUILTIN_USB_ID] = &udev_builtin_usb_id,
};

void udev_builtin_init(void) {
        FOREACH_ELEMENT(b, builtins)
                if (*b && (*b)->init)
                        (*b)->init();
}

void udev_builtin_exit(void) {
        FOREACH_ELEMENT(b, builtins)
                if (*b && (*b)->exit)
                        (*b)->exit();
}

UdevReloadFlags udev_builtin_should_reload(void) {
        UdevReloadFlags flags = 0;

        for (UdevBuiltinCommand i = 0; i < _UDEV_BUILTIN_MAX; i++)
                if (builtins[i] && builtins[i]->should_reload && builtins[i]->should_reload())
                        flags |= 1u << i;

        if (flags != 0)
                flags |= UDEV_RELOAD_KILL_WORKERS;

        return flags;
}

void udev_builtin_reload(UdevReloadFlags flags) {
        for (UdevBuiltinCommand i = 0; i < _UDEV_BUILTIN_MAX; i++) {
                if (!BIT_SET(flags, i) || !builtins[i])
                        continue;
                if (builtins[i]->exit)
                        builtins[i]->exit();
                if (builtins[i]->init)
                        builtins[i]->init();
        }
}

void udev_builtin_list(void) {
        FOREACH_ELEMENT(b, builtins)
                if (*b)
                        fprintf(stderr, "  %-14s  %s\n", (*b)->name, (*b)->help);
}

const char* udev_builtin_name(UdevBuiltinCommand cmd) {
        assert(cmd >= 0 && cmd < _UDEV_BUILTIN_MAX);

        if (!builtins[cmd])
                return NULL;

        return builtins[cmd]->name;
}

bool udev_builtin_run_once(UdevBuiltinCommand cmd) {
        assert(cmd >= 0 && cmd < _UDEV_BUILTIN_MAX);

        if (!builtins[cmd])
                return false;

        return builtins[cmd]->run_once;
}

UdevBuiltinCommand udev_builtin_lookup(const char *command) {
        size_t n;

        assert(command);

        command += strspn(command, WHITESPACE);
        n = strcspn(command, WHITESPACE);
        for (UdevBuiltinCommand i = 0; i < _UDEV_BUILTIN_MAX; i++)
                if (builtins[i] && strneq(builtins[i]->name, command, n))
                        return i;

        return _UDEV_BUILTIN_INVALID;
}

int udev_builtin_run(UdevEvent *event, UdevBuiltinCommand cmd, const char *command) {
        _cleanup_strv_free_ char **argv = NULL;
        int r;

        assert(event);
        assert(event->dev);
        assert(cmd >= 0 && cmd < _UDEV_BUILTIN_MAX);
        assert(command);

        if (!builtins[cmd])
                return -EOPNOTSUPP;

        r = strv_split_full(&argv, command, NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_RETAIN_ESCAPE);
        if (r < 0)
                return r;

        /* we need '0' here to reset the internal state */
        optind = 0;
        return builtins[cmd]->cmd(event, strv_length(argv), argv);
}

int udev_builtin_add_property(UdevEvent *event, const char *key, const char *val) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int r;

        assert(key);

        r = device_add_property(dev, key, val);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to add property '%s%s%s'",
                                              key, val ? "=" : "", strempty(val));

        if (event->event_mode == EVENT_UDEVADM_TEST_BUILTIN)
                printf("%s=%s\n", key, strempty(val));

        return 0;
}

int udev_builtin_add_propertyf(UdevEvent *event, const char *key, const char *valf, ...) {
        _cleanup_free_ char *val = NULL;
        va_list ap;
        int r;

        assert(event);
        assert(key);
        assert(valf);

        va_start(ap, valf);
        r = vasprintf(&val, valf, ap);
        va_end(ap);
        if (r < 0)
                return log_oom_debug();

        return udev_builtin_add_property(event, key, val);
}

int udev_builtin_import_property(UdevEvent *event, const char *key) {
        const char *val;
        int r;

        assert(event);
        assert(event->dev);

        if (!event->dev_db_clone)
                return 0;

        r = sd_device_get_property_value(event->dev_db_clone, key, &val);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_device_debug_errno(event->dev_db_clone, r, "Failed to get property \"%s\", ignoring: %m", key);

        r = udev_builtin_add_property(event, key, val);
        if (r < 0)
                return r;

        return 1;
}
