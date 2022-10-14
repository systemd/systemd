/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * load kernel modules
 *
 * Copyright © 2011 ProFUSION embedded systems
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "device-util.h"
#include "module-util.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"

static struct kmod_ctx *ctx = NULL;

_printf_(6,0) static void udev_kmod_log(void *data, int priority, const char *file, int line, const char *fn, const char *format, va_list args) {
        log_internalv(priority, 0, file, line, fn, format, args);
}

static int builtin_kmod(sd_device *dev, sd_netlink **rtnl, int argc, char *argv[], bool test) {
        int r;

        assert(dev);

        if (!ctx)
                return 0;

        if (argc < 2 || !streq(argv[1], "load"))
                return log_device_warning_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: expected: load [module…]", argv[0]);

        char **modules = strv_skip(argv, 2);
        if (strv_isempty(modules)) {
                const char *modalias;

                r = sd_device_get_property_value(dev, "MODALIAS", &modalias);
                if (r < 0)
                        return log_device_warning_errno(dev, r, "Failed to read property \"MODALIAS\".");

                (void) module_load_and_warn(ctx, modalias, /* verbose = */ false);
        } else
                STRV_FOREACH(module, modules)
                        (void) module_load_and_warn(ctx, *module, /* verbose = */ false);

        return 0;
}

/* called at udev startup and reload */
static int builtin_kmod_init(void) {
        if (ctx)
                return 0;

        ctx = kmod_new(NULL, NULL);
        if (!ctx)
                return -ENOMEM;

        log_debug("Loading kernel module index.");
        kmod_set_log_fn(ctx, udev_kmod_log, NULL);
        kmod_load_resources(ctx);
        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_kmod_exit(void) {
        log_debug("Unload kernel module index.");
        ctx = kmod_unref(ctx);
}

/* called every couple of seconds during event activity; 'true' if config has changed */
static bool builtin_kmod_should_reload(void) {
        if (!ctx)
                return false;

        if (kmod_validate_resources(ctx) != KMOD_RESOURCES_OK) {
                log_debug("Kernel module index needs reloading.");
                return true;
        }

        return false;
}

const UdevBuiltin udev_builtin_kmod = {
        .name = "kmod",
        .cmd = builtin_kmod,
        .init = builtin_kmod_init,
        .exit = builtin_kmod_exit,
        .should_reload = builtin_kmod_should_reload,
        .help = "Kernel module loader",
        .run_once = false,
};
