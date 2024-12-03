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

static int builtin_kmod(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int r;

        if (event->event_mode != EVENT_UDEV_WORKER) {
                log_device_debug(dev, "Running in test mode, skipping execution of 'kmod' builtin command.");
                return 0;
        }

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
                        return log_device_warning_errno(dev, r, "Failed to read property \"MODALIAS\": %m");

                (void) module_load_and_warn(ctx, modalias, /* verbose = */ false);
        } else
                STRV_FOREACH(module, modules)
                        (void) module_load_and_warn(ctx, *module, /* verbose = */ false);

        return 0;
}

/* called at udev startup and reload */
static int builtin_kmod_init(void) {
        int r;

        if (ctx)
                return 0;

        log_debug("Loading kernel module index.");

        r = module_setup_context(&ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize libkmod context: %m");

        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_kmod_exit(void) {
        if (!ctx)
                return;

        log_debug("Unload kernel module index.");
        ctx = sym_kmod_unref(ctx);
}

/* called every couple of seconds during event activity; 'true' if config has changed */
static bool builtin_kmod_should_reload(void) {
        if (!ctx)
                return false;

        if (sym_kmod_validate_resources(ctx) != KMOD_RESOURCES_OK) {
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
