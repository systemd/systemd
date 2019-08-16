/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * load kernel modules
 *
 * Copyright © 2011 ProFUSION embedded systems
 */

#include <errno.h>
#include <libkmod.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "module-util.h"
#include "string-util.h"
#include "udev-builtin.h"

static struct kmod_ctx *ctx = NULL;

_printf_(6,0) static void udev_kmod_log(void *data, int priority, const char *file, int line, const char *fn, const char *format, va_list args) {
        log_internalv(priority, 0, file, line, fn, format, args);
}

static int builtin_kmod(sd_device *dev, int argc, char *argv[], bool test) {
        int i;

        if (!ctx)
                return 0;

        if (argc < 3 || !streq(argv[1], "load"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: expected: load <module>", argv[0]);

        for (i = 2; argv[i]; i++)
                (void) module_load_and_warn(ctx, argv[i], false);

        return 0;
}

/* called at udev startup and reload */
static int builtin_kmod_init(void) {
        if (ctx)
                return 0;

        ctx = kmod_new(NULL, NULL);
        if (!ctx)
                return -ENOMEM;

        log_debug("Load module index");
        kmod_set_log_fn(ctx, udev_kmod_log, NULL);
        kmod_load_resources(ctx);
        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_kmod_exit(void) {
        log_debug("Unload module index");
        ctx = kmod_unref(ctx);
}

/* called every couple of seconds during event activity; 'true' if config has changed */
static bool builtin_kmod_validate(void) {
        log_debug("Validate module index");
        if (!ctx)
                return false;
        return (kmod_validate_resources(ctx) != KMOD_RESOURCES_OK);
}

const UdevBuiltin udev_builtin_kmod = {
        .name = "kmod",
        .cmd = builtin_kmod,
        .init = builtin_kmod_init,
        .exit = builtin_kmod_exit,
        .validate = builtin_kmod_validate,
        .help = "Kernel module loader",
        .run_once = false,
};
