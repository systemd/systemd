/*
 * load kernel modules
 *
 * Copyright (C) 2011-2012 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2011 ProFUSION embedded systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <libkmod.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "string-util.h"
#include "udev.h"

/* this is used without locking because this builtin is accessed only by a single thread;
 * the udevd Manager workers are fork()ed processes that each get their own copy of this builtin
 */
static struct kmod_ctx *ctx = NULL;

_printf_(6,0) static void udev_kmod_log(void *data, int priority, const char *file, int line, const char *fn, const char *format, va_list args) {
        log_internalv(priority, 0, file, line, fn, format, args);
}

static int builtin_kmod_init(struct udev *udev);
static void builtin_kmod_exit(struct udev *udev);

static int builtin_kmod_validate(struct udev *udev) {
        int r;

        r = kmod_validate_resources(ctx);
        switch (r) {
        case KMOD_RESOURCES_MUST_RELOAD:
                log_debug("Reload module index");
                kmod_unload_resources(ctx);
                return kmod_load_resources(ctx);
        default:
                log_error("unknown response from kmod_validate_resources : %d", r);
                /* fall through */
        case KMOD_RESOURCES_MUST_RECREATE:
                log_debug("Recreate module index");
                builtin_kmod_exit(udev);
                return builtin_kmod_init(udev);
        case KMOD_RESOURCES_OK:
                break;
        }

        return EXIT_SUCCESS;
}

static int load_module(struct udev *udev, const char *alias) {
        struct kmod_list *list = NULL;
        struct kmod_list *l;
        int err;

        err = builtin_kmod_validate(udev);
        if (err)
                return err;

        err = kmod_module_new_from_lookup(ctx, alias, &list);
        if (err < 0)
                return err;

        if (list == NULL)
                log_debug("No module matches '%s'", alias);

        kmod_list_foreach(l, list) {
                struct kmod_module *mod = kmod_module_get_module(l);

                err = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
                if (err == KMOD_PROBE_APPLY_BLACKLIST)
                        log_debug("Module '%s' is blacklisted", kmod_module_get_name(mod));
                else if (err == 0)
                        log_debug("Inserted '%s'", kmod_module_get_name(mod));
                else
                        log_debug("Failed to insert '%s'", kmod_module_get_name(mod));

                kmod_module_unref(mod);
        }

        kmod_module_unref_list(list);
        return err;
}

static int builtin_kmod(struct udev_device *dev, int argc, char *argv[], bool test) {
        struct udev *udev = udev_device_get_udev(dev);
        int i;

        if (argc < 3 || !streq(argv[1], "load")) {
                log_error("expect: %s load <module>", argv[0]);
                return EXIT_FAILURE;
        }

        for (i = 2; argv[i]; i++) {
                log_debug("Execute '%s' '%s'", argv[1], argv[i]);
                load_module(udev, argv[i]);
        }

        return EXIT_SUCCESS;
}

/* called at udev startup and reload */
static int builtin_kmod_init(struct udev *udev) {
        assert(!ctx);

        ctx = kmod_new(NULL, NULL);
        if (!ctx)
                return -ENOMEM;

        log_debug("Load module index");
        kmod_set_log_fn(ctx, udev_kmod_log, udev);
        kmod_load_resources(ctx);
        return 0;
}

/* called on udev shutdown and reload request */
static void builtin_kmod_exit(struct udev *udev) {
        log_debug("Unload module index");
        ctx = kmod_unref(ctx);
}

const struct udev_builtin udev_builtin_kmod = {
        .name = "kmod",
        .cmd = builtin_kmod,
        .init = builtin_kmod_init,
        .exit = builtin_kmod_exit,
        .help = "Kernel module loader",
        .run_once = false,
};
