/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libkmod.h>

#include "macro.h"
#include "execute.h"

#include "kmod-setup.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

static void systemd_kmod_log(
                void *data,
                int priority,
                const char *file, int line,
                const char *fn,
                const char *format,
                va_list args) {

        /* library logging is enabled at debug only */
        log_metav(LOG_DEBUG, file, line, fn, format, args);
}

#pragma GCC diagnostic pop

int kmod_setup(void) {

        static const char kmod_table[] =
                /* This one we need to load explicitly, since
                 * auto-loading on use doesn't work before udev
                 * created the ghost device nodes, and we need it
                 * earlier than that. */
                "autofs4\0" "/sys/class/misc/autofs\0"

                /* This one we need to load explicitly, since
                 * auto-loading of IPv6 is not done when we try to
                 * configure ::1 on the loopback device. */
                "ipv6\0"    "/sys/module/ipv6\0"

                "unix\0"    "/proc/net/unix\0";

        struct kmod_ctx *ctx = NULL;
        const char *name, *path;
        int r;

        NULSTR_FOREACH_PAIR(name, path, kmod_table) {
                struct kmod_module *mod;

                if (access(path, F_OK) >= 0)
                        continue;

                log_debug("Your kernel apparently lacks built-in %s support. Might be a good idea to compile it in. "
                          "We'll now try to work around this by loading the module...",
                          name);

                if (!ctx) {
                        ctx = kmod_new(NULL, NULL);
                        if (!ctx)
                                return log_oom();

                        kmod_set_log_fn(ctx, systemd_kmod_log, NULL);
                        kmod_load_resources(ctx);
                }

                r = kmod_module_new_from_name(ctx, name, &mod);
                if (r < 0) {
                        log_error("Failed to lookup module '%s'", name);
                        continue;
                }

                r = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
                if (r == 0)
                        log_info("Inserted module '%s'", kmod_module_get_name(mod));
                else if (r == KMOD_PROBE_APPLY_BLACKLIST)
                        log_info("Module '%s' is blacklisted", kmod_module_get_name(mod));
                else
                        log_error("Failed to insert module '%s'", kmod_module_get_name(mod));

                kmod_module_unref(mod);
        }

        if (ctx)
                kmod_unref(ctx);

        return 0;
}
