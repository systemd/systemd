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

#include <unistd.h>
#include <string.h>

#ifdef HAVE_KMOD
#include <libkmod.h>
#endif

#include "macro.h"
#include "capability.h"
#include "bus-util.h"
#include "kmod-setup.h"

#ifdef HAVE_KMOD
static void systemd_kmod_log(
                void *data,
                int priority,
                const char *file, int line,
                const char *fn,
                const char *format,
                va_list args) {

        /* library logging is enabled at debug only */
        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_DEBUG, 0, file, line, fn, format, args);
        REENABLE_WARNING;
}
#endif

int kmod_setup(void) {
#ifdef HAVE_KMOD

        static const struct {
                const char *module;
                const char *path;
                bool warn_if_unavailable:1;
                bool warn_if_module:1;
                bool (*condition_fn)(void);
        } kmod_table[] = {
                /* auto-loading on use doesn't work before udev is up */
                { "autofs4",   "/sys/class/misc/autofs",    true,   false,   NULL      },

                /* early configure of ::1 on the loopback device */
                { "ipv6",      "/sys/module/ipv6",          false,  true,    NULL      },

                /* this should never be a module */
                { "unix",      "/proc/net/unix",            true,   true,    NULL      },

                /* IPC is needed before we bring up any other services */
                { "kdbus",     "/sys/fs/kdbus",             false,  false,   is_kdbus_wanted },

#ifdef HAVE_LIBIPTC
                /* netfilter is needed by networkd, nspawn among others, and cannot be autoloaded */
                { "ip_tables", "/proc/net/ip_tables_names", false,  false,   NULL      },
#endif
        };
        struct kmod_ctx *ctx = NULL;
        unsigned int i;
        int r;

        if (have_effective_cap(CAP_SYS_MODULE) == 0)
                return 0;

        for (i = 0; i < ELEMENTSOF(kmod_table); i++) {
                struct kmod_module *mod;

                if (kmod_table[i].path && access(kmod_table[i].path, F_OK) >= 0)
                        continue;

                if (kmod_table[i].condition_fn && !kmod_table[i].condition_fn())
                        continue;

                if (kmod_table[i].warn_if_module)
                        log_debug("Your kernel apparently lacks built-in %s support. Might be "
                                  "a good idea to compile it in. We'll now try to work around "
                                  "this by loading the module...", kmod_table[i].module);

                if (!ctx) {
                        ctx = kmod_new(NULL, NULL);
                        if (!ctx)
                                return log_oom();

                        kmod_set_log_fn(ctx, systemd_kmod_log, NULL);
                        kmod_load_resources(ctx);
                }

                r = kmod_module_new_from_name(ctx, kmod_table[i].module, &mod);
                if (r < 0) {
                        log_error("Failed to lookup module '%s'", kmod_table[i].module);
                        continue;
                }

                r = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
                if (r == 0)
                        log_info("Inserted module '%s'", kmod_module_get_name(mod));
                else if (r == KMOD_PROBE_APPLY_BLACKLIST)
                        log_info("Module '%s' is blacklisted", kmod_module_get_name(mod));
                else {
                        bool print_warning = kmod_table[i].warn_if_unavailable || (r < 0 && r != -ENOSYS);

                        log_full_errno(print_warning ? LOG_WARNING : LOG_DEBUG, r,
                                       "Failed to insert module '%s': %m", kmod_module_get_name(mod));
                }

                kmod_module_unref(mod);
        }

        if (ctx)
                kmod_unref(ctx);

#endif
        return 0;
}
