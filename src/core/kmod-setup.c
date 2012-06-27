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

static const char * const kmod_table[] = {
        "autofs4", "/sys/class/misc/autofs",
        "ipv6",    "/sys/module/ipv6",
        "unix",    "/proc/net/unix"
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static void systemd_kmod_log(void *data, int priority, const char *file, int line,
                             const char *fn, const char *format, va_list args)
{
        log_metav(priority, file, line, fn, format, args);
}
#pragma GCC diagnostic pop

int kmod_setup(void) {
        unsigned i;
        struct kmod_ctx *ctx = NULL;
        struct kmod_module *mod;
        int err;

        for (i = 0; i < ELEMENTSOF(kmod_table); i += 2) {

                if (access(kmod_table[i+1], F_OK) >= 0)
                        continue;

                log_debug("Your kernel apparently lacks built-in %s support. Might be a good idea to compile it in. "
                          "We'll now try to work around this by loading the module...",
                          kmod_table[i]);

                if (!ctx) {
                        ctx = kmod_new(NULL, NULL);
                        if (!ctx) {
                                log_error("Failed to allocate memory for kmod");
                                return -ENOMEM;
                        }

                        kmod_set_log_fn(ctx, systemd_kmod_log, NULL);

                        kmod_load_resources(ctx);
                }

                err = kmod_module_new_from_name(ctx, kmod_table[i], &mod);
                if (err < 0) {
                        log_error("Failed to load module '%s'", kmod_table[i]);
                        continue;
                }

                err = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
                if (err == 0)
                        log_info("Inserted module '%s'", kmod_module_get_name(mod));
                else if (err == KMOD_PROBE_APPLY_BLACKLIST)
                        log_info("Module '%s' is blacklisted", kmod_module_get_name(mod));
                else
                        log_error("Failed to insert '%s'", kmod_module_get_name(mod));

                kmod_module_unref(mod);
        }

        if (ctx)
                kmod_unref(ctx);

        return 0;
}
