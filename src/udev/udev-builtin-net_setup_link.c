/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen

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

#include "link-config.h"
#include "udev.h"
#include "log.h"

static link_config_ctx *ctx = NULL;

static int builtin_net_setup_link(struct udev_device *dev, int argc, char **argv, bool test) {
        _cleanup_free_ char *driver = NULL;
        const char *name;
        link_config *link;
        int r;

        if (argc > 1) {
                log_error("This program takes no arguments.");
                return EXIT_FAILURE;
        }

        r = link_get_driver(ctx, dev, &driver);
        if (r >= 0)
                udev_builtin_add_property(dev, test, "ID_NET_DRIVER", driver);

        r = link_config_get(ctx, dev, &link);
        if (r < 0) {
                if (r == -ENOENT) {
                        log_debug("No matching link configuration found.");
                        return EXIT_SUCCESS;
                } else {
                        log_error("Could not get link config: %s", strerror(-r));
                        return EXIT_FAILURE;
                }
        }

        r = link_config_apply(ctx, link, dev, &name);
        if (r < 0) {
                log_error("Could not apply link config to %s: %s", udev_device_get_sysname(dev), strerror(-r));
                return EXIT_FAILURE;
        }

        if (name)
                udev_builtin_add_property(dev, test, "ID_NET_NAME", name);

        return EXIT_SUCCESS;
}

static int builtin_net_setup_link_init(struct udev *udev) {
        int r;

        if (ctx)
                return 0;

        r = link_config_ctx_new(&ctx);
        if (r < 0)
                return r;

        r = link_config_load(ctx);
        if (r < 0)
                return r;

        log_debug("Created link configuration context.");
        return 0;
}

static void builtin_net_setup_link_exit(struct udev *udev) {
        link_config_ctx_free(ctx);
        ctx = NULL;
        log_debug("Unloaded link configuration context.");
}

static bool builtin_net_setup_link_validate(struct udev *udev) {
        log_debug("Check if link configuration needs reloading.");
        if (!ctx)
                return false;

        return link_config_should_reload(ctx);
}

const struct udev_builtin udev_builtin_net_setup_link = {
        .name = "net_setup_link",
        .cmd = builtin_net_setup_link,
        .init = builtin_net_setup_link_init,
        .exit = builtin_net_setup_link_exit,
        .validate = builtin_net_setup_link_validate,
        .help = "configure network link",
        .run_once = false,
};
