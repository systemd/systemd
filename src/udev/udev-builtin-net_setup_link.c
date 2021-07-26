/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "link-config.h"
#include "log.h"
#include "string-util.h"
#include "udev-builtin.h"

static LinkConfigContext *ctx = NULL;

static int builtin_net_setup_link(sd_device *dev, int argc, char **argv, bool test) {
        _cleanup_free_ char *driver = NULL;
        const char *name = NULL;
        LinkConfig *link;
        int r;

        if (argc > 1)
                return log_device_error_errno(dev, SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        r = link_get_driver(ctx, dev, &driver);
        if (r < 0)
                log_device_full_errno(dev, ERRNO_IS_NOT_SUPPORTED(r) || r == -ENODEV ? LOG_DEBUG : LOG_WARNING,
                                      r, "Failed to query device driver: %m");
        else
                udev_builtin_add_property(dev, test, "ID_NET_DRIVER", driver);

        r = link_config_get(ctx, dev, &link);
        if (r < 0) {
                if (r == -ENODEV)
                        return log_device_debug_errno(dev, r, "Link vanished while searching for configuration for it.");
                if (r == -ENOENT) {
                        log_device_debug_errno(dev, r, "No matching link configuration found, ignoring device.");
                        return 0;
                }

                return log_device_error_errno(dev, r, "Failed to get link config: %m");
        }

        r = link_config_apply(ctx, link, dev, &name);
        if (r == -ENODEV)
                log_device_debug_errno(dev, r, "Link vanished while applying configuration, ignoring.");
        else if (r < 0)
                log_device_warning_errno(dev, r, "Could not apply link configuration, ignoring: %m");

        udev_builtin_add_property(dev, test, "ID_NET_LINK_FILE", link->filename);

        if (name)
                udev_builtin_add_property(dev, test, "ID_NET_NAME", name);

        return 0;
}

static int builtin_net_setup_link_init(void) {
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

static void builtin_net_setup_link_exit(void) {
        ctx = link_config_ctx_free(ctx);
        log_debug("Unloaded link configuration context.");
}

static bool builtin_net_setup_link_validate(void) {
        log_debug("Check if link configuration needs reloading.");
        if (!ctx)
                return false;

        return link_config_should_reload(ctx);
}

const UdevBuiltin udev_builtin_net_setup_link = {
        .name = "net_setup_link",
        .cmd = builtin_net_setup_link,
        .init = builtin_net_setup_link_init,
        .exit = builtin_net_setup_link_exit,
        .validate = builtin_net_setup_link_validate,
        .help = "Configure network link",
        .run_once = false,
};
