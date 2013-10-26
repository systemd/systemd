/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

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

#include "ethtool-util.h"

#include "util.h"
#include "log.h"
#include "strv.h"
#include "path-util.h"
#include "conf-parser.h"
#include "conf-files.h"

struct link_config_ctx {
        LIST_HEAD(link_config, links);

        int ethtool_fd;

        char **link_dirs;
        usec_t *link_dirs_ts_usec;
};

int link_config_ctx_new(link_config_ctx **ret) {
        link_config_ctx *ctx;
        int r;

        if (!ret)
                return -EINVAL;

        ctx = new0(link_config_ctx, 1);
        if (!ctx)
                return -ENOMEM;

        r = ethtool_connect(&ctx->ethtool_fd);
        if (r < 0) {
                link_config_ctx_free(ctx);
                return r;
        }

        LIST_HEAD_INIT(ctx->links);

        ctx->link_dirs = strv_new("/etc/net/links",
                                  "/run/net/links",
                                  "/usr/lib/net/links",
                                  NULL);
        if (!ctx->link_dirs) {
                log_error("failed to build link config directory array");
                link_config_ctx_free(ctx);
                return -ENOMEM;
        }
        if (!path_strv_canonicalize_uniq(ctx->link_dirs)) {
                log_error("failed to canonicalize link config directories\n");
                link_config_ctx_free(ctx);
                return -ENOMEM;
        }

        ctx->link_dirs_ts_usec = calloc(strv_length(ctx->link_dirs), sizeof(usec_t));
        if(!ctx->link_dirs_ts_usec) {
                link_config_ctx_free(ctx);
                return -ENOMEM;
        }

        *ret = ctx;
        return 0;
}

static void link_configs_free(link_config_ctx *ctx) {
        link_config *link, *link_next;

        if (!ctx)
                return;

        LIST_FOREACH_SAFE(links, link, link_next, ctx->links) {
                free(link->filename);
                free(link->match_path);
                free(link->match_driver);
                free(link->match_type);
                free(link->description);

                free(link);
        }
}

void link_config_ctx_free(link_config_ctx *ctx) {
        if (!ctx)
                return;

        close_nointr_nofail(ctx->ethtool_fd);
        strv_free(ctx->link_dirs);
        free(ctx->link_dirs_ts_usec);
        link_configs_free(ctx);

        free(ctx);

        return;
}

static int load_link(link_config_ctx *ctx, const char *filename) {
        link_config *link;
        FILE *file;
        int r;

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return errno;
        }

        link = new0(link_config, 1);
        if (!link) {
                r = log_oom();
                goto failure;
        }

        r = config_parse(NULL, filename, file, "Match\0Link\0Ethernet\0", config_item_perf_lookup,
                         (void*) link_config_gperf_lookup, false, false, link);
        if (r < 0) {
                log_warning("Colud not parse config file %s: %s", filename, strerror(-r));
                goto failure;
        } else
                log_info("Parsed configuration file %s", filename);

        link->filename = strdup(filename);

        LIST_PREPEND(links, ctx->links, link);

        return 0;

failure:
        free(link);
        return r;
}

int link_config_load(link_config_ctx *ctx) {
        int r;
        char **files, **f;

        link_configs_free(ctx);

        /* update timestamps */
        paths_check_timestamp(ctx->link_dirs, ctx->link_dirs_ts_usec, true);

        r = conf_files_list_strv(&files, ".link", NULL, (const char **)ctx->link_dirs);
        if (r < 0) {
                log_error("failed to enumerate link files: %s", strerror(-r));
                return r;
        }

        STRV_FOREACH_BACKWARDS(f, files) {
                r = load_link(ctx, *f);
                if (r < 0)
                        return r;
        }

        return 0;
}

bool link_config_should_reload(link_config_ctx *ctx) {
        return paths_check_timestamp(ctx->link_dirs, ctx->link_dirs_ts_usec, false);
}

static bool match_config(link_config *match, struct udev_device *device) {
        const char *property;

        if (match->match_mac) {
                property = udev_device_get_sysattr_value(device, "address");
                if (!property || !streq(match->match_mac, property)) {
                        log_debug("Device MAC address (%s) did not match MACAddress=%s", property, match->match_mac);
                        return 0;
                }
        }

        if (match->match_path) {
                property = udev_device_get_property_value(device, "ID_PATH");
                if (!property || !streq(match->match_path, property)) {
                        log_debug("Device's persistent path (%s) did not match Path=%s", property, match->match_path);
                        return 0;
                }
        }

        if (match->match_driver) {
                property = udev_device_get_driver(device);
                if (!property || !streq(match->match_driver, property)) {
                        log_debug("Device driver (%s) did not match Driver=%s", property, match->match_driver);
                        return 0;
                }
        }

        if (match->match_type) {
                property = udev_device_get_devtype(device);
                if (!property || !streq(match->match_type, property)) {
                        log_debug("Device type (%s) did not match Type=%s", property, match->match_type);
                        return 0;
                }
        }

        return 1;
}

int link_config_get(link_config_ctx *ctx, struct udev_device *device, link_config **ret) {
        link_config *link;

        LIST_FOREACH(links, link, ctx->links) {
                if (!match_config(link, device)) {
                        log_info("Config file %s does not apply to device %s", link->filename, udev_device_get_sysname(device));
                } else {
                        log_info("Config file %s applies to device %s", link->filename, udev_device_get_sysname(device));
                        *ret = link;
                        return 0;
                }
        }

        return -ENOENT;
}

int link_config_apply(link_config_ctx *ctx, link_config *config, struct udev_device *device) {
        const char *name;
        int r;

        name = udev_device_get_sysname(device);
        if (!name)
                return -EINVAL;

        log_info("Configuring %s", name);

        if (config->description) {
                r = udev_device_set_sysattr_value(device, "ifalias",
                                                  config->description);
                if (r < 0)
                        log_warning("Could not set description of %s to '%s': %s",
                                    name, config->description, strerror(-r));
                else
                        log_info("Set link description of %s to '%s'", name,
                                 config->description);
        }

        if (config->speed || config->duplex) {
                r = ethtool_set_speed(ctx->ethtool_fd, name,
                                      config->speed, config->duplex);
                if (r < 0)
                        log_warning("Could not set speed or duplex of %s to %u Mbytes (%s): %s",
                                    name, config->speed, config->duplex, strerror(-r));
                else
                        log_info("Set speed or duplex of %s to %u Mbytes (%s)", name,
                                 config->speed, config->duplex);
        }

        if (config->wol) {
                r = ethtool_set_wol(ctx->ethtool_fd, name, config->wol);
                if (r < 0)
                        log_warning("Could not set WakeOnLan of %s to %s: %s",
                                    name, config->wol, strerror(-r));
                else
                        log_info("Set WakeOnLan of %s to %s", name, config->wol);
        }

        return 0;
}
