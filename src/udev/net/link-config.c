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

#include <netinet/ether.h>
#include <net/if.h>

#include "sd-id128.h"

#include "link-config.h"
#include "ethtool-util.h"

#include "libudev-private.h"
#include "sd-rtnl.h"
#include "util.h"
#include "log.h"
#include "strv.h"
#include "path-util.h"
#include "conf-parser.h"
#include "conf-files.h"
#include "fileio.h"
#include "hashmap.h"

struct link_config_ctx {
        LIST_HEAD(link_config, links);

        int ethtool_fd;

        sd_rtnl *rtnl;

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

        r = sd_rtnl_open(0, &ctx->rtnl);
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

        if (ctx->ethtool_fd >= 0)
                close_nointr_nofail(ctx->ethtool_fd);

        sd_rtnl_unref(ctx->rtnl);

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

static int rtnl_set_properties(sd_rtnl *rtnl, int ifindex, const char *name, const struct ether_addr *mac, unsigned int mtu) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *message;
        bool need_update = false;
        int r;

        assert(rtnl);
        assert(ifindex > 0);

        r = sd_rtnl_message_link_new(RTM_NEWLINK, ifindex, 0, 0, &message);
        if (r < 0)
                return r;

        if (name) {
                r = sd_rtnl_message_append(message, IFLA_IFNAME, name);
                if (r < 0)
                        return r;

                need_update = true;
        }

        if (mac) {
                r = sd_rtnl_message_append(message, IFLA_ADDRESS, mac);
                if (r < 0)
                        return r;

                need_update = true;
        }

        if (mtu > 0) {
                r = sd_rtnl_message_append(message, IFLA_MTU, &mtu);
                if (r < 0)
                        return r;

                need_update = true;
        }

        if  (need_update) {
                r = sd_rtnl_send_with_reply_and_block(rtnl, message, 5 * USEC_PER_SEC, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static bool enable_name_policy(void) {
        _cleanup_free_ char *line;
        char *w, *state;
        int r;
        size_t l;

        r = read_one_line_file("/proc/cmdline", &line);
        if (r < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return true; /* something is very wrong, let's not make it worse */
        }

        FOREACH_WORD_QUOTED(w, l, line, state)
                if (strneq(w, "net.ifnames=0", l))
                        return false;

        return true;
}

static bool mac_is_random(struct udev_device *device) {
        const char *s;
        int type;

        s = udev_device_get_sysattr_value(device, "addr_assign_type");
        if (!s)
                return -EINVAL;
        type = strtoul(s, NULL, 0);

        /* check for NET_ADDR_RANDOM */
        return type == 1;
}

static bool mac_is_permanent(struct udev_device *device) {
        const char *s;
        int type;

        s = udev_device_get_sysattr_value(device, "addr_assign_type");
        if (!s)
                return -EINVAL;
        type = strtoul(s, NULL, 0);

        /* check for NET_ADDR_PERM */
        return type == 0;
}

static int get_mac(struct udev_device *device, bool want_random, struct ether_addr **ret) {
        struct ether_addr *mac;
        unsigned int seed;
        int r, i;

        mac = calloc(1, sizeof(struct ether_addr));
        if (!mac)
                return -ENOMEM;

        if (want_random)
                seed = random_u();
        else {
                const char *name;
                sd_id128_t machine;
                char machineid_buf[33];
                const char *seed_str;

                /* fetch some persistent data unique (on this machine) to this device */
                name = udev_device_get_property_value(device, "ID_NET_NAME_ONBOARD");
                if (!name) {
                        name = udev_device_get_property_value(device, "ID_NET_NAME_SLOT");
                        if (!name) {
                                name = udev_device_get_property_value(device, "ID_NET_NAME_PATH");
                                if (!name)
                                        return -1;
                        }
                }
                /* fetch some persistent data unique to this machine */
                r = sd_id128_get_machine(&machine);
                if (r < 0)
                        return -1;

                /* combine the data */
                seed_str = strappenda(name, sd_id128_to_string(machine, machineid_buf));

                /* hash to get seed */
                seed = string_hash_func(seed_str);
        }

        srandom(seed);

        for(i = 0; i < ETH_ALEN; i++) {
                mac->ether_addr_octet[i] = random();
        }

        /* see eth_random_addr in the kernel */
        mac->ether_addr_octet[0] &= 0xfe;        /* clear multicast bit */
        mac->ether_addr_octet[0] |= 0x02;        /* set local assignment bit (IEEE802) */

        *ret = mac;

        return 0;
}

int link_config_apply(link_config_ctx *ctx, link_config *config, struct udev_device *device) {
        const char *name;
        char *new_name = NULL;
        struct ether_addr *mac = NULL;
        int r, ifindex;

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

        ifindex = udev_device_get_ifindex(device);
        if (ifindex <= 0) {
                log_warning("Could not find ifindex");
                return -ENODEV;
        }

        if (config->name_policy && enable_name_policy()) {
                char **policy;

                STRV_FOREACH(policy, config->name_policy) {
                        if (streq(*policy, "onboard")) {
                                r = strdup_or_null(udev_device_get_property_value(device, "ID_NET_NAME_ONBOARD"), &new_name);
                                if (r < 0)
                                        return r;
                                if (new_name)
                                        break;
                        } else if (streq(*policy, "slot")) {
                                r = strdup_or_null(udev_device_get_property_value(device, "ID_NET_NAME_SLOT"), &new_name);
                                if (r < 0)
                                        return r;
                                if (new_name)
                                        break;
                        } else if (streq(*policy, "path")) {
                                r = strdup_or_null(udev_device_get_property_value(device, "ID_NET_NAME_PATH"), &new_name);
                                if (r < 0)
                                        return r;
                                if (new_name)
                                        break;
                        } else if (streq(*policy, "mac")) {
                                r = strdup_or_null(udev_device_get_property_value(device, "ID_NET_NAME_MAC"), &new_name);
                                if (r < 0)
                                        return r;
                                if (new_name)
                                        break;
                        } else
                                log_warning("Invalid link naming policy '%s', ignoring.", *policy);
                }
        }

        if (!new_name && config->name) {
                new_name = calloc(1, IFNAMSIZ);
                strscpy(new_name, IFNAMSIZ, config->name);
        }

        if (config->mac_policy) {
                if (streq(config->mac_policy, "persistent")) {
                        if (!mac_is_permanent(device)) {
                                r = get_mac(device, false, &mac);
                                if (r < 0)
                                        return r;
                        }
                } else if (streq(config->mac_policy, "random")) {
                        if (!mac_is_random(device)) {
                                r = get_mac(device, true, &mac);
                                if (r < 0)
                                        return r;
                        }
                } else
                        log_warning("Invalid MACAddress policy '%s', ignoring.", config->mac_policy);
        }

        if (!mac && config->mac) {
                mac = calloc(1, sizeof(struct ether_addr));
                r = sscanf(config->mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                           &mac->ether_addr_octet[0],
                           &mac->ether_addr_octet[1],
                           &mac->ether_addr_octet[2],
                           &mac->ether_addr_octet[3],
                           &mac->ether_addr_octet[4],
                           &mac->ether_addr_octet[5]);
                if (r != 6) {
                        r = -EINVAL;
                        goto out;
                }
        }

        r = rtnl_set_properties(ctx->rtnl, ifindex, new_name, mac, config->mtu);
        if (r < 0) {
                log_warning("Could not set Name, MACAddress or MTU on %s: %s", name, strerror(-r));
                goto out;
        }

        return 0;
out:
        free(new_name);
        free(mac);
        return r;
}
