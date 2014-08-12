/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <stdbool.h>
#include <getopt.h>

#include "sd-network.h"
#include "sd-rtnl.h"
#include "libudev.h"

#include "build.h"
#include "util.h"
#include "pager.h"
#include "rtnl-util.h"
#include "udev-util.h"
#include "arphrd-list.h"
#include "local-addresses.h"

static bool arg_no_pager = false;
static bool arg_legend = true;
static bool arg_all = false;

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static int link_get_type_string(int iftype, struct udev_device *d, char **ret) {
        const char *t;
        char *p;

        if (iftype == ARPHRD_ETHER && d) {
                const char *devtype, *id = NULL;
                /* WLANs have iftype ARPHRD_ETHER, but we want
                 * to show a more useful type string for
                 * them */

                devtype = udev_device_get_devtype(d);
                if (streq_ptr(devtype, "wlan"))
                        id = "wlan";
                else if (streq_ptr(devtype, "wwan"))
                        id = "wwan";

                if (id) {
                        p = strdup(id);
                        if (!p)
                                return -ENOMEM;

                        *ret = p;
                        return 1;
                }
        }

        t = arphrd_to_name(iftype);
        if (!t) {
                *ret = NULL;
                return 0;
        }

        p = strdup(t);
        if (!p)
                return -ENOMEM;

        ascii_strlower(p);
        *ret = p;

        return 0;
}

static int list_links(char **args, unsigned n) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        sd_rtnl_message *i;
        unsigned c = 0;
        int r;

        pager_open_if_enabled();

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0) {
                log_error("Failed to connect to netlink: %s", strerror(-r));
                return r;
        }

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev: %m");
                return -errno;
        }

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_request_dump(req, true);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_call(rtnl, req, 0, &reply);
        if (r < 0) {
                log_error("Failed to enumerate links: %s", strerror(-r));
                return r;
        }

        if (arg_legend)
                printf("%3s %-16s %-10s %-10s %-10s\n", "IDX", "LINK", "TYPE", "ADMIN", "OPERATIONAL");

        for (i = reply; i; i = sd_rtnl_message_next(i)) {
                _cleanup_free_ char *state = NULL, *operational_state = NULL;
                _cleanup_udev_device_unref_ struct udev_device *d = NULL;
                const char *on_color = "", *off_color = "";
                 char devid[2 + DECIMAL_STR_MAX(int)];
                _cleanup_free_ char *t = NULL;
                const char *name;
                unsigned iftype;
                uint16_t type;
                int ifindex;

                r = sd_rtnl_message_get_type(i, &type);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                if (type != RTM_NEWLINK)
                        continue;

                r = sd_rtnl_message_link_get_ifindex(i, &ifindex);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                r = sd_rtnl_message_read_string(i, IFLA_IFNAME, &name);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                r = sd_rtnl_message_link_get_type(i, &iftype);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                sd_network_get_link_state(ifindex, &state);
                sd_network_get_link_operational_state(ifindex, &operational_state);

                sprintf(devid, "n%i", ifindex);
                d = udev_device_new_from_device_id(udev, devid);

                link_get_type_string(iftype, d, &t);

                if (streq_ptr(operational_state, "routable")) {
                        on_color = ansi_highlight_green();
                        off_color = ansi_highlight_off();
                } else if (streq_ptr(operational_state, "degraded")) {
                        on_color = ansi_highlight_yellow();
                        off_color = ansi_highlight_off();
                }

                printf("%3i %-16s %-10s %-10s %s%-10s%s\n", ifindex, name, strna(t), strna(state), on_color, strna(operational_state), off_color);
                c++;
        }

        if (arg_legend)
                printf("\n%u links listed.\n", c);

        return 0;
}

static int dump_addresses(sd_rtnl *rtnl, const char *prefix, int ifindex) {
        _cleanup_free_ struct local_address *local = NULL;
        int r, n, i;

        n = local_addresses(rtnl, ifindex, &local);
        if (n < 0)
                return n;

        for (i = 0; i < n; i++) {
                _cleanup_free_ char *pretty = NULL;

                r = in_addr_to_string(local[i].family, &local[i].address, &pretty);
                if (r < 0)
                        return r;

                printf("%*s%s\n",
                       (int) strlen(prefix),
                       i == 0 ? prefix : "",
                       pretty);
        }

        return 0;
}

static void dump_list(const char *prefix, char **l) {
        char **i;

        STRV_FOREACH(i, l) {
                printf("%*s%s\n",
                       (int) strlen(prefix),
                       i == l ? prefix : "",
                       *i);
        }
}

static int link_status_one(sd_rtnl *rtnl, struct udev *udev, const char *name) {
        _cleanup_strv_free_ char **dns = NULL, **ntp = NULL;
        _cleanup_free_ char *state = NULL, *operational_state = NULL;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        char devid[2 + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *t = NULL;
        const char *driver = NULL, *path = NULL, *vendor = NULL, *model = NULL;
        const char *on_color = "", *off_color = "";
        struct ether_addr e;
        unsigned iftype;
        int r, ifindex;
        bool have_mac;
        uint32_t mtu;

        assert(rtnl);
        assert(udev);
        assert(name);

        if (safe_atoi(name, &ifindex) >= 0 && ifindex > 0)
                r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, ifindex);
        else {
                r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
                if (r < 0)
                        return rtnl_log_create_error(r);

                r = sd_rtnl_message_append_string(req, IFLA_IFNAME, name);
        }

        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_call(rtnl, req, 0, &reply);
        if (r < 0) {
                log_error("Failed to query link: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_link_get_ifindex(reply, &ifindex);
        if (r < 0)
                return rtnl_log_parse_error(r);

        r = sd_rtnl_message_read_string(reply, IFLA_IFNAME, &name);
        if (r < 0)
                return rtnl_log_parse_error(r);

        r = sd_rtnl_message_link_get_type(reply, &iftype);
        if (r < 0)
                return rtnl_log_parse_error(r);

        have_mac = sd_rtnl_message_read_ether_addr(reply, IFLA_ADDRESS, &e) >= 0;

        if (have_mac) {
                const uint8_t *p;
                bool all_zeroes = true;

                for (p = (uint8_t*) &e; p < (uint8_t*) &e + sizeof(e); p++)
                        if (*p != 0) {
                                all_zeroes = false;
                                break;
                        }

                if (all_zeroes)
                        have_mac = false;
        }

        sd_rtnl_message_read_u32(reply, IFLA_MTU, &mtu);

        sd_network_get_link_state(ifindex, &state);
        sd_network_get_link_operational_state(ifindex, &operational_state);

        sd_network_get_link_dns(ifindex, &dns);
        sd_network_get_link_ntp(ifindex, &ntp);

        sprintf(devid, "n%i", ifindex);
        d = udev_device_new_from_device_id(udev, devid);

        link_get_type_string(iftype, d, &t);

        if (d) {
                driver = udev_device_get_property_value(d, "ID_NET_DRIVER");
                path = udev_device_get_property_value(d, "ID_PATH");

                vendor = udev_device_get_property_value(d, "ID_VENDOR_FROM_DATABASE");
                if (!vendor)
                        vendor = udev_device_get_property_value(d, "ID_VENDOR");

                model = udev_device_get_property_value(d, "ID_MODEL_FROM_DATABASE");
                if (!model)
                        model = udev_device_get_property_value(d, "ID_MODEL");
        }

        if (streq_ptr(operational_state, "routable")) {
                on_color = ansi_highlight_green();
                off_color = ansi_highlight_off();
        } else if (streq_ptr(operational_state, "degraded")) {
                on_color = ansi_highlight_yellow();
                off_color = ansi_highlight_off();
        }

        printf("%s%s%s %i: %s\n", on_color, draw_special_char(DRAW_BLACK_CIRCLE), off_color, ifindex, name);

        printf("        Type: %s\n"
               "       State: %s%s%s (%s)\n",
               strna(t),
               on_color, strna(operational_state), off_color,
               strna(state));

        if (path)
                printf("        Path: %s\n", path);
        if (driver)
                printf("      Driver: %s\n", driver);
        if (vendor)
                printf("      Vendor: %s\n", vendor);
        if (model)
                printf("       Model: %s\n", model);

        if (have_mac)
                printf("  HW Address: %s\n", ether_ntoa(&e));

        if (mtu > 0)
                printf("         MTU: %u\n", mtu);

        dump_addresses(rtnl, "     Address: ", ifindex);

        if (!strv_isempty(dns))
                dump_list("         DNS: ", dns);
        if (!strv_isempty(ntp))
                dump_list("         NTP: ", ntp);

        return 0;
}

static int link_status(char **args, unsigned n) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        char **name;
        int r;

        if (n <= 1 && !arg_all) {
                _cleanup_free_ char *operational_state = NULL;
                _cleanup_strv_free_ char **dns = NULL, **ntp = NULL;

                sd_network_get_operational_state(&operational_state);
                if (operational_state)
                        printf("       State: %s\n", operational_state);

                sd_network_get_dns(&dns);
                if (!strv_isempty(dns))
                        dump_list("         DNS: ", dns);

                sd_network_get_dns(&ntp);
                if (!strv_isempty(ntp))
                        dump_list("         NTP: ", ntp);

                return 0;
        }

        pager_open_if_enabled();

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0) {
                log_error("Failed to connect to netlink: %s", strerror(-r));
                return r;
        }

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev: %m");
                return -errno;
        }

        if (arg_all) {
                _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;
                sd_rtnl_message *i;
                bool space = false;
                uint16_t type;

                r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
                if (r < 0)
                        return rtnl_log_create_error(r);

                r = sd_rtnl_message_request_dump(req, true);
                if (r < 0)
                        return rtnl_log_create_error(r);

                r = sd_rtnl_call(rtnl, req, 0, &reply);
                if (r < 0) {
                        log_error("Failed to enumerate links: %s", strerror(-r));
                        return r;
                }

                for (i = reply; i; i = sd_rtnl_message_next(i)) {
                        const char *nn;

                        r = sd_rtnl_message_get_type(i, &type);
                        if (r < 0)
                                return rtnl_log_parse_error(r);

                        if (type != RTM_NEWLINK)
                                continue;

                        r = sd_rtnl_message_read_string(i, IFLA_IFNAME, &nn);
                        if (r < 0)
                                return rtnl_log_parse_error(r);

                        if (space)
                                fputc('\n', stdout);

                        link_status_one(rtnl, udev, nn);
                        space = true;
                }
        }

        STRV_FOREACH(name, args + 1) {
                if (name != args+1)
                        fputc('\n', stdout);

                link_status_one(rtnl, udev, *name);
        }

        return 0;
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Query and control the networking subsystem.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --no-pager         Do not pipe output into a pager\n"
               "     --no-legend        Do not show the headers and footers\n"
               "  -a --all              Show status for all links\n\n"
               "Commands:\n"
               "  list                  List links\n"
               "  status LINK           Show link status\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
                { "no-legend", no_argument,       NULL, ARG_NO_LEGEND },
                { "all",       no_argument,       NULL, 'a'           },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ha", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

static int networkctl_main(int argc, char *argv[]) {

        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(char **args, unsigned n);
        } verbs[] = {
                { "list",   LESS, 1, list_links  },
                { "status", MORE, 1, link_status },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "list" */
                i = 0;
        else {
                if (streq(argv[optind], "help")) {
                        help();
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation %s", argv[optind]);
                        return -EINVAL;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        return -EINVAL;
                }

                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }

                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        return verbs[i].dispatch(argv + optind, left);
}

int main(int argc, char* argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = networkctl_main(argc, argv);

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
