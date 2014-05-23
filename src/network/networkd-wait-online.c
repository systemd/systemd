/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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
#include <linux/if.h>
#include <getopt.h>

#include "sd-event.h"
#include "event-util.h"
#include "sd-rtnl.h"
#include "rtnl-util.h"
#include "sd-daemon.h"
#include "sd-network.h"
#include "network-util.h"
#include "network-internal.h"
#include "networkd-wait-online.h"

#include "conf-parser.h"
#include "strv.h"
#include "util.h"
#include "build.h"

static bool arg_quiet = false;
static char **arg_interfaces = NULL;

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Block until network is configured.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "  -q --quiet                Do not show status information\n"
               "  -i --interface=INTERFACE  Block until at least these interfaces have appeared\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'         },
                { "version",         no_argument,       NULL, ARG_VERSION },
                { "quiet",           no_argument,       NULL, 'q'         },
                { "interface",       required_argument, NULL, 'i'         },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hq", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'i':
                        if (strv_extend(&arg_interfaces, optarg) < 0)
                                return log_oom();

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

static bool all_configured(Manager *m) {
        _cleanup_free_ unsigned *indices = NULL;
        char **ifname;
        bool one_ready = false;
        int r, n, i;

        n = sd_network_get_ifindices(&indices);
        if (n <= 0)
                return false;

        /* wait for networkd to be aware of all the links given on the commandline */
        STRV_FOREACH(ifname, arg_interfaces) {
                _cleanup_rtnl_message_unref_ sd_rtnl_message *message = NULL, *reply = NULL;
                bool found = false;
                int index;

                r = sd_rtnl_message_new_link(m->rtnl, &message, RTM_GETLINK, 0);
                if (r < 0) {
                        log_warning("could not create GETLINK message: %s", strerror(-r));
                        return false;
                }

                r = sd_rtnl_message_append_string(message, IFLA_IFNAME, *ifname);
                if (r < 0) {
                        log_warning("could not attach ifname to GETLINK message: %s", strerror(-r));
                        return false;
                }

                r = sd_rtnl_call(m->rtnl, message, 0, &reply);
                if (r < 0) {
                        if (r != -ENODEV)
                                log_warning("could not get link info for %s: %s", *ifname,
                                            strerror(-r));

                        /* link does not yet exist */
                        return false;
                }

                r = sd_rtnl_message_link_get_ifindex(reply, &index);
                if (r < 0) {
                        log_warning("could not get ifindex: %s", strerror(-r));
                        return false;
                }

                if (index <= 0) {
                        log_warning("invalid ifindex %d for %s", index, *ifname);
                        return false;
                }

                for (i = 0; i < n; i++) {
                        if (indices[i] == (unsigned) index) {
                                found = true;
                                break;
                        }
                }

                if (!found) {
                        /* link exists, but networkd is not yet aware of it */
                        return false;
                }
        }

        /* wait for all links networkd manages to be in admin state 'configured'
           and at least one link to gain a carrier */
        for (i = 0; i < n; i++) {
                _cleanup_free_ char *state = NULL, *oper_state = NULL;

                if (sd_network_link_is_loopback(indices[i]))
                        /* ignore loopback devices */
                        continue;

                r = sd_network_get_link_state(indices[i], &state);
                if (r == -EBUSY || (r >= 0 && !streq(state, "configured")))
                        /* not yet processed by udev, or managed by networkd, but not yet configured */
                        return false;

                r = sd_network_get_link_operational_state(indices[i], &oper_state);
                if (r >= 0 &&
                    (streq(oper_state, "degraded") ||
                     streq(oper_state, "routable")))
                        /* we wait for at least one link to be ready,
                           regardless of who manages it */
                        one_ready = true;
        }

        return one_ready;
}

static int monitor_event_handler(sd_event_source *s, int fd, uint32_t revents,
                         void *userdata) {
        Manager *m = userdata;

        assert(m);
        assert(m->event);

        if (all_configured(m))
                sd_event_exit(m->event, 0);

        sd_network_monitor_flush(m->monitor);

        return 1;
}

void manager_free(Manager *m) {
        if (!m)
                return;

        sd_event_unref(m->event);
        sd_rtnl_unref(m->rtnl);

        free(m);
}

int main(int argc, char *argv[]) {
        _cleanup_manager_free_ Manager *m = NULL;
        _cleanup_event_source_unref_ sd_event_source *event_source = NULL;
        int r, fd, events;

        umask(0022);

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_quiet)
                log_set_max_level(LOG_WARNING);

        m = new0(Manager, 1);
        if (!m)
                return log_oom();

        r = sd_event_new(&m->event);
        if (r < 0) {
                log_error("Could not create event: %s", strerror(-r));
                goto out;
        }

        r = sd_rtnl_open(&m->rtnl, 0);
        if (r < 0) {
                log_error("Could not create rtnl: %s", strerror(-r));
                goto out;
        }

        r = sd_network_monitor_new(NULL, &m->monitor);
        if (r < 0) {
                log_error("Could not create monitor: %s", strerror(-r));
                goto out;
        }

        fd = sd_network_monitor_get_fd(m->monitor);
        if (fd < 0) {
                log_error("Could not get monitor fd: %s", strerror(-r));
                goto out;
        }

        events = sd_network_monitor_get_events(m->monitor);
        if (events < 0) {
                log_error("Could not get monitor events: %s", strerror(-r));
                goto out;
        }

        r = sd_event_add_io(m->event, &event_source, fd, events, &monitor_event_handler,
                            m);
        if (r < 0) {
                log_error("Could not add io event source: %s", strerror(-r));
                goto out;
        }

        if (all_configured(m)) {
                r = 0;
                goto out;
        }

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Waiting for network connections...");

        r = sd_event_loop(m->event);
        if (r < 0) {
                log_error("Event loop failed: %s", strerror(-r));
                goto out;
        }

out:
        sd_notify(false,
                  "STATUS=All interfaces configured...");

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
