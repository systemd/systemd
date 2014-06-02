/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

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

#include <arpa/inet.h>
#include <resolv.h>
#include <linux/if.h>

#include "resolved.h"
#include "event-util.h"
#include "network-util.h"
#include "sd-dhcp-lease.h"
#include "dhcp-lease-internal.h"
#include "network-internal.h"
#include "conf-parser.h"

static int set_fallback_dns(Manager *m, const char *string) {
        char *word, *state;
        size_t length;
        int r;

        assert(m);
        assert(string);

        FOREACH_WORD_QUOTED(word, length, string, state) {
                _cleanup_free_ Address *address = NULL;
                Address *tail;
                _cleanup_free_ char *addrstr = NULL;

                address = new0(Address, 1);
                if (!address)
                        return -ENOMEM;

                addrstr = strndup(word, length);
                if (!addrstr)
                        return -ENOMEM;

                r = net_parse_inaddr(addrstr, &address->family, &address->in_addr);
                if (r < 0) {
                        log_debug("Ignoring invalid DNS address '%s'", addrstr);
                        continue;
                }

                LIST_FIND_TAIL(addresses, m->fallback_dns, tail);
                LIST_INSERT_AFTER(addresses, m->fallback_dns, tail, address);
                address = NULL;
        }

        return 0;
}

int config_parse_dnsv(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Manager *m = userdata;
        Address *address;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(m);

        while ((address = m->fallback_dns)) {
                LIST_REMOVE(addresses, m->fallback_dns, address);
                free(address);
        }

        set_fallback_dns(m, rvalue);

        return 0;
}

static int manager_parse_config_file(Manager *m) {
        static const char fn[] = "/etc/systemd/resolved.conf";
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);

        f = fopen(fn, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open configuration file %s: %m", fn);
                return -errno;
        }

        r = config_parse(NULL, fn, f, "Resolve\0", config_item_perf_lookup,
                         (void*) resolved_gperf_lookup, false, false, m);
        if (r < 0)
                log_warning("Failed to parse configuration file: %s", strerror(-r));

        return r;
}

int manager_new(Manager **ret) {
        _cleanup_manager_free_ Manager *m = NULL;
        int r;

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = set_fallback_dns(m, DNS_SERVERS);
        if (r < 0)
                return r;

        r = manager_parse_config_file(m);
        if (r < 0)
                return r;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        sd_event_add_signal(m->event, NULL, SIGTERM, NULL,  NULL);
        sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

        sd_event_set_watchdog(m->event, true);

        *ret = m;
        m = NULL;

        return 0;
}

void manager_free(Manager *m) {
        Address *address;

        if (!m)
                return;

        sd_event_unref(m->event);

        while ((address = m->fallback_dns)) {
                LIST_REMOVE(addresses, m->fallback_dns, address);
                free(address);
        }

        free(m);
}

static void append_dns(FILE *f, void *dns, unsigned char family, unsigned *count) {
        char buf[INET6_ADDRSTRLEN];
        const char *address;

        assert(f);
        assert(dns);
        assert(count);

        address = inet_ntop(family, dns, buf, INET6_ADDRSTRLEN);
        if (!address) {
                log_warning("Invalid DNS address. Ignoring.");
                return;
        }

        if (*count == MAXNS)
                fputs("# Too many DNS servers configured, the following entries "
                      "may be ignored\n", f);

        fprintf(f, "nameserver %s\n", address);

        (*count) ++;
}

int manager_update_resolv_conf(Manager *m) {
        const char *path = "/run/systemd/resolve/resolv.conf";
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
         _cleanup_free_ unsigned *indices = NULL;
        Address *address;
        unsigned count = 0;
        int n, r, i;

        assert(m);

        r = fopen_temporary(path, &f, &temp_path);
        if (r < 0)
                return r;

        fchmod(fileno(f), 0644);

        fputs("# This file is managed by systemd-resolved(8). Do not edit.\n#\n"
              "# Third party programs must not access this file directly, but\n"
              "# only through the symlink at /etc/resolv.conf. To manage\n"
              "# resolv.conf(5) in a different way, replace the symlink by a\n"
              "# static file or a different symlink.\n\n", f);

        n = sd_network_get_ifindices(&indices);
        if (n < 0)
                n = 0;

        for (i = 0; i < n; i++) {
                _cleanup_dhcp_lease_unref_ sd_dhcp_lease *lease = NULL;
                struct in_addr *nameservers;
                struct in6_addr *nameservers6;
                size_t nameservers_size;

                r = sd_network_dhcp_use_dns(indices[i]);
                if (r > 0) {
                        r = sd_network_get_dhcp_lease(indices[i], &lease);
                        if (r >= 0) {
                                r = sd_dhcp_lease_get_dns(lease, &nameservers, &nameservers_size);
                                if (r >= 0) {
                                        unsigned j;

                                        for (j = 0; j < nameservers_size; j++)
                                                append_dns(f, &nameservers[j], AF_INET, &count);
                                }
                        }
                }

                r = sd_network_get_dns(indices[i], &nameservers, &nameservers_size);
                if (r >= 0) {
                        unsigned j;

                        for (j = 0; j < nameservers_size; j++)
                                append_dns(f, &nameservers[j], AF_INET, &count);

                        free(nameservers);
                }

                r = sd_network_get_dns6(indices[i], &nameservers6, &nameservers_size);
                if (r >= 0) {
                        unsigned j;

                        for (j = 0; j < nameservers_size; j++)
                                append_dns(f, &nameservers6[j], AF_INET6, &count);

                        free(nameservers6);
                }
        }

        LIST_FOREACH(addresses, address, m->fallback_dns)
                append_dns(f, &address->in_addr, address->family, &count);

        fflush(f);

        if (ferror(f) || rename(temp_path, path) < 0) {
                r = -errno;
                unlink(path);
                unlink(temp_path);
                return r;
        }

        return 0;
}

static int manager_network_event_handler(sd_event_source *s, int fd, uint32_t revents,
                                         void *userdata) {
        Manager *m = userdata;
        int r;

        assert(m);

        r = manager_update_resolv_conf(m);
        if (r < 0)
                log_warning("Could not update resolv.conf: %s", strerror(-r));

        sd_network_monitor_flush(m->network_monitor);

        return 0;
}

int manager_network_monitor_listen(Manager *m) {
        _cleanup_event_source_unref_ sd_event_source *event_source = NULL;
        _cleanup_network_monitor_unref_ sd_network_monitor *monitor = NULL;
        int r, fd, events;

        r = sd_network_monitor_new(NULL, &monitor);
        if (r < 0)
                return r;

        fd = sd_network_monitor_get_fd(monitor);
        if (fd < 0)
                return fd;

        events = sd_network_monitor_get_events(monitor);
        if (events < 0)
                return events;

        r = sd_event_add_io(m->event, &event_source, fd, events,
                            &manager_network_event_handler, m);
        if (r < 0)
                return r;

        m->network_monitor = monitor;
        m->network_event_source = event_source;
        monitor = NULL;
        event_source = NULL;

        return 0;
}
