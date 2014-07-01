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

#include <sys/socket.h>
#include <linux/if.h>

#include "conf-parser.h"
#include "path-util.h"
#include "networkd.h"
#include "network-internal.h"
#include "libudev-private.h"
#include "udev-util.h"
#include "rtnl-util.h"
#include "mkdir.h"
#include "virt.h"

#include "sd-rtnl.h"

const char* const network_dirs[] = {
        "/etc/systemd/network",
        "/run/systemd/network",
        "/usr/lib/systemd/network",
#ifdef HAVE_SPLIT_USR
        "/lib/systemd/network",
#endif
        NULL};

static int dispatch_sigterm(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = userdata;

        assert(m);

        log_received_signal(LOG_INFO, si);

        sd_event_exit(m->event, 0);
        return 0;
}

static int setup_signals(Manager *m) {
        sigset_t mask;
        int r;

        assert(m);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        r = sd_event_add_signal(m->event, &m->sigterm_event_source, SIGTERM, dispatch_sigterm, m);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, &m->sigint_event_source, SIGINT, dispatch_sigterm, m);
        if (r < 0)
                return r;

        return 0;
}

static int setup_default_address_pool(Manager *m) {
        AddressPool *p;
        int r;

        assert(m);

        /* Add in the well-known private address ranges. */

        r = address_pool_new_from_string(m, &p, AF_INET6, "fc00::", 7);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "192.168.0.0", 16);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "172.16.0.0", 12);
        if (r < 0)
                return r;

        r = address_pool_new_from_string(m, &p, AF_INET, "10.0.0.0", 8);
        if (r < 0)
                return r;

        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_manager_free_ Manager *m = NULL;
        int r;

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->state_file = strdup("/run/systemd/netif/state");
        if (!m->state_file)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        sd_event_set_watchdog(m->event, true);

        r = sd_rtnl_open(&m->rtnl, 3, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR,
                         RTNLGRP_IPV6_IFADDR);
        if (r < 0)
                return r;

        r = sd_bus_default_system(&m->bus);
        if (r < 0 && r != -ENOENT) /* TODO: drop when we can rely on kdbus */
                return r;

        r = setup_signals(m);
        if (r < 0)
                return r;

        /* udev does not initialize devices inside containers,
         * so we rely on them being already initialized before
         * entering the container */
        if (detect_container(NULL) <= 0) {
                m->udev = udev_new();
                if (!m->udev)
                        return -ENOMEM;

                m->udev_monitor = udev_monitor_new_from_netlink(m->udev, "udev");
                if (!m->udev_monitor)
                        return -ENOMEM;
        }

        m->links = hashmap_new(uint64_hash_func, uint64_compare_func);
        if (!m->links)
                return -ENOMEM;

        m->netdevs = hashmap_new(string_hash_func, string_compare_func);
        if (!m->netdevs)
                return -ENOMEM;

        LIST_HEAD_INIT(m->networks);

        r = setup_default_address_pool(m);
        if (r < 0)
                return r;

        *ret = m;
        m = NULL;

        return 0;
}

void manager_free(Manager *m) {
        Network *network;
        NetDev *netdev;
        Link *link;
        AddressPool *pool;

        if (!m)
                return;

        free(m->state_file);

        udev_monitor_unref(m->udev_monitor);
        udev_unref(m->udev);
        sd_bus_unref(m->bus);
        sd_event_source_unref(m->udev_event_source);
        sd_event_source_unref(m->sigterm_event_source);
        sd_event_source_unref(m->sigint_event_source);
        sd_event_unref(m->event);

        while ((link = hashmap_first(m->links)))
                link_unref(link);
        hashmap_free(m->links);

        while ((network = m->networks))
                network_free(network);

        while ((netdev = hashmap_first(m->netdevs)))
                netdev_unref(netdev);
        hashmap_free(m->netdevs);

        while ((pool = m->address_pools))
                address_pool_free(pool);

        sd_rtnl_unref(m->rtnl);

        free(m);
}

int manager_load_config(Manager *m) {
        int r;

        /* update timestamp */
        paths_check_timestamp(network_dirs, &m->network_dirs_ts_usec, true);

        r = netdev_load(m);
        if (r < 0)
                return r;

        r = network_load(m);
        if (r < 0)
                return r;

        return 0;
}

bool manager_should_reload(Manager *m) {
        return paths_check_timestamp(network_dirs, &m->network_dirs_ts_usec, false);
}

static int manager_udev_process_link(Manager *m, struct udev_device *device) {
        Link *link = NULL;
        int r, ifindex;

        assert(m);
        assert(device);

        if (!streq_ptr(udev_device_get_action(device), "add"))
                return 0;

        ifindex = udev_device_get_ifindex(device);
        if (ifindex <= 0) {
                log_debug("ignoring udev ADD event for device with invalid ifindex");
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r == -ENODEV)
                return 0;
        else if (r < 0)
                return r;

        r = link_initialized(link, device);
        if (r < 0)
                return r;

        return 0;
}

static int manager_rtnl_process_link(sd_rtnl *rtnl, sd_rtnl_message *message, void *userdata) {
        Manager *m = userdata;
        Link *link = NULL;
        NetDev *netdev = NULL;
        uint16_t type;
        char *name;
        int r, ifindex;

        assert(rtnl);
        assert(message);
        assert(m);

        r = sd_rtnl_message_get_type(message, &type);
        if (r < 0) {
                log_warning("rtnl: could not get message type");
                return 0;
        }

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0 || ifindex <= 0) {
                log_warning("rtnl: received link message without valid ifindex");
                return 0;
        } else
                link_get(m, ifindex, &link);

        r = sd_rtnl_message_read_string(message, IFLA_IFNAME, &name);
        if (r < 0 || !name) {
                log_warning("rtnl: received link message without valid ifname");
                return 0;
        } else
                netdev_get(m, name, &netdev);

        switch (type) {
        case RTM_NEWLINK:
                if (!link) {
                        /* link is new, so add it */
                        r = link_add(m, message, &link);
                        if (r < 0) {
                                log_debug("could not add new link: %s",
                                           strerror(-r));
                                return 0;
                        }
                }

                if (netdev) {
                        /* netdev exists, so make sure the ifindex matches */
                        r = netdev_set_ifindex(netdev, message);
                        if (r < 0) {
                                log_debug("could not set ifindex on netdev");
                                return 0;
                        }
                }

                r = link_update(link, message);
                if (r < 0)
                        return 0;

                break;

        case RTM_DELLINK:
                link_drop(link);
                netdev_drop(netdev);

                break;

        default:
                assert_not_reached("Received invalid RTNL message type.");
        }

        return 1;
}

int manager_rtnl_enumerate_links(Manager *m) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;
        sd_rtnl_message *link;
        int r, k;

        assert(m);
        assert(m->rtnl);

        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_rtnl_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (link = reply; link; link = sd_rtnl_message_next(link)) {
                uint16_t type;

                k = sd_rtnl_message_get_type(link, &type);
                if (k < 0)
                        return k;

                if (type != RTM_NEWLINK)
                        continue;

                k = manager_rtnl_process_link(m->rtnl, link, m);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int manager_dispatch_link_udev(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        struct udev_monitor *monitor = m->udev_monitor;
        _cleanup_udev_device_unref_ struct udev_device *device = NULL;

        device = udev_monitor_receive_device(monitor);
        if (!device)
                return -ENOMEM;

        manager_udev_process_link(m, device);
        return 0;
}

int manager_udev_listen(Manager *m) {
        int r;

        if (detect_container(NULL) > 0)
                return 0;

        assert(m->udev_monitor);

        r = udev_monitor_filter_add_match_subsystem_devtype(m->udev_monitor, "net", NULL);
        if (r < 0) {
                log_error("Could not add udev monitor filter: %s", strerror(-r));
                return r;
        }

        r = udev_monitor_enable_receiving(m->udev_monitor);
        if (r < 0) {
                log_error("Could not enable udev monitor");
                return r;
        }

        r = sd_event_add_io(m->event,
                        &m->udev_event_source,
                        udev_monitor_get_fd(m->udev_monitor),
                        EPOLLIN, manager_dispatch_link_udev,
                        m);
        if (r < 0)
                return r;

        return 0;
}

int manager_rtnl_listen(Manager *m) {
        int r;

        assert(m);

        r = sd_rtnl_attach_event(m->rtnl, m->event, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_NEWLINK, &manager_rtnl_process_link, m);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_DELLINK, &manager_rtnl_process_link, m);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_NEWADDR, &link_rtnl_process_address, m);
        if (r < 0)
                return r;

        r = sd_rtnl_add_match(m->rtnl, RTM_DELADDR, &link_rtnl_process_address, m);
        if (r < 0)
                return r;

        return 0;
}

int manager_bus_listen(Manager *m) {
        int r;

        assert(m->event);

        if (!m->bus) /* TODO: drop when we can rely on kdbus */
                return 0;

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return r;

        return 0;
}

int manager_save(Manager *m) {
        Link *link;
        Iterator i;
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        LinkOperationalState operstate = LINK_OPERSTATE_UNKNOWN;
        const char *operstate_str;
        int r;

        assert(m);
        assert(m->state_file);

        HASHMAP_FOREACH(link, m->links, i) {
                if (link->flags & IFF_LOOPBACK)
                        continue;

                if (link->operstate > operstate)
                        operstate = link->operstate;
        }

        operstate_str = link_operstate_to_string(operstate);
        assert(operstate_str);

        r = fopen_temporary(m->state_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "OPER_STATE=%s\n", operstate_str);

        fflush(f);

        if (ferror(f) || rename(temp_path, m->state_file) < 0) {
                r = -errno;
                unlink(m->state_file);
                unlink(temp_path);
        }

finish:
        if (r < 0)
                log_error("Failed to save network state to %s: %s", m->state_file, strerror(-r));

        return r;
}

int manager_address_pool_acquire(Manager *m, unsigned family, unsigned prefixlen, union in_addr_union *found) {
        AddressPool *p;
        int r;

        assert(m);
        assert(prefixlen > 0);
        assert(found);

        LIST_FOREACH(address_pools, p, m->address_pools) {
                if (p->family != family)
                        continue;

                r = address_pool_acquire(p, prefixlen, found);
                if (r != 0)
                        return r;
        }

        return 0;
}
