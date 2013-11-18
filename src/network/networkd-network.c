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

#include "networkd.h"
#include "net-util.h"
#include "path-util.h"
#include "conf-files.h"
#include "conf-parser.h"

static int network_load_one(Manager *manager, const char *filename) {
        _cleanup_network_free_ Network *network = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        int r;

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return errno;
        }

        network = new0(Network, 1);
        if (!network)
                return log_oom();

        LIST_HEAD_INIT(network->addresses);

        r = config_parse(NULL, filename, file, "Match\0Network\0", config_item_perf_lookup,
                        (void*) network_gperf_lookup, false, false, network);
        if (r < 0) {
                log_warning("Could not parse config file %s: %s", filename, strerror(-r));
                return r;
        } else
                log_debug("Parsed configuration file %s", filename);

        network->filename = strdup(filename);
        if (!network->filename)
                return log_oom();

        network->manager = manager;

        LIST_PREPEND(networks, manager->networks, network);
        network = NULL;

        return 0;
}

int network_load(Manager *manager) {
        Network *network;
        char **files, **f;
        int r;

        assert(manager);

        while ((network = manager->networks))
                network_free(network);

        /* update timestamp */
        paths_check_timestamp(manager->network_dirs, &manager->network_dirs_ts_usec, true);

        r = conf_files_list_strv(&files, ".network", NULL, (const char **)manager->network_dirs);
        if (r < 0) {
                log_error("failed to enumerate network files: %s", strerror(-r));
                return r;
        }

        STRV_FOREACH_BACKWARDS(f, files) {
                r = network_load_one(manager, *f);
                if (r < 0)
                        return r;
        }

        strv_free(files);

        return 0;
}

bool network_should_reload(Manager *manager) {
        return paths_check_timestamp(manager->network_dirs, &manager->network_dirs_ts_usec, false);
}

void network_free(Network *network) {
        Route *route;
        Address *address;

        if (!network)
                return;

        free(network->filename);

        free(network->match_mac);
        free(network->match_path);
        free(network->match_driver);
        free(network->match_type);
        free(network->match_name);

        free(network->description);

        while ((route = network->routes))
                route_free(route);

        while ((address = network->addresses))
                address_free(address);

        LIST_REMOVE(networks, network->manager->networks, network);

        free(network);
}

int network_get(Manager *manager, struct udev_device *device, Network **ret) {
        Network *network;

        assert(manager);
        assert(device);
        assert(ret);

        if (network_should_reload(manager))
                network_load(manager);

        LIST_FOREACH(networks, network, manager->networks) {
                if (net_match_config(network->match_mac, network->match_path,
                                        network->match_driver, network->match_type,
                                        network->match_name,
                                        udev_device_get_sysattr_value(device, "address"),
                                        udev_device_get_property_value(device, "ID_PATH"),
                                        udev_device_get_driver(device),
                                        udev_device_get_devtype(device),
                                        udev_device_get_sysname(device))) {
                        log_debug("Network file %s applies to link %s",
                                        network->filename,
                                        udev_device_get_sysname(device));
                        *ret = network;
                        return 0;
                }
        }

        *ret = NULL;

        return -ENOENT;
}

int network_apply(Manager *manager, Network *network, Link *link) {
        int r;

        log_info("Network '%s' being applied to link '%u'",
                        network->description, (unsigned) link->ifindex);

        link->network = network;

        r = link_configure(link);
        if (r < 0)
                return r;

        return 0;
}
