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
#include "list.h"

#define VLANID_MAX 4094

static const char* const netdev_kind_table[] = {
        [NETDEV_KIND_BRIDGE] = "bridge",
        [NETDEV_KIND_BOND] = "bond",
        [NETDEV_KIND_VLAN] = "vlan",
};

DEFINE_STRING_TABLE_LOOKUP(netdev_kind, NetDevKind);
DEFINE_CONFIG_PARSE_ENUM(config_parse_netdev_kind, netdev_kind, NetDevKind, "Failed to parse netdev kind");

void netdev_free(NetDev *netdev) {
        netdev_enslave_callback *callback;

        if (!netdev)
                return;

        while ((callback = netdev->callbacks)) {
                LIST_REMOVE(callbacks, netdev->callbacks, callback);
                free(callback);
        }

        if (netdev->name)
                hashmap_remove(netdev->manager->netdevs, netdev->name);

        free(netdev->filename);

        free(netdev->description);
        free(netdev->name);

        free(netdev);
}

int netdev_get(Manager *manager, const char *name, NetDev **ret) {
        NetDev *netdev;

        assert(manager);
        assert(name);
        assert(ret);

        netdev = hashmap_get(manager->netdevs, name);
        if (!netdev) {
                *ret = NULL;
                return -ENOENT;
        }

        *ret = netdev;

        return 0;
}

static int netdev_enter_failed(NetDev *netdev) {
        netdev->state = NETDEV_STATE_FAILED;

        return 0;
}

static int netdev_enslave_ready(NetDev *netdev, Link* link, sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(netdev);
        assert(netdev->state == NETDEV_STATE_READY);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(link);
        assert(callback);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &req,
                                     RTM_SETLINK, link->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not allocate RTM_SETLINK message: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(req, IFLA_MASTER, netdev->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_MASTER attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(netdev->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not send rtnetlink message: %s",
                                 strerror(-r));
                return r;
        }

        log_debug_netdev(netdev, "enslaving link '%s'", link->ifname);

        return 0;
}

static int netdev_enter_ready(NetDev *netdev) {
        netdev_enslave_callback *callback;

        assert(netdev);
        assert(netdev->name);

        netdev->state = NETDEV_STATE_READY;

        log_info_netdev(netdev, "netdev ready");

        LIST_FOREACH(callbacks, callback, netdev->callbacks) {
                /* enslave the links that were attempted to be enslaved befor the
                 * link was ready */
                netdev_enslave_ready(netdev, callback->link, callback->callback);
        }

        return 0;
}

static int netdev_create_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        NetDev *netdev = userdata;
        int r;

        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_rtnl_message_get_errno(m);
        if (r < 0) {
                log_warning_netdev(netdev, "netdev failed: %s", strerror(-r));
                netdev_enter_failed(netdev);

                return 1;
        }

        return 1;
}

static int netdev_create(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        const char *kind;
        int r;

        assert(netdev);
        assert(!(netdev->kind == NETDEV_KIND_VLAN) ||
               (link && callback && netdev->vlanid <= VLANID_MAX));
        assert(netdev->name);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &req, RTM_NEWLINK, 0);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not allocate RTM_NEWLINK message: %s",
                                 strerror(-r));
                return r;
        }

        if (link) {
                r = sd_rtnl_message_append_u32(req, IFLA_LINK, link->ifindex);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_LINK attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_append_string(req, IFLA_IFNAME, netdev->name);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container(req, IFLA_LINKINFO);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not open IFLA_LINKINFO container: %s",
                                 strerror(-r));
                return r;
        }

        kind = netdev_kind_to_string(netdev->kind);
        if (!kind) {
                log_error_netdev(netdev, "Invalid kind");
                return -EINVAL;
        }

        r = sd_rtnl_message_append_string(req, IFLA_INFO_KIND, kind);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_INFO_KIND attribute: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->vlanid <= VLANID_MAX) {
                r = sd_rtnl_message_open_container(req, IFLA_INFO_DATA);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not open IFLA_INFO_DATA container: %s",
                                         strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_append_u16(req, IFLA_VLAN_ID, netdev->vlanid);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_VLAN_ID attribute: %s",
                                         strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_close_container(req);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not close IFLA_INFO_DATA container %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_close_container(req);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not close IFLA_LINKINFO container %s",
                                 strerror(-r));
                return r;
        }

        if (link)
                r = sd_rtnl_call_async(netdev->manager->rtnl, req, callback, link, 0, NULL);
        else
                r = sd_rtnl_call_async(netdev->manager->rtnl, req, &netdev_create_handler, netdev, 0, NULL);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        log_debug_netdev(netdev, "creating netdev");

        netdev->state = NETDEV_STATE_CREATING;

        return 0;
}

int netdev_enslave(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback) {
        if (netdev->kind == NETDEV_KIND_VLAN)
                return netdev_create(netdev, link, callback);

        if (netdev->state == NETDEV_STATE_READY) {
                netdev_enslave_ready(netdev, link, callback);
        } else {
                /* the netdev is not yet read, save this request for when it is*/
                netdev_enslave_callback *cb;

                cb = new0(netdev_enslave_callback, 1);
                if (!cb)
                        return log_oom();

                cb->callback = callback;
                cb->link = link;

                LIST_PREPEND(callbacks, netdev->callbacks, cb);
        }

        return 0;
}

int netdev_set_ifindex(NetDev *netdev, int ifindex) {
        assert(netdev);
        assert(ifindex > 0);

        if (netdev->ifindex > 0) {
                if (netdev->ifindex == ifindex)
                        return 0;
                else
                        return -EEXIST;
        }

        netdev->ifindex = ifindex;

        netdev_enter_ready(netdev);

        return 0;
}

static int netdev_load_one(Manager *manager, const char *filename) {
        _cleanup_netdev_free_ NetDev *netdev = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        int r;

        assert(manager);
        assert(filename);

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return errno;
        }

        netdev = new0(NetDev, 1);
        if (!netdev)
                return log_oom();

        netdev->manager = manager;
        netdev->state = _NETDEV_STATE_INVALID;
        netdev->kind = _NETDEV_KIND_INVALID;
        netdev->vlanid = VLANID_MAX + 1;

        r = config_parse(NULL, filename, file, "Match\0NetDev\0VLAN\0", config_item_perf_lookup,
                        (void*) network_netdev_gperf_lookup, false, false, netdev);
        if (r < 0) {
                log_warning("Could not parse config file %s: %s", filename, strerror(-r));
                return r;
        }

        if (netdev->kind == _NETDEV_KIND_INVALID) {
                log_warning("NetDev without Kind configured in %s. Ignoring", filename);
                return 0;
        }

        if (!netdev->name) {
                log_warning("NetDev without Name configured in %s. Ignoring", filename);
                return 0;
        }

        if (netdev->kind == NETDEV_KIND_VLAN && netdev->vlanid > VLANID_MAX) {
                log_warning("VLAN without valid Id configured in %s. Ignoring", filename);
                return 0;
        }

        netdev->filename = strdup(filename);
        if (!netdev->filename)
                return log_oom();

        if (net_match_config(NULL, NULL, NULL, NULL, NULL,
                             netdev->match_host, netdev->match_virt,
                             netdev->match_kernel, netdev->match_arch,
                             NULL, NULL, NULL, NULL, NULL, NULL) <= 0)
                return 0;

        r = hashmap_put(netdev->manager->netdevs, netdev->name, netdev);
        if (r < 0)
                return r;

        LIST_HEAD_INIT(netdev->callbacks);

        if (netdev->kind != NETDEV_KIND_VLAN) {
                r = netdev_create(netdev, NULL, NULL);
                if (r < 0)
                        return r;
        }

        netdev = NULL;

        return 0;
}

int netdev_load(Manager *manager) {
        NetDev *netdev;
        char **files, **f;
        int r;

        assert(manager);

        while ((netdev = hashmap_first(manager->netdevs)))
                netdev_free(netdev);

        r = conf_files_list_strv(&files, ".netdev", NULL, network_dirs);
        if (r < 0) {
                log_error("Failed to enumerate netdev files: %s", strerror(-r));
                return r;
        }

        STRV_FOREACH_BACKWARDS(f, files) {
                r = netdev_load_one(manager, *f);
                if (r < 0)
                        return r;
        }

        strv_free(files);

        return 0;
}
