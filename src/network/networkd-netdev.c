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

#include <net/if.h>

#include "networkd.h"
#include "network-internal.h"
#include "path-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "list.h"

#define VLANID_MAX 4094

static const char* const netdev_kind_table[_NETDEV_KIND_MAX] = {
        [NETDEV_KIND_BRIDGE] = "bridge",
        [NETDEV_KIND_BOND] = "bond",
        [NETDEV_KIND_VLAN] = "vlan",
        [NETDEV_KIND_MACVLAN] = "macvlan",
        [NETDEV_KIND_IPIP] = "ipip",
        [NETDEV_KIND_GRE] = "gre",
        [NETDEV_KIND_SIT] = "sit",
};

DEFINE_STRING_TABLE_LOOKUP(netdev_kind, NetDevKind);
DEFINE_CONFIG_PARSE_ENUM(config_parse_netdev_kind, netdev_kind, NetDevKind, "Failed to parse netdev kind");

static const char* const macvlan_mode_table[_NETDEV_MACVLAN_MODE_MAX] = {
        [NETDEV_MACVLAN_MODE_PRIVATE] = "private",
        [NETDEV_MACVLAN_MODE_VEPA] = "vepa",
        [NETDEV_MACVLAN_MODE_BRIDGE] = "bridge",
        [NETDEV_MACVLAN_MODE_PASSTHRU] = "passthru",
};

DEFINE_STRING_TABLE_LOOKUP(macvlan_mode, MacVlanMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_macvlan_mode, macvlan_mode, MacVlanMode, "Failed to parse macvlan mode");

static void netdev_cancel_callbacks(NetDev *netdev) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        netdev_enslave_callback *callback;

        if (!netdev)
                return;

        rtnl_message_new_synthetic_error(-ENODEV, 0, &m);

        while ((callback = netdev->callbacks)) {
                if (m) {
                        assert(callback->link);
                        assert(callback->callback);
                        assert(netdev->manager);
                        assert(netdev->manager->rtnl);

                        callback->callback(netdev->manager->rtnl, m, link);
                }

                LIST_REMOVE(callbacks, netdev->callbacks, callback);
                free(callback);
        }
}

static void netdev_free(NetDev *netdev) {
        if (!netdev)
                return;

        netdev_cancel_callbacks(netdev);

        if (netdev->ifname)
                hashmap_remove(netdev->manager->netdevs, netdev->ifname);

        free(netdev->filename);

        free(netdev->description);
        free(netdev->ifname);

        condition_free_list(netdev->match_host);
        condition_free_list(netdev->match_virt);
        condition_free_list(netdev->match_kernel);
        condition_free_list(netdev->match_arch);

        free(netdev);
}

NetDev *netdev_unref(NetDev *netdev) {
        if (netdev && (-- netdev->n_ref <= 0))
                netdev_free(netdev);

        return NULL;
}

NetDev *netdev_ref(NetDev *netdev) {
        if (netdev)
                assert_se(++ netdev->n_ref >= 2);

        return netdev;
}

void netdev_drop(NetDev *netdev) {
        if (!netdev || netdev->state == NETDEV_STATE_LINGER)
                return;

        netdev->state = NETDEV_STATE_LINGER;

        log_debug_netdev(netdev, "netdev removed");

        netdev_cancel_callbacks(netdev);

        netdev_unref(netdev);

        return;
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
        assert(netdev->ifname);

        if (netdev->state != NETDEV_STATE_CREATING)
                return 0;

        netdev->state = NETDEV_STATE_READY;

        log_info_netdev(netdev, "netdev ready");

        LIST_FOREACH(callbacks, callback, netdev->callbacks) {
                /* enslave the links that were attempted to be enslaved before the
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
        if (r == -EEXIST)
                log_debug_netdev(netdev, "netdev exists, using existing");
        else if (r < 0) {
                log_warning_netdev(netdev, "netdev could not be created: %s", strerror(-r));
                netdev_drop(netdev);

                return 1;
        }

        return 1;
}

int config_parse_tunnel_address(const char *unit,
                                const char *filename,
                                unsigned line,
                                const char *section,
                                unsigned section_line,
                                const char *lvalue,
                                int ltype,
                                const char *rvalue,
                                void *data,
                                void *userdata) {
        NetDev *n = data;
        unsigned char family = AF_INET;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = net_parse_inaddr(rvalue, &family, n);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Tunnel address is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }
       return 0;
}

static int netdev_create(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        const char *kind;
        int r;

        assert(netdev);
        assert(!(netdev->kind == NETDEV_KIND_VLAN || netdev->kind == NETDEV_KIND_MACVLAN) ||
               (link && callback));
        assert(netdev->ifname);
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

        r = sd_rtnl_message_append_string(req, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME attribute: %s",
                                 strerror(-r));
                return r;
        }

        if(netdev->mtu) {
                r = sd_rtnl_message_append_u32(req, IFLA_MTU, netdev->mtu);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_MTU attribute: %s",
                                         strerror(-r));
                        return r;
                }
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

        r = sd_rtnl_message_open_container_union(req, IFLA_INFO_DATA, kind);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not open IFLA_INFO_DATA container: %s",
                                  strerror(-r));
                return r;
        }

        if (netdev->vlanid <= VLANID_MAX) {
                r = sd_rtnl_message_append_u16(req, IFLA_VLAN_ID, netdev->vlanid);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_VLAN_ID attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if (netdev->macvlan_mode != _NETDEV_MACVLAN_MODE_INVALID) {
        r = sd_rtnl_message_append_u32(req, IFLA_MACVLAN_MODE, netdev->macvlan_mode);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_MACVLAN_MODE attribute: %s",
                                 strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_close_container(req);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not close IFLA_INFO_DATA container %s",
                                 strerror(-r));
                return r;
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
        int r;

        if (netdev->kind == NETDEV_KIND_VLAN || netdev->kind == NETDEV_KIND_MACVLAN)
                return netdev_create(netdev, link, callback);

        if(netdev->kind == NETDEV_KIND_IPIP ||
           netdev->kind == NETDEV_KIND_GRE ||
           netdev->kind ==  NETDEV_KIND_SIT)
                return netdev_create_tunnel(link, netdev_create_handler);

        if (netdev->state == NETDEV_STATE_READY) {
                r = netdev_enslave_ready(netdev, link, callback);
                if (r < 0)
                        return r;
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

int netdev_set_ifindex(NetDev *netdev, sd_rtnl_message *message) {
        uint16_t type;
        const char *kind;
        char *received_kind;
        char *received_name;
        int r, ifindex;

        assert(netdev);
        assert(message);

        r = sd_rtnl_message_get_type(message, &type);
        if (r < 0) {
                log_error_netdev(netdev, "Could not get rtnl message type");
                return r;
        }

        if (type != RTM_NEWLINK) {
                log_error_netdev(netdev, "Can not set ifindex from unexpected rtnl message type");
                return -EINVAL;
        }

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_error_netdev(netdev, "Could not get ifindex: %s", strerror(-r));
                netdev_enter_failed(netdev);
                return r;
        } else if (ifindex <= 0) {
                log_error_netdev(netdev, "Got invalid ifindex: %d", ifindex);
                netdev_enter_failed(netdev);
                return r;
        }


        if (netdev->ifindex > 0) {
                if (netdev->ifindex != ifindex) {
                        log_error_netdev(netdev, "Could not set ifindex to %d, already set to %d",
                                         ifindex, netdev->ifindex);
                        netdev_enter_failed(netdev);
                        return -EEXIST;
                } else
                        /* ifindex already set to the same for this netdev */
                        return 0;
        }

        r = sd_rtnl_message_read_string(message, IFLA_IFNAME, &received_name);
        if (r < 0) {
                log_error_netdev(netdev, "Could not get IFNAME");
                return r;
        }

        if (!streq(netdev->ifname, received_name)) {
                log_error_netdev(netdev, "Received newlink with wrong IFNAME %s",
                                 received_name);
                netdev_enter_failed(netdev);
                return r;
        }

        r = sd_rtnl_message_enter_container(message, IFLA_LINKINFO);
        if (r < 0) {
                log_error_netdev(netdev, "Could not get LINKINFO");
                return r;
        }

        r = sd_rtnl_message_read_string(message, IFLA_INFO_KIND, &received_kind);
        if (r < 0) {
                log_error_netdev(netdev, "Could not get KIND");
                return r;
        }

        r = sd_rtnl_message_exit_container(message);
        if (r < 0) {
                log_error_netdev(netdev, "Could not exit container");
                return r;
        }

        kind = netdev_kind_to_string(netdev->kind);
        if (!kind) {
                log_error_netdev(netdev, "Could not get kind");
                netdev_enter_failed(netdev);
                return -EINVAL;
        }

        if (!streq(kind, received_kind)) {
                log_error_netdev(netdev, "Received newlink with wrong KIND %s, "
                                 "expected %s", received_kind, kind);
                netdev_enter_failed(netdev);
                return r;
        }

        netdev->ifindex = ifindex;

        log_debug_netdev(netdev, "netdev has index %d", netdev->ifindex);

        netdev_enter_ready(netdev);

        return 0;
}

static int netdev_load_one(Manager *manager, const char *filename) {
        _cleanup_netdev_unref_ NetDev *netdev = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        int r;

        assert(manager);
        assert(filename);

        if (null_or_empty_path(filename)) {
                log_debug("skipping empty file: %s", filename);
                return 0;
        }

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return -errno;
        }

        netdev = new0(NetDev, 1);
        if (!netdev)
                return log_oom();

        netdev->n_ref = 1;
        netdev->manager = manager;
        netdev->state = _NETDEV_STATE_INVALID;
        netdev->kind = _NETDEV_KIND_INVALID;
        netdev->macvlan_mode = _NETDEV_MACVLAN_MODE_INVALID;
        netdev->vlanid = VLANID_MAX + 1;

        r = config_parse(NULL, filename, file, "Match\0NetDev\0VLAN\0MACVLAN\0Tunnel\0",
                         config_item_perf_lookup, (void*) network_netdev_gperf_lookup,
                         false, false, netdev);
        if (r < 0) {
                log_warning("Could not parse config file %s: %s", filename, strerror(-r));
                return r;
        }

        if (netdev->kind == _NETDEV_KIND_INVALID) {
                log_warning("NetDev without Kind configured in %s. Ignoring", filename);
                return 0;
        }

        if (!netdev->ifname) {
                log_warning("NetDev without Name configured in %s. Ignoring", filename);
                return 0;
        }

        if (netdev->kind == NETDEV_KIND_VLAN && netdev->vlanid > VLANID_MAX) {
                log_warning("VLAN without valid Id configured in %s. Ignoring", filename);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_VLAN && netdev->vlanid <= VLANID_MAX) {
                log_warning("VLAN Id configured for a %s in %s. Ignoring",
                            netdev_kind_to_string(netdev->kind), filename);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_MACVLAN &&
            netdev->macvlan_mode != _NETDEV_MACVLAN_MODE_INVALID) {
                log_warning("MACVLAN Mode configured for a %s in %s. Ignoring",
                            netdev_kind_to_string(netdev->kind), filename);
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

        r = hashmap_put(netdev->manager->netdevs, netdev->ifname, netdev);
        if (r < 0)
                return r;

        LIST_HEAD_INIT(netdev->callbacks);

        if (netdev->kind != NETDEV_KIND_VLAN &&
            netdev->kind != NETDEV_KIND_MACVLAN &&
            netdev->kind != NETDEV_KIND_IPIP &&
            netdev->kind != NETDEV_KIND_GRE &&
            netdev->kind != NETDEV_KIND_SIT) {
                r = netdev_create(netdev, NULL, NULL);
                if (r < 0)
                        return r;
        }

        log_debug_netdev(netdev, "loaded %s", netdev_kind_to_string(netdev->kind));

        netdev = NULL;

        return 0;
}

int netdev_load(Manager *manager) {
        NetDev *netdev;
        char **files, **f;
        int r;

        assert(manager);

        while ((netdev = hashmap_first(manager->netdevs)))
                netdev_unref(netdev);

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
