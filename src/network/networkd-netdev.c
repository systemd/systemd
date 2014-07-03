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
#include "siphash24.h"

static const char* const netdev_kind_table[_NETDEV_KIND_MAX] = {
        [NETDEV_KIND_BRIDGE] = "bridge",
        [NETDEV_KIND_BOND] = "bond",
        [NETDEV_KIND_VLAN] = "vlan",
        [NETDEV_KIND_MACVLAN] = "macvlan",
        [NETDEV_KIND_VXLAN] = "vxlan",
        [NETDEV_KIND_IPIP] = "ipip",
        [NETDEV_KIND_GRE] = "gre",
        [NETDEV_KIND_SIT] = "sit",
        [NETDEV_KIND_VETH] = "veth",
        [NETDEV_KIND_VTI] = "vti",
        [NETDEV_KIND_DUMMY] = "dummy",
        [NETDEV_KIND_TUN] = "tun",
        [NETDEV_KIND_TAP] = "tap",
};

DEFINE_STRING_TABLE_LOOKUP(netdev_kind, NetDevKind);
DEFINE_CONFIG_PARSE_ENUM(config_parse_netdev_kind, netdev_kind, NetDevKind, "Failed to parse netdev kind");

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
        free(netdev->ifname_peer);
        free(netdev->mac);
        free(netdev->mac_peer);
        free(netdev->user_name);
        free(netdev->group_name);

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

        link_ref(link);

        log_debug_netdev(netdev, "enslaving link '%s'", link->ifname);

        return 0;
}

static int netdev_enter_ready(NetDev *netdev) {
        netdev_enslave_callback *callback, *callback_next;
        int r;

        assert(netdev);
        assert(netdev->ifname);

        if (netdev->state != NETDEV_STATE_CREATING)
                return 0;

        netdev->state = NETDEV_STATE_READY;

        log_info_netdev(netdev, "netdev ready");

        LIST_FOREACH_SAFE(callbacks, callback, callback_next, netdev->callbacks) {
                /* enslave the links that were attempted to be enslaved before the
                 * link was ready */
                r = netdev_enslave_ready(netdev, callback->link, callback->callback);
                if (r < 0)
                        return r;

                LIST_REMOVE(callbacks, netdev->callbacks, callback);
                link_unref(callback->link);
                free(callback);
        }

        return 0;
}

/* callback for netdev's created without a backing Link */
static int netdev_create_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        _cleanup_netdev_unref_ NetDev *netdev = userdata;
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

static int netdev_create(NetDev *netdev) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        const char *kind;
        int r;

        assert(netdev);
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

        r = sd_rtnl_message_append_string(req, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME attribute: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->mtu) {
                r = sd_rtnl_message_append_u32(req, IFLA_MTU, netdev->mtu);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_MTU attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if (netdev->mac) {
                r = sd_rtnl_message_append_ether_addr(req, IFLA_ADDRESS, netdev->mac);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Colud not append IFLA_ADDRESS attribute: %s",
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

        r = sd_rtnl_call_async(netdev->manager->rtnl, req, &netdev_create_handler, netdev, 0, NULL);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        netdev_ref(netdev);

        log_debug_netdev(netdev, "creating netdev");

        netdev->state = NETDEV_STATE_CREATING;

        return 0;
}

/* the callback must be called, possibly after a timeout, as otherwise the Link will hang */
int netdev_enslave(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback) {
        int r;

        switch(netdev->kind) {
        case NETDEV_KIND_VLAN:
                return netdev_create_vlan(netdev, link, callback);
        case NETDEV_KIND_MACVLAN:
                return netdev_create_macvlan(netdev, link, callback);
        case NETDEV_KIND_VXLAN:
                return netdev_create_vxlan(netdev, link, callback);
        case NETDEV_KIND_IPIP:
        case NETDEV_KIND_GRE:
        case NETDEV_KIND_SIT:
        case NETDEV_KIND_VTI:
                return netdev_create_tunnel(netdev, link, callback);
        default:
                break;
        }

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
                link_ref(link);

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

        if (netdev->kind == NETDEV_KIND_TAP)
                /* the kernel does not distinguish between tun and tap */
                kind = "tun";
        else {
                kind = netdev_kind_to_string(netdev->kind);
                if (!kind) {
                        log_error_netdev(netdev, "Could not get kind");
                        netdev_enter_failed(netdev);
                        return -EINVAL;
                }
        }

        if (!streq(kind, received_kind)) {
                log_error_netdev(netdev,
                                 "Received newlink with wrong KIND %s, "
                                 "expected %s", received_kind, kind);
                netdev_enter_failed(netdev);
                return r;
        }

        netdev->ifindex = ifindex;

        log_debug_netdev(netdev, "netdev has index %d", netdev->ifindex);

        netdev_enter_ready(netdev);

        return 0;
}

#define HASH_KEY SD_ID128_MAKE(52,e1,45,bd,00,6f,29,96,21,c6,30,6d,83,71,04,48)

static int netdev_get_mac(const char *ifname, struct ether_addr **ret) {
        _cleanup_free_ struct ether_addr *mac = NULL;
        uint8_t result[8];
        size_t l, sz;
        uint8_t *v;
        int r;

        assert(ifname);
        assert(ret);

        mac = new0(struct ether_addr, 1);
        if (!mac)
                return -ENOMEM;

        l = strlen(ifname);
        sz = sizeof(sd_id128_t) + l;
        v = alloca(sz);

        /* fetch some persistent data unique to the machine */
        r = sd_id128_get_machine((sd_id128_t*) v);
        if (r < 0)
                return r;

        /* combine with some data unique (on this machine) to this
         * netdev */
        memcpy(v + sizeof(sd_id128_t), ifname, l);

        /* Let's hash the host machine ID plus the container name. We
         * use a fixed, but originally randomly created hash key here. */
        siphash24(result, v, sz, HASH_KEY.bytes);

        assert_cc(ETH_ALEN <= sizeof(result));
        memcpy(mac->ether_addr_octet, result, ETH_ALEN);

        /* see eth_random_addr in the kernel */
        mac->ether_addr_octet[0] &= 0xfe;        /* clear multicast bit */
        mac->ether_addr_octet[0] |= 0x02;        /* set local assignment bit (IEEE802) */

        *ret = mac;
        mac = NULL;

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
        netdev->vxlanid = VXLAN_VID_MAX + 1;
        netdev->tunnel_pmtudisc = true;
        netdev->learning = true;

        r = config_parse(NULL, filename, file,
                         "Match\0NetDev\0VLAN\0MACVLAN\0VXLAN\0Tunnel\0Peer\0Tun\0Tap\0",
                         config_item_perf_lookup, (void*) network_netdev_gperf_lookup,
                         false, false, netdev);
        if (r < 0) {
                log_warning("Could not parse config file %s: %s", filename, strerror(-r));
                return r;
        }

        switch (netdev->kind) {
        case _NETDEV_KIND_INVALID:
                log_warning("NetDev without Kind configured in %s. Ignoring", filename);
                return 0;
        case NETDEV_KIND_VLAN:
                if (netdev->vlanid > VLANID_MAX) {
                        log_warning("VLAN without valid Id configured in %s. Ignoring", filename);
                        return 0;
                }
                break;
        case NETDEV_KIND_VXLAN:
                if (netdev->vxlanid > VXLAN_VID_MAX) {
                        log_warning("VXLAN without valid Id configured in %s. Ignoring", filename);
                        return 0;
                }
                break;
        case NETDEV_KIND_IPIP:
        case NETDEV_KIND_GRE:
        case NETDEV_KIND_SIT:
        case NETDEV_KIND_VTI:
                if (netdev->local.in.s_addr == INADDR_ANY) {
                        log_warning("Tunnel without local address configured in %s. Ignoring", filename);
                        return 0;
                }
                if (netdev->remote.in.s_addr == INADDR_ANY) {
                        log_warning("Tunnel without remote address configured in %s. Ignoring", filename);
                        return 0;
                }
                if (netdev->family != AF_INET) {
                        log_warning("Tunnel with invalid address family configured in %s. Ignoring", filename);
                        return 0;
                }
                break;
        default:
                break;
        }

        if (!netdev->ifname) {
                log_warning("NetDev without Name configured in %s. Ignoring", filename);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_VLAN && netdev->vlanid <= VLANID_MAX) {
                log_warning("VLAN Id configured for a %s in %s. Ignoring",
                            netdev_kind_to_string(netdev->kind), filename);
                return 0;
        }

        if (netdev->kind != NETDEV_KIND_VXLAN && netdev->vxlanid <= VXLAN_VID_MAX) {
                log_warning("VXLAN Id configured for a %s in %s. Ignoring",
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

        if (!netdev->mac) {
                r = netdev_get_mac(netdev->ifname, &netdev->mac);
                if (r < 0) {
                        log_error("Failed to generate predictable MAC address for %s",
                                  netdev->ifname);
                        return r;
                }
        }

        r = hashmap_put(netdev->manager->netdevs, netdev->ifname, netdev);
        if (r < 0)
                return r;

        LIST_HEAD_INIT(netdev->callbacks);

        switch (netdev->kind) {
        case NETDEV_KIND_VETH:
                if (!netdev->ifname_peer) {
                        log_warning("Veth NetDev without peer name configured "
                                    "in %s. Ignoring", filename);
                        return 0;
                }

                if (!netdev->mac) {
                        r = netdev_get_mac(netdev->ifname_peer, &netdev->mac_peer);
                        if (r < 0) {
                                log_error("Failed to generate predictable MAC address for %s",
                                          netdev->ifname_peer);
                                return r;
                        }
                }

                r = netdev_create_veth(netdev, netdev_create_handler);
                if (r < 0)
                        return r;

                break;
        case NETDEV_KIND_DUMMY:
                r = netdev_create_dummy(netdev, netdev_create_handler);
                if (r < 0)
                        return r;

                break;
        case NETDEV_KIND_BRIDGE:
        case NETDEV_KIND_BOND:
                r = netdev_create(netdev);
                if (r < 0)
                        return r;
                break;

        case NETDEV_KIND_TUN:
        case NETDEV_KIND_TAP:
                r = netdev_create_tuntap(netdev);
                if (r < 0)
                        return r;
                break;

        default:
                break;
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
