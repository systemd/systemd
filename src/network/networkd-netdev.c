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

#include "networkd-netdev.h"
#include "networkd-link.h"
#include "network-internal.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "list.h"
#include "siphash24.h"

const NetDevVTable * const netdev_vtable[_NETDEV_KIND_MAX] = {
        [NETDEV_KIND_BRIDGE] = &bridge_vtable,
        [NETDEV_KIND_BOND] = &bond_vtable,
        [NETDEV_KIND_VLAN] = &vlan_vtable,
        [NETDEV_KIND_MACVLAN] = &macvlan_vtable,
        [NETDEV_KIND_IPVLAN] = &ipvlan_vtable,
        [NETDEV_KIND_VXLAN] = &vxlan_vtable,
        [NETDEV_KIND_IPIP] = &ipip_vtable,
        [NETDEV_KIND_GRE] = &gre_vtable,
        [NETDEV_KIND_GRETAP] = &gretap_vtable,
        [NETDEV_KIND_IP6GRE] = &ip6gre_vtable,
        [NETDEV_KIND_IP6GRETAP] = &ip6gretap_vtable,
        [NETDEV_KIND_SIT] = &sit_vtable,
        [NETDEV_KIND_VTI] = &vti_vtable,
        [NETDEV_KIND_VTI6] = &vti6_vtable,
        [NETDEV_KIND_VETH] = &veth_vtable,
        [NETDEV_KIND_DUMMY] = &dummy_vtable,
        [NETDEV_KIND_TUN] = &tun_vtable,
        [NETDEV_KIND_TAP] = &tap_vtable,
        [NETDEV_KIND_IP6TNL] = &ip6tnl_vtable,
};

static const char* const netdev_kind_table[_NETDEV_KIND_MAX] = {
        [NETDEV_KIND_BRIDGE] = "bridge",
        [NETDEV_KIND_BOND] = "bond",
        [NETDEV_KIND_VLAN] = "vlan",
        [NETDEV_KIND_MACVLAN] = "macvlan",
        [NETDEV_KIND_IPVLAN] = "ipvlan",
        [NETDEV_KIND_VXLAN] = "vxlan",
        [NETDEV_KIND_IPIP] = "ipip",
        [NETDEV_KIND_GRE] = "gre",
        [NETDEV_KIND_GRETAP] = "gretap",
        [NETDEV_KIND_IP6GRE] = "ip6gre",
        [NETDEV_KIND_IP6GRETAP] = "ip6gretap",
        [NETDEV_KIND_SIT] = "sit",
        [NETDEV_KIND_VETH] = "veth",
        [NETDEV_KIND_VTI] = "vti",
        [NETDEV_KIND_VTI6] = "vti6",
        [NETDEV_KIND_DUMMY] = "dummy",
        [NETDEV_KIND_TUN] = "tun",
        [NETDEV_KIND_TAP] = "tap",
        [NETDEV_KIND_IP6TNL] = "ip6tnl",
};

DEFINE_STRING_TABLE_LOOKUP(netdev_kind, NetDevKind);
DEFINE_CONFIG_PARSE_ENUM(config_parse_netdev_kind, netdev_kind, NetDevKind, "Failed to parse netdev kind");

static void netdev_cancel_callbacks(NetDev *netdev) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        netdev_join_callback *callback;

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
        free(netdev->mac);

        condition_free_list(netdev->match_host);
        condition_free_list(netdev->match_virt);
        condition_free_list(netdev->match_kernel);
        condition_free_list(netdev->match_arch);

        if (NETDEV_VTABLE(netdev) &&
            NETDEV_VTABLE(netdev)->done)
                NETDEV_VTABLE(netdev)->done(netdev);

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

        log_netdev_debug(netdev, "netdev removed");

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
        assert(IN_SET(netdev->kind, NETDEV_KIND_BRIDGE, NETDEV_KIND_BOND));
        assert(link);
        assert(callback);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_append_u32(req, IFLA_MASTER, netdev->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_MASTER attribute: %m");

        r = sd_rtnl_call_async(netdev->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0)
                return log_netdev_error(netdev, "Could not send rtnetlink message: %m");

        link_ref(link);

        log_netdev_debug(netdev, "Enslaving link '%s'", link->ifname);

        return 0;
}

static int netdev_enter_ready(NetDev *netdev) {
        netdev_join_callback *callback, *callback_next;
        int r;

        assert(netdev);
        assert(netdev->ifname);

        if (netdev->state != NETDEV_STATE_CREATING)
                return 0;

        netdev->state = NETDEV_STATE_READY;

        log_netdev_info(netdev, "netdev ready");

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
                log_netdev_info(netdev, "netdev exists, using existing without changing its parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r, "netdev could not be created: %m");
                netdev_drop(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "Created");

        return 1;
}

int netdev_enslave(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback) {
        int r;

        assert(netdev);
        assert(IN_SET(netdev->kind, NETDEV_KIND_BRIDGE, NETDEV_KIND_BOND));

        if (netdev->state == NETDEV_STATE_READY) {
                r = netdev_enslave_ready(netdev, link, callback);
                if (r < 0)
                        return r;
        } else {
                /* the netdev is not yet read, save this request for when it is */
                netdev_join_callback *cb;

                cb = new0(netdev_join_callback, 1);
                if (!cb)
                        return log_oom();

                cb->callback = callback;
                cb->link = link;
                link_ref(link);

                LIST_PREPEND(callbacks, netdev->callbacks, cb);

                log_netdev_debug(netdev, "Will enslave '%s', when ready", link->ifname);
        }

        return 0;
}

int netdev_set_ifindex(NetDev *netdev, sd_rtnl_message *message) {
        uint16_t type;
        const char *kind;
        const char *received_kind;
        const char *received_name;
        int r, ifindex;

        assert(netdev);
        assert(message);

        r = sd_rtnl_message_get_type(message, &type);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not get rtnl message type: %m");

        if (type != RTM_NEWLINK) {
                log_netdev_error(netdev, "Cannot set ifindex from unexpected rtnl message type.");
                return -EINVAL;
        }

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_netdev_error_errno(netdev, r, "Could not get ifindex: %m");
                netdev_enter_failed(netdev);
                return r;
        } else if (ifindex <= 0) {
                log_netdev_error(netdev, "Got invalid ifindex: %d", ifindex);
                netdev_enter_failed(netdev);
                return -EINVAL;
        }

        if (netdev->ifindex > 0) {
                if (netdev->ifindex != ifindex) {
                        log_netdev_error(netdev, "Could not set ifindex to %d, already set to %d",
                                         ifindex, netdev->ifindex);
                        netdev_enter_failed(netdev);
                        return -EEXIST;
                } else
                        /* ifindex already set to the same for this netdev */
                        return 0;
        }

        r = sd_rtnl_message_read_string(message, IFLA_IFNAME, &received_name);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not get IFNAME: %m");

        if (!streq(netdev->ifname, received_name)) {
                log_netdev_error(netdev, "Received newlink with wrong IFNAME %s", received_name);
                netdev_enter_failed(netdev);
                return r;
        }

        r = sd_rtnl_message_enter_container(message, IFLA_LINKINFO);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not get LINKINFO: %m");

        r = sd_rtnl_message_read_string(message, IFLA_INFO_KIND, &received_kind);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not get KIND: %m");

        r = sd_rtnl_message_exit_container(message);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not exit container: %m");

        if (netdev->kind == NETDEV_KIND_TAP)
                /* the kernel does not distinguish between tun and tap */
                kind = "tun";
        else {
                kind = netdev_kind_to_string(netdev->kind);
                if (!kind) {
                        log_netdev_error(netdev, "Could not get kind");
                        netdev_enter_failed(netdev);
                        return -EINVAL;
                }
        }

        if (!streq(kind, received_kind)) {
                log_netdev_error(netdev,
                                 "Received newlink with wrong KIND %s, "
                                 "expected %s", received_kind, kind);
                netdev_enter_failed(netdev);
                return r;
        }

        netdev->ifindex = ifindex;

        log_netdev_debug(netdev, "netdev has index %d", netdev->ifindex);

        netdev_enter_ready(netdev);

        return 0;
}

#define HASH_KEY SD_ID128_MAKE(52,e1,45,bd,00,6f,29,96,21,c6,30,6d,83,71,04,48)

int netdev_get_mac(const char *ifname, struct ether_addr **ret) {
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

static int netdev_create(NetDev *netdev, Link *link,
                         sd_rtnl_message_handler_t callback) {
        int r;

        assert(netdev);
        assert(!link || callback);

        /* create netdev */
        if (NETDEV_VTABLE(netdev)->create) {
                assert(!link);

                r = NETDEV_VTABLE(netdev)->create(netdev);
                if (r < 0)
                        return r;

                log_netdev_debug(netdev, "Created");
        } else {
                _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;

                r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, 0);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not allocate RTM_NEWLINK message: %m");

                r = sd_rtnl_message_append_string(m, IFLA_IFNAME, netdev->ifname);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_IFNAME, attribute: %m");

                if (netdev->mac) {
                        r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append IFLA_ADDRESS attribute: %m");
                }

                if (netdev->mtu) {
                        r = sd_rtnl_message_append_u32(m, IFLA_MTU, netdev->mtu);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append IFLA_MTU attribute: %m");
                }

                if (link) {
                        r = sd_rtnl_message_append_u32(m, IFLA_LINK, link->ifindex);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINK attribute: %m");
                }

                r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

                r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, netdev_kind_to_string(netdev->kind));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

                if (NETDEV_VTABLE(netdev)->fill_message_create) {
                        r = NETDEV_VTABLE(netdev)->fill_message_create(netdev, link, m);
                        if (r < 0)
                                return r;
                }

                r = sd_rtnl_message_close_container(m);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

                r = sd_rtnl_message_close_container(m);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

                if (link) {
                        r = sd_rtnl_call_async(netdev->manager->rtnl, m, callback, link, 0, NULL);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not send rtnetlink message: %m");

                        link_ref(link);
                } else {
                        r = sd_rtnl_call_async(netdev->manager->rtnl, m, netdev_create_handler, netdev, 0, NULL);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not send rtnetlink message: %m");

                        netdev_ref(netdev);
                }

                netdev->state = NETDEV_STATE_CREATING;

                log_netdev_debug(netdev, "Creating");
        }

        return 0;
}

/* the callback must be called, possibly after a timeout, as otherwise the Link will hang */
int netdev_join(NetDev *netdev, Link *link, sd_rtnl_message_handler_t callback) {
        int r;

        assert(netdev);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(NETDEV_VTABLE(netdev));

        switch (NETDEV_VTABLE(netdev)->create_type) {
        case NETDEV_CREATE_MASTER:
                r = netdev_enslave(netdev, link, callback);
                if (r < 0)
                        return r;

                break;
        case NETDEV_CREATE_STACKED:
                r = netdev_create(netdev, link, callback);
                if (r < 0)
                        return r;

                break;
        default:
                assert_not_reached("Can not join independent netdev");
        }

        return 0;
}

static int netdev_load_one(Manager *manager, const char *filename) {
        _cleanup_netdev_unref_ NetDev *netdev = NULL;
        _cleanup_free_ NetDev *netdev_raw = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        int r;

        assert(manager);
        assert(filename);

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return -errno;
        }

        if (null_or_empty_fd(fileno(file))) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        netdev_raw = new0(NetDev, 1);
        if (!netdev_raw)
                return log_oom();

        netdev_raw->kind = _NETDEV_KIND_INVALID;

        r = config_parse(NULL, filename, file,
                         "Match\0NetDev\0",
                         config_item_perf_lookup, network_netdev_gperf_lookup,
                         true, false, true, netdev_raw);
        if (r < 0)
                return r;

        r = fseek(file, 0, SEEK_SET);
        if (r < 0)
                return -errno;

        /* skip out early if configuration does not match the environment */
        if (net_match_config(NULL, NULL, NULL, NULL, NULL,
                             netdev_raw->match_host, netdev_raw->match_virt,
                             netdev_raw->match_kernel, netdev_raw->match_arch,
                             NULL, NULL, NULL, NULL, NULL, NULL) <= 0)
                return 0;

        if (!NETDEV_VTABLE(netdev_raw)) {
                log_warning("NetDev with invalid Kind configured in %s. Ignoring", filename);
                return 0;
        }

        if (!netdev_raw->ifname) {
                log_warning("NetDev without Name configured in %s. Ignoring", filename);
                return 0;
        }

        netdev = malloc0(NETDEV_VTABLE(netdev_raw)->object_size);
        if (!netdev)
                return log_oom();

        netdev->n_ref = 1;
        netdev->manager = manager;
        netdev->state = _NETDEV_STATE_INVALID;
        netdev->kind = netdev_raw->kind;
        netdev->ifname = netdev_raw->ifname;

        if (NETDEV_VTABLE(netdev)->init)
                NETDEV_VTABLE(netdev)->init(netdev);

        r = config_parse(NULL, filename, file,
                         NETDEV_VTABLE(netdev)->sections,
                         config_item_perf_lookup, network_netdev_gperf_lookup,
                         false, false, false, netdev);
        if (r < 0)
                return r;

        /* verify configuration */
        if (NETDEV_VTABLE(netdev)->config_verify) {
                r = NETDEV_VTABLE(netdev)->config_verify(netdev, filename);
                if (r < 0)
                        return 0;
        }

        netdev->filename = strdup(filename);
        if (!netdev->filename)
                return log_oom();

        if (!netdev->mac) {
                r = netdev_get_mac(netdev->ifname, &netdev->mac);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate predictable MAC address for %s: %m", netdev->ifname);
        }

        r = hashmap_put(netdev->manager->netdevs, netdev->ifname, netdev);
        if (r < 0)
                return r;

        LIST_HEAD_INIT(netdev->callbacks);

        log_netdev_debug(netdev, "loaded %s", netdev_kind_to_string(netdev->kind));

        switch (NETDEV_VTABLE(netdev)->create_type) {
        case NETDEV_CREATE_MASTER:
        case NETDEV_CREATE_INDEPENDENT:
                r = netdev_create(netdev, NULL, NULL);
                if (r < 0)
                        return 0;

                break;
        default:
                break;
        }

        netdev = NULL;

        return 0;
}

int netdev_load(Manager *manager) {
        _cleanup_strv_free_ char **files = NULL;
        NetDev *netdev;
        char **f;
        int r;

        assert(manager);

        while ((netdev = hashmap_first(manager->netdevs)))
                netdev_unref(netdev);

        r = conf_files_list_strv(&files, ".netdev", NULL, network_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate netdev files: %m");

        STRV_FOREACH_BACKWARDS(f, files) {
                r = netdev_load_one(manager, *f);
                if (r < 0)
                        return r;
        }

        return 0;
}
