/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>

#include "missing_network.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "string-table.h"
#include "sysctl-util.h"

static const char *const set_link_operation_table[_SET_LINK_OPERATION_MAX] = {
        [SET_LINK_ADDRESS_GENERATION_MODE] = "IPv6LL address generation mode",
        [SET_LINK_BOND]                    = "bond configurations",
        [SET_LINK_BRIDGE]                  = "bridge configurations",
        [SET_LINK_BRIDGE_VLAN]             = "bridge VLAN configurations",
        [SET_LINK_FLAGS]                   = "link flags",
        [SET_LINK_GROUP]                   = "interface group",
        [SET_LINK_MAC]                     = "MAC address",
        [SET_LINK_MASTER]                  = "master interface",
        [SET_LINK_MTU]                     = "MTU",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(set_link_operation, SetLinkOperation);

static int get_link_default_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_getlink_handler_internal(rtnl, m, link, "Failed to sync link information");
}

static int get_link_master_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        if (get_link_default_handler(rtnl, m, link) > 0)
                link->master_set = true;
        return 0;
}

static int set_link_handler_internal(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Link *link,
                SetLinkOperation op,
                bool ignore,
                link_netlink_message_handler_t get_link_handler) {

        int r;

        assert(m);
        assert(link);
        assert(link->set_link_messages > 0);
        assert(op >= 0 && op < _SET_LINK_OPERATION_MAX);

        link->set_link_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                const char *error_msg;

                error_msg = strjoina("Failed to set ", set_link_operation_to_string(op), ignore ? ", ignoring" : "");
                log_link_message_warning_errno(link, m, r, error_msg);

                if (!ignore)
                        link_enter_failed(link);
                return 0;
        }

        log_link_debug(link, "%s set.", set_link_operation_to_string(op));

        if (get_link_handler) {
                r = link_call_getlink(link, get_link_handler);
                if (r < 0) {
                        link_enter_failed(link);
                        return 0;
                }
        }

        if (link->set_link_messages == 0)
                link_check_ready(link);

        return 1;
}

static int link_set_addrgen_mode_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        r = set_link_handler_internal(rtnl, m, link, SET_LINK_ADDRESS_GENERATION_MODE, true, NULL);
        if (r <= 0)
                return r;

        r = link_drop_ipv6ll_addresses(link);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to drop IPv6LL addresses: %m");
                link_enter_failed(link);
        }

        return 0;
}

static int link_set_bond_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_BOND, true, NULL);
}

static int link_set_bridge_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_BRIDGE, true, NULL);
}

static int link_set_bridge_vlan_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_BRIDGE_VLAN, true, NULL);
}

static int link_set_flags_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_FLAGS, true, get_link_default_handler);
}

static int link_set_group_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_GROUP, true, NULL);
}

static int link_set_mac_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_MAC, true, get_link_default_handler);
}

static int link_set_master_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_MASTER, true, get_link_master_handler);
}

static int link_set_mtu_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        r = set_link_handler_internal(rtnl, m, link, SET_LINK_MTU, true, get_link_default_handler);
        if (r <= 0)
                return r;

        /* The kernel resets ipv6 mtu after changing device mtu;
         * we must set this here, after we've set device mtu */
        r = link_set_ipv6_mtu(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to set IPv6 MTU, ignoring: %m");

        if (link->entering_to_join_netdev) {
                r = link_enter_join_netdev(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 0;
}

static int link_configure(
                Link *link,
                SetLinkOperation op,
                void *userdata,
                link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->network);
        assert(op >= 0 && op < _SET_LINK_OPERATION_MAX);
        assert(callback);

        log_link_debug(link, "Setting %s", set_link_operation_to_string(op));

        if (op == SET_LINK_BOND) {
                r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_NEWLINK, link->master_ifindex);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not allocate RTM_NEWLINK message: %m");
        } else {
                r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not allocate RTM_SETLINK message: %m");
        }

        switch (op) {
        case SET_LINK_ADDRESS_GENERATION_MODE:
                r = sd_netlink_message_open_container(req, IFLA_AF_SPEC);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not open IFLA_AF_SPEC container: %m");

                r = sd_netlink_message_open_container(req, AF_INET6);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not open AF_INET6 container: %m");

                r = sd_netlink_message_append_u8(req, IFLA_INET6_ADDR_GEN_MODE, PTR_TO_UINT8(userdata));
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not append IFLA_INET6_ADDR_GEN_MODE attribute: %m");

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not close AF_INET6 container: %m");

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not close IFLA_AF_SPEC container: %m");
                break;
        case SET_LINK_BOND:
                r = sd_netlink_message_set_flags(req, NLM_F_REQUEST | NLM_F_ACK);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not set netlink message flags: %m");

                r = sd_netlink_message_open_container(req, IFLA_LINKINFO);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not open IFLA_LINKINFO container: %m");

                r = sd_netlink_message_open_container_union(req, IFLA_INFO_DATA, "bond");
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not open IFLA_INFO_DATA container: %m");

                if (link->network->active_slave) {
                        r = sd_netlink_message_append_u32(req, IFLA_BOND_ACTIVE_SLAVE, link->ifindex);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BOND_ACTIVE_SLAVE attribute: %m");
                }

                if (link->network->primary_slave) {
                        r = sd_netlink_message_append_u32(req, IFLA_BOND_PRIMARY, link->ifindex);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BOND_PRIMARY attribute: %m");
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not close IFLA_INFO_DATA container: %m");

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not close IFLA_LINKINFO container: %m");

                break;
        case SET_LINK_BRIDGE:
                r = sd_rtnl_message_link_set_family(req, AF_BRIDGE);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not set message family: %m");

                r = sd_netlink_message_open_container(req, IFLA_PROTINFO);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not open IFLA_PROTINFO container: %m");

                if (link->network->use_bpdu >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_GUARD, link->network->use_bpdu);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_GUARD attribute: %m");
                }

                if (link->network->hairpin >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MODE, link->network->hairpin);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_MODE attribute: %m");
                }

                if (link->network->fast_leave >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_FAST_LEAVE, link->network->fast_leave);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_FAST_LEAVE attribute: %m");
                }

                if (link->network->allow_port_to_be_root >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_PROTECT, link->network->allow_port_to_be_root);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_PROTECT attribute: %m");
                }

                if (link->network->unicast_flood >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_UNICAST_FLOOD, link->network->unicast_flood);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_UNICAST_FLOOD attribute: %m");
                }

                if (link->network->multicast_flood >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MCAST_FLOOD, link->network->multicast_flood);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_MCAST_FLOOD attribute: %m");
                }

                if (link->network->multicast_to_unicast >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MCAST_TO_UCAST, link->network->multicast_to_unicast);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_MCAST_TO_UCAST attribute: %m");
                }

                if (link->network->neighbor_suppression >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_NEIGH_SUPPRESS, link->network->neighbor_suppression);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_NEIGH_SUPPRESS attribute: %m");
                }

                if (link->network->learning >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_LEARNING, link->network->learning);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_LEARNING attribute: %m");
                }

                if (link->network->bridge_proxy_arp >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_PROXYARP, link->network->bridge_proxy_arp);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_PROXYARP attribute: %m");
                }

                if (link->network->bridge_proxy_arp_wifi >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_PROXYARP_WIFI, link->network->bridge_proxy_arp_wifi);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_PROXYARP_WIFI attribute: %m");
                }

                if (link->network->cost != 0) {
                        r = sd_netlink_message_append_u32(req, IFLA_BRPORT_COST, link->network->cost);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_COST attribute: %m");
                }

                if (link->network->priority != LINK_BRIDGE_PORT_PRIORITY_INVALID) {
                        r = sd_netlink_message_append_u16(req, IFLA_BRPORT_PRIORITY, link->network->priority);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_PRIORITY attribute: %m");
                }

                if (link->network->multicast_router != _MULTICAST_ROUTER_INVALID) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MULTICAST_ROUTER, link->network->multicast_router);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRPORT_MULTICAST_ROUTER attribute: %m");
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not close IFLA_PROTINFO container: %m");
                break;
        case SET_LINK_BRIDGE_VLAN:
                r = sd_rtnl_message_link_set_family(req, AF_BRIDGE);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not set message family: %m");

                r = sd_netlink_message_open_container(req, IFLA_AF_SPEC);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not open IFLA_AF_SPEC container: %m");

                if (!link->network->bridge) {
                        /* master needs BRIDGE_FLAGS_SELF flag*/
                        r = sd_netlink_message_append_u16(req, IFLA_BRIDGE_FLAGS, BRIDGE_FLAGS_SELF);
                        if (r < 0)
                                return log_link_debug_errno(link, r, "Could not append IFLA_BRIDGE_FLAGS attribute: %m");
                }

                r = bridge_vlan_append_info(link, req, link->network->pvid, link->network->br_vid_bitmap, link->network->br_untagged_bitmap);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not append VLANs: %m");

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not close IFLA_AF_SPEC container: %m");

                break;
        case SET_LINK_FLAGS: {
                unsigned ifi_change = 0, ifi_flags = 0;

                if (link->network->arp >= 0) {
                        ifi_change |= IFF_NOARP;
                        SET_FLAG(ifi_flags, IFF_NOARP, link->network->arp == 0);
                }

                if (link->network->multicast >= 0) {
                        ifi_change |= IFF_MULTICAST;
                        SET_FLAG(ifi_flags, IFF_MULTICAST, link->network->multicast);
                }

                if (link->network->allmulticast >= 0) {
                        ifi_change |= IFF_ALLMULTI;
                        SET_FLAG(ifi_flags, IFF_ALLMULTI, link->network->allmulticast);
                }

                if (link->network->promiscuous >= 0) {
                        ifi_change |= IFF_PROMISC;
                        SET_FLAG(ifi_flags, IFF_PROMISC, link->network->promiscuous);
                }

                r = sd_rtnl_message_link_set_flags(req, ifi_flags, ifi_change);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not set link flags: %m");

                break;
        }
        case SET_LINK_GROUP:
                r = sd_netlink_message_append_u32(req, IFLA_GROUP, link->network->group);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not append IFLA_GROUP attribute: %m");
                break;
        case SET_LINK_MAC:
                r = sd_netlink_message_append_ether_addr(req, IFLA_ADDRESS, link->network->mac);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not append IFLA_ADDRESS attribute: %m");
                break;
        case SET_LINK_MASTER:
                r = sd_netlink_message_append_u32(req, IFLA_MASTER, PTR_TO_UINT32(userdata));
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not append IFLA_MASTER attribute: %m");
                break;
        case SET_LINK_MTU:
                r = sd_netlink_message_append_u32(req, IFLA_MTU, PTR_TO_UINT32(userdata));
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not append IFLA_MTU attribute: %m");
                break;
        default:
                assert_not_reached("Invalid set link operation");
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not send RTM_SETLINK message: %m");

        link_ref(link);
        return 0;
}

static bool netdev_is_ready(NetDev *netdev) {
        assert(netdev);

        if (netdev->state != NETDEV_STATE_READY)
                return false;
        if (netdev->ifindex == 0)
                return false;

        return true;
}

static bool link_is_ready_to_call_set_link(Request *req) {
        SetLinkOperation op;
        Link *link;
        int r;

        assert(req);

        link = req->link;
        op = req->set_link_operation;

        if (!IN_SET(link->state, LINK_STATE_INITIALIZED, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        switch (op) {
        case SET_LINK_BOND:
        case SET_LINK_BRIDGE:
        case SET_LINK_BRIDGE_VLAN:
                if (!link->master_set)
                        return false;
                break;
        case SET_LINK_MASTER: {
                uint32_t m = 0;

                assert(link->network);

                if (link->network->batadv) {
                        if (!netdev_is_ready(link->network->batadv))
                                return false;
                        m = link->network->batadv->ifindex;
                } else if (link->network->bond) {
                        if (!netdev_is_ready(link->network->bond))
                                return false;
                        m = link->network->bond->ifindex;

                        if (FLAGS_SET(link->flags, IFF_UP)) {
                                /* link must be down when joining to bond master. */
                                r = link_down(link, NULL);
                                if (r < 0) {
                                        link_enter_failed(link);
                                        return false;
                                }
                        }
                } else if (link->network->bridge) {
                        if (!netdev_is_ready(link->network->bridge))
                                return false;
                        m = link->network->bridge->ifindex;
                } else if (link->network->vrf) {
                        if (!netdev_is_ready(link->network->vrf))
                                return false;
                        m = link->network->vrf->ifindex;
                }

                req->userdata = UINT32_TO_PTR(m);
                break;
        }
        default:
                break;
        }

        return true;
}

int request_process_set_link(Request *req) {
        int r;

        assert(req);
        assert(req->link);
        assert(req->type == REQUEST_TYPE_SET_LINK);
        assert(req->set_link_operation >= 0 && req->set_link_operation < _SET_LINK_OPERATION_MAX);
        assert(req->netlink_handler);

        if (!link_is_ready_to_call_set_link(req))
                return 0;

        r = link_configure(req->link, req->set_link_operation, req->userdata, req->netlink_handler);
        if (r < 0)
                return log_link_error_errno(req->link, r, "Failed to set %s: %m",
                                            set_link_operation_to_string(req->set_link_operation));

        return 1;
}

static int link_request_set_link(
                Link *link,
                SetLinkOperation op,
                link_netlink_message_handler_t netlink_handler,
                Request **ret) {

        Request *req;
        int r;

        assert(link);
        assert(op >= 0 && op < _SET_LINK_OPERATION_MAX);
        assert(netlink_handler);

        r = link_queue_request(link, REQUEST_TYPE_SET_LINK, INT_TO_PTR(op), false,
                               &link->set_link_messages, netlink_handler, &req);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request to set %s: %m",
                                            set_link_operation_to_string(op));

        log_link_debug(link, "Requested to set %s", set_link_operation_to_string(op));

        if (ret)
                *ret = req;
        return 0;
}

int link_request_to_set_addrgen_mode(Link *link) {
        Request *req;
        uint8_t mode;
        int r;

        assert(link);
        assert(link->network);

        if (!socket_ipv6_is_supported())
                return 0;

        if (!link_ipv6ll_enabled(link))
                mode = IN6_ADDR_GEN_MODE_NONE;
        else if (link->network->ipv6ll_address_gen_mode >= 0)
                mode = link->network->ipv6ll_address_gen_mode;
        else {
                r = sysctl_read_ip_property(AF_INET6, link->ifname, "stable_secret", NULL);
                if (r < 0) {
                        /* The file may not exist. And even if it exists, when stable_secret is unset,
                         * reading the file fails with ENOMEM when read_full_virtual_file(), which uses
                         * read() as the backend, and EIO when read_one_line_file() which uses fgetc(). */
                        log_link_debug_errno(link, r, "Failed to read sysctl property stable_secret, ignoring: %m");

                        mode = IN6_ADDR_GEN_MODE_EUI64;
                } else
                        mode = IN6_ADDR_GEN_MODE_STABLE_PRIVACY;
        }

        r = link_request_set_link(link, SET_LINK_ADDRESS_GENERATION_MODE, link_set_addrgen_mode_handler, &req);
        if (r < 0)
                return r;

        req->userdata = UINT8_TO_PTR(mode);
        return 0;
}

int link_request_to_set_bond(Link *link) {
        assert(link);
        assert(link->network);

        if (!link->network->bond)
                return 0;

        return link_request_set_link(link, SET_LINK_BOND, link_set_bond_handler, NULL);
}

int link_request_to_set_bridge(Link *link) {
        assert(link);
        assert(link->network);

        if (!link->network->bridge)
                return 0;

        return link_request_set_link(link, SET_LINK_BRIDGE, link_set_bridge_handler, NULL);
}

int link_request_to_set_bridge_vlan(Link *link) {
        assert(link);
        assert(link->network);

        if (!link->network->use_br_vlan)
                return 0;

        if (!link->network->bridge && !streq_ptr(link->kind, "bridge"))
                return 0;

        return link_request_set_link(link, SET_LINK_BRIDGE_VLAN, link_set_bridge_vlan_handler, NULL);
}

int link_request_to_set_flags(Link *link) {
        assert(link);
        assert(link->network);

        if (link->network->arp < 0 &&
            link->network->multicast < 0 &&
            link->network->allmulticast < 0 &&
            link->network->promiscuous < 0)
                return 0;

        return link_request_set_link(link, SET_LINK_FLAGS, link_set_flags_handler, NULL);
}

int link_request_to_set_group(Link *link) {
        assert(link);
        assert(link->network);

        if (!link->network->group_set)
                return 0;

        return link_request_set_link(link, SET_LINK_GROUP, link_set_group_handler, NULL);
}

int link_request_to_set_mac(Link *link) {
        assert(link);
        assert(link->network);

        if (!link->network->mac)
                return 0;

        return link_request_set_link(link, SET_LINK_MAC, link_set_mac_handler, NULL);
}

int link_request_to_set_master(Link *link) {
        assert(link);

        link->master_set = false;

        return link_request_set_link(link, SET_LINK_MASTER, link_set_master_handler, NULL);
}

int link_request_to_set_mtu(Link *link, uint32_t mtu) {
        Request *req = NULL;  /* avoid false maybe-uninitialized warning */
        int r;

        assert(link);

        /* IPv6 protocol requires a minimum MTU of IPV6_MTU_MIN(1280) bytes on the interface. Bump up
         * MTU bytes to IPV6_MTU_MIN. */
        if (mtu < IPV6_MIN_MTU && link_ipv6_enabled(link)) {
                log_link_warning(link, "Bumping MTU to " STRINGIFY(IPV6_MIN_MTU) ", as IPv6 is enabled "
                                 "and requires a minimum MTU of " STRINGIFY(IPV6_MIN_MTU) " bytes");
                mtu = IPV6_MIN_MTU;
        }

        if (link->mtu == mtu)
                return 0;

        r = link_request_set_link(link, SET_LINK_MTU, link_set_mtu_handler, &req);
        if (r < 0)
                return r;

        req->userdata = UINT32_TO_PTR(mtu);
        return 0;
}

static bool link_reduces_vlan_mtu(Link *link) {
        /* See netif_reduces_vlan_mtu() in kernel. */
        return streq_ptr(link->kind, "macsec");
}

static uint32_t link_get_requested_mtu_by_stacked_netdevs(Link *link) {
        uint32_t mtu = 0;
        NetDev *dev;

        HASHMAP_FOREACH(dev, link->network->stacked_netdevs)
                if (dev->kind == NETDEV_KIND_VLAN && dev->mtu > 0)
                        /* See vlan_dev_change_mtu() in kernel. */
                        mtu = MAX(mtu, link_reduces_vlan_mtu(link) ? dev->mtu + 4 : dev->mtu);

                else if (dev->kind == NETDEV_KIND_MACVLAN && dev->mtu > mtu)
                        /* See macvlan_change_mtu() in kernel. */
                        mtu = dev->mtu;

        return mtu;
}

int link_configure_mtu(Link *link) {
        uint32_t mtu;

        assert(link);
        assert(link->network);

        if (link->network->mtu > 0)
                return link_request_to_set_mtu(link, link->network->mtu);

        mtu = link_get_requested_mtu_by_stacked_netdevs(link);
        if (link->mtu >= mtu)
                return 0;

        log_link_notice(link, "Bumping MTU bytes from %"PRIu32" to %"PRIu32" because of stacked device. "
                        "If it is not desired, then please explicitly specify MTUBytes= setting.",
                        link->mtu, mtu);

        return link_request_to_set_mtu(link, mtu);
}
