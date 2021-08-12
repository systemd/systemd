/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "missing_network.h"
#include "netlink-util.h"
#include "networkd-can.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-setlink.h"
#include "string-table.h"

static const char *const set_link_operation_table[_SET_LINK_OPERATION_MAX] = {
        [SET_LINK_ADDRESS_GENERATION_MODE] = "IPv6LL address generation mode",
        [SET_LINK_BOND]                    = "bond configurations",
        [SET_LINK_BRIDGE]                  = "bridge configurations",
        [SET_LINK_BRIDGE_VLAN]             = "bridge VLAN configurations",
        [SET_LINK_CAN]                     = "CAN interface configurations",
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

static int get_link_update_flag_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        assert(link);
        assert(link->set_flags_messages > 0);

        link->set_flags_messages--;

        return get_link_default_handler(rtnl, m, link);
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
                goto on_error;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                const char *error_msg;

                error_msg = strjoina("Failed to set ", set_link_operation_to_string(op), ignore ? ", ignoring" : "");
                log_link_message_warning_errno(link, m, r, error_msg);

                if (!ignore)
                        link_enter_failed(link);
                goto on_error;
        }

        log_link_debug(link, "%s set.", set_link_operation_to_string(op));

        if (get_link_handler) {
                r = link_call_getlink(link, get_link_handler);
                if (r < 0) {
                        link_enter_failed(link);
                        goto on_error;
                }
        }

        if (link->set_link_messages == 0)
                link_check_ready(link);

        return 1;

on_error:
        switch (op) {
        case SET_LINK_FLAGS:
                assert(link->set_flags_messages > 0);
                link->set_flags_messages--;
                break;
        case SET_LINK_MASTER:
                link->master_set = true;
                break;
        default:
                break;
        }

        return 0;
}

static int link_set_addrgen_mode_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        r = set_link_handler_internal(rtnl, m, link, SET_LINK_ADDRESS_GENERATION_MODE, /* ignore = */ true, NULL);
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
        return set_link_handler_internal(rtnl, m, link, SET_LINK_BOND, /* ignore = */ false, NULL);
}

static int link_set_bridge_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_BRIDGE, /* ignore = */ true, NULL);
}

static int link_set_bridge_vlan_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_BRIDGE_VLAN, /* ignore = */ false, NULL);
}

static int link_set_can_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_CAN, /* ignore = */ false, NULL);
}

static int link_set_flags_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_FLAGS, /* ignore = */ false, get_link_update_flag_handler);
}

static int link_set_group_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_GROUP, /* ignore = */ false, NULL);
}

static int link_set_mac_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_MAC, /* ignore = */ true, get_link_default_handler);
}

static int link_set_mac_allow_retry_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->set_link_messages > 0);

        link->set_link_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r == -EBUSY) {
                /* Most real network devices refuse to set its hardware address with -EBUSY when its
                 * operstate is not down. See, eth_prepare_mac_addr_change() in net/ethernet/eth.c
                 * of kernel. */

                log_link_message_debug_errno(link, m, r, "Failed to set MAC address, retrying again: %m");

                r = link_request_to_set_mac(link, /* allow_retry = */ false);
                if (r < 0)
                        link_enter_failed(link);

                return 0;
        }

        /* set_link_mac_handler() also decrement set_link_messages, so once increment the value. */
        link->set_link_messages++;
        return link_set_mac_handler(rtnl, m, link);
}

static int link_set_master_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return set_link_handler_internal(rtnl, m, link, SET_LINK_MASTER, /* ignore = */ false, get_link_master_handler);
}

static int link_unset_master_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        /* Some devices do not support setting master ifindex. Let's ignore error on unsetting master ifindex. */
        return set_link_handler_internal(rtnl, m, link, SET_LINK_MASTER, /* ignore = */ true, get_link_master_handler);
}

static int link_set_mtu_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        r = set_link_handler_internal(rtnl, m, link, SET_LINK_MTU, /* ignore = */ true, get_link_default_handler);
        if (r <= 0)
                return r;

        /* The kernel resets ipv6 mtu after changing device mtu;
         * we must set this here, after we've set device mtu */
        r = link_set_ipv6_mtu(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to set IPv6 MTU, ignoring: %m");

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
        } else if (op == SET_LINK_CAN) {
                r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_NEWLINK, link->ifindex);
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
                        /* master needs BRIDGE_FLAGS_SELF flag */
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
        case SET_LINK_CAN:
                r = can_set_netlink_message(link, req);
                if (r < 0)
                        return r;
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
        op = PTR_TO_INT(req->set_link_operation_ptr);

        if (!IN_SET(link->state, LINK_STATE_INITIALIZED, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        switch (op) {
        case SET_LINK_BOND:
        case SET_LINK_BRIDGE:
        case SET_LINK_BRIDGE_VLAN:
                if (!link->master_set)
                        return false;
                break;
        case SET_LINK_CAN:
                /* Do not check link->set_flgas_messages here, as it is ok even if link->flags
                 * is outdated, and checking the counter causes a deadlock. */
                if (FLAGS_SET(link->flags, IFF_UP)) {
                        /* The CAN interface must be down to configure bitrate, etc... */
                        r = link_down(link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return false;
                        }
                }
                break;
        case SET_LINK_MAC:
                if (req->netlink_handler == link_set_mac_handler) {
                        /* This is the second trial to set MTU. On the first attempt
                         * req->netlink_handler points to link_set_mac_allow_retry_handler().
                         * The first trial failed as the interface was up. */
                        r = link_down(link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return false;
                        }
                }
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

                        /* Do not check link->set_flgas_messages here, as it is ok even if link->flags
                         * is outdated, and checking the counter causes a deadlock. */
                        if (FLAGS_SET(link->flags, IFF_UP)) {
                                /* link must be down when joining to bond master. */
                                r = link_down(link);
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
        SetLinkOperation op;
        int r;

        assert(req);
        assert(req->link);
        assert(req->type == REQUEST_TYPE_SET_LINK);
        assert(req->netlink_handler);

        op = PTR_TO_INT(req->set_link_operation_ptr);

        assert(op >= 0 && op < _SET_LINK_OPERATION_MAX);

        if (!link_is_ready_to_call_set_link(req))
                return 0;

        r = link_configure(req->link, op, req->userdata, req->netlink_handler);
        if (r < 0)
                return log_link_error_errno(req->link, r, "Failed to set %s: %m",
                                            set_link_operation_to_string(op));

        if (op == SET_LINK_FLAGS)
                req->link->set_flags_messages++;

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
        else if (in6_addr_is_set(&link->network->ipv6ll_stable_secret))
                mode = IN6_ADDR_GEN_MODE_STABLE_PRIVACY;
        else
                mode = IN6_ADDR_GEN_MODE_EUI64;

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

int link_request_to_set_can(Link *link) {
        assert(link);
        assert(link->network);

        if (link->iftype != ARPHRD_CAN)
                return 0;

        if (!streq_ptr(link->kind, "can"))
                return 0;

        return link_request_set_link(link, SET_LINK_CAN, link_set_can_handler, NULL);
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

int link_request_to_set_mac(Link *link, bool allow_retry) {
        assert(link);
        assert(link->network);

        if (!link->network->mac)
                return 0;

        if (link->hw_addr.length != sizeof(struct ether_addr)) {
                /* Note that for now we only support changing hardware addresses on Ethernet. */
                log_link_debug(link, "Size of the hardware address (%zu) does not match the size of MAC address (%zu), ignoring.",
                               link->hw_addr.length, sizeof(struct ether_addr));
                return 0;
        }

        if (ether_addr_equal(&link->hw_addr.ether, link->network->mac))
                return 0;

        return link_request_set_link(link, SET_LINK_MAC,
                                     allow_retry ? link_set_mac_allow_retry_handler : link_set_mac_handler,
                                     NULL);
}

int link_request_to_set_master(Link *link) {
        assert(link);
        assert(link->network);

        link->master_set = false;

        if (link->network->batadv || link->network->bond || link->network->bridge || link->network->vrf)
                return link_request_set_link(link, SET_LINK_MASTER, link_set_master_handler, NULL);
        else
                return link_request_set_link(link, SET_LINK_MASTER, link_unset_master_handler, NULL);
}

int link_request_to_set_mtu(Link *link, uint32_t mtu) {
        Request *req;
        const char *origin;
        uint32_t min_mtu;
        int r;

        assert(link);
        assert(link->network);

        min_mtu = link->min_mtu;
        origin = "the minimum MTU of the interface";
        if (link_ipv6_enabled(link)) {
                /* IPv6 protocol requires a minimum MTU of IPV6_MTU_MIN(1280) bytes on the interface. Bump up
                 * MTU bytes to IPV6_MTU_MIN. */
                if (min_mtu < IPV6_MIN_MTU) {
                        min_mtu = IPV6_MIN_MTU;
                        origin = "the minimum IPv6 MTU";
                }
                if (min_mtu < link->network->ipv6_mtu) {
                        min_mtu = link->network->ipv6_mtu;
                        origin = "the requested IPv6 MTU in IPv6MTUBytes=";
                }
        }

        if (mtu < min_mtu) {
                log_link_warning(link, "Bumping the requested MTU %"PRIu32" to %s (%"PRIu32")",
                                 mtu, origin, min_mtu);
                mtu = min_mtu;
        }

        if (mtu > link->max_mtu) {
                log_link_warning(link, "Reducing the requested MTU %"PRIu32" to the interface's maximum MTU %"PRIu32".",
                                 mtu, link->max_mtu);
                mtu = link->max_mtu;
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

static int link_up_or_down_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, bool up, bool check_ready) {
        int r;

        assert(m);
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                goto on_error;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, up ?
                                               "Could not bring up interface, ignoring" :
                                               "Could not bring down interface, ignoring");

        r = link_call_getlink(link, get_link_update_flag_handler);
        if (r < 0) {
                link_enter_failed(link);
                goto on_error;
        }

        if (check_ready) {
                link->activated = true;
                link_check_ready(link);
        }

        return 1;

on_error:
        assert(link->set_flags_messages > 0);
        link->set_flags_messages--;

        return 0;
}

static int link_activate_up_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_up_or_down_handler_internal(rtnl, m, link, true, true);
}

static int link_activate_down_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_up_or_down_handler_internal(rtnl, m, link, false, true);
}

static int link_up_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_up_or_down_handler_internal(rtnl, m, link, true, false);
}

static int link_down_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_up_or_down_handler_internal(rtnl, m, link, false, false);
}

static const char *up_or_down(bool up) {
        return up ? "up" : "down";
}

static int link_up_or_down(Link *link, bool up, link_netlink_message_handler_t callback) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(callback);

        log_link_debug(link, "Bringing link %s", up_or_down(up));

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_flags(req, up ? IFF_UP : 0, IFF_UP);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not set link flags: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

int link_down(Link *link) {
        int r;

        assert(link);

        r = link_up_or_down(link, false, link_down_handler);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to bring down interface: %m");

        link->set_flags_messages++;
        return 0;
}

static bool link_is_ready_to_activate(Link *link) {
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_INITIALIZED, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        if (link->set_link_messages > 0)
                return false;

        return true;
}

int request_process_activation(Request *req) {
        Link *link;
        bool up;
        int r;

        assert(req);
        assert(req->link);
        assert(req->type == REQUEST_TYPE_ACTIVATE_LINK);
        assert(req->netlink_handler);

        link = req->link;
        up = PTR_TO_INT(req->userdata);

        if (!link_is_ready_to_activate(link))
                return 0;

        r = link_up_or_down(link, up, req->netlink_handler);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to bring %s: %m", up_or_down(up));

        return 1;
}

int link_request_to_activate(Link *link) {
        Request *req;
        bool up;
        int r;

        assert(link);
        assert(link->network);

        switch (link->network->activation_policy) {
        case ACTIVATION_POLICY_BOUND:
                r = link_handle_bound_to_list(link);
                if (r < 0)
                        return r;
                _fallthrough_;
        case ACTIVATION_POLICY_MANUAL:
                link->activated = true;
                link_check_ready(link);
                return 0;
        case ACTIVATION_POLICY_UP:
        case ACTIVATION_POLICY_ALWAYS_UP:
                up = true;
                break;
        case ACTIVATION_POLICY_DOWN:
        case ACTIVATION_POLICY_ALWAYS_DOWN:
                up = false;
                break;
        default:
                assert_not_reached("invalid activation policy");
        }

        link->activated = false;

        r = link_queue_request(link, REQUEST_TYPE_ACTIVATE_LINK, NULL, false, &link->set_flags_messages,
                               up ? link_activate_up_handler : link_activate_down_handler, &req);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request to activate link: %m");

        req->userdata = INT_TO_PTR(up);

        log_link_debug(link, "Requested to activate link");
        return 0;
}

static bool link_is_ready_to_bring_up_or_down(Link *link) {
        assert(link);

        if (link->state == LINK_STATE_UNMANAGED)
                return true;

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        if (link->set_link_messages > 0)
                return false;

        if (!link->activated)
                return false;

        return true;
}

int request_process_link_up_or_down(Request *req) {
        Link *link;
        bool up;
        int r;

        assert(req);
        assert(req->link);
        assert(req->type == REQUEST_TYPE_UP_DOWN);

        link = req->link;
        up = PTR_TO_INT(req->userdata);

        if (!link_is_ready_to_bring_up_or_down(link))
                return 0;

        r = link_up_or_down(link, up, req->netlink_handler);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to bring %s: %m", up_or_down(up));

        return 1;
}

int link_request_to_bring_up_or_down(Link *link, bool up) {
        Request *req;
        int r;

        assert(link);

        r = link_queue_request(link, REQUEST_TYPE_UP_DOWN, NULL, false, &link->set_flags_messages,
                               up ? link_up_handler : link_down_handler, &req);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request to bring %s link: %m",
                                            up_or_down(up));

        req->userdata = INT_TO_PTR(up);

        log_link_debug(link, "Requested to bring link %s", up_or_down(up));
        return 0;
}
