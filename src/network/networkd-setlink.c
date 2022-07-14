/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_bridge.h>

#include "missing_network.h"
#include "netif-util.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-can.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-setlink.h"

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
                Request *req,
                Link *link,
                bool ignore,
                link_netlink_message_handler_t get_link_handler) {

        int r;

        assert(m);
        assert(req);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                const char *error_msg;

                error_msg = strjoina("Failed to set ", request_type_to_string(req->type), ignore ? ", ignoring" : "");
                log_link_message_warning_errno(link, m, r, error_msg);

                if (!ignore)
                        link_enter_failed(link);
                return 0;
        }

        log_link_debug(link, "%s set.", request_type_to_string(req->type));

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

static int link_set_addrgen_mode_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        int r;

        r = set_link_handler_internal(rtnl, m, req, link, /* ignore = */ true, NULL);
        if (r <= 0)
                return r;

        r = link_drop_ipv6ll_addresses(link);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to drop IPv6LL addresses: %m");
                link_enter_failed(link);
        }

        return 0;
}

static int link_set_bond_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ false, NULL);
}

static int link_set_bridge_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ true, NULL);
}

static int link_set_bridge_vlan_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ false, NULL);
}

static int link_set_can_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ false, NULL);
}

static int link_set_flags_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ false, get_link_default_handler);
}

static int link_set_group_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ false, NULL);
}

static int link_set_ipoib_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ true, NULL);
}

static int link_set_mac_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ true, get_link_default_handler);
}

static int link_set_mac_allow_retry_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        int r;

        assert(m);
        assert(link);

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

        return link_set_mac_handler(rtnl, m, req, link, userdata);
}

static int link_set_master_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ false, get_link_master_handler);
}

static int link_unset_master_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        /* Some devices do not support setting master ifindex. Let's ignore error on unsetting master ifindex. */
        return set_link_handler_internal(rtnl, m, req, link, /* ignore = */ true, get_link_master_handler);
}

static int link_set_mtu_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        int r;

        r = set_link_handler_internal(rtnl, m, req, link, /* ignore = */ true, get_link_default_handler);
        if (r <= 0)
                return r;

        /* The kernel resets ipv6 mtu after changing device mtu;
         * we must set this here, after we've set device mtu */
        r = link_set_ipv6_mtu(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to set IPv6 MTU, ignoring: %m");

        return 0;
}

static int link_configure_fill_message(
                Link *link,
                sd_netlink_message *req,
                RequestType type,
                void *userdata) {
        int r;

        switch (type) {
        case REQUEST_TYPE_SET_LINK_ADDRESS_GENERATION_MODE:
                r = ipv6ll_addrgen_mode_fill_message(req, PTR_TO_UINT8(userdata));
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_SET_LINK_BOND:
                r = sd_netlink_message_set_flags(req, NLM_F_REQUEST | NLM_F_ACK);
                if (r < 0)
                        return r;

                r = sd_netlink_message_open_container(req, IFLA_LINKINFO);
                if (r < 0)
                        return r;

                r = sd_netlink_message_open_container_union(req, IFLA_INFO_DATA, "bond");
                if (r < 0)
                        return r;

                if (link->network->active_slave) {
                        r = sd_netlink_message_append_u32(req, IFLA_BOND_ACTIVE_SLAVE, link->ifindex);
                        if (r < 0)
                                return r;
                }

                if (link->network->primary_slave) {
                        r = sd_netlink_message_append_u32(req, IFLA_BOND_PRIMARY, link->ifindex);
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;

                break;
        case REQUEST_TYPE_SET_LINK_BRIDGE:
                r = sd_rtnl_message_link_set_family(req, AF_BRIDGE);
                if (r < 0)
                        return r;

                r = sd_netlink_message_open_container(req, IFLA_PROTINFO);
                if (r < 0)
                        return r;

                if (link->network->use_bpdu >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_GUARD, link->network->use_bpdu);
                        if (r < 0)
                                return r;
                }

                if (link->network->hairpin >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MODE, link->network->hairpin);
                        if (r < 0)
                                return r;
                }

                if (link->network->isolated >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_ISOLATED, link->network->isolated);
                        if (r < 0)
                                return r;
                }

                if (link->network->fast_leave >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_FAST_LEAVE, link->network->fast_leave);
                        if (r < 0)
                                return r;
                }

                if (link->network->allow_port_to_be_root >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_PROTECT, link->network->allow_port_to_be_root);
                        if (r < 0)
                                return r;
                }

                if (link->network->unicast_flood >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_UNICAST_FLOOD, link->network->unicast_flood);
                        if (r < 0)
                                return r;
                }

                if (link->network->multicast_flood >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MCAST_FLOOD, link->network->multicast_flood);
                        if (r < 0)
                                return r;
                }

                if (link->network->multicast_to_unicast >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MCAST_TO_UCAST, link->network->multicast_to_unicast);
                        if (r < 0)
                                return r;
                }

                if (link->network->neighbor_suppression >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_NEIGH_SUPPRESS, link->network->neighbor_suppression);
                        if (r < 0)
                                return r;
                }

                if (link->network->learning >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_LEARNING, link->network->learning);
                        if (r < 0)
                                return r;
                }

                if (link->network->bridge_proxy_arp >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_PROXYARP, link->network->bridge_proxy_arp);
                        if (r < 0)
                                return r;
                }

                if (link->network->bridge_proxy_arp_wifi >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_PROXYARP_WIFI, link->network->bridge_proxy_arp_wifi);
                        if (r < 0)
                                return r;
                }

                if (link->network->cost != 0) {
                        r = sd_netlink_message_append_u32(req, IFLA_BRPORT_COST, link->network->cost);
                        if (r < 0)
                                return r;
                }

                if (link->network->priority != LINK_BRIDGE_PORT_PRIORITY_INVALID) {
                        r = sd_netlink_message_append_u16(req, IFLA_BRPORT_PRIORITY, link->network->priority);
                        if (r < 0)
                                return r;
                }

                if (link->network->multicast_router != _MULTICAST_ROUTER_INVALID) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MULTICAST_ROUTER, link->network->multicast_router);
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_SET_LINK_BRIDGE_VLAN:
                r = sd_rtnl_message_link_set_family(req, AF_BRIDGE);
                if (r < 0)
                        return r;

                r = sd_netlink_message_open_container(req, IFLA_AF_SPEC);
                if (r < 0)
                        return r;

                if (link->master_ifindex <= 0) {
                        /* master needs BRIDGE_FLAGS_SELF flag */
                        r = sd_netlink_message_append_u16(req, IFLA_BRIDGE_FLAGS, BRIDGE_FLAGS_SELF);
                        if (r < 0)
                                return r;
                }

                r = bridge_vlan_append_info(link, req, link->network->pvid, link->network->br_vid_bitmap, link->network->br_untagged_bitmap);
                if (r < 0)
                        return r;

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;

                break;
        case REQUEST_TYPE_SET_LINK_CAN:
                r = can_set_netlink_message(link, req);
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_SET_LINK_FLAGS: {
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
                        return r;

                break;
        }
        case REQUEST_TYPE_SET_LINK_GROUP:
                r = sd_netlink_message_append_u32(req, IFLA_GROUP, (uint32_t) link->network->group);
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_SET_LINK_MAC:
                r = netlink_message_append_hw_addr(req, IFLA_ADDRESS, &link->requested_hw_addr);
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_SET_LINK_IPOIB:
                r = ipoib_set_netlink_message(link, req);
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_SET_LINK_MASTER:
                r = sd_netlink_message_append_u32(req, IFLA_MASTER, PTR_TO_UINT32(userdata));
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_SET_LINK_MTU:
                r = sd_netlink_message_append_u32(req, IFLA_MTU, PTR_TO_UINT32(userdata));
                if (r < 0)
                        return r;
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

static int link_configure(Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(req);

        log_link_debug(link, "Setting %s", request_type_to_string(req->type));

        if (req->type == REQUEST_TYPE_SET_LINK_BOND)
                r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_NEWLINK, link->master_ifindex);
        else if (IN_SET(req->type, REQUEST_TYPE_SET_LINK_CAN, REQUEST_TYPE_SET_LINK_IPOIB))
                r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_NEWLINK, link->ifindex);
        else
                r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = link_configure_fill_message(link, m, req->type, req->userdata);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool netdev_is_ready(NetDev *netdev) {
        assert(netdev);

        if (netdev->state != NETDEV_STATE_READY)
                return false;
        if (netdev->ifindex == 0)
                return false;

        return true;
}

static int link_is_ready_to_set_link(Link *link, Request *req) {
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(req);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        switch (req->type) {
        case REQUEST_TYPE_SET_LINK_BOND:
        case REQUEST_TYPE_SET_LINK_BRIDGE:
                if (!link->master_set)
                        return false;

                if (link->network->keep_master && link->master_ifindex <= 0)
                        return false;
                break;

        case REQUEST_TYPE_SET_LINK_BRIDGE_VLAN:
                if (!link->master_set)
                        return false;

                if (link->network->keep_master && link->master_ifindex <= 0 && !streq_ptr(link->kind, "bridge"))
                        return false;

                break;

        case REQUEST_TYPE_SET_LINK_CAN:
                /* Do not check link->set_flgas_messages here, as it is ok even if link->flags
                 * is outdated, and checking the counter causes a deadlock. */
                if (FLAGS_SET(link->flags, IFF_UP)) {
                        /* The CAN interface must be down to configure bitrate, etc... */
                        r = link_down_now(link);
                        if (r < 0)
                                return r;
                }
                break;

        case REQUEST_TYPE_SET_LINK_MAC:
                if (req->netlink_handler == link_set_mac_handler) {
                        /* This is the second attempt to set hardware address. On the first attempt
                         * req->netlink_handler points to link_set_mac_allow_retry_handler().
                         * The first attempt failed as the interface was up. */
                        r = link_down_now(link);
                        if (r < 0)
                                return r;
                }
                break;

        case REQUEST_TYPE_SET_LINK_MASTER: {
                uint32_t m = 0;
                Request req_mac = {
                        .link = link,
                        .type = REQUEST_TYPE_SET_LINK_MAC,
                };

                if (link->network->batadv) {
                        if (!netdev_is_ready(link->network->batadv))
                                return false;
                        m = link->network->batadv->ifindex;
                } else if (link->network->bond) {
                        if (ordered_set_contains(link->manager->request_queue, &req_mac))
                                return false;
                        if (!netdev_is_ready(link->network->bond))
                                return false;
                        m = link->network->bond->ifindex;

                        /* Do not check link->set_flgas_messages here, as it is ok even if link->flags
                         * is outdated, and checking the counter causes a deadlock. */
                        if (FLAGS_SET(link->flags, IFF_UP)) {
                                /* link must be down when joining to bond master. */
                                r = link_down_now(link);
                                if (r < 0)
                                        return r;
                        }
                } else if (link->network->bridge) {
                        if (ordered_set_contains(link->manager->request_queue, &req_mac))
                                return false;
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
        case REQUEST_TYPE_SET_LINK_MTU: {
                Request req_ipoib = {
                        .link = link,
                        .type = REQUEST_TYPE_SET_LINK_IPOIB,
                };

                return !ordered_set_contains(link->manager->request_queue, &req_ipoib);
        }
        default:
                break;
        }

        return true;
}

static int link_process_set_link(Request *req, Link *link, void *userdata) {
        int r;

        assert(req);
        assert(link);

        r = link_is_ready_to_set_link(link, req);
        if (r <= 0)
                return r;

        r = link_configure(link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set %s", request_type_to_string(req->type));

        return 1;
}

static int link_request_set_link(
                Link *link,
                RequestType type,
                request_netlink_handler_t netlink_handler,
                Request **ret) {

        Request *req;
        int r;

        assert(link);

        r = link_queue_request_full(link, type, NULL, NULL, NULL, NULL,
                                    link_process_set_link,
                                    &link->set_link_messages,
                                    netlink_handler,
                                    &req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request to set %s: %m",
                                              request_type_to_string(type));

        log_link_debug(link, "Requested to set %s", request_type_to_string(type));

        if (ret)
                *ret = req;
        return 0;
}

int link_request_to_set_addrgen_mode(Link *link) {
        IPv6LinkLocalAddressGenMode mode;
        Request *req;
        int r;

        assert(link);
        assert(link->network);

        if (!socket_ipv6_is_supported())
                return 0;

        mode = link_get_ipv6ll_addrgen_mode(link);

        if (mode == link->ipv6ll_address_gen_mode)
                return 0;

        /* If the link is already up, then changing the mode by netlink does not take effect until the
         * link goes down. Hence, we need to reset the interface. However, setting the mode by sysctl
         * does not need that. Let's use the sysctl interface when the link is already up.
         * See also issue #22424. */
        if (mode != IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE &&
            FLAGS_SET(link->flags, IFF_UP)) {
                r = link_set_ipv6ll_addrgen_mode(link, mode);
                if (r < 0)
                        log_link_warning_errno(link, r, "Cannot set IPv6 address generation mode, ignoring: %m");

                return 0;
        }

        r = link_request_set_link(link, REQUEST_TYPE_SET_LINK_ADDRESS_GENERATION_MODE,
                                  link_set_addrgen_mode_handler,
                                  &req);
        if (r < 0)
                return r;

        req->userdata = UINT8_TO_PTR(mode);
        return 0;
}

int link_request_to_set_bond(Link *link) {
        assert(link);
        assert(link->network);

        if (!link->network->bond) {
                Link *master;

                if (!link->network->keep_master)
                        return 0;

                if (link_get_master(link, &master) < 0)
                        return 0;

                if (!streq_ptr(master->kind, "bond"))
                        return 0;
        }

        return link_request_set_link(link, REQUEST_TYPE_SET_LINK_BOND,
                                     link_set_bond_handler, NULL);
}

int link_request_to_set_bridge(Link *link) {
        assert(link);
        assert(link->network);

        if (!link->network->bridge) {
                Link *master;

                if (!link->network->keep_master)
                        return 0;

                if (link_get_master(link, &master) < 0)
                        return 0;

                if (!streq_ptr(master->kind, "bridge"))
                        return 0;
        }

        return link_request_set_link(link, REQUEST_TYPE_SET_LINK_BRIDGE,
                                     link_set_bridge_handler,
                                     NULL);
}

int link_request_to_set_bridge_vlan(Link *link) {
        assert(link);
        assert(link->network);

        if (!link->network->use_br_vlan)
                return 0;

        if (!link->network->bridge && !streq_ptr(link->kind, "bridge")) {
                Link *master;

                if (!link->network->keep_master)
                        return 0;

                if (link_get_master(link, &master) < 0)
                        return 0;

                if (!streq_ptr(master->kind, "bridge"))
                        return 0;
        }

        return link_request_set_link(link, REQUEST_TYPE_SET_LINK_BRIDGE_VLAN,
                                     link_set_bridge_vlan_handler,
                                     NULL);
}

int link_request_to_set_can(Link *link) {
        assert(link);
        assert(link->network);

        if (link->iftype != ARPHRD_CAN)
                return 0;

        if (!streq_ptr(link->kind, "can"))
                return 0;

        return link_request_set_link(link, REQUEST_TYPE_SET_LINK_CAN,
                                     link_set_can_handler,
                                     NULL);
}

int link_request_to_set_flags(Link *link) {
        assert(link);
        assert(link->network);

        if (link->network->arp < 0 &&
            link->network->multicast < 0 &&
            link->network->allmulticast < 0 &&
            link->network->promiscuous < 0)
                return 0;

        return link_request_set_link(link, REQUEST_TYPE_SET_LINK_FLAGS,
                                     link_set_flags_handler,
                                     NULL);
}

int link_request_to_set_group(Link *link) {
        assert(link);
        assert(link->network);

        if (link->network->group < 0)
                return 0;

        return link_request_set_link(link, REQUEST_TYPE_SET_LINK_GROUP,
                                     link_set_group_handler,
                                     NULL);
}

int link_request_to_set_mac(Link *link, bool allow_retry) {
        int r;

        assert(link);
        assert(link->network);

        if (link->network->hw_addr.length == 0)
                return 0;

        link->requested_hw_addr = link->network->hw_addr;
        r = net_verify_hardware_address(link->ifname, /* is_static = */ true,
                                        link->iftype, &link->hw_addr, &link->requested_hw_addr);
        if (r < 0)
                return r;

        if (hw_addr_equal(&link->hw_addr, &link->requested_hw_addr))
                return 0;

        return link_request_set_link(link, REQUEST_TYPE_SET_LINK_MAC,
                                     allow_retry ? link_set_mac_allow_retry_handler : link_set_mac_handler,
                                     NULL);
}

int link_request_to_set_ipoib(Link *link) {
        assert(link);
        assert(link->network);

        if (link->iftype != ARPHRD_INFINIBAND)
                return 0;

        if (link->network->ipoib_mode < 0 &&
            link->network->ipoib_umcast < 0)
                return 0;

        return link_request_set_link(link, REQUEST_TYPE_SET_LINK_IPOIB,
                                     link_set_ipoib_handler,
                                     NULL);
}

int link_request_to_set_master(Link *link) {
        assert(link);
        assert(link->network);

        if (link->network->keep_master) {
                link->master_set = true;
                return 0;
        }

        link->master_set = false;

        if (link->network->batadv || link->network->bond || link->network->bridge || link->network->vrf)
                return link_request_set_link(link, REQUEST_TYPE_SET_LINK_MASTER,
                                             link_set_master_handler,
                                             NULL);
        else
                return link_request_set_link(link, REQUEST_TYPE_SET_LINK_MASTER,
                                             link_unset_master_handler,
                                             NULL);
}

int link_request_to_set_mtu(Link *link, uint32_t mtu) {
        const char *origin;
        uint32_t min_mtu;
        Request *req;
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

        r = link_request_set_link(link, REQUEST_TYPE_SET_LINK_MTU,
                                  link_set_mtu_handler,
                                  &req);
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

static int link_up_dsa_slave(Link *link) {
        Link *master;
        int r;

        assert(link);

        /* For older kernels (specifically, older than 9d5ef190e5615a7b63af89f88c4106a5bc127974, kernel-5.12),
         * it is necessary to bring up a DSA slave that its master interface is already up. And bringing up
         * the slave fails with -ENETDOWN. So, let's bring up the master even if it is not managed by us,
         * and try to bring up the slave after the master becomes up. */

        if (link->dsa_master_ifindex <= 0)
                return 0;

        if (!streq_ptr(link->driver, "dsa"))
                return 0;

        if (link_get_by_index(link->manager, link->dsa_master_ifindex, &master) < 0)
                return 0;

        if (master->state == LINK_STATE_UNMANAGED) {
                /* If the DSA master interface is unmanaged, then it will never become up.
                 * Let's request to bring up the master. */
                r = link_request_to_bring_up_or_down(master, /* up = */ true);
                if (r < 0)
                        return r;
        }

        r = link_request_to_bring_up_or_down(link, /* up = */ true);
        if (r < 0)
                return r;

        return 1;
}

static int link_up_or_down_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        bool on_activate, up;
        int r;

        assert(m);
        assert(req);
        assert(link);

        on_activate = req->type == REQUEST_TYPE_ACTIVATE_LINK;
        up = PTR_TO_INT(req->userdata);

        r = sd_netlink_message_get_errno(m);
        if (r == -ENETDOWN && up && link_up_dsa_slave(link) > 0)
                log_link_message_debug_errno(link, m, r, "Could not bring up dsa slave, retrying again after dsa master becomes up");
        else if (r < 0)
                log_link_message_warning_errno(link, m, r, up ?
                                               "Could not bring up interface, ignoring" :
                                               "Could not bring down interface, ignoring");

        r = link_call_getlink(link, get_link_update_flag_handler);
        if (r < 0) {
                link_enter_failed(link);
                return 0;
        }

        link->set_flags_messages++;

        if (on_activate) {
                link->activated = true;
                link_check_ready(link);
        }

        return 0;
}

static const char *up_or_down(bool up) {
        return up ? "up" : "down";
}

static int link_up_or_down(Link *link, bool up, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        log_link_debug(link, "Bringing link %s", up_or_down(up));

        r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_set_flags(m, up ? IFF_UP : 0, IFF_UP);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool link_is_ready_to_activate(Link *link) {
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        if (link->set_link_messages > 0)
                return false;

        return true;
}

static int link_process_activation(Request *req, Link *link, void *userdata) {
        bool up = PTR_TO_INT(userdata);
        int r;

        assert(req);
        assert(link);

        if (!link_is_ready_to_activate(link))
                return 0;

        r = link_up_or_down(link, up, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to activate link: %m");

        return 1;
}

int link_request_to_activate(Link *link) {
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
                assert_not_reached();
        }

        link->activated = false;

        r = link_queue_request_full(link, REQUEST_TYPE_ACTIVATE_LINK,
                                    INT_TO_PTR(up), NULL, NULL, NULL,
                                    link_process_activation,
                                    &link->set_flags_messages,
                                    link_up_or_down_handler, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request to activate link: %m");

        log_link_debug(link, "Requested to activate link");
        return 0;
}

static bool link_is_ready_to_bring_up_or_down(Link *link, bool up) {
        assert(link);

        if (up && link->dsa_master_ifindex > 0) {
                Link *master;

                /* The master interface must be up. See comments in link_up_dsa_slave(). */

                if (link_get_by_index(link->manager, link->dsa_master_ifindex, &master) < 0)
                        return false;

                if (!FLAGS_SET(master->flags, IFF_UP))
                        return false;
        }

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

static int link_process_up_or_down(Request *req, Link *link, void *userdata) {
        bool up = PTR_TO_INT(userdata);
        int r;

        assert(req);
        assert(link);

        if (!link_is_ready_to_bring_up_or_down(link, up))
                return 0;

        r = link_up_or_down(link, up, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to bring link %s: %m", up_or_down(up));

        return 1;
}

int link_request_to_bring_up_or_down(Link *link, bool up) {
        int r;

        assert(link);

        r = link_queue_request_full(link, REQUEST_TYPE_UP_DOWN,
                                    INT_TO_PTR(up), NULL, NULL, NULL,
                                    link_process_up_or_down,
                                    &link->set_flags_messages,
                                    link_up_or_down_handler, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request to bring link %s: %m",
                                              up_or_down(up));

        log_link_debug(link, "Requested to bring link %s", up_or_down(up));
        return 0;
}

static int link_down_now_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->set_flags_messages > 0);

        link->set_flags_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not bring down interface, ignoring");

        r = link_call_getlink(link, get_link_update_flag_handler);
        if (r < 0) {
                link_enter_failed(link);
                return 0;
        }

        link->set_flags_messages++;
        return 0;
}

int link_down_now(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_link_debug(link, "Bringing link down");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_flags(req, 0, IFF_UP);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not set link flags: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_down_now_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not send rtnetlink message: %m");

        link->set_flags_messages++;
        link_ref(link);
        return 0;
}

static int link_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not remove interface, ignoring");

        return 0;
}

int link_remove(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_link_debug(link, "Removing link.");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_DELLINK, link->ifindex);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not allocate RTM_DELLINK message: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}
