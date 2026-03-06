/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <netinet/in.h>

#include "sd-netlink.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "device-private.h"
#include "missing-network.h"
#include "netif-util.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-can.h"
#include "networkd-ipv4acd.h"
#include "networkd-ipv4ll.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-setlink.h"
#include "networkd-sriov.h"
#include "networkd-wiphy.h"
#include "ordered-set.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"

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
                log_link_message_warning_errno(link, m, r, "Failed to set %s%s",
                                               request_type_to_string(req->type),
                                               ignore ? ", ignoring" : "");

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

        r = set_link_handler_internal(rtnl, m, req, link, /* ignore= */ true, NULL);
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
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ false, NULL);
}

static int link_set_bridge_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ true, NULL);
}

static int link_set_bridge_vlan_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        r = set_link_handler_internal(rtnl, m, req, link, /* ignore= */ false, NULL);
        if (r <= 0)
                return r;

        link->bridge_vlan_set = true;
        return 0;
}

static int link_del_bridge_vlan_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ false, NULL);
}

static int link_set_can_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ false, NULL);
}

static int link_set_flags_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ false, get_link_default_handler);
}

static int link_set_group_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ false, NULL);
}

static int link_set_ipoib_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ true, NULL);
}

static int link_set_mac_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ true, get_link_default_handler);
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

                log_link_message_debug_errno(link, m, r, "Failed to set MAC address, retrying again");

                r = link_request_to_set_mac(link, /* allow_retry= */ false);
                if (r < 0)
                        link_enter_failed(link);

                return 0;
        }

        return link_set_mac_handler(rtnl, m, req, link, userdata);
}

static int link_set_master_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ false, get_link_master_handler);
}

static int link_unset_master_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        /* Some devices do not support setting master ifindex. Let's ignore error on unsetting master ifindex. */
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ true, get_link_master_handler);
}

static int link_set_mtu_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, void *userdata) {
        return set_link_handler_internal(rtnl, m, req, link, /* ignore= */ true, get_link_default_handler);
}

static int link_get_arp(Link *link) {
        assert(link);

        /* This returns tristate. */

        if (!link->network)
                return -1;

        /* If ARP= is explicitly specified, use the setting. */
        if (link->network->arp >= 0)
                return link->network->arp;

        /* Enable ARP when IPv4ACD is enabled. */
        if (link_ipv4acd_enabled(link))
                return true;

        /* Similarly, enable ARP when IPv4LL is enabled. */
        if (link_ipv4ll_enabled(link))
                return true;

        /* Otherwise, do not change the flag. */
        return -1;
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
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_GUARD, !link->network->use_bpdu);
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
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_PROTECT, !link->network->allow_port_to_be_root);
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

                if (link->network->bridge_locked >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_LOCKED, link->network->bridge_locked);
                        if (r < 0)
                                return r;
                }

                if (link->network->bridge_mac_authentication_bypass >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_MAB, link->network->bridge_mac_authentication_bypass);
                        if (r < 0)
                                return r;
                }

                if (link->network->bridge_vlan_tunnel >= 0) {
                        r = sd_netlink_message_append_u8(req, IFLA_BRPORT_VLAN_TUNNEL, link->network->bridge_vlan_tunnel);
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_SET_LINK_BRIDGE_VLAN:
                r = bridge_vlan_set_message(link, req, /* is_set= */ true);
                if (r < 0)
                        return r;
                break;
        case REQUEST_TYPE_DEL_LINK_BRIDGE_VLAN:
                r = bridge_vlan_set_message(link, req, /* is_set= */ false);
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

                int arp = link_get_arp(link);

                if (arp >= 0) {
                        ifi_change |= IFF_NOARP;
                        SET_FLAG(ifi_flags, IFF_NOARP, arp == 0);
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
        else if (req->type == REQUEST_TYPE_DEL_LINK_BRIDGE_VLAN)
                r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_DELLINK, link->ifindex);
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

static uint32_t link_adjust_mtu(Link *link, uint32_t mtu) {
        const char *origin;
        uint32_t min_mtu;

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

        return mtu;
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

        case REQUEST_TYPE_DEL_LINK_BRIDGE_VLAN:
                return link->bridge_vlan_set;

        case REQUEST_TYPE_SET_LINK_CAN:
                /* Do not check link->set_flags_messages here, as it is ok even if link->flags
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

                        /* If the kind of the link is "bond", we need
                         * set the slave link down as well. */
                        if (streq_ptr(link->kind, "bond")) {
                                r = link_down_slave_links(link);
                                if (r < 0)
                                        return r;
                        }
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

                if (m == (uint32_t) link->master_ifindex) {
                        /* The requested master is already set. */
                        link->master_set = true;
                        return -EALREADY; /* indicate to cancel the request. */
                }

                /* Do not check link->set_flags_messages here, as it is ok even if link->flags is outdated,
                 * and checking the counter causes a deadlock. */
                if (link->network->bond && FLAGS_SET(link->flags, IFF_UP)) {
                        /* link must be down when joining to bond master. */
                        r = link_down_now(link);
                        if (r < 0)
                                return r;
                }

                if (link->network->bridge && !FLAGS_SET(link->flags, IFF_UP) && link->dev) {
                        /* Some devices require the port to be up before joining the bridge.
                         *
                         * E.g. Texas Instruments SoC Ethernet running in switch mode:
                         * https://docs.kernel.org/networking/device_drivers/ethernet/ti/am65_nuss_cpsw_switchdev.html#enabling-switch
                         * > Port’s netdev devices have to be in UP before joining to the bridge to avoid
                         * > overwriting of bridge configuration as CPSW switch driver completely reloads its
                         * > configuration when first port changes its state to UP. */

                        r = device_get_property_bool(link->dev, "ID_NET_BRING_UP_BEFORE_JOINING_BRIDGE");
                        if (r < 0 && r != -ENOENT)
                                log_link_warning_errno(link, r, "Failed to get or parse ID_NET_BRING_UP_BEFORE_JOINING_BRIDGE property, ignoring: %m");
                        else if (r > 0) {
                                r = link_up_now(link);
                                if (r < 0)
                                        return r;
                        }
                }

                req->userdata = UINT32_TO_PTR(m);
                break;
        }
        case REQUEST_TYPE_SET_LINK_MTU: {
                if (ordered_set_contains(link->manager->request_queue,
                                         &(const Request) {
                                                 .link = link,
                                                 .type = REQUEST_TYPE_SET_LINK_IPOIB,
                                         }))
                        return false;

                /* Changing FD mode may affect MTU.
                 * See https://docs.kernel.org/networking/can.html#can-fd-flexible-data-rate-driver-support
                 *   MTU = 16 (CAN_MTU)   => Classical CAN device
                 *   MTU = 72 (CANFD_MTU) => CAN FD capable device */
                if (ordered_set_contains(link->manager->request_queue,
                                         &(const Request) {
                                                 .link = link,
                                                 .type = REQUEST_TYPE_SET_LINK_CAN,
                                         }))
                        return false;

                /* Now, it is ready to set MTU, but before setting, adjust requested MTU. */
                uint32_t mtu = link_adjust_mtu(link, PTR_TO_UINT32(req->userdata));
                if (mtu == link->mtu)
                        return -EALREADY; /* Not necessary to set the same value. */

                req->userdata = UINT32_TO_PTR(mtu);
                break;
        }
        default:
                ;
        }

        return true;
}

static int link_process_set_link(Request *req, Link *link, void *userdata) {
        int r;

        assert(req);
        assert(link);

        r = link_is_ready_to_set_link(link, req);
        if (r == -EALREADY)
                return 1; /* Cancel the request. */
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
        int r;

        assert(link);
        assert(link->network);

        /* If nothing configured, use the default vlan ID. */
        if (memeqzero(link->network->bridge_vlan_bitmap, BRIDGE_VLAN_BITMAP_LEN * sizeof(uint32_t)) &&
            link->network->bridge_vlan_pvid == BRIDGE_VLAN_KEEP_PVID)
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

        link->bridge_vlan_set = false;

        r = link_request_set_link(link, REQUEST_TYPE_SET_LINK_BRIDGE_VLAN,
                                  link_set_bridge_vlan_handler,
                                  NULL);
        if (r < 0)
                return r;

        r = link_request_set_link(link, REQUEST_TYPE_DEL_LINK_BRIDGE_VLAN,
                                  link_del_bridge_vlan_handler,
                                  NULL);
        if (r < 0)
                return r;

        return 0;
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

        if (link_get_arp(link) < 0 &&
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
        r = net_verify_hardware_address(link->ifname, /* is_static= */ true,
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
                /* When KeepMaster=yes, BatmanAdvanced=, Bond=, Bridge=, and VRF= are ignored. */
                link->master_set = true;
                return 0;

        } else if (link->network->batadv || link->network->bond || link->network->bridge || link->network->vrf) {
                link->master_set = false;
                return link_request_set_link(link, REQUEST_TYPE_SET_LINK_MASTER,
                                             link_set_master_handler,
                                             NULL);

        } else if (link->master_ifindex != 0) {
                /* Unset master only when it is set. */
                link->master_set = false;
                return link_request_set_link(link, REQUEST_TYPE_SET_LINK_MASTER,
                                             link_unset_master_handler,
                                             NULL);

        } else {
                /* Nothing we need to do. */
                link->master_set = true;
                return 0;
        }
}

int link_request_to_set_mtu(Link *link, uint32_t mtu) {
        Request *req;
        int r;

        assert(link);

        if (mtu == 0)
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
                r = link_request_to_bring_up_or_down(master, /* up= */ true);
                if (r < 0)
                        return r;
        }

        r = link_request_to_bring_up_or_down(link, /* up= */ true);
        if (r < 0)
                return r;

        return 1;
}

static const char* up_or_down(bool up) {
        return up ? "up" : "down";
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
                log_link_message_warning_errno(link, m, r, "Could not bring %s interface, ignoring", up_or_down(up));

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

static int link_up_or_down(Link *link, bool up, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        /* The log message is checked in the test. Please also update test_bond_active_slave() in
         * test/test-network/systemd-networkd-tests.py. when the log message below is modified. */
        log_link_debug(link, "Bringing link %s", up_or_down(up));

        r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_set_flags(m, up ? IFF_UP : 0, IFF_UP);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool link_is_ready_to_activate_one(Link *link, bool allow_unmanaged) {
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED, LINK_STATE_UNMANAGED))
                return false;

        if (!link->network)
                return allow_unmanaged;

        if (link->set_link_messages > 0)
                return false;

        return true;
}

 static bool link_is_ready_to_activate(Link *link, bool up) {
        assert(link);

        if (!check_ready_for_all_sr_iov_ports(link, /* allow_unmanaged= */ false,
                                              link_is_ready_to_activate_one))
                return false;

        if (up && link_rfkilled(link) > 0)
                return false;

        return true;
}

static int link_process_activation(Request *req, Link *link, void *userdata) {
        bool up = PTR_TO_INT(userdata);
        int r;

        assert(req);
        assert(link);

        if (!link_is_ready_to_activate(link, up))
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

        if (up && link_rfkilled(link) > 0)
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

static int link_up_or_down_now_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link, bool up) {
        int r;

        assert(m);
        assert(link);
        assert(link->set_flags_messages > 0);

        link->set_flags_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not bring %s interface, ignoring", up_or_down(up));

        r = link_call_getlink(link, get_link_update_flag_handler);
        if (r < 0) {
                link_enter_failed(link);
                return 0;
        }

        link->set_flags_messages++;
        return 0;
}

static int link_up_now_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_up_or_down_now_handler(rtnl, m, link, /* up= */ true);
}

static int link_down_now_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_up_or_down_now_handler(rtnl, m, link, /* up= */ false);
}

int link_up_or_down_now(Link *link, bool up) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_link_debug(link, "Bringing link %s", up_or_down(up));

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_flags(req, up ? IFF_UP : 0, IFF_UP);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not set link flags: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               up ? link_up_now_handler : link_down_now_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not send rtnetlink message: %m");

        link->set_flags_messages++;
        link_ref(link);
        return 0;
}

typedef struct SetLinkVarlinkContext {
        Link *link;
        sd_varlink *vlink;
        bool up;
} SetLinkVarlinkContext;

static SetLinkVarlinkContext* set_link_varlink_context_free(SetLinkVarlinkContext *ctx) {
        if (!ctx)
                return NULL;

        if (ctx->vlink)
                sd_varlink_unref(ctx->vlink);
        if (ctx->link)
                link_unref(ctx->link);
        return mfree(ctx);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SetLinkVarlinkContext*, set_link_varlink_context_free);

static void set_link_varlink_context_destroy(SetLinkVarlinkContext *ctx) {
        set_link_varlink_context_free(ctx);
}

static int link_up_or_down_now_varlink_handler(sd_netlink *rtnl, sd_netlink_message *m, SetLinkVarlinkContext *ctx) {
        int r;

        assert(m);
        assert(ctx);

        Link *link = ASSERT_PTR(ctx->link);
        sd_varlink *vlink = ASSERT_PTR(ctx->vlink);
        bool up = ctx->up;

        assert(link->set_flags_messages > 0);

        link->set_flags_messages--;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                (void) sd_varlink_error_errno(vlink, r);
                log_link_message_warning_errno(link, m, r, "Could not bring %s interface", up_or_down(up));
        } else
                (void) sd_varlink_reply(vlink, NULL);

        if (link->state == LINK_STATE_LINGER)
                return 0;

        r = link_call_getlink(link, get_link_update_flag_handler);
        if (r < 0) {
                link_enter_failed(link);
                return 0;
        }

        link->set_flags_messages++;
        return 0;
}

int link_up_or_down_now_by_varlink(Link *link, bool up, sd_varlink *vlink) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_link_debug(link, "Bringing link %s (varlink)", up_or_down(up));

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_flags(req, up ? IFF_UP : 0, IFF_UP);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not set link flags: %m");

        _cleanup_(set_link_varlink_context_freep) SetLinkVarlinkContext *ctx = new(SetLinkVarlinkContext, 1);
        if (!ctx)
                return log_oom();

        *ctx = (SetLinkVarlinkContext) {
                .link = link_ref(link),
                .vlink = sd_varlink_ref(vlink),
                .up = up,
        };

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               link_up_or_down_now_varlink_handler,
                               set_link_varlink_context_destroy,
                               ctx);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not send rtnetlink message: %m");

        TAKE_PTR(ctx);
        link->set_flags_messages++;
        return 0;
}

int link_down_slave_links(Link *link) {
        Link *slave;
        int r;

        assert(link);

        SET_FOREACH(slave, link->slaves) {
                r = link_down_now(slave);
                if (r < 0)
                        return r;
        }

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
