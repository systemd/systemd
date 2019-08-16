/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>
#include <linux/can/netlink.h>

#include "netlink-util.h"
#include "networkd-can.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "string-util.h"

static int link_up_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                /* we warn but don't fail the link, as it may be brought up later */
                log_link_warning_errno(link, r, "Could not bring up interface: %m");

        return 1;
}

static int link_up_can(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);

        log_link_debug(link, "Bringing CAN link up");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set link flags: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_up_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int link_set_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        log_link_debug(link, "Set link");

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_error_errno(link, r, "Failed to configure CAN link: %m");
                link_enter_failed(link);
        }

        return 1;
}

static int link_set_can(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_link_debug(link, "Configuring CAN link.");

        r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_NEWLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to allocate netlink message: %m");

        r = sd_netlink_message_set_flags(m, NLM_F_REQUEST | NLM_F_ACK);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set netlink flags: %m");

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to open netlink container: %m");

        r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, link->kind);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_INFO_DATA attribute: %m");

        if (link->network->can_bitrate > 0 || link->network->can_sample_point > 0) {
                struct can_bittiming bt = {
                        .bitrate = link->network->can_bitrate,
                        .sample_point = link->network->can_sample_point,
                };

                if (link->network->can_bitrate > UINT32_MAX) {
                        log_link_error(link, "bitrate (%zu) too big.", link->network->can_bitrate);
                        return -ERANGE;
                }

                log_link_debug(link, "Setting bitrate = %d bit/s", bt.bitrate);
                if (link->network->can_sample_point > 0)
                        log_link_debug(link, "Setting sample point = %d.%d%%", bt.sample_point / 10, bt.sample_point % 10);
                else
                        log_link_debug(link, "Using default sample point");

                r = sd_netlink_message_append_data(m, IFLA_CAN_BITTIMING, &bt, sizeof(bt));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_CAN_BITTIMING attribute: %m");
        }

        if (link->network->can_restart_us > 0) {
                char time_string[FORMAT_TIMESPAN_MAX];
                uint64_t restart_ms;

                if (link->network->can_restart_us == USEC_INFINITY)
                        restart_ms = 0;
                else
                        restart_ms = DIV_ROUND_UP(link->network->can_restart_us, USEC_PER_MSEC);

                format_timespan(time_string, FORMAT_TIMESPAN_MAX, restart_ms * 1000, MSEC_PER_SEC);

                if (restart_ms > UINT32_MAX) {
                        log_link_error(link, "restart timeout (%s) too big.", time_string);
                        return -ERANGE;
                }

                log_link_debug(link, "Setting restart = %s", time_string);

                r = sd_netlink_message_append_u32(m, IFLA_CAN_RESTART_MS, restart_ms);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_CAN_RESTART_MS attribute: %m");
        }

        if (link->network->can_triple_sampling >= 0) {
                struct can_ctrlmode cm = {
                        .mask = CAN_CTRLMODE_3_SAMPLES,
                        .flags = link->network->can_triple_sampling ? CAN_CTRLMODE_3_SAMPLES : 0,
                };

                log_link_debug(link, "%sabling triple-sampling", link->network->can_triple_sampling ? "En" : "Dis");

                r = sd_netlink_message_append_data(m, IFLA_CAN_CTRLMODE, &cm, sizeof(cm));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_CAN_CTRLMODE attribute: %m");
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to close netlink container: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to close netlink container: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, m, link_set_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        if (!(link->flags & IFF_UP))
                return link_up_can(link);

        return 0;
}

static int link_down_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not bring down interface: %m");
                link_enter_failed(link);
                return 1;
        }

        r = link_set_can(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

int link_configure_can(Link *link) {
        int r;

        link_set_state(link, LINK_STATE_CONFIGURING);

        if (streq_ptr(link->kind, "can")) {
                /* The CAN interface must be down to configure bitrate, etc... */
                if ((link->flags & IFF_UP)) {
                        r = link_down(link, link_down_handler);
                        if (r < 0) {
                                link_enter_failed(link);
                                return r;
                        }
                } else {
                        r = link_set_can(link);
                        if (r < 0) {
                                link_enter_failed(link);
                                return r;
                        }
                }

                return 0;
        }

        if (!(link->flags & IFF_UP)) {
                r = link_up_can(link);
                if (r < 0) {
                        link_enter_failed(link);
                        return r;
                }
        }

        return 0;
}
