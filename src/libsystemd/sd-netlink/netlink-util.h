/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "netlink-util-rtnl.h"
#include "socket-util.h"

#define netlink_call_async(nl, ret_slot, message, callback, destroy_callback, userdata) \
        ({                                                              \
                int (*_callback_)(sd_netlink *, sd_netlink_message *, typeof(userdata)) = callback; \
                void (*_destroy_)(typeof(userdata)) = destroy_callback; \
                sd_netlink_call_async(nl, ret_slot, message,            \
                                      (sd_netlink_message_handler_t) _callback_, \
                                      (sd_netlink_destroy_t) _destroy_, \
                                      userdata, 0, __func__);           \
        })

#define netlink_add_match(nl, ret_slot, match, callback, destroy_callback, userdata, description) \
        ({                                                              \
                int (*_callback_)(sd_netlink *, sd_netlink_message *, typeof(userdata)) = callback; \
                void (*_destroy_)(typeof(userdata)) = destroy_callback; \
                sd_netlink_add_match(nl, ret_slot, match,               \
                                     (sd_netlink_message_handler_t) _callback_, \
                                     (sd_netlink_destroy_t) _destroy_,  \
                                     userdata, description);            \
        })

#define genl_add_match(nl, ret_slot, family, group, cmd, callback, destroy_callback, userdata, description) \
        ({                                                              \
                int (*_callback_)(sd_netlink *, sd_netlink_message *, typeof(userdata)) = callback; \
                void (*_destroy_)(typeof(userdata)) = destroy_callback; \
                sd_genl_add_match(nl, ret_slot, family, group, cmd,     \
                                  (sd_netlink_message_handler_t) _callback_, \
                                  (sd_netlink_destroy_t) _destroy_,     \
                                  userdata, description);               \
        })

int netlink_message_append_hw_addr(sd_netlink_message *m, unsigned short type, const struct hw_addr_data *data);
int netlink_message_append_in_addr_union(sd_netlink_message *m, unsigned short type, int family, const union in_addr_union *data);
int netlink_message_append_sockaddr_union(sd_netlink_message *m, unsigned short type, const union sockaddr_union *data);

int netlink_message_read_hw_addr(sd_netlink_message *m, unsigned short type, struct hw_addr_data *data);
int netlink_message_read_in_addr_union(sd_netlink_message *m, unsigned short type, int family, union in_addr_union *data);
