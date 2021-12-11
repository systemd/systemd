/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

typedef struct Link Link;
typedef struct Request Request;

typedef enum SetLinkOperation {
        SET_LINK_ADDRESS_GENERATION_MODE, /* Setting IPv6LL address generation mode. */
        SET_LINK_BOND,                    /* Setting bond configs. */
        SET_LINK_BRIDGE,                  /* Setting bridge configs. */
        SET_LINK_BRIDGE_VLAN,             /* Setting bridge VLAN configs. */
        SET_LINK_CAN,                     /* Setting CAN interface configs. */
        SET_LINK_FLAGS,                   /* Setting IFF_NOARP or friends. */
        SET_LINK_GROUP,                   /* Setting interface group. */
        SET_LINK_IPOIB,                   /* Setting IPoIB configs. */
        SET_LINK_MAC,                     /* Setting MAC address. */
        SET_LINK_MASTER,                  /* Setting IFLA_MASTER. */
        SET_LINK_MTU,                     /* Setting MTU. */
        _SET_LINK_OPERATION_MAX,
        _SET_LINK_OPERATION_INVALID = -EINVAL,
} SetLinkOperation;

/* SetLinkOperation is casted to int, then stored in void* with INT_TO_PTR(). */
assert_cc(sizeof(SetLinkOperation) <= sizeof(void*));
assert_cc(sizeof(SetLinkOperation) <= sizeof(int));

int link_request_to_set_addrgen_mode(Link *link);
int link_request_to_set_bond(Link *link);
int link_request_to_set_bridge(Link *link);
int link_request_to_set_bridge_vlan(Link *link);
int link_request_to_set_can(Link *link);
int link_request_to_set_flags(Link *link);
int link_request_to_set_group(Link *link);
int link_request_to_set_mac(Link *link, bool allow_retry);
int link_request_to_set_ipoib(Link *link);
int link_request_to_set_master(Link *link);
int link_request_to_set_mtu(Link *link, uint32_t mtu);

int link_configure_mtu(Link *link);

int request_process_set_link(Request *req);

int link_down(Link *link);

int request_process_activation(Request *req);
int link_request_to_activate(Link *link);

int request_process_link_up_or_down(Request *req);
int link_request_to_bring_up_or_down(Link *link, bool up);

int link_remove(Link *link);
