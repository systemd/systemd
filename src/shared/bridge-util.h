/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <linux/if_bridge.h>

#include "conf-parser.h"

typedef enum BridgeState {
        NETDEV_BRIDGE_STATE_DISABLED   = BR_STATE_DISABLED,
        NETDEV_BRIDGE_STATE_LISTENING  = BR_STATE_LISTENING,
        NETDEV_BRIDGE_STATE_LEARNING   = BR_STATE_LEARNING,
        NETDEV_BRIDGE_STATE_FORWARDING = BR_STATE_FORWARDING,
        NETDEV_BRIDGE_STATE_BLOCKING   = BR_STATE_BLOCKING,
        _NETDEV_BRIDGE_STATE_MAX,
        _NETDEV_BRIDGE_STATE_INVALID   = -EINVAL,
} BridgeState;

const char* bridge_state_to_string(BridgeState d) _const_;
BridgeState bridge_state_from_string(const char *d) _pure_;
