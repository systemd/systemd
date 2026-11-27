/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "netlink-types.h"

#define CTRL_GENL_NAME "nlctrl"

typedef struct GenericNetlinkFamily GenericNetlinkFamily;

int genl_family_new(
                sd_netlink *nl,
                const char *expected_family_name,
                const NLAPolicySet *policy_set,
                sd_netlink_message *message,
                const GenericNetlinkFamily **ret);

void genl_clear_family(sd_netlink *nl);
