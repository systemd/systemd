/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dhcp-message.h"

typedef enum {
        DUMP_DHCP_MESSAGE_LEGEND = 1 << 0,
        DUMP_DHCP_MESSAGE_FULL   = 1 << 1,
} DumpDHCPMessageFlag;

int dump_dhcp_options(sd_dhcp_message *message, char * const *args, DumpDHCPMessageFlag flags);
int dump_dhcp_header(sd_dhcp_message *message, DumpDHCPMessageFlag flags);
