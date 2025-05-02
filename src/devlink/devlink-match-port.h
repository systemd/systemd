/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct DevlinkMatchPort {
        uint32_t index;
        bool index_valid;
        char *ifname;
        bool split;
} DevlinkMatchPort;
