/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

void fuzz_forbid_network(void);
int fuzz_bind_netlink_address(int fd, uint32_t nl_pid, uint32_t nl_groups);
