/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "networkd-forward.h"

int link_request_sr_iov_vfs(Link *link);

int link_set_sr_iov_ifindices(Link *link);
void link_clear_sr_iov_ifindices(Link *link);

bool check_ready_for_all_sr_iov_ports(
                Link *link,
                bool allow_unmanaged, /* for the main target */
                bool (check_one)(Link *link, bool allow_unmanaged));
