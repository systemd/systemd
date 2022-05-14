/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "netif-sriov.h"

typedef struct Link Link;

int link_request_sr_iov_vfs(Link *link);

int link_get_sr_iov_phys_port(Link *link, Link **ret);
int link_get_sr_iov_virt_ports(Link *link, int **ret);
