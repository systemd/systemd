/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include "netif-sriov.h"

typedef struct Link Link;

int link_configure_sr_iov(Link *link);
