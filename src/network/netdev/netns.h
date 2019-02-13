/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "netdev/netdev.h"

#define NETNS_RUN_DIR "/run/systemd/netif/netns"

int netdev_configure_namespace(NetDev *netdev);
