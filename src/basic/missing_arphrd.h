/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/if_arp.h>

#include "macro-fundamental.h"

/* Fix naming mismatches between glibc and linux UAPI :/ */
#ifndef ARPHRD_IEEE802154_PHY
#  define ARPHRD_IEEE802154_PHY 805
#else
assert_cc(ARPHRD_IEEE802154_PHY == 805);
#endif

#ifndef ARPHRD_IEEE802154_MONITOR
#  define ARPHRD_IEEE802154_MONITOR 805
#else
assert_cc(ARPHRD_IEEE802154_MONITOR == 805);
#endif

// used in basic/arphrd-util.c, network/netdev/tunnel.c

#ifndef ARPHRD_IP6GRE
# define ARPHRD_IP6GRE 823
#else
assert_cc(ARPHRD_IP6GRE == 823);
#endif

// used in network/netdev/nlmon.c

#ifndef ARPHRD_NETLINK
# define ARPHRD_NETLINK 824
#else
assert_cc(ARPHRD_NETLINK == 824);
#endif

// used in network/

#ifndef ARPHRD_CAN
# define ARPHRD_CAN 280
#else
assert_cc(ARPHRD_CAN == 280);
#endif
