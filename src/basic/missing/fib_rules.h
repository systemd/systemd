/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/fib_rules.h>

#if !HAVE_FRA_TUN_ID /* linux@e7030878fc8448492b6e5cecd574043f63271298 (4.3) */
#define FRA_TUN_ID      12
#endif

#if !HAVE_FRA_SUPPRESS_PREFIXLEN /* linux@6ef94cfafba159d6b1a902ccb3349ac6a34ff6ad, 73f5698e77219bfc3ea1903759fe8e20ab5b285e (3.12) */
#define FRA_SUPPRESS_IFGROUP 13
#define FRA_SUPPRESS_PREFIXLEN 14
#endif

#if !HAVE_FRA_PAD /* linux@b46f6ded906ef0be52a4881ba50a084aeca64d7e (4.7) */
#define FRA_PAD         18
#endif

#if !HAVE_FRA_L3MDEV /* linux@96c63fa7393d0a346acfe5a91e0c7d4c7782641b (4.8) */
#define FRA_L3MDEV      19
#endif

#if !HAVE_FRA_UID_RANGE /* linux@622ec2c9d52405973c9f1ca5116eb1c393adfc7d (4.10) */
#define FRA_UID_RANGE   20

struct fib_rule_uid_range {
        __u32 start;
        __u32 end;
};
#endif

#if !HAVE_FRA_DPORT_RANGE /* linux@1b71af6053af1bd2f849e9fda4f71c1e3f145dcf, bfff4862653bb96001ab57c1edd6d03f48e5f035 (4.17) */
#define FRA_PROTOCOL    21
#define FRA_IP_PROTO    22
#define FRA_SPORT_RANGE 23
#define FRA_DPORT_RANGE 24

#undef  FRA_MAX
#define FRA_MAX         24

struct fib_rule_port_range {
        __u16 start;
        __u16 end;
};
#endif
