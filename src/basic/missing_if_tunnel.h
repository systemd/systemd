/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/if_tunnel.h>

#if !HAVE_IFLA_VTI_FWMARK /* linux@0a473b82cb23e7a35c4be6e9765c8487a65e8f55 (4.12) */
#define IFLA_VTI_FWMARK 6

#undef  IFLA_VTI_MAX
#define IFLA_VTI_MAX    6
#endif

#if !HAVE_IFLA_IPTUN_ENCAP_DPORT /* linux@56328486539ddd07cbaafec7a542a2c8a3043623 (3.18)*/
#define IFLA_IPTUN_ENCAP_TYPE       15
#define IFLA_IPTUN_ENCAP_FLAGS      16
#define IFLA_IPTUN_ENCAP_SPORT      17
#define IFLA_IPTUN_ENCAP_DPORT      18
#endif

#if !HAVE_IFLA_IPTUN_COLLECT_METADATA /* linux@cfc7381b3002756b1dcada32979e942aa3126e31 (4.9) */
#define IFLA_IPTUN_COLLECT_METADATA 19
#endif

#if !HAVE_IFLA_IPTUN_FWMARK /* linux@0a473b82cb23e7a35c4be6e9765c8487a65e8f55 (4.12) */
#define IFLA_IPTUN_FWMARK           20

#undef  IFLA_IPTUN_MAX
#define IFLA_IPTUN_MAX              20
#endif

#if !HAVE_IFLA_GRE_ENCAP_DPORT /* linux@4565e9919cda747815547e2e5d7b78f15efbffdf (3.18) */
#define IFLA_GRE_ENCAP_TYPE       14
#define IFLA_GRE_ENCAP_FLAGS      15
#define IFLA_GRE_ENCAP_SPORT      16
#define IFLA_GRE_ENCAP_DPORT      17
#endif

#if !HAVE_IFLA_GRE_COLLECT_METADATA /* linux@2e15ea390e6f4466655066d97e22ec66870a042c (4.3) */
#define IFLA_GRE_COLLECT_METADATA 18
#endif

#if !HAVE_IFLA_GRE_IGNORE_DF /* linux@22a59be8b7693eb2d0897a9638f5991f2f8e4ddd (4.8) */
#define IFLA_GRE_IGNORE_DF        19
#endif

#if !HAVE_IFLA_GRE_FWMARK /* linux@0a473b82cb23e7a35c4be6e9765c8487a65e8f55 (4.12) */
#define IFLA_GRE_FWMARK           20
#endif

#if !HAVE_IFLA_GRE_ERSPAN_INDEX /* linux@84e54fe0a5eaed696dee4019c396f8396f5a908b (4.14) */
#define IFLA_GRE_ERSPAN_INDEX     21
#endif

#if !HAVE_IFLA_GRE_ERSPAN_HWID /* linux@f551c91de262ba36b20c3ac19538afb4f4507441 (4.16) */
#define IFLA_GRE_ERSPAN_VER       22
#define IFLA_GRE_ERSPAN_DIR       23
#define IFLA_GRE_ERSPAN_HWID      24

#undef  IFLA_GRE_MAX
#define IFLA_GRE_MAX              24
#endif
