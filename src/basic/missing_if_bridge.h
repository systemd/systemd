/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if !HAVE_IFLA_BRIDGE_VLAN_TUNNEL_INFO /* linux@b3c7ef0adadc5768e0baa786213c6bd1ce521a77 (4.11) */
#define IFLA_BRIDGE_VLAN_TUNNEL_INFO 3

#undef IFLA_BRIDGE_MAX
#define IFLA_BRIDGE_MAX 3
#endif

#ifndef BRIDGE_VLAN_INFO_RANGE_BEGIN
#define BRIDGE_VLAN_INFO_RANGE_BEGIN (1 << 3) /* VLAN is start of vlan range */
#endif

#ifndef BRIDGE_VLAN_INFO_RANGE_END
#define BRIDGE_VLAN_INFO_RANGE_END (1 << 4) /* VLAN is end of vlan range */
#endif

#ifndef BRIDGE_VLAN_INFO_BRENTRY
#define BRIDGE_VLAN_INFO_BRENTRY (1 << 5) /* Global bridge VLAN entry */
#endif
