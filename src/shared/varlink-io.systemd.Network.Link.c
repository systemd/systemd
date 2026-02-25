/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Network.h"
#include "varlink-io.systemd.Network.Link.h"

#define VARLINK_NETWORK_INTERFACE_INPUTS                                \
        SD_VARLINK_FIELD_COMMENT("Index of the interface. If specified together with InterfaceName, both must reference the same link."), \
        SD_VARLINK_DEFINE_INPUT(InterfaceIndex, SD_VARLINK_INT, SD_VARLINK_NULLABLE), \
        SD_VARLINK_FIELD_COMMENT("Name of the interface. If specified together with InterfaceIndex, both must reference the same link."), \
        SD_VARLINK_DEFINE_INPUT(InterfaceName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE)

static SD_VARLINK_DEFINE_METHOD(
                Describe,
                VARLINK_NETWORK_INTERFACE_INPUTS,
                SD_VARLINK_FIELD_COMMENT("Interface description"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Interface, Interface, 0));

static SD_VARLINK_DEFINE_METHOD(
                Up,
                VARLINK_NETWORK_INTERFACE_INPUTS,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Down,
                VARLINK_NETWORK_INTERFACE_INPUTS,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Renew,
                VARLINK_NETWORK_INTERFACE_INPUTS,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                ForceRenew,
                VARLINK_NETWORK_INTERFACE_INPUTS,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Reconfigure,
                VARLINK_NETWORK_INTERFACE_INPUTS,
                VARLINK_DEFINE_POLKIT_INPUT);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Network_Link,
                "io.systemd.Network.Link",
                SD_VARLINK_SYMBOL_COMMENT("Bring the specified link up."),
                &vl_method_Up,
                SD_VARLINK_SYMBOL_COMMENT("Bring the specified link down."),
                &vl_method_Down,
                SD_VARLINK_SYMBOL_COMMENT("Renew DHCP leases on the specified link."),
                &vl_method_Renew,
                SD_VARLINK_SYMBOL_COMMENT("Force-renew DHCP server leases on the specified link."),
                &vl_method_ForceRenew,
                SD_VARLINK_SYMBOL_COMMENT("Unconditionally reconfigure the specified link."),
                &vl_method_Reconfigure,
                SD_VARLINK_SYMBOL_COMMENT("Describe the specified link by index or name."),
                &vl_method_Describe,
                &vl_type_Address,
                &vl_type_BitRates,
                &vl_type_DHCPLease,
                &vl_type_DHCPServer,
                &vl_type_DHCPServerLease,
                &vl_type_DHCPv6Client,
                &vl_type_DHCPv6ClientPD,
                &vl_type_DHCPv6ClientVendorOption,
                &vl_type_DNS,
                &vl_type_DNSSECNegativeTrustAnchor,
                &vl_type_DNSSetting,
                &vl_type_Domain,
                &vl_type_Interface,
                &vl_type_LinkState,
                &vl_type_LinkAddressState,
                &vl_type_LinkOnlineState,
                &vl_type_LinkRequiredAddressFamily,
                &vl_type_LLDPNeighbor,
                &vl_type_NDisc,
                &vl_type_Neighbor,
                &vl_type_NextHop,
                &vl_type_NextHopGroup,
                &vl_type_NTP,
                &vl_type_Pref64,
                &vl_type_PrivateOption,
                &vl_type_Route,
                &vl_type_SIP);
