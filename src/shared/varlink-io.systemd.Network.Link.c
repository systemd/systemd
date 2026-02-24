/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Network.Link.h"

#define VARLINK_NETWORK_INTERFACE_INPUTS                                \
        SD_VARLINK_FIELD_COMMENT("Index of the interface. If specified together with InterfaceName, both must reference the same link."), \
        SD_VARLINK_DEFINE_INPUT(InterfaceIndex, SD_VARLINK_INT, SD_VARLINK_NULLABLE), \
        SD_VARLINK_FIELD_COMMENT("Name of the interface. If specified together with InterfaceIndex, both must reference the same link."), \
        SD_VARLINK_DEFINE_INPUT(InterfaceName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE)

static SD_VARLINK_DEFINE_METHOD(
                Up,
                VARLINK_NETWORK_INTERFACE_INPUTS,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Down,
                VARLINK_NETWORK_INTERFACE_INPUTS,
                VARLINK_DEFINE_POLKIT_INPUT);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Network_Link,
                "io.systemd.Network.Link",
                SD_VARLINK_SYMBOL_COMMENT("Bring the specified link up."),
                &vl_method_Up,
                SD_VARLINK_SYMBOL_COMMENT("Bring the specified link down."),
                &vl_method_Down);
