/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Network.h"

static VARLINK_DEFINE_METHOD(
                GetStates,
                VARLINK_DEFINE_OUTPUT(AddressState, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(IPv4AddressState, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(IPv6AddressState, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(CarrierState, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(OnlineState, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(OperationalState, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(
                GetNamespaceId,
                VARLINK_DEFINE_OUTPUT(NamespaceId, VARLINK_INT, 0),
                VARLINK_DEFINE_OUTPUT(NamespaceNSID, VARLINK_INT, VARLINK_NULLABLE));

static VARLINK_DEFINE_STRUCT_TYPE(
                LLDPNeighbor,
                VARLINK_DEFINE_FIELD(ChassisID, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(RawChassisID, VARLINK_INT, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(PortID, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(RawPortID, VARLINK_INT, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(PortDescription, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(SystemName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(SystemDescription, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(EnabledCapabilities, VARLINK_INT, VARLINK_NULLABLE));

static VARLINK_DEFINE_STRUCT_TYPE(
                LLDPNeighborsByInterface,
                VARLINK_DEFINE_FIELD(InterfaceIndex, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(InterfaceName, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(InterfaceAlternativeNames, VARLINK_STRING, VARLINK_ARRAY|VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD_BY_TYPE(Neighbors, LLDPNeighbor, VARLINK_ARRAY));

static VARLINK_DEFINE_METHOD(
                GetLLDPNeighbors,
                VARLINK_DEFINE_INPUT(InterfaceIndex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(InterfaceName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(Neighbors, LLDPNeighborsByInterface, VARLINK_ARRAY));

VARLINK_DEFINE_INTERFACE(
                io_systemd_Network,
                "io.systemd.Network",
                &vl_method_GetStates,
                &vl_method_GetNamespaceId,
                &vl_method_GetLLDPNeighbors,
                &vl_type_LLDPNeighbor,
                &vl_type_LLDPNeighborsByInterface);
