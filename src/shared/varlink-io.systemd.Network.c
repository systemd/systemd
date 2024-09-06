/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Network.h"

static SD_VARLINK_DEFINE_METHOD(
                GetStates,
                SD_VARLINK_DEFINE_OUTPUT(AddressState, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(IPv4AddressState, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(IPv6AddressState, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(CarrierState, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(OnlineState, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(OperationalState, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                GetNamespaceId,
                SD_VARLINK_DEFINE_OUTPUT(NamespaceId, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_OUTPUT(NamespaceNSID, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                LLDPNeighbor,
                SD_VARLINK_DEFINE_FIELD(ChassisID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(RawChassisID, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(PortID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(RawPortID, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(PortDescription, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(SystemName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(SystemDescription, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(EnabledCapabilities, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                LLDPNeighborsByInterface,
                SD_VARLINK_DEFINE_FIELD(InterfaceIndex, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(InterfaceName, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(InterfaceAlternativeNames, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Neighbors, LLDPNeighbor, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                GetLLDPNeighbors,
                SD_VARLINK_DEFINE_INPUT(InterfaceIndex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(InterfaceName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Neighbors, LLDPNeighborsByInterface, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                SetPersistentStorage,
                SD_VARLINK_DEFINE_INPUT(Ready, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_ERROR(StorageReadOnly);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Network,
                "io.systemd.Network",
                &vl_method_GetStates,
                &vl_method_GetNamespaceId,
                &vl_method_GetLLDPNeighbors,
                &vl_method_SetPersistentStorage,
                &vl_type_LLDPNeighbor,
                &vl_type_LLDPNeighborsByInterface,
                &vl_error_StorageReadOnly);
