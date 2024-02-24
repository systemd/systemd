/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Network.h"

static VARLINK_DEFINE_METHOD(GetStates,
                             VARLINK_DEFINE_OUTPUT(AddressState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(IPv4AddressState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(IPv6AddressState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(CarrierState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(OnlineState, VARLINK_STRING, VARLINK_NULLABLE),
                             VARLINK_DEFINE_OUTPUT(OperationalState, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(GetNamespaceId,
                             VARLINK_DEFINE_OUTPUT(NamespaceId, VARLINK_INT, 0),
                             VARLINK_DEFINE_OUTPUT(NamespaceNSID, VARLINK_INT, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                StartDHCPServer,
                VARLINK_DEFINE_INPUT(InterfaceIndex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(InterfaceName, VARLINK_STRING, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                StopDHCPServer,
                VARLINK_DEFINE_INPUT(InterfaceIndex, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(InterfaceName, VARLINK_STRING, VARLINK_NULLABLE));

static VARLINK_DEFINE_ERROR(NoDHCPServer);
static VARLINK_DEFINE_ERROR(DHCPServerNotReady);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Network,
                "io.systemd.Network",
                &vl_method_GetStates,
                &vl_method_GetNamespaceId,
                &vl_method_StartDHCPServer,
                &vl_method_StopDHCPServer,
                &vl_error_NoDHCPServer,
                &vl_error_DHCPServerNotReady);
