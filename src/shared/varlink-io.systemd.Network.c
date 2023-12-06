/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Network.h"

static VARLINK_DEFINE_METHOD(GetStates,
                             VARLINK_DEFINE_OUTPUT(AddressState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(IPv4AddressState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(IPv6AddressState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(CarrierState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(OnlineState, VARLINK_STRING, 0),
                             VARLINK_DEFINE_OUTPUT(OperationalState, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(GetNamespaceId,
                             VARLINK_DEFINE_OUTPUT(NamespaceId, VARLINK_INT, 0));

VARLINK_DEFINE_INTERFACE(
                io_systemd_Network,
                "io.systemd.Network",
                &vl_method_GetStates,
                &vl_method_GetNamespaceId);
