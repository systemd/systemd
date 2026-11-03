/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Resolve.Link.h"

static SD_VARLINK_DEFINE_ERROR(IsLoopback);
static SD_VARLINK_DEFINE_ERROR(ManagedByNetworkd);

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                DNSServerContext,
                /* The address and family are always required as input, so are not nullable. */
                SD_VARLINK_FIELD_COMMENT("IPv4 or IPv6 address of the server."),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Address family of the server, one of AF_INET or AF_INET6."),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Port number of the server."),
                SD_VARLINK_DEFINE_FIELD(port, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Interface index for which this server is configured."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Server Name Indication (SNI) of the server."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SetDNS,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Index of the interface to configure."),
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("DNS servers to configure on the link"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(servers, DNSServerContext, SD_VARLINK_ARRAY));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Resolve_Link,
                "io.systemd.Resolve.Link",
                SD_VARLINK_SYMBOL_COMMENT("The specified interface is managed by systemd-networkd. The request should be re-directed to systemd-networkd."),
                &vl_error_ManagedByNetworkd,
                SD_VARLINK_SYMBOL_COMMENT("The specified interface is a loopback interface, and cannot be configured."),
                &vl_error_IsLoopback,
                SD_VARLINK_SYMBOL_COMMENT("DNS server configuration input."),
                &vl_type_DNSServerContext,
                SD_VARLINK_SYMBOL_COMMENT("Set the per-link DNS server list."),
                &vl_method_SetDNS);
