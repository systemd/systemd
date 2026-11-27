/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink-idl.h"

/* The generic parts of a DNS server given as URI, shared by DNSServer and DNSServerContext. Their meaning is
 * left to the transports of systemd-resolved. */
#define DNS_SERVER_URI_FIELDS                                           \
        SD_VARLINK_FIELD_COMMENT("URI scheme selecting the transports of the server, e.g. \"dnss\". Unset if the server was configured without a scheme, in which case DNSOverTLS= decides."), \
        SD_VARLINK_DEFINE_FIELD(scheme, SD_VARLINK_STRING, SD_VARLINK_NULLABLE), \
        SD_VARLINK_FIELD_COMMENT("URI path, without the leading slash."), \
        SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE), \
        SD_VARLINK_FIELD_COMMENT("URI query, without the leading question mark."), \
        SD_VARLINK_DEFINE_FIELD(query, SD_VARLINK_STRING, SD_VARLINK_NULLABLE), \
        SD_VARLINK_FIELD_COMMENT("URI fragment parameters other than the server name and interface, e.g. {\"downgrade\": \"5353\"}. A parameter without value has an empty string."), \
        SD_VARLINK_DEFINE_FIELD(parameters, SD_VARLINK_STRING, SD_VARLINK_MAP|SD_VARLINK_NULLABLE)

extern const sd_varlink_symbol vl_type_DNSProtocol;
extern const sd_varlink_symbol vl_type_DNSOverTLSMode;
extern const sd_varlink_symbol vl_type_ResolveSupport;
extern const sd_varlink_symbol vl_type_ResolvConfMode;
extern const sd_varlink_symbol vl_type_ResourceKey;
extern const sd_varlink_symbol vl_type_ResourceRecord;
extern const sd_varlink_symbol vl_type_DNSServer;
extern const sd_varlink_symbol vl_type_DNSScope;
extern const sd_varlink_symbol vl_type_SearchDomain;
extern const sd_varlink_symbol vl_type_DNSConfiguration;

extern const sd_varlink_interface vl_interface_io_systemd_Resolve;
