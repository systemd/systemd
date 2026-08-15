/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.InstanceMetadata.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                WellKnown,
                SD_VARLINK_DEFINE_ENUM_VALUE(base),
                SD_VARLINK_DEFINE_ENUM_VALUE(hostname),
                SD_VARLINK_DEFINE_ENUM_VALUE(region),
                SD_VARLINK_DEFINE_ENUM_VALUE(zone),
                SD_VARLINK_DEFINE_ENUM_VALUE(ipv4_public),
                SD_VARLINK_DEFINE_ENUM_VALUE(ipv6_public),
                SD_VARLINK_DEFINE_ENUM_VALUE(ssh_key),
                SD_VARLINK_DEFINE_ENUM_VALUE(userdata),
                SD_VARLINK_DEFINE_ENUM_VALUE(userdata_base),
                SD_VARLINK_DEFINE_ENUM_VALUE(userdata_base64));

static SD_VARLINK_DEFINE_METHOD(
                Get,
                SD_VARLINK_FIELD_COMMENT("The key to retrieve"),
                SD_VARLINK_DEFINE_INPUT(key, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Start with a well-known key"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(wellKnown, WellKnown, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The network interface to use"),
                SD_VARLINK_DEFINE_INPUT(interface, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Refresh cached data if older (CLOCK_BOOTTIME, µs)"),
                SD_VARLINK_DEFINE_INPUT(refreshUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to accept cached data"),
                SD_VARLINK_DEFINE_INPUT(cache, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The firewall mark value to use"),
                SD_VARLINK_DEFINE_INPUT(firewallMark, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Controls whether to wait for connectivity"),
                SD_VARLINK_DEFINE_INPUT(wait, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The data in Base64 encoding."),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The interface the data was found on."),
                SD_VARLINK_DEFINE_OUTPUT(interface, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                GetVendorInfo,
                SD_VARLINK_FIELD_COMMENT("The detected cloud vendor"),
                SD_VARLINK_DEFINE_OUTPUT(vendor, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The URL to acquire the token from"),
                SD_VARLINK_DEFINE_OUTPUT(tokenUrl, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The HTTP header to configure the refresh timeout for the token in"),
                SD_VARLINK_DEFINE_OUTPUT(refreshHeaderName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The base URL to acquire the data from"),
                SD_VARLINK_DEFINE_OUTPUT(dataUrl, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A suffix to append to the data URL"),
                SD_VARLINK_DEFINE_OUTPUT(dataUrlSuffix, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The HTTP header to pass the token in when requesting data"),
                SD_VARLINK_DEFINE_OUTPUT(tokenHeaderName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Additional HTTP headers to pass when acquiring data"),
                SD_VARLINK_DEFINE_OUTPUT(extraHeader, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("IPv4 address of IMDS server"),
                SD_VARLINK_DEFINE_OUTPUT(addressIPv4, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("IPv6 address of IMDS server"),
                SD_VARLINK_DEFINE_OUTPUT(addressIPv6, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Well-known fields"),
                SD_VARLINK_DEFINE_OUTPUT(wellKnown, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(
                KeyNotFound);

static SD_VARLINK_DEFINE_ERROR(
                WellKnownKeyUnset);

static SD_VARLINK_DEFINE_ERROR(
                NotAvailable);

static SD_VARLINK_DEFINE_ERROR(
                NotSupported);

static SD_VARLINK_DEFINE_ERROR(
                CommunicationFailure);

static SD_VARLINK_DEFINE_ERROR(
                Timeout);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_InstanceMetadata,
                "io.systemd.InstanceMetadata",
                SD_VARLINK_INTERFACE_COMMENT("APIs for acquiring cloud IMDS information."),
                SD_VARLINK_SYMBOL_COMMENT("Well known data fields"),
                &vl_type_WellKnown,
                SD_VARLINK_SYMBOL_COMMENT("Acquire data."),
                &vl_method_Get,
                SD_VARLINK_SYMBOL_COMMENT("Get information about cloud vendor and IMDS connectivity."),
                &vl_method_GetVendorInfo,
                SD_VARLINK_SYMBOL_COMMENT("The requested key is not found on the IMDS server."),
                &vl_error_KeyNotFound,
                SD_VARLINK_SYMBOL_COMMENT("IMDS is disabled or otherwise not available."),
                &vl_error_NotAvailable,
                SD_VARLINK_SYMBOL_COMMENT("IMDS is not supported."),
                &vl_error_NotSupported,
                SD_VARLINK_SYMBOL_COMMENT("Well-known key is not set."),
                &vl_error_WellKnownKeyUnset,
                SD_VARLINK_SYMBOL_COMMENT("Communication with IMDS failed."),
                &vl_error_CommunicationFailure,
                SD_VARLINK_SYMBOL_COMMENT("Timeout reached"),
                &vl_error_Timeout);
