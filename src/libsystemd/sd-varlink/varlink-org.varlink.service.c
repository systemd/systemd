/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-org.varlink.service.h"

static SD_VARLINK_DEFINE_METHOD(
                GetInfo,
                SD_VARLINK_FIELD_COMMENT("String identifying the vendor of this service"),
                SD_VARLINK_DEFINE_OUTPUT(vendor, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("String identifying the product implementing this service"),
                SD_VARLINK_DEFINE_OUTPUT(product, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Version string of this product"),
                SD_VARLINK_DEFINE_OUTPUT(version, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Web URL pointing to additional information about this service"),
                SD_VARLINK_DEFINE_OUTPUT(url, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("List of interfaces implemented by this service"),
                SD_VARLINK_DEFINE_OUTPUT(interfaces, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                GetInterfaceDescription,
                SD_VARLINK_FIELD_COMMENT("Name of interface to query interface description of"),
                SD_VARLINK_DEFINE_INPUT(interface, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Interface description in Varlink IDL format"),
                SD_VARLINK_DEFINE_OUTPUT(description, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                InterfaceNotFound,
                SD_VARLINK_FIELD_COMMENT("Name of interface that was called but does not exist"),
                SD_VARLINK_DEFINE_FIELD(interface, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                MethodNotFound,
                SD_VARLINK_FIELD_COMMENT("Name of method that was called but does not exist"),
                SD_VARLINK_DEFINE_FIELD(method, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                MethodNotImplemented,
                SD_VARLINK_FIELD_COMMENT("Name of method that was called but is not implemented."),
                SD_VARLINK_DEFINE_FIELD(method, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                InvalidParameter,
                SD_VARLINK_FIELD_COMMENT("Name of the invalid parameter"),
                SD_VARLINK_DEFINE_FIELD(parameter, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(PermissionDenied);

static SD_VARLINK_DEFINE_ERROR(ExpectedMore);

/* As per https://varlink.org/Service */
SD_VARLINK_DEFINE_INTERFACE(
                org_varlink_service,
                "org.varlink.service",
                SD_VARLINK_INTERFACE_COMMENT("General Varlink service interface"),
                SD_VARLINK_SYMBOL_COMMENT("Get service meta information"),
                &vl_method_GetInfo,
                SD_VARLINK_SYMBOL_COMMENT("Get description of an implemented interface in Varlink IDL format"),
                &vl_method_GetInterfaceDescription,
                SD_VARLINK_SYMBOL_COMMENT("Error returned if a method is called on an unknown interface"),
                &vl_error_InterfaceNotFound,
                SD_VARLINK_SYMBOL_COMMENT("Error returned if an unknown method is called on an known interface"),
                &vl_error_MethodNotFound,
                SD_VARLINK_SYMBOL_COMMENT("Error returned if an method is called that is known but not implemented"),
                &vl_error_MethodNotImplemented,
                SD_VARLINK_SYMBOL_COMMENT("Error returned if a method is called with an invalid parameter"),
                &vl_error_InvalidParameter,
                SD_VARLINK_SYMBOL_COMMENT("General permission error"),
                &vl_error_PermissionDenied,
                SD_VARLINK_SYMBOL_COMMENT("A method was called with the 'more' flag off, but it may only be called with the flag turned on"),
                &vl_error_ExpectedMore);
