/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-org.varlink.service.h"

static SD_VARLINK_DEFINE_METHOD(
                GetInfo,
                SD_VARLINK_DEFINE_OUTPUT(vendor, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(product, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(version, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(url, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(interfaces, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                GetInterfaceDescription,
                SD_VARLINK_DEFINE_INPUT(interface, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(description, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                InterfaceNotFound,
                SD_VARLINK_DEFINE_FIELD(interface, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                MethodNotFound,
                SD_VARLINK_DEFINE_FIELD(method, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                MethodNotImplemented,
                SD_VARLINK_DEFINE_FIELD(method, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                InvalidParameter,
                SD_VARLINK_DEFINE_FIELD(parameter, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(PermissionDenied);

static SD_VARLINK_DEFINE_ERROR(ExpectedMore);

/* As per https://varlink.org/Service */
SD_VARLINK_DEFINE_INTERFACE(
                org_varlink_service,
                "org.varlink.service",
                &vl_method_GetInfo,
                &vl_method_GetInterfaceDescription,
                &vl_error_InterfaceNotFound,
                &vl_error_MethodNotFound,
                &vl_error_MethodNotImplemented,
                &vl_error_InvalidParameter,
                &vl_error_PermissionDenied,
                &vl_error_ExpectedMore);
