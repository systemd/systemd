/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-org.varlink.service.h"

static VARLINK_DEFINE_METHOD(
                GetInfo,
                VARLINK_DEFINE_OUTPUT(vendor, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(product, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(version, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(url, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(interfaces, VARLINK_STRING, VARLINK_ARRAY));

static VARLINK_DEFINE_METHOD(
                GetInterfaceDescription,
                VARLINK_DEFINE_OUTPUT(interface, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(
                InterfaceNotFound,
                VARLINK_DEFINE_FIELD(interface, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(
                MethodNotFound,
                VARLINK_DEFINE_FIELD(method, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(
                MethodNotImplemented,
                VARLINK_DEFINE_FIELD(method, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(
                InvalidParameter,
                VARLINK_DEFINE_FIELD(parameter, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(PermissionDenied);

static VARLINK_DEFINE_ERROR(ExpectedMore);

/* As per https://varlink.org/Service */
VARLINK_DEFINE_INTERFACE(
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
