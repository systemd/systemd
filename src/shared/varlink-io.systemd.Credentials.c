/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Credentials.h"

static VARLINK_DEFINE_METHOD(
                Encrypt,
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(text, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(data, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(timestamp, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(notAfter, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(blob, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(
                Decrypt,
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(blob, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(timestamp, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(data, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(BadFormat);
static VARLINK_DEFINE_ERROR(NameMismatch);
static VARLINK_DEFINE_ERROR(TimeMismatch);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Credentials,
                "io.systemd.Credentials",
                &vl_method_Encrypt,
                &vl_method_Decrypt,
                &vl_error_BadFormat,
                &vl_error_NameMismatch,
                &vl_error_TimeMismatch);
