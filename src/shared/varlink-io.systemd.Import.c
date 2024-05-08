/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Import.h"

static VARLINK_DEFINE_ENUM_TYPE(
                ImageClass,
                VARLINK_DEFINE_ENUM_VALUE(machine),
                VARLINK_DEFINE_ENUM_VALUE(portable),
                VARLINK_DEFINE_ENUM_VALUE(sysext),
                VARLINK_DEFINE_ENUM_VALUE(confext));

static VARLINK_DEFINE_ENUM_TYPE(
                RemoteType,
                VARLINK_DEFINE_ENUM_VALUE(raw),
                VARLINK_DEFINE_ENUM_VALUE(tar));

static VARLINK_DEFINE_ENUM_TYPE(
                ImageVerify,
                VARLINK_DEFINE_ENUM_VALUE(no),
                VARLINK_DEFINE_ENUM_VALUE(checksum),
                VARLINK_DEFINE_ENUM_VALUE(signature));

static VARLINK_DEFINE_METHOD(
                ListTransfers,
                VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(id, VARLINK_INT, 0),
                VARLINK_DEFINE_OUTPUT(type, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(remote, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(local, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(class, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(percent, VARLINK_FLOAT, 0));

static VARLINK_DEFINE_METHOD(
                Pull,
                VARLINK_DEFINE_INPUT(remote, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(local, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT_BY_TYPE(type, RemoteType, 0),
                VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, 0),
                VARLINK_DEFINE_INPUT_BY_TYPE(verify, ImageVerify, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(force, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(readOnly, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(keepDownload, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, VARLINK_BOOL, VARLINK_NULLABLE));

static VARLINK_DEFINE_ERROR(AlreadyInProgress);
static VARLINK_DEFINE_ERROR(TransferCancelled);
static VARLINK_DEFINE_ERROR(TransferFailed);
static VARLINK_DEFINE_ERROR(NoTransfers);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Import,
                "io.systemd.Import",
                &vl_type_ImageClass,
                &vl_type_RemoteType,
                &vl_type_ImageVerify,
                &vl_method_ListTransfers,
                &vl_method_Pull,
                &vl_error_AlreadyInProgress,
                &vl_error_TransferCancelled,
                &vl_error_TransferFailed,
                &vl_error_NoTransfers);
