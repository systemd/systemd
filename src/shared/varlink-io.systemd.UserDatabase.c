/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.UserDatabase.h"

static VARLINK_DEFINE_METHOD(
                GetUserRecord,
                VARLINK_DEFINE_INPUT(uid, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(userName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(service, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(record, VARLINK_OBJECT, 0),
                VARLINK_DEFINE_OUTPUT(incomplete, VARLINK_BOOL, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                GetGroupRecord,
                VARLINK_DEFINE_INPUT(gid, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(groupName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(service, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(record, VARLINK_OBJECT, 0),
                VARLINK_DEFINE_OUTPUT(incomplete, VARLINK_BOOL, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                GetMemberships,
                VARLINK_DEFINE_INPUT(userName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(groupName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(service, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(userName, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(groupName, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(NoRecordFound);
static VARLINK_DEFINE_ERROR(BadService);
static VARLINK_DEFINE_ERROR(ServiceNotAvailable);
static VARLINK_DEFINE_ERROR(ConflictingRecordNotFound);
static VARLINK_DEFINE_ERROR(EnumerationNotSupported);

/* As per https://systemd.io/USER_GROUP_API/ */
VARLINK_DEFINE_INTERFACE(
                io_systemd_UserDatabase,
                "io.systemd.UserDatabase",
                &vl_method_GetUserRecord,
                &vl_method_GetGroupRecord,
                &vl_method_GetMemberships,
                &vl_error_NoRecordFound,
                &vl_error_BadService,
                &vl_error_ServiceNotAvailable,
                &vl_error_ConflictingRecordNotFound,
                &vl_error_EnumerationNotSupported);
