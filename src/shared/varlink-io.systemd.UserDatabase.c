/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.UserDatabase.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                GetUserRecord,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("The numeric 32bit UNIX UID of the record, if look-up by UID is desired."),
                SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The UNIX user name of the record, if look-up by name is desired."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The userdb provider service to search on. Must be set to the base name of the userdb entrypoint socket. This is necessary in order to support services that implement multiple userdb services on the same socket."),
                SD_VARLINK_FIELD_COMMENT("Names to search for in a fuzzy fashion."),
                SD_VARLINK_DEFINE_INPUT(fuzzyNames, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("User dispositions to limit search by."),
                SD_VARLINK_DEFINE_INPUT(dispositionMask, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Minimum UID to restrict search too."),
                SD_VARLINK_DEFINE_INPUT(uidMin, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Maximum UID to restrict search too."),
                SD_VARLINK_DEFINE_INPUT(uidMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The userdb provider to search on. Must be set to the name of the userdb entrypoint socket. This is necessary in order to support services that implement multiple userdb services on the same socket."),
                SD_VARLINK_DEFINE_INPUT(service, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The retrieved user record."),
                SD_VARLINK_DEFINE_OUTPUT(record, SD_VARLINK_OBJECT, 0),
                SD_VARLINK_FIELD_COMMENT("If set to true, indicates that the user record is not complete, i.e. that the 'privileged' section has been stripped because the client lacks the privileges to access it."),
                SD_VARLINK_DEFINE_OUTPUT(incomplete, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                GetGroupRecord,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("The numeric 32bit UNIX GID of the record, if look-up by GID is desired."),
                SD_VARLINK_DEFINE_INPUT(gid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The UNIX group name of the record, if look-up by name is desired."),
                SD_VARLINK_DEFINE_INPUT(groupName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The userdb provider service to search on. Must be set to the base name of the userdb entrypoint socket. This is necessary in order to support services that implement multiple userdb services on the same socket."),
                SD_VARLINK_FIELD_COMMENT("Additional names to search for in a fuzzy fashion."),
                SD_VARLINK_DEFINE_INPUT(fuzzyNames, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Group dispositions to limit search by."),
                SD_VARLINK_DEFINE_INPUT(dispositionMask, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Minimum GID to restrict search too."),
                SD_VARLINK_DEFINE_INPUT(gidMin, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Maximum GID to restrict search too."),
                SD_VARLINK_DEFINE_INPUT(gidMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The userdb provider to search on. Must be set to the name of the userdb entrypoint socket. This is necessary in order to support services that implement multiple userdb services on the same socket."),
                SD_VARLINK_DEFINE_INPUT(service, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The retrieved group record."),
                SD_VARLINK_DEFINE_OUTPUT(record, SD_VARLINK_OBJECT, 0),
                SD_VARLINK_FIELD_COMMENT("If set to true, indicates that the group record is not complete, i.e. that the 'privileged' section has been stripped because the client lacks the privileges to access it."),
                SD_VARLINK_DEFINE_OUTPUT(incomplete, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                GetMemberships,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("The UNIX user name of the user to search for memberships for."),
                SD_VARLINK_DEFINE_INPUT(userName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The UNIX group name of the group to search for memberships for."),
                SD_VARLINK_DEFINE_INPUT(groupName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The userdb provider to search on. Must be set to the base name of the userdb entrypoint socket. This is necessary in order to support services that implement multiple userdb services on the same socket."),
                SD_VARLINK_DEFINE_INPUT(service, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The UNIX user name of a discovered membership relationship."),
                SD_VARLINK_DEFINE_OUTPUT(userName, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The UNIX group name of a discovered membership relationship."),
                SD_VARLINK_DEFINE_OUTPUT(groupName, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(NoRecordFound);
static SD_VARLINK_DEFINE_ERROR(BadService);
static SD_VARLINK_DEFINE_ERROR(ServiceNotAvailable);
static SD_VARLINK_DEFINE_ERROR(ConflictingRecordFound);
static SD_VARLINK_DEFINE_ERROR(EnumerationNotSupported);
static SD_VARLINK_DEFINE_ERROR(NonMatchingRecordFound);

/* As per https://systemd.io/USER_GROUP_API/ */
SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_UserDatabase,
                "io.systemd.UserDatabase",
                SD_VARLINK_INTERFACE_COMMENT("APIs for querying user and group records."),
                SD_VARLINK_SYMBOL_COMMENT("Retrieve one or more user records. Look-up is either keyed by UID or user name, or if neither is specified all known records are enumerated."),
                &vl_method_GetUserRecord,
                SD_VARLINK_SYMBOL_COMMENT("Retrieve one or more group records. Look-up is either keyed by GID or group name, or if neither is specified all known records are enumerated."),
                &vl_method_GetGroupRecord,
                SD_VARLINK_SYMBOL_COMMENT("Retrieve membership relationships between users and groups."),
                &vl_method_GetMemberships,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that no matching user or group record was found."),
                &vl_error_NoRecordFound,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that the contacted service does not implement the specified service name."),
                &vl_error_BadService,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that the backing service currently is not operational and no answer can be provided."),
                &vl_error_ServiceNotAvailable,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that there's a user record matching either UID/GID or the user/group name, but not both at the same time."),
                &vl_error_ConflictingRecordFound,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that there's a user record matching the primary UID/GID or user/group, but that doesn't match the additional specified matches."),
                &vl_error_NonMatchingRecordFound,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that retrieval of user/group records on this service is only supported if either user/group name or UID/GID are specified, but not if nothing is specified."),
                &vl_error_EnumerationNotSupported);
