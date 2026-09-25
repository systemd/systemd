/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-idl-common.h"
#include "varlink-io.systemd.AppInstance.h"

static SD_VARLINK_DEFINE_METHOD(
                Register,
                SD_VARLINK_FIELD_COMMENT("The app's ID, in RDNS format (i.e. com.example.MyApp)"),
                SD_VARLINK_DEFINE_INPUT(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The collection ID that the app came from (if known), in RDNS format (i.e. org.flathub)"),
                SD_VARLINK_DEFINE_INPUT(collection, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The sandbox engine registering this app (if any) (i.e. flatpak)"),
                SD_VARLINK_DEFINE_INPUT(sandbox, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Initial permissions for this app"),
                SD_VARLINK_DEFINE_INPUT(permissions, SD_VARLINK_ANY, SD_VARLINK_MAP|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Entitlements held by this app"),
                SD_VARLINK_DEFINE_INPUT(entitlements, SD_VARLINK_ANY, SD_VARLINK_MAP|SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Query,
                SD_VARLINK_FIELD_COMMENT("PID of the instance to query"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(targetPid, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A socket FD connected to the instance to query"),
                SD_VARLINK_DEFINE_INPUT(targetConnection, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("cgroup path of the instance to query"),
                SD_VARLINK_DEFINE_INPUT(targetCgroup, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The generation number for this data"),
                SD_VARLINK_DEFINE_OUTPUT(generation, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Unique cgroup path of this app instance"),
                SD_VARLINK_DEFINE_OUTPUT(cgroup, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Instance's app ID"),
                SD_VARLINK_DEFINE_OUTPUT(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Instance's collection ID"),
                SD_VARLINK_DEFINE_OUTPUT(collection, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Instance's sandbox engine"),
                SD_VARLINK_DEFINE_OUTPUT(sandbox, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Instance's current permissions"),
                SD_VARLINK_DEFINE_OUTPUT(permissions, SD_VARLINK_ANY, SD_VARLINK_MAP),
                SD_VARLINK_FIELD_COMMENT("Instance's held entitlements"),
                SD_VARLINK_DEFINE_OUTPUT(entitlements, SD_VARLINK_ANY, SD_VARLINK_MAP));

static SD_VARLINK_DEFINE_METHOD(
                SetPermissions,
                SD_VARLINK_FIELD_COMMENT("PID of the instance to update"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(targetPid, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A socket FD connected to the instance to update"),
                SD_VARLINK_DEFINE_INPUT(targetConnection, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("cgroup path of the instance to query"),
                SD_VARLINK_DEFINE_INPUT(targetCgroup, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The generation number returned by the last query, to enforce atomicity"),
                SD_VARLINK_DEFINE_INPUT(generation, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("New permissions for this instance"),
                SD_VARLINK_DEFINE_INPUT(permissions, SD_VARLINK_ANY, SD_VARLINK_MAP));

static SD_VARLINK_DEFINE_ERROR(RegistrationBusy);
static SD_VARLINK_DEFINE_ERROR(ConflictingTarget);
static SD_VARLINK_DEFINE_ERROR(NoSuchInstance);
static SD_VARLINK_DEFINE_ERROR(Stale);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_AppInstance,
                "io.systemd.AppInstance",
                SD_VARLINK_INTERFACE_COMMENT("API for managing running instances of apps"),
                SD_VARLINK_SYMBOL_COMMENT("Register an instance of an app. The app must do this before it talks to any service that may query appd"),
                &vl_method_Register,
                SD_VARLINK_SYMBOL_COMMENT("Query the known information about an instance of an app"),
                &vl_method_Query,
                SD_VARLINK_SYMBOL_COMMENT("Change the permissions for an instance of the app"),
                &vl_method_SetPermissions,
                SD_VARLINK_SYMBOL_COMMENT("An object for referencing UNIX processes"),
                &vl_type_ProcessId,
                SD_VARLINK_SYMBOL_COMMENT("The app's existing registration is now in active use and can no longer be amended."),
                &vl_error_RegistrationBusy,
                SD_VARLINK_SYMBOL_COMMENT("More than one of targetPid/targetConnection/targetCgroup was specified, and they don't refer to the same app instance"),
                &vl_error_ConflictingTarget,
                SD_VARLINK_SYMBOL_COMMENT("Failed to find the target instance"),
                &vl_error_NoSuchInstance,
                SD_VARLINK_SYMBOL_COMMENT("Known information about instance has changed since the last query"),
                &vl_error_Stale);
