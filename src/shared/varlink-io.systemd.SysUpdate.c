/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.SysUpdate.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                TargetClass,
                SD_VARLINK_FIELD_COMMENT("Container or machine managed by systemd-machined.service(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(machine),
                SD_VARLINK_FIELD_COMMENT("Portable service."),
                SD_VARLINK_DEFINE_ENUM_VALUE(portable),
                SD_VARLINK_FIELD_COMMENT("System extension managed by systemd-sysext.service(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(sysext),
                SD_VARLINK_FIELD_COMMENT("Configuration extension managed by systemd-confext.service(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(confext),
                SD_VARLINK_FIELD_COMMENT("Host system."),
                SD_VARLINK_DEFINE_ENUM_VALUE(host),
                SD_VARLINK_FIELD_COMMENT("Component managed by systemd-sysupdate.service(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(component));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TargetIdentifier,
                SD_VARLINK_FIELD_COMMENT("Where the target was enumerated."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(class, TargetClass, 0),
                SD_VARLINK_FIELD_COMMENT("Name of the target, unique within a class."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                CheckNew,
                SD_VARLINK_FIELD_COMMENT("Target to check for updates for."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(target, TargetIdentifier, 0),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The version string for the new version which is available."),
                SD_VARLINK_DEFINE_OUTPUT(available, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(NoUpdateNeeded);
static SD_VARLINK_DEFINE_ERROR(NoSuchTarget);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_SysUpdate,
                "io.systemd.SysUpdate",
                SD_VARLINK_INTERFACE_COMMENT("APIs to manage system updates"),

                /* Methods */
                SD_VARLINK_SYMBOL_COMMENT("Check if there’s a new version available"),
                &vl_method_CheckNew,

                /* Types */
                SD_VARLINK_SYMBOL_COMMENT("Class of a Target."),
                &vl_type_TargetClass,
                SD_VARLINK_SYMBOL_COMMENT("Identifier for a component of the system (i.e. the host itself, a sysext, a confext, etc.) that can be updated by systemd-sysupdate(8)."),
                &vl_type_TargetIdentifier,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that no update is currently available to update to."),
                &vl_error_NoUpdateNeeded,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating the specified target doesn’t exist"),
                &vl_error_NoSuchTarget);
