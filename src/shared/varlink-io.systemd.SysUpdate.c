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

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Target,
                SD_VARLINK_FIELD_COMMENT("Identifier for the target."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(id, TargetIdentifier, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Feature,
                SD_VARLINK_FIELD_COMMENT("Identifier for the feature."),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A short human readable description of the feature."),
                SD_VARLINK_DEFINE_FIELD(description, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A URL to documentation for the feature."),
                SD_VARLINK_DEFINE_FIELD(documentation, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A URL to an AppStream catalog XML file describing the feature."),
                SD_VARLINK_DEFINE_FIELD(appstream, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the feature is enabled."),
                SD_VARLINK_DEFINE_FIELD(isEnabled, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Array of IDs of the transfers (including currently disabled ones) which are controlled by this feature."),
                SD_VARLINK_DEFINE_FIELD(transfers, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                ListFeatures,
                SD_VARLINK_FIELD_COMMENT("Target to list features for."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(target, TargetIdentifier, 0),
                SD_VARLINK_FIELD_COMMENT("The configured features."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(features, Feature, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                CheckNew,
                SD_VARLINK_FIELD_COMMENT("Target to check for updates for."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(target, TargetIdentifier, 0),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The version string for the new version which is available."),
                SD_VARLINK_DEFINE_OUTPUT(available, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                ListTargets,
                SD_VARLINK_FIELD_COMMENT("The configured targets."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(targets, Target, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(NoUpdateNeeded);
static SD_VARLINK_DEFINE_ERROR(NoSuchTarget);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_SysUpdate,
                "io.systemd.SysUpdate",
                SD_VARLINK_INTERFACE_COMMENT("APIs to manage system updates"),

                /* Methods */
                SD_VARLINK_SYMBOL_COMMENT("Show optional features"),
                &vl_method_ListFeatures,
                SD_VARLINK_SYMBOL_COMMENT("Check if there’s a new version available"),
                &vl_method_CheckNew,
                SD_VARLINK_SYMBOL_COMMENT("Show targets"),
                &vl_method_ListTargets,

                /* Types */
                SD_VARLINK_SYMBOL_COMMENT("Class of a Target."),
                &vl_type_TargetClass,
                SD_VARLINK_SYMBOL_COMMENT("Identifier for a component of the system (i.e. the host itself, a sysext, a confext, etc.) that can be updated by systemd-sysupdate(8)."),
                &vl_type_TargetIdentifier,
                SD_VARLINK_SYMBOL_COMMENT("Type containing a configured sysupdate target."),
                &vl_type_Target,
                SD_VARLINK_SYMBOL_COMMENT("Type containing a configured sysupdate feature."),
                &vl_type_Feature,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that no update is currently available to update to."),
                &vl_error_NoUpdateNeeded,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating the specified target doesn’t exist"),
                &vl_error_NoSuchTarget);
