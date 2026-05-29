/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Sysupdate.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Configuration,
                SD_VARLINK_FIELD_COMMENT("Alternate filesystem root to operate on."),
                SD_VARLINK_DEFINE_FIELD(rootDirectory, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Component to update."),
                SD_VARLINK_DEFINE_FIELD(component, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Alternate directory containing transfer definitions."),
                SD_VARLINK_DEFINE_FIELD(definitions, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Alternate disk image to use as file system root."),
                SD_VARLINK_DEFINE_FIELD(image, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Disk image dissection policy."),
                SD_VARLINK_DEFINE_FIELD(imagePolicy, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Force signature verification on or off."),
                SD_VARLINK_DEFINE_FIELD(verify, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Do not fetch metadata from the network."),
                SD_VARLINK_DEFINE_FIELD(offline, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Alternate directory to transfer sources from."),
                SD_VARLINK_DEFINE_FIELD(transferSource, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                CheckNew,
                SD_VARLINK_FIELD_COMMENT("Alternate configuration arguments to use."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(configuration, Configuration, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The version string for the new version which is available."),
                SD_VARLINK_DEFINE_OUTPUT(available, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(NoUpdateNeeded);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Sysupdate,
                "io.systemd.Sysupdate",
                SD_VARLINK_INTERFACE_COMMENT("APIs to manage system updates"),

                /* Methods */
                SD_VARLINK_SYMBOL_COMMENT("Check if there’s a new version available"),
                &vl_method_CheckNew,

                /* Types */
                SD_VARLINK_SYMBOL_COMMENT("Type containing non-standard configuration parameters for sysupdate transfers."),
                &vl_type_Configuration,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that no update is currently available to update to."),
                &vl_error_NoUpdateNeeded);
