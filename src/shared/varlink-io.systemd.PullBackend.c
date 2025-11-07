/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.PullBackend.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                PullMode,
                SD_VARLINK_FIELD_COMMENT("A raw image"),
                SD_VARLINK_DEFINE_ENUM_VALUE(raw),
                SD_VARLINK_FIELD_COMMENT("A tar archive"),
                SD_VARLINK_DEFINE_ENUM_VALUE(tar));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PullInstance,
                SD_VARLINK_FIELD_COMMENT("Version of the instance"),
                SD_VARLINK_DEFINE_FIELD(version, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Directory containing the cache of the instance when it was downloaded"),
                SD_VARLINK_DEFINE_FIELD(cachedir, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Location of the instance"),
                SD_VARLINK_DEFINE_FIELD(location, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                Pull,
                SD_VARLINK_FIELD_COMMENT("Version to download"),
                SD_VARLINK_DEFINE_INPUT(version, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Download mode"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(mode, PullMode, 0),
                SD_VARLINK_FIELD_COMMENT("Sync files after download"),
                SD_VARLINK_DEFINE_INPUT(fsync, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Checksum of downloaded image"),
                SD_VARLINK_DEFINE_INPUT(checksum, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("URL to download from"),
                SD_VARLINK_DEFINE_INPUT(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Destination for download"),
                SD_VARLINK_DEFINE_INPUT(destination, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Cache directory"),
                SD_VARLINK_DEFINE_INPUT(cachedir, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Instances to use for delta updating"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(instances, PullInstance, SD_VARLINK_NULLABLE | SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(InvalidChecksum);
static SD_VARLINK_DEFINE_ERROR(PullError);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PullBackend,
                "io.systemd.PullBackend",
                SD_VARLINK_INTERFACE_COMMENT("An interface for downloading disk images"),
                SD_VARLINK_SYMBOL_COMMENT("Download mode"),
                &vl_type_PullMode,
                SD_VARLINK_SYMBOL_COMMENT("Instance to use for delta updates"),
                &vl_type_PullInstance,
                SD_VARLINK_SYMBOL_COMMENT("Downloads a disk image"),
                &vl_method_Pull,
                SD_VARLINK_SYMBOL_COMMENT("The specified checksum is invalid"),
                &vl_error_InvalidChecksum,
                SD_VARLINK_SYMBOL_COMMENT("An error occured while pulling the download"),
                &vl_error_PullError);
