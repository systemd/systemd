/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"


#include "varlink-io.systemd.Import.h"
#include "varlink-io.systemd.PullWorker.h"


static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PullInstance,
                SD_VARLINK_FIELD_COMMENT("Version of the instance"),
                SD_VARLINK_DEFINE_FIELD(version, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Path to the location of the instance on the system"),
                SD_VARLINK_DEFINE_FIELD(location, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                Pull,
                SD_VARLINK_FIELD_COMMENT("Version of the instance to download"),
                SD_VARLINK_DEFINE_INPUT(version, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Download mode"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(mode, RemoteType, 0),
                SD_VARLINK_FIELD_COMMENT("Sync files after download"),
                SD_VARLINK_DEFINE_INPUT(fsync, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Verification mode"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(verify, ImageVerify, 0),
                SD_VARLINK_FIELD_COMMENT("Checksum of downloaded data"),
                SD_VARLINK_DEFINE_INPUT(checksum, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("URL to download from"),
                SD_VARLINK_DEFINE_INPUT(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Destination for download"),
                SD_VARLINK_DEFINE_INPUT(destinationFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Instances to reuse data from for delta-updating"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(instances, PullInstance, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Start offset for data in destination"),
                SD_VARLINK_DEFINE_INPUT(offset, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Maximum size of written data"),
                SD_VARLINK_DEFINE_INPUT(maxSize, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Create subvolume for target"),
                SD_VARLINK_DEFINE_INPUT(subvolume, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(InvalidParameters);
static SD_VARLINK_DEFINE_ERROR(PullError);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PullWorker,
                "io.systemd.PullWorker",
                SD_VARLINK_INTERFACE_COMMENT("An interface for directly downloading data"),
                SD_VARLINK_SYMBOL_COMMENT("Download mode"),
                &vl_type_RemoteType,
                SD_VARLINK_SYMBOL_COMMENT("Verification mode"),
                &vl_type_ImageVerify,
                SD_VARLINK_SYMBOL_COMMENT("Instances to reuse data from for delta-updating"),
                &vl_type_PullInstance,
                SD_VARLINK_SYMBOL_COMMENT("Download from a URL into your system"),
                &vl_method_Pull,
                SD_VARLINK_SYMBOL_COMMENT("A parameter is invalid"),
                &vl_error_InvalidParameters,
                SD_VARLINK_SYMBOL_COMMENT("An error occured while pulling the data"),
                &vl_error_PullError);
