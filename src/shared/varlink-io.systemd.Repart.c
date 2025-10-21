/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-io.systemd.Repart.h"

static SD_VARLINK_DEFINE_METHOD(
                ListCandidateDevices,
                SD_VARLINK_FIELD_COMMENT("The device node path of the block device."),
                SD_VARLINK_DEFINE_OUTPUT(node, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Control whether to include the root disk of the currently booted OS in the list. Defaults to false, i.e. the root disk is included."),
                SD_VARLINK_DEFINE_INPUT(ignoreRoot, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Control whether to include block devices with zero size in the list, i.e. typically block devices without any inserted medium. Defaults to false, i.e. empty block devices are included."),
                SD_VARLINK_DEFINE_INPUT(ignoreEmpty, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("List of symlinks pointing to the device node, if any."),
                SD_VARLINK_DEFINE_OUTPUT(symlinks, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The Linux kernel disk sequence number identifying the medium."),
                SD_VARLINK_DEFINE_OUTPUT(diskseq, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The size of the block device in bytes."),
                SD_VARLINK_DEFINE_OUTPUT(sizeBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoCandidateDevices);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Repart,
                "io.systemd.Repart",
                SD_VARLINK_INTERFACE_COMMENT("API for declaratively re-partitioning disks using systemd-repart."),
                SD_VARLINK_SYMBOL_COMMENT("Return a list of candidate block devices, i.e. that support partition scanning and other requirements for successful operation."),
                &vl_method_ListCandidateDevices,
                SD_VARLINK_SYMBOL_COMMENT("Not a single candidate block device could be found."),
                &vl_error_NoCandidateDevices);
