/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-idl-common.h"

SD_VARLINK_DEFINE_STRUCT_TYPE(
                Timestamp,
                SD_VARLINK_FIELD_COMMENT("Timestamp in µs in the CLOCK_REALTIME clock (wallclock)"),
                SD_VARLINK_DEFINE_FIELD(realtime, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp in µs in the CLOCK_MONOTONIC clock"),
                SD_VARLINK_DEFINE_FIELD(monotonic, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                ProcessId,
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX PID value"),
                SD_VARLINK_DEFINE_FIELD(pid, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("64bit inode number of pidfd if known"),
                SD_VARLINK_DEFINE_FIELD(pidfdId, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Boot ID of the system the inode number belongs to"),
                SD_VARLINK_DEFINE_FIELD(bootId, SD_VARLINK_INT, SD_VARLINK_NULLABLE));
