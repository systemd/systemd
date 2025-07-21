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
                SD_VARLINK_DEFINE_FIELD(bootId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                RateLimit,
                SD_VARLINK_FIELD_COMMENT("The ratelimit interval"),
                SD_VARLINK_DEFINE_FIELD(intervalUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The ratelimit burst"),
                SD_VARLINK_DEFINE_FIELD(burst, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResourceLimit,
                SD_VARLINK_FIELD_COMMENT("The soft resource limit. RLIM_INFINITY is mapped to unset value"),
                SD_VARLINK_DEFINE_FIELD(soft, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The hard resource limit. RLIM_INFINITY is mapped to unset value"),
                SD_VARLINK_DEFINE_FIELD(hard, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResourceLimitTable,
                SD_VARLINK_FIELD_COMMENT("See setrlimit(2) for details"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CPU, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(FSIZE, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(DATA, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(STACK, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CORE, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RSS, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(NOFILE, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(AS, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(NPROC, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(MEMLOCK, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(LOCKS, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SIGPENDING, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(MSGQUEUE, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(NICE, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RTPRIO, ResourceLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RTTIME, ResourceLimit, SD_VARLINK_NULLABLE));
