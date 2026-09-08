/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.VarlinkMonitor.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                MonitorFilter,
                SD_VARLINK_FIELD_COMMENT("Match traffic where sender or peer has this UID."),
                SD_VARLINK_DEFINE_FIELD(uid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Match traffic where sender or peer has this PID."),
                SD_VARLINK_DEFINE_FIELD(pid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Match traffic where sender or peer has this pidfd inode."),
                SD_VARLINK_DEFINE_FIELD(pidfdId, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Match traffic on this socket path. Empty string matches sockets without a path."),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(
                BadFilter,
                SD_VARLINK_DEFINE_FIELD(parameter, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Acquire,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Capture filters. Each filter's fields are ANDed; the array is ORed. If unset, captures all traffic."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(filters, MonitorFilter, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("File descriptor index for the BPF ring buffer."),
                SD_VARLINK_DEFINE_OUTPUT(ringbufFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_VarlinkMonitor,
                "io.systemd.VarlinkMonitor",
                SD_VARLINK_INTERFACE_COMMENT("Monitor Varlink socket traffic via BPF."),

                &vl_type_MonitorFilter,
                SD_VARLINK_SYMBOL_COMMENT("A filter parameter is invalid."),
                &vl_error_BadFilter,
                SD_VARLINK_SYMBOL_COMMENT("Start monitoring varlink traffic with the given filters. Returns a BPF ring buffer fd and keeps the connection open until the client disconnects."),
                &vl_method_Acquire);
