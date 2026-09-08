/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.VarlinkMonitor.h"

static SD_VARLINK_DEFINE_METHOD(
                Setup,
                SD_VARLINK_FIELD_COMMENT("Request polkit authorization to monitor traffic of arbitrary UIDs."),
                SD_VARLINK_DEFINE_INPUT(authorize, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("File descriptor index for the BPF ring buffer."),
                SD_VARLINK_DEFINE_OUTPUT(ringbufFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(Start);

static SD_VARLINK_DEFINE_METHOD(Stop);

static SD_VARLINK_DEFINE_ERROR(BadState);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_VarlinkMonitor,
                "io.systemd.VarlinkMonitor",
                SD_VARLINK_INTERFACE_COMMENT("Monitor Varlink socket traffic via BPF."),

                /* Methods */
                SD_VARLINK_SYMBOL_COMMENT("Configure the monitor and receive the BPF ring buffer file descriptor."),
                &vl_method_Setup,
                SD_VARLINK_SYMBOL_COMMENT("Attach the BPF probes and start capturing traffic."),
                &vl_method_Start,
                SD_VARLINK_SYMBOL_COMMENT("Detach the BPF probes and stop capturing traffic."),
                &vl_method_Stop,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("Method call not allowed in current state."),
                &vl_error_BadState);
