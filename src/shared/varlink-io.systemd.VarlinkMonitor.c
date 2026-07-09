/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.VarlinkMonitor.h"

static SD_VARLINK_DEFINE_METHOD(
                Setup,
                SD_VARLINK_FIELD_COMMENT("File descriptor index of the shared ring buffer memfd for delivering captured packets."),
                SD_VARLINK_DEFINE_INPUT(ringbufFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("UID to monitor traffic for. If null, defaults to the caller's UID."),
                SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("File descriptor index of the eventfd used to notify the reader of new data."),
                SD_VARLINK_DEFINE_OUTPUT(eventfdReadFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("File descriptor index of the eventfd used to notify the writer that the reader has consumed data."),
                SD_VARLINK_DEFINE_OUTPUT(eventfdWriteFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(Start);

static SD_VARLINK_DEFINE_METHOD(Stop);

static SD_VARLINK_DEFINE_ERROR(InvalidUID);
static SD_VARLINK_DEFINE_ERROR(BadState);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_VarlinkMonitor,
                "io.systemd.VarlinkMonitor",
                SD_VARLINK_INTERFACE_COMMENT("Interface for monitoring varlink traffic via BPF. Captured packets are delivered through a shared ring buffer."),

                /* Methods */
                SD_VARLINK_SYMBOL_COMMENT("Initialize the monitor by providing a ring buffer memfd and optionally a UID to monitor. Returns eventfds for reader/writer synchronization."),
                &vl_method_Setup,
                SD_VARLINK_SYMBOL_COMMENT("Start capturing varlink traffic. Requires Setup to have been called first."),
                &vl_method_Start,
                SD_VARLINK_SYMBOL_COMMENT("Stop capturing varlink traffic. The monitor can be restarted with Start."),
                &vl_method_Stop,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("Invalid user id"),
                &vl_error_InvalidUID,
                SD_VARLINK_SYMBOL_COMMENT("Method call not allowed in current state"),
                &vl_error_BadState);
