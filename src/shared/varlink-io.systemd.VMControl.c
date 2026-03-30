/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.VMControl.h"

static SD_VARLINK_DEFINE_METHOD(Pause);
static SD_VARLINK_DEFINE_METHOD(Resume);
static SD_VARLINK_DEFINE_METHOD(Powerdown);
static SD_VARLINK_DEFINE_METHOD(Reset);

static SD_VARLINK_DEFINE_METHOD(
                QueryStatus,
                SD_VARLINK_DEFINE_OUTPUT(running, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_OUTPUT(status, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                SubscribeEvents,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_DEFINE_INPUT(filter, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(event, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(timestampSeconds, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(timestampMicroseconds, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(ready, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NotConnected);
static SD_VARLINK_DEFINE_ERROR(NotSupported);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_VMControl,
                "io.systemd.VMControl",
                SD_VARLINK_SYMBOL_COMMENT("Pause a running virtual machine"),
                &vl_method_Pause,
                SD_VARLINK_SYMBOL_COMMENT("Resume a paused virtual machine"),
                &vl_method_Resume,
                SD_VARLINK_SYMBOL_COMMENT("Request a clean shutdown of the virtual machine"),
                &vl_method_Powerdown,
                SD_VARLINK_SYMBOL_COMMENT("Reset the virtual machine"),
                &vl_method_Reset,
                SD_VARLINK_SYMBOL_COMMENT("Query the current status of the virtual machine"),
                &vl_method_QueryStatus,
                SD_VARLINK_SYMBOL_COMMENT("Subscribe to VM events. Returns a stream of events as they occur."),
                &vl_method_SubscribeEvents,
                SD_VARLINK_SYMBOL_COMMENT("The QMP connection to the VM is not available"),
                &vl_error_NotConnected,
                SD_VARLINK_SYMBOL_COMMENT("The requested operation is not supported"),
                &vl_error_NotSupported);
