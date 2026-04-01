/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.MachineInstance.h"

static SD_VARLINK_DEFINE_METHOD(
                Terminate,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                PowerOff,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Reboot,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Pause,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Resume,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                QueryStatus,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_DEFINE_OUTPUT(running, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_OUTPUT(status, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                SubscribeEvents,
                SD_VARLINK_REQUIRES_MORE,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_DEFINE_INPUT(filter, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(event, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(timestampUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(ready, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NotConnected);
static SD_VARLINK_DEFINE_ERROR(NotSupported);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_MachineInstance,
                "io.systemd.MachineInstance",
                SD_VARLINK_SYMBOL_COMMENT("Forcefully terminate the machine immediately"),
                &vl_method_Terminate,
                SD_VARLINK_SYMBOL_COMMENT("Request a clean shutdown of the machine"),
                &vl_method_PowerOff,
                SD_VARLINK_SYMBOL_COMMENT("Reboot the machine"),
                &vl_method_Reboot,
                SD_VARLINK_SYMBOL_COMMENT("Pause/freeze the machine"),
                &vl_method_Pause,
                SD_VARLINK_SYMBOL_COMMENT("Resume a paused machine"),
                &vl_method_Resume,
                SD_VARLINK_SYMBOL_COMMENT("Query the current status of the machine"),
                &vl_method_QueryStatus,
                SD_VARLINK_SYMBOL_COMMENT("Subscribe to machine events. Returns a stream of events as they occur."),
                &vl_method_SubscribeEvents,
                SD_VARLINK_SYMBOL_COMMENT("The connection to the machine backend is not available"),
                &vl_error_NotConnected,
                SD_VARLINK_SYMBOL_COMMENT("The requested operation is not supported"),
                &vl_error_NotSupported);
