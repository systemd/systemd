/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Shutdown.h"

static SD_VARLINK_DEFINE_METHOD(
                PowerOff,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Skip active inhibitors and force the operation"),
                SD_VARLINK_DEFINE_INPUT(skipInhibitors, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_METHOD(
                Reboot,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Skip active inhibitors and force the operation"),
                SD_VARLINK_DEFINE_INPUT(skipInhibitors, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_METHOD(
                Halt,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Skip active inhibitors and force the operation"),
                SD_VARLINK_DEFINE_INPUT(skipInhibitors, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_METHOD(
                KExec,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Skip active inhibitors and force the operation"),
                SD_VARLINK_DEFINE_INPUT(skipInhibitors, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_METHOD(
                SoftReboot,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Skip active inhibitors and force the operation"),
                SD_VARLINK_DEFINE_INPUT(skipInhibitors, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(AlreadyInProgress);
static SD_VARLINK_DEFINE_ERROR(
                BlockedByInhibitor,
                SD_VARLINK_FIELD_COMMENT("Who is holding the inhibitor"),
                SD_VARLINK_DEFINE_FIELD(who, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Why the inhibitor is held"),
                SD_VARLINK_DEFINE_FIELD(why, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Shutdown,
                "io.systemd.Shutdown",
                SD_VARLINK_INTERFACE_COMMENT("APIs for shutting down or rebooting the system."),
                SD_VARLINK_SYMBOL_COMMENT("Power off the system"),
                &vl_method_PowerOff,
                SD_VARLINK_SYMBOL_COMMENT("Reboot the system"),
                &vl_method_Reboot,
                SD_VARLINK_SYMBOL_COMMENT("Halt the system"),
                &vl_method_Halt,
                SD_VARLINK_SYMBOL_COMMENT("Reboot the system via kexec"),
                &vl_method_KExec,
                SD_VARLINK_SYMBOL_COMMENT("Reboot userspace only"),
                &vl_method_SoftReboot,
                SD_VARLINK_SYMBOL_COMMENT("Another shutdown or sleep operation is already in progress"),
                &vl_error_AlreadyInProgress,
                SD_VARLINK_SYMBOL_COMMENT("Operation denied due to active block inhibitor"),
                &vl_error_BlockedByInhibitor);
