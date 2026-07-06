/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.VarlinkMonitor.h"

static SD_VARLINK_DEFINE_METHOD(
                Setup,
                SD_VARLINK_FIELD_COMMENT("FIXME"),
                SD_VARLINK_DEFINE_INPUT(ringbufFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("FIXME"),
                SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("FIXME"),
                SD_VARLINK_DEFINE_OUTPUT(eventfdReadFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("FIXME"),
                SD_VARLINK_DEFINE_OUTPUT(eventfdWriteFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(Start);

static SD_VARLINK_DEFINE_METHOD(Stop);

static SD_VARLINK_DEFINE_ERROR(InvalidUID);
static SD_VARLINK_DEFINE_ERROR(BadState);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_VarlinkMonitor,
                "io.systemd.VarlinkMonitor",
                SD_VARLINK_INTERFACE_COMMENT("FIXME"),

                /* Methods */
                SD_VARLINK_SYMBOL_COMMENT("FIXME"),
                &vl_method_Setup,
                SD_VARLINK_SYMBOL_COMMENT("FIXME"),
                &vl_method_Start,
                SD_VARLINK_SYMBOL_COMMENT("FIXME"),
                &vl_method_Stop,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("Invalid user id"),
                &vl_error_InvalidUID,
                SD_VARLINK_SYMBOL_COMMENT("Method call not allowed in current state"),
                &vl_error_BadState);
