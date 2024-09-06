/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.PCRExtend.h"

static SD_VARLINK_DEFINE_METHOD(
                Extend,
                SD_VARLINK_DEFINE_INPUT(pcr, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(text, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(data, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PCRExtend,
                "io.systemd.PCRExtend",
                &vl_method_Extend);
