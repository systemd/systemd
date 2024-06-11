/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.PCRExtend.h"

static VARLINK_DEFINE_METHOD(
                Extend,
                VARLINK_DEFINE_INPUT(pcr, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(nvpcr, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(allocate, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(text, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(data, VARLINK_STRING, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                AllocateNvPCR,
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(
                DeleteNvPCR,
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(NoSuchNvPCR);

VARLINK_DEFINE_INTERFACE(
                io_systemd_PCRExtend,
                "io.systemd.PCRExtend",
                &vl_method_Extend,
                &vl_method_AllocateNvPCR,
                &vl_method_DeleteNvPCR,
                &vl_error_NoSuchNvPCR);
