/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.PCRExtend.h"

static SD_VARLINK_DEFINE_METHOD(
                Extend,
                SD_VARLINK_FIELD_COMMENT("PCR number to extend, in range of 0…23. Either this or 'nvpcr' must be specified, not both, not neither."),
                SD_VARLINK_DEFINE_INPUT(pcr, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("NvPCR to extend, identified by a string. Either this or 'pcr' must be specified, not both, not neither."),
                SD_VARLINK_DEFINE_INPUT(nvpcr, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Text string to measure. (Specify either this, or the 'data' field below, not both)"),
                SD_VARLINK_DEFINE_INPUT(text, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Binary data to measure, encoded in Base64. (Specify either this, or the 'text' field above, not both)"),
                SD_VARLINK_DEFINE_INPUT(data, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoSuchNvPCR);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PCRExtend,
                "io.systemd.PCRExtend",
                SD_VARLINK_INTERFACE_COMMENT("TPM PCR Extension APIs"),
                SD_VARLINK_SYMBOL_COMMENT("Measure some text or binary data into a PCR"),
                &vl_method_Extend,
                &vl_error_NoSuchNvPCR);
