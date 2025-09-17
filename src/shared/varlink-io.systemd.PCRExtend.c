/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.PCRExtend.h"

static SD_VARLINK_DEFINE_METHOD(
                Extend,
                SD_VARLINK_FIELD_COMMENT("PCR number to extend, in range of 0…23"),
                SD_VARLINK_DEFINE_INPUT(pcr, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Text string to measure. (Specify either this, or the 'data' field below, not both)"),
                SD_VARLINK_DEFINE_INPUT(text, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Binary data to measure, encoded in Base64. (Specify either this, or the 'text' field above, not both)"),
                SD_VARLINK_DEFINE_INPUT(data, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PCRExtend,
                "io.systemd.PCRExtend",
                SD_VARLINK_INTERFACE_COMMENT("TPM PCR Extension APIs"),
                SD_VARLINK_SYMBOL_COMMENT("Measure some text or binary data into a PCR"),
                &vl_method_Extend);
