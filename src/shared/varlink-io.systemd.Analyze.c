/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Analyze.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Diagnostic,
                SD_VARLINK_FIELD_COMMENT(
                                "Diagnostic severity. Current values are 'error', 'warning', 'notice', "
                                "and 'info'; clients must accept additional values."),
                SD_VARLINK_DEFINE_FIELD(severity, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT(
                                "Human-readable diagnostic text. This text is not a stable identifier and "
                                "must not be matched by programs."),
                SD_VARLINK_DEFINE_FIELD(message, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Unit associated with the diagnostic, if known."),
                SD_VARLINK_DEFINE_FIELD(unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Configuration file associated with the diagnostic, if known."),
                SD_VARLINK_DEFINE_FIELD(configurationFile, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("One-based line number in configurationFile, if known."),
                SD_VARLINK_DEFINE_FIELD(configurationLine, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT(
                                "Stable systemd MESSAGE_ID associated with the diagnostic, if one was "
                                "emitted."),
                SD_VARLINK_DEFINE_FIELD(messageId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Verify,
                SD_VARLINK_FIELD_COMMENT(
                                "Absolute, normalized unit file paths to verify. If unset, null, or empty, "
                                "all effective non-alias, unmasked unit-file entries selected by this "
                                "endpoint's lookup path are verified."),
                SD_VARLINK_DEFINE_INPUT(unitFiles, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT(
                                "Diagnostics in verification order. An empty array means no findings; "
                                "verification findings are returned as successful method replies."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(diagnostics, Diagnostic, SD_VARLINK_ARRAY));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Analyze,
                "io.systemd.Analyze",
                SD_VARLINK_INTERFACE_COMMENT(
                                "Offline unit-file analysis APIs. The endpoint determines whether the "
                                "system or user unit lookup path is used."),
                SD_VARLINK_SYMBOL_COMMENT("A structured unit-file verification diagnostic."),
                &vl_type_Diagnostic,
                SD_VARLINK_SYMBOL_COMMENT(
                                "Verify selected unit files, or the effective non-alias, unmasked entries "
                                "selected by the lookup path when no selection is supplied."),
                &vl_method_Verify);
