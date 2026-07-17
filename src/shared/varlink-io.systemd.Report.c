/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Report.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                SignMode,
                SD_VARLINK_FIELD_COMMENT("Emit whatever signatures are available, never fail on signing."),
                SD_VARLINK_DEFINE_ENUM_VALUE(bestEffort),
                SD_VARLINK_FIELD_COMMENT("Require at least one signature; tolerate individual signer failures. (Default.)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(requireOne),
                SD_VARLINK_FIELD_COMMENT("Require every signing mechanism to succeed with a signature."),
                SD_VARLINK_DEFINE_ENUM_VALUE(requireAll));

static SD_VARLINK_DEFINE_METHOD(
                Generate,
                SD_VARLINK_FIELD_COMMENT("Selects which metrics to include in the report, as an array of metric family names or prefixes thereof. If unset or empty all available metrics are included. This matches the [MATCH…] arguments of the systemd-report command line tool."),
                SD_VARLINK_DEFINE_INPUT(matches, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The generated report as a JSON object. This mode does not sign the report, hence a precise binary formatting of the JSON data is not relevant."),
                SD_VARLINK_DEFINE_OUTPUT(report, SD_VARLINK_OBJECT, 0));

static SD_VARLINK_DEFINE_METHOD(
                GenerateSigned,
                SD_VARLINK_FIELD_COMMENT("Selects which metrics to include in the report, as an array of metric family names or prefixes thereof. If unset or empty all available metrics are included. This matches the [MATCH…] arguments of the systemd-report command line tool."),
                SD_VARLINK_DEFINE_INPUT(matches, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("How to handle multiple signers. Defaults to requireOne if unset."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(mode, SignMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The generated, signed report in Base64. A precise binary formatting of the JSON data is important to authenticate the signature. This data contains a JSON-SEQ compliant stream of objects, the first being the report, the following ones signature objects."),
                SD_VARLINK_DEFINE_OUTPUT(reportData, SD_VARLINK_STRING, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Report,
                "io.systemd.Report",
                SD_VARLINK_INTERFACE_COMMENT("Frontend API for generating system reports. This interface is implemented by systemd-report, which aggregates the metrics exposed by the io.systemd.Metrics services linked into /run/systemd/report/."),
                SD_VARLINK_SYMBOL_COMMENT("Policy for how multiple signers are aggregated."),
                &vl_type_SignMode,
                SD_VARLINK_SYMBOL_COMMENT("Generate a report and return it as a JSON object."),
                &vl_method_Generate,
                SD_VARLINK_SYMBOL_COMMENT("Generate a signed report and return it Base64 encoded."),
                &vl_method_GenerateSigned);
