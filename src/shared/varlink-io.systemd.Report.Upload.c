/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Report.Upload.h"

static SD_VARLINK_DEFINE_METHOD(
                Upload,
                SD_VARLINK_FIELD_COMMENT("Report data as JSON variant. Either this field or reportData (below) have to be specified. This mode is used if signing is not used, and hence a precise binary formatting of the JSON data is not relevant."),
                SD_VARLINK_DEFINE_INPUT(report, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Report data in Base64. Either this field or report (above) have to be specified. This mode is used if signing is enabled, as a precise binary formatting of the JSON data is important to authenticate the signature. This data contains a JSON-SEQ compliant stream of objects, the first being the report, the following ones signature objects."),
                SD_VARLINK_DEFINE_INPUT(reportData, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Report_Upload,
                "io.systemd.Report.Upload",
                SD_VARLINK_INTERFACE_COMMENT("Backend API for uploading reports. This interface shall be implemented by services linked into /run/systemd/report.upload/"),
                SD_VARLINK_SYMBOL_COMMENT("Upload a report now."),
                &vl_method_Upload);
