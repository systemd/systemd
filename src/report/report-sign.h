/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "report.h"

DECLARE_STRING_TABLE_LOOKUP(report_sign_mode, ReportSignMode);

int context_sign_report(
                Context *context,
                sd_json_variant *report,
                ReportSignMode mode,
                sd_json_format_flags_t format_flags,
                FILE *output);

int context_sign_report_as_string(
                Context *context,
                sd_json_variant *report,
                ReportSignMode mode,
                sd_json_format_flags_t format_flags,
                char **ret);
