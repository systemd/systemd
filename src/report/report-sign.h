/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "report.h"

int context_sign_report(Context *context, sd_json_variant *report, sd_json_format_flags_t format_flags, FILE *output);
