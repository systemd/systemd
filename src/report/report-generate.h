/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "report.h"

int context_build_report(Context *context, sd_json_variant **ret);

int context_generate_report(Context *context);
