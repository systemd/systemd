/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "job-mode.h"
#include "string-table.h"

static const char* const job_mode_table[_JOB_MODE_MAX] = {
        [JOB_FAIL]                 = "fail",
        [JOB_REPLACE]              = "replace",
        [JOB_REPLACE_IRREVERSIBLY] = "replace-irreversibly",
        [JOB_ISOLATE]              = "isolate",
        [JOB_FLUSH]                = "flush",
        [JOB_IGNORE_DEPENDENCIES]  = "ignore-dependencies",
        [JOB_IGNORE_REQUIREMENTS]  = "ignore-requirements",
        [JOB_TRIGGERING]           = "triggering",
        [JOB_RESTART_DEPENDENCIES] = "restart-dependencies",
};

DEFINE_STRING_TABLE_LOOKUP(job_mode, JobMode);
