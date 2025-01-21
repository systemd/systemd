/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

typedef enum JobMode JobMode;

enum JobMode {
        JOB_FAIL,                /* Fail if a conflicting job is already queued */
        JOB_REPLACE,             /* Replace an existing conflicting job */
        JOB_REPLACE_IRREVERSIBLY,/* Like JOB_REPLACE + produce irreversible jobs */
        JOB_ISOLATE,             /* Start a unit, and stop all others */
        JOB_FLUSH,               /* Flush out all other queued jobs when queueing this one */
        JOB_IGNORE_DEPENDENCIES, /* Ignore both requirement and ordering dependencies */
        JOB_IGNORE_REQUIREMENTS, /* Ignore requirement dependencies */
        JOB_TRIGGERING,          /* Adds TRIGGERED_BY dependencies to the same transaction */
        JOB_RESTART_DEPENDENCIES,/* A "start" job for the specified unit becomes "restart" for depending units */
        _JOB_MODE_MAX,
        _JOB_MODE_INVALID = -EINVAL,
};

const char* job_mode_to_string(JobMode t) _const_;
JobMode job_mode_from_string(const char *s) _pure_;
