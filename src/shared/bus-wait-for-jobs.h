/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "macro.h"

typedef struct BusWaitForJobs BusWaitForJobs;

typedef enum WaitJobsFlags {
        BUS_WAIT_JOBS_LOG_ERROR   = 1 << 0,
        BUS_WAIT_JOBS_LOG_SUCCESS = 1 << 1,
} WaitJobsFlags;

BusWaitForJobs* bus_wait_for_jobs_free(BusWaitForJobs *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(BusWaitForJobs*, bus_wait_for_jobs_free);

int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret);
int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path);
int bus_wait_for_jobs(BusWaitForJobs *d, WaitJobsFlags flags, const char* const* extra_args);
int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, WaitJobsFlags flags, const char* const* extra_args);
