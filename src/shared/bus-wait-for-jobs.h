/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct BusWaitForJobs BusWaitForJobs;

typedef enum WaitJobsFlags {
        BUS_WAIT_JOBS_LOG_ERROR   = 1 << 0,
        BUS_WAIT_JOBS_LOG_SUCCESS = 1 << 1,
} WaitJobsFlags;

_sync_ BusWaitForJobs* bus_wait_for_jobs_free(BusWaitForJobs *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(BusWaitForJobs*, bus_wait_for_jobs_free);

_may_suspend_ int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret);
_sync_ int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path);
_may_suspend_ int bus_wait_for_jobs_full(BusWaitForJobs *d, WaitJobsFlags flags, const char* const* extra_args);
_may_suspend_ static inline int bus_wait_for_jobs(BusWaitForJobs *d, WaitJobsFlags flags) {
        return SD_AWAIT(bus_wait_for_jobs_full(d, flags, /* extra_args= */ NULL));
}
int bus_wait_for_jobs_one_full(BusWaitForJobs *d, const char *path, WaitJobsFlags flags, const char* const* extra_args);
static inline int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, WaitJobsFlags flags) {
        return bus_wait_for_jobs_one_full(d, path, flags, /* extra_args= */ NULL);
}
