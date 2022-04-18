/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "macro.h"

typedef struct BusWaitForJobs BusWaitForJobs;

int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret);
BusWaitForJobs* bus_wait_for_jobs_free(BusWaitForJobs *d);
int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path);
int bus_wait_for_jobs(BusWaitForJobs *d, bool quiet, const char* const* extra_args);
int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, bool quiet, const char* const* extra_args);
/* Call SubscribeWithFlags, but only once, and cache the result - returns 1 if new method is found */
int bus_subscribe_with_flags_cached(sd_bus *bus);

DEFINE_TRIVIAL_CLEANUP_FUNC(BusWaitForJobs*, bus_wait_for_jobs_free);
