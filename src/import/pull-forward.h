/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum PullJobState PullJobState;

typedef struct PullJob PullJob;

typedef struct OciPull OciPull;
typedef struct RawPull RawPull;
typedef struct TarPull TarPull;

typedef void (*PullJobFinished)(PullJob *job);
typedef int (*PullJobOpenDisk)(PullJob *job);
typedef int (*PullJobHeader)(PullJob *job, const char *header, size_t sz);
typedef void (*PullJobProgress)(PullJob *job);
typedef int (*PullJobNotFound)(PullJob *job, char **ret_new_url);

typedef void (*OciPullFinished)(OciPull *pull, int error, void *userdata);
typedef void (*RawPullFinished)(RawPull *p, int error, void *userdata);
typedef void (*TarPullFinished)(TarPull *p, int error, void *userdata);
