/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "import-util.h"
#include "macro.h"
#include "pull-common.h"

typedef struct RawPull RawPull;

typedef void (*RawPullFinished)(RawPull *pull, int error, void *userdata);

int raw_pull_new(RawPull **pull, sd_event *event, const char *image_root, RawPullFinished on_finished, void *userdata);
RawPull* raw_pull_unref(RawPull *pull);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawPull*, raw_pull_unref);

int raw_pull_start(RawPull *pull, const char *url, const char *local, uint64_t offset, uint64_t size_max, PullFlags flags, ImportVerify verify, const char *checksum);
