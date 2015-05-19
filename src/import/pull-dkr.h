/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

#include "sd-event.h"
#include "util.h"

typedef enum { DKR_PULL_V1, DKR_PULL_V2 } DkrPullVersion;
typedef struct DkrPull DkrPull;

typedef void (*DkrPullFinished)(DkrPull *pull, int error, void *userdata);

int dkr_pull_new(DkrPull **pull, sd_event *event, const char *index_url, const char *image_root, DkrPullFinished on_finished, void *userdata);
DkrPull* dkr_pull_unref(DkrPull *pull);

DEFINE_TRIVIAL_CLEANUP_FUNC(DkrPull*, dkr_pull_unref);

int dkr_pull_start(DkrPull *pull, const char *name, const char *tag, const char *local, bool force_local, DkrPullVersion version);
