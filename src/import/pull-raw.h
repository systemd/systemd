/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "sd-event.h"
#include "macro.h"
#include "import-util.h"

typedef struct RawPull RawPull;

typedef void (*RawPullFinished)(RawPull *pull, int error, void *userdata);

int raw_pull_new(RawPull **pull, sd_event *event, const char *image_root, RawPullFinished on_finished, void *userdata);
RawPull* raw_pull_unref(RawPull *pull);

DEFINE_TRIVIAL_CLEANUP_FUNC(RawPull*, raw_pull_unref);

int raw_pull_start(RawPull *pull, const char *url, const char *local, bool force_local, ImportVerify verify, bool settings);
