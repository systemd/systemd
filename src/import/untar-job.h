/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Codethink Limited.

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
#include "ratelimit.h"

typedef struct UnTarJob UnTarJob;

typedef int (*UnTarJobRead)(UnTarJob *job);
typedef void (*UnTarJobProgress)(UnTarJob *job, unsigned percent);
typedef void (*UnTarJobFinished)(UnTarJob *job, int error);

struct UnTarJob {
        sd_event *event;
        sd_event_source *input_event_source;

        /* params */
        int input_fd;
        char *path;

        /* nullable params */
        UnTarJobRead on_read;
        UnTarJobProgress on_progress;
        UnTarJobFinished on_finished;
        void *userdata;

        /* internal state */
        /*   for keeping track of subprocess */
        int tar_fd;
        pid_t tar_pid;
        /*   for read buffering to pass to on_read */
        uint8_t buffer[16*1024];
        size_t buffer_size;
        /*   for progress */
        struct stat st;
        unsigned input_processed;
        unsigned last_percent;
        RateLimit progress_rate_limit;
};

int untar_job_new(UnTarJob **job, sd_event *event, UnTarJobRead on_read, UnTarJobProgress on_progress, UnTarJobFinished on_finished, void *userdata);
UnTarJob *untar_job_unref(UnTarJob *job);

DEFINE_TRIVIAL_CLEANUP_FUNC(UnTarJob*, untar_job_unref);

int untar_job_begin(UnTarJob *j, int input_fd, const char *path);
