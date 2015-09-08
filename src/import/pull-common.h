/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <stdbool.h>

#include "pull-job.h"
#include "import-util.h"

int pull_make_local_copy(const char *final, const char *root, const char *local, bool force_local);

int pull_find_old_etags(const char *url, const char *root, int dt, const char *prefix, const char *suffix, char ***etags);

int pull_make_path(const char *url, const char *etag, const char *image_root, const char *prefix, const char *suffix, char **ret);

int pull_make_settings_job(PullJob **ret, const char *url, CurlGlue *glue, PullJobFinished on_finished, void *userdata);
int pull_make_verification_jobs(PullJob **ret_checksum_job, PullJob **ret_signature_job, ImportVerify verify, const char *url, CurlGlue *glue, PullJobFinished on_finished, void *userdata);

int pull_verify(PullJob *main_job, PullJob *settings_job, PullJob *checksum_job, PullJob *signature_job);
