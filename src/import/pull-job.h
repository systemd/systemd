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

#include <gcrypt.h>

#include "macro.h"
#include "curl-util.h"
#include "import-compress.h"

typedef struct PullJob PullJob;

typedef void (*PullJobFinished)(PullJob *job);
typedef int (*PullJobOpenDisk)(PullJob *job);
typedef int (*PullJobHeader)(PullJob *job, const char *header, size_t sz);
typedef void (*PullJobProgress)(PullJob *job);

typedef enum PullJobState {
        PULL_JOB_INIT,
        PULL_JOB_ANALYZING, /* Still reading into ->payload, to figure out what we have */
        PULL_JOB_RUNNING,  /* Writing to destination */
        PULL_JOB_DONE,
        PULL_JOB_FAILED,
        _PULL_JOB_STATE_MAX,
        _PULL_JOB_STATE_INVALID = -1,
} PullJobState;

#define PULL_JOB_STATE_IS_COMPLETE(j) (IN_SET((j)->state, PULL_JOB_DONE, PULL_JOB_FAILED))

typedef enum PullJobCompression {
        PULL_JOB_UNCOMPRESSED,
        PULL_JOB_XZ,
        PULL_JOB_GZIP,
        PULL_JOB_BZIP2,
        _PULL_JOB_COMPRESSION_MAX,
        _PULL_JOB_COMPRESSION_INVALID = -1,
} PullJobCompression;

struct PullJob {
        PullJobState state;
        int error;

        char *url;

        void *userdata;
        PullJobFinished on_finished;
        PullJobOpenDisk on_open_disk;
        PullJobHeader on_header;
        PullJobProgress on_progress;

        CurlGlue *glue;
        CURL *curl;
        struct curl_slist *request_header;

        char *etag;
        char **old_etags;
        bool etag_exists;

        uint64_t content_length;
        uint64_t written_compressed;
        uint64_t written_uncompressed;

        uint64_t uncompressed_max;
        uint64_t compressed_max;

        uint8_t *payload;
        size_t payload_size;
        size_t payload_allocated;

        int disk_fd;

        usec_t mtime;

        ImportCompress compress;

        unsigned progress_percent;
        usec_t start_usec;
        usec_t last_status_usec;

        bool allow_sparse;

        bool calc_checksum;
        gcry_md_hd_t checksum_context;

        char *checksum;

        bool grow_machine_directory;
        uint64_t written_since_last_grow;
};

int pull_job_new(PullJob **job, const char *url, CurlGlue *glue, void *userdata);
PullJob* pull_job_unref(PullJob *job);

int pull_job_begin(PullJob *j);

void pull_job_curl_on_finished(CurlGlue *g, CURL *curl, CURLcode result);

DEFINE_TRIVIAL_CLEANUP_FUNC(PullJob*, pull_job_unref);
