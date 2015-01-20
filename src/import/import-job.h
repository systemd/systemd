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

#include <lzma.h>
#include <zlib.h>
#include <gcrypt.h>

#include "macro.h"
#include "curl-util.h"

typedef struct ImportJob ImportJob;

typedef void (*ImportJobFinished)(ImportJob *job);
typedef int (*ImportJobOpenDisk)(ImportJob *job);

typedef enum ImportJobState {
        IMPORT_JOB_INIT,
        IMPORT_JOB_ANALYZING, /* Still reading into ->payload, to figure out what we have */
        IMPORT_JOB_RUNNING,  /* Writing to destination */
        IMPORT_JOB_DONE,
        IMPORT_JOB_FAILED,
        _IMPORT_JOB_STATE_MAX,
        _IMPORT_JOB_STATE_INVALID = -1,
} ImportJobState;

#define IMPORT_JOB_STATE_IS_COMPLETE(j) (IN_SET((j)->state, IMPORT_JOB_DONE, IMPORT_JOB_FAILED))

typedef enum ImportJobCompression {
        IMPORT_JOB_UNCOMPRESSED,
        IMPORT_JOB_XZ,
        IMPORT_JOB_GZIP,
        _IMPORT_JOB_COMPRESSION_MAX,
        _IMPORT_JOB_COMPRESSION_INVALID = -1,
} ImportJobCompression;

struct ImportJob {
        ImportJobState state;
        int error;

        char *url;

        void *userdata;
        ImportJobFinished on_finished;
        ImportJobOpenDisk on_open_disk;

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

        ImportJobCompression compressed;
        lzma_stream xz;
        z_stream gzip;

        unsigned progress_percent;
        usec_t start_usec;
        usec_t last_status_usec;

        bool allow_sparse;

        bool calc_hash;
        gcry_md_hd_t hash_context;

        char *sha256;
};

int import_job_new(ImportJob **job, const char *url, CurlGlue *glue, void *userdata);
ImportJob* import_job_unref(ImportJob *job);

int import_job_begin(ImportJob *j);

void import_job_curl_on_finished(CurlGlue *g, CURL *curl, CURLcode result);
