/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>

#include "curl-util.h"
#include "import-compress.h"
#include "macro.h"
#include "openssl-util.h"
#include "pull-common.h"

typedef struct PullJob PullJob;

typedef void (*PullJobFinished)(PullJob *job);
typedef int (*PullJobOpenDisk)(PullJob *job);
typedef int (*PullJobHeader)(PullJob *job, const char *header, size_t sz);
typedef void (*PullJobProgress)(PullJob *job);
typedef int (*PullJobNotFound)(PullJob *job, char **ret_new_url);

typedef enum PullJobState {
        PULL_JOB_INIT,
        PULL_JOB_ANALYZING, /* Still reading into ->payload, to figure out what we have */
        PULL_JOB_RUNNING,   /* Writing to destination */
        PULL_JOB_DONE,
        PULL_JOB_FAILED,
        _PULL_JOB_STATE_MAX,
        _PULL_JOB_STATE_INVALID = -EINVAL,
} PullJobState;

#define PULL_JOB_IS_COMPLETE(j) (IN_SET((j)->state, PULL_JOB_DONE, PULL_JOB_FAILED))

struct PullJob {
        PullJobState state;
        int error;

        char *url;

        void *userdata;
        PullJobFinished on_finished;
        PullJobOpenDisk on_open_disk;
        PullJobHeader on_header;
        PullJobProgress on_progress;
        PullJobNotFound on_not_found;

        CurlGlue *glue;
        CURL *curl;
        struct curl_slist *request_header;

        char *etag;
        char **old_etags;
        bool etag_exists;

        uint64_t content_length;
        uint64_t written_compressed;
        uint64_t written_uncompressed;
        uint64_t offset;

        uint64_t uncompressed_max;
        uint64_t compressed_max;

        uint8_t *payload;
        size_t payload_size;

        int disk_fd;
        bool close_disk_fd;
        struct stat disk_stat;

        usec_t mtime;

        ImportCompress compress;

        unsigned progress_percent;
        usec_t start_usec;
        usec_t last_status_usec;

        bool calc_checksum;
        hash_context_t checksum_ctx;

        char *checksum;
        bool sync;
        bool force_memory;
};

int pull_job_new(PullJob **job, const char *url, CurlGlue *glue, void *userdata);
PullJob* pull_job_unref(PullJob *job);

int pull_job_begin(PullJob *j);

void pull_job_curl_on_finished(CurlGlue *g, CURL *curl, CURLcode result);

void pull_job_close_disk_fd(PullJob *j);

DEFINE_TRIVIAL_CLEANUP_FUNC(PullJob*, pull_job_unref);
