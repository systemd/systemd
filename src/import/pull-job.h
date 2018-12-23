/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <gcrypt.h>

#include "curl-util.h"
#include "import-compress.h"
#include "macro.h"

typedef struct PullJob PullJob;

typedef void (*PullJobFinished)(PullJob *job);
typedef int (*PullJobOpenDisk)(PullJob *job);
typedef int (*PullJobHeader)(PullJob *job, const char *header, size_t sz);
typedef void (*PullJobProgress)(PullJob *job);

typedef enum PullJobState
{
        PULL_JOB_INIT,
        PULL_JOB_ANALYZING, /* Still reading into ->payload, to figure out what we have */
        PULL_JOB_RUNNING,   /* Writing to destination */
        PULL_JOB_DONE,
        PULL_JOB_FAILED,
        _PULL_JOB_STATE_MAX,
        _PULL_JOB_STATE_INVALID = -1,
} PullJobState;

typedef enum VerificationStyle
{
        VERIFICATION_STYLE_UNSET,
        VERIFICATION_PER_FILE,      /* SuSE-style ".sha256" files with inline signature */
        VERIFICATION_PER_DIRECTORY, /* Ubuntu-style SHA256SUM files with detach SHA256SUM.gpg signatures */
} VerificationStyle;

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

        VerificationStyle style;
};

int pull_job_new(PullJob **job, const char *url, CurlGlue *glue, void *userdata);
PullJob *pull_job_unref(PullJob *job);

int pull_job_begin(PullJob *j);

void pull_job_curl_on_finished(CurlGlue *g, CURL *curl, CURLcode result);

DEFINE_TRIVIAL_CLEANUP_FUNC(PullJob *, pull_job_unref);
