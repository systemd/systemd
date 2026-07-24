/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* The prefix shared by all our Varlink error IDs. */
#define TIMESTAMP_ERROR(id) "io.systemd.Timestamp." id

typedef struct Manager Manager;
typedef struct TimestampRequest TimestampRequest;

struct Manager {
        sd_event *event;
        sd_varlink_server *varlink_server;

        /* Lazily allocated on first use of the respective transport. */
        CurlGlue *curl_glue;
        sd_resolve *resolve;

        /* Configuration (from timestampd.conf) */
        char *authority;                /* default Time-Stamp Authority URL */
        usec_t connection_timeout_usec;
        uint64_t data_size_max;         /* how much data we are willing to digest, UINT64_MAX for no limit */

        /* All in-flight TimestampRequest objects. */
        Set *requests;
};

int manager_new(Manager **ret);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_parse_config(Manager *m);

const struct ConfigPerfItem* timestampd_gperf_lookup(const char *key, GPERF_LEN_TYPE length);
