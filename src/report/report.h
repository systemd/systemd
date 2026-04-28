/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#include "iovec-wrapper.h"

#define REPORT_PRIV_KEY_FILE CERTIFICATE_ROOT "/private/systemd-report.pem"
#define REPORT_CERT_FILE     CERTIFICATE_ROOT "/certs/systemd-report.pem"
#define REPORT_TRUST_FILE    CERTIFICATE_ROOT "/ca/trusted.pem"

#define REPORT_UPLOAD_DIR "/run/systemd/metrics-upload"

extern char *arg_url, *arg_key, *arg_cert, *arg_trust;
extern char **arg_extra_headers;
extern usec_t arg_network_timeout_usec;
extern sd_json_format_flags_t arg_json_format_flags;

typedef enum Action {
        ACTION_LIST_METRICS,
        ACTION_DESCRIBE_METRICS,
        ACTION_BUILD_REPORT,
        ACTION_UPLOAD_REPORT,
        _ACTION_MAX,
        _ACTION_INVALID = -EINVAL,
} Action;

/* The structure for collected "metrics". */
typedef struct Context {
        Action action;
        sd_event *event;
        Set *link_infos;
        sd_json_variant **metrics;  /* Collected metrics for sorting */
        size_t n_metrics, n_skipped_metrics, n_invalid_metrics;

        int upload_result;
        struct iovec_wrapper upload_answer;
} Context;

int report_collected(Context *context);
