/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef enum MetricFamilyType {
        METRIC_FAMILY_TYPE_COUNTER,
        METRIC_FAMILY_TYPE_GAUGE,
        METRIC_FAMILY_TYPE_STRING,
        _METRIC_FAMILY_TYPE_MAX,
        _METRIC_FAMILY_TYPE_INVALID = -EINVAL,
} MetricFamilyType;

typedef struct MetricFamily MetricFamily;

typedef struct MetricFamilyContext {
        const MetricFamily* metric_family;
        sd_varlink *link;
} MetricFamilyContext;

typedef int (*metric_family_generate_func_t) (MetricFamilyContext *mfc, void *userdata);

typedef struct MetricFamily {
        const char *name;
        const char *description;
        MetricFamilyType type;
        metric_family_generate_func_t generate;
} MetricFamily;

int metrics_setup_varlink_server(
                sd_varlink_server **server, /* in and out param */
                sd_varlink_server_flags_t flags,
                sd_event *event,
                sd_varlink_method_t vl_method_list_cb,
                sd_varlink_method_t vl_method_describe_cb,
                void *userdata);

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(metric_family_type, MetricFamilyType);

int metrics_method_describe(const MetricFamily metric_family_table[], sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int metrics_method_list(const MetricFamily metric_family_table[], sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int metric_build_send_string(MetricFamilyContext* context, const char *object, const char *value, sd_json_variant *fields);
int metric_build_send_unsigned(MetricFamilyContext* context, const char *object, uint64_t value, sd_json_variant *fields);
