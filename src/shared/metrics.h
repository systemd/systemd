/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum MetricFamilyType {
        METRIC_FAMILY_TYPE_COUNTER,
        METRIC_FAMILY_TYPE_GAUGE,
        METRIC_FAMILY_TYPE_STRING,
        _METRIC_FAMILY_TYPE_MAX,
        _METRIC_FAMILY_TYPE_INVALID = -EINVAL,
} MetricFamilyType;

typedef struct MetricFamily MetricFamily;
typedef int (*metric_family_iterate_cb_t) (sd_varlink *link, const MetricFamily *mf, void *userdata);
typedef int (*metric_family_fill_metric_cb_t) (sd_json_variant **v, void *userdata);

typedef struct MetricFamily {
        const char *name;
        const char *description;
        MetricFamilyType type;
        metric_family_iterate_cb_t iterate_cb;
        metric_family_fill_metric_cb_t fill_metric_cb;
} MetricFamily;

int metrics_setup_varlink_server(
                sd_varlink_server **server, /* in and out param */
                sd_varlink_server_flags_t flags,
                sd_event *event,
                sd_varlink_method_t vl_method_list_cb,
                sd_varlink_method_t vl_method_describe_cb,
                void *userdata);
int metrics_listen_varlink_address(sd_varlink_server *server, const char *address);

const char* metric_family_type_to_string(MetricFamilyType t) _const_;
int metrics_method_describe(const MetricFamily metric_family_table[], sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int metrics_method_list(const MetricFamily metric_family_table[], sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int metric_build_full_json_one(sd_varlink *link, const MetricFamily *mf, const char *object, sd_json_variant *value, char **fields);
int metric_build_body_json_one(sd_varlink *link, const MetricFamily *mf, const char *object, void *userdata);
int metric_set_value_string(sd_json_variant **v, const char *value);
int metric_set_value_unsigned(sd_json_variant **v, uint64_t value);
int metric_set_fields(sd_json_variant **v, char **fields);
