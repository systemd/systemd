/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-io.systemd.Metrics.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                MetricFamilyType,
                SD_VARLINK_FIELD_COMMENT("A counter metric family type which is a monotonically increasing value"),
                SD_VARLINK_DEFINE_ENUM_VALUE(counter),
                SD_VARLINK_FIELD_COMMENT("A gauge metric family type which is a value that can go up and down"),
                SD_VARLINK_DEFINE_ENUM_VALUE(gauge),
                SD_VARLINK_FIELD_COMMENT("A string metric family type"),
                SD_VARLINK_DEFINE_ENUM_VALUE(string));

static SD_VARLINK_DEFINE_ERROR(NoSuchMetric);

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Metric name, e.g. io.systemd.Manager.unitsByTypeTotal or io.systemd.Manager.unitActiveState"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                /* metric value has various types depending on MetricFamilyType and actual data double/int/uint */
                SD_VARLINK_FIELD_COMMENT("Metric value"),
                SD_VARLINK_DEFINE_OUTPUT(value, SD_VARLINK_ANY, 0),
                SD_VARLINK_FIELD_COMMENT("Metric object name can be unit name, process name, etc, e.g. dev-hvc0.device"),
                SD_VARLINK_DEFINE_OUTPUT(object, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Metric fields are values to differentiate between different metrics in the same metric family"),
                SD_VARLINK_DEFINE_OUTPUT(fields, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Describe,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Metric family name"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Metric family description"),
                SD_VARLINK_DEFINE_OUTPUT(description, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Metric family type"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, MetricFamilyType, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Metrics,
                "io.systemd.Metrics",
                SD_VARLINK_INTERFACE_COMMENT("Metrics APIs"),
                SD_VARLINK_SYMBOL_COMMENT("An enum representing various metric family types"),
                &vl_type_MetricFamilyType,
                SD_VARLINK_SYMBOL_COMMENT("Method to get a list of metrics among which the collection of related metrics forms a metric family"),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("Method to get the metric families"),
                &vl_method_Describe,
                SD_VARLINK_SYMBOL_COMMENT("No such metric found"),
                &vl_error_NoSuchMetric);
