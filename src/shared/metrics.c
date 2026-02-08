/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "json-util.h"
#include "log.h"
#include "metrics.h"
#include "string-table.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-util.h"

int metrics_setup_varlink_server(
                sd_varlink_server **server, /* in and out param */
                sd_varlink_server_flags_t flags,
                sd_event *event,
                sd_varlink_method_t vl_method_list_cb,
                sd_varlink_method_t vl_method_describe_cb,
                void *userdata) {

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(server);
        assert(event);

        if (*server)
                return 0;

        r = varlink_server_new(&s, flags, userdata);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(s, &vl_interface_io_systemd_Metrics);
        if (r < 0)
                return log_debug_errno(r, "Failed to add varlink metrics interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Metrics.List",
                        vl_method_list_cb,
                        "io.systemd.Metrics.Describe",
                        vl_method_describe_cb);
        if (r < 0)
                return log_debug_errno(r, "Failed to register varlink metrics methods: %m");

        r = sd_varlink_server_set_description(s, "systemd varlink metrics server");
        if (r < 0)
                return log_debug_errno(r, "Failed to set varlink metrics server description: %m");

        r = sd_varlink_server_attach_event(s, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_debug_errno(r, "Failed to attach varlink metrics server to event loop: %m");

        *server = TAKE_PTR(s);

        return 0;
}

static const char * const metric_family_type_table[_METRIC_FAMILY_TYPE_MAX] = {
        [METRIC_FAMILY_TYPE_COUNTER] = "counter",
        [METRIC_FAMILY_TYPE_GAUGE]   = "gauge",
        [METRIC_FAMILY_TYPE_STRING]  = "string",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(metric_family_type, MetricFamilyType);

static int metric_family_build_json(const MetricFamily *mf, sd_json_variant **ret) {
        assert(mf);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("name", mf->name),
                        SD_JSON_BUILD_PAIR_STRING("description", mf->description),
                        SD_JSON_BUILD_PAIR_STRING("type", metric_family_type_to_string(mf->type)));
}

int metrics_method_describe(
                const MetricFamily metric_family_table[],
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(metric_family_table);
        assert(link);
        assert(parameters);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_set_sentinel(link, "io.systemd.Metrics.NoSuchMetric");
        if (r < 0)
                return r;

        for (const MetricFamily *mf = metric_family_table; mf && mf->name; mf++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = metric_family_build_json(mf, &v);
                if (r < 0)
                        return log_debug_errno(r, "Failed to describe metric family '%s': %m", mf->name);

                r = sd_varlink_reply(link, v);
                if (r < 0)
                        return log_debug_errno(r, "Failed to send varlink reply: %m");
        }

        return 0;
}

int metrics_method_list(
                const MetricFamily metric_family_table[],
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(metric_family_table);
        assert(link);
        assert(parameters);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_set_sentinel(link, "io.systemd.Metrics.NoSuchMetric");
        if (r < 0)
                return r;

        MetricFamilyContext ctx = { .link = link };
        for (const MetricFamily *mf = metric_family_table; mf && mf->name; mf++) {
                assert(mf->generate);

                ctx.metric_family = mf;
                r = mf->generate(&ctx, userdata);
                if (r < 0)
                        return log_debug_errno(
                                        r, "Failed to list metrics for metric family '%s': %m", mf->name);
        }

        return 0;
}

static int metric_build_send(MetricFamilyContext *context, const char *object, sd_json_variant *value, sd_json_variant *fields) {
        assert(context);
        assert(value);
        assert(context->link);
        assert(context->metric_family);

        if (fields) {
                assert(sd_json_variant_is_object(fields));

                _unused_ const char *k;
                _unused_ sd_json_variant *e;
                JSON_VARIANT_OBJECT_FOREACH(k, e, fields)
                        assert(sd_json_variant_is_string(e));
        }

        return sd_varlink_replybo(context->link,
                        SD_JSON_BUILD_PAIR_STRING("name", context->metric_family->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("object", object),
                        SD_JSON_BUILD_PAIR("value", SD_JSON_BUILD_VARIANT(value)),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("fields", fields));
}

int metric_build_send_string(MetricFamilyContext *context, const char *object, const char *value, sd_json_variant *fields) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(value);

        r = sd_json_variant_new_string(&v, value);
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate JSON string: %m");

        return metric_build_send(context, object, v, fields);
}

int metric_build_send_unsigned(MetricFamilyContext *context, const char *object, uint64_t value, sd_json_variant *fields) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        r = sd_json_variant_new_unsigned(&v, value);
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate JSON unsigned: %m");

        return metric_build_send(context, object, v, fields);
}
