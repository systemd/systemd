/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "json-util.h"
#include "log.h"
#include "metrics.h"
#include "string-table.h"
#include "strv.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-serialize.h"
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
                return log_debug_errno(r, "Failed to allocate varlink metrics server object: %m");
        r = sd_varlink_server_add_interface(s, &vl_interface_io_systemd_Metrics);

        if (r < 0)
                return log_debug_errno(r, "Failed to add varlink metrics interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                s,
                "io.systemd.Metrics.List", vl_method_list_cb,
                "io.systemd.Metrics.Describe", vl_method_describe_cb);
        if (r < 0)
                return log_debug_errno(r, "Failed to register varlink metrics methods: %m");

        r = sd_varlink_server_attach_event(s, event, SD_EVENT_PRIORITY_NORMAL);

        if (r < 0)
                return log_debug_errno(r, "Failed to attach varlink metrics connection to event loop: %m");
        *server = TAKE_PTR(s);
        return 0;
}

int metrics_listen_varlink_address(sd_varlink_server *server, const char *address) {
        int r;

        assert(server);
        assert(address);

        /* a new server will have empty list of addresses anyway */
        if (varlink_server_contains_socket(server, address))
                return 0;

        r = sd_varlink_server_listen_address(server, address, 0666 | SD_VARLINK_SERVER_MODE_MKDIR_0755);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind to metrics varlink socket '%s': %m", address);

        return 0;
}

static const char * const metric_family_type_table[_METRIC_FAMILY_TYPE_MAX] = {
        [METRIC_FAMILY_TYPE_COUNTER] = "counter",
        [METRIC_FAMILY_TYPE_GAUGE]   = "gauge",
        [METRIC_FAMILY_TYPE_STRING]  = "string",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(metric_family_type, MetricFamilyType);

static int metric_family_build_json_one(sd_varlink *link, const MetricFamily* mf, bool more) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(mf);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("name", mf->name),
                        SD_JSON_BUILD_PAIR_STRING("description", mf->description),
                        SD_JSON_BUILD_PAIR_STRING("type", metric_family_type_to_string(mf->type)));
        if (r < 0)
                return r;

        if (more)
                return sd_varlink_notify(link, v);

        return sd_varlink_reply(link, v);
}

int metrics_method_describe(const MetricFamily metric_family_table[], sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(metric_family_table);
        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        const MetricFamily *previous = NULL;
        for (const MetricFamily *mf = metric_family_table; mf && mf->name; mf++) {
                if (previous) {
                        r = metric_family_build_json_one(link, previous, /* more= */ true);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to describe metric family '%s': %m", previous->name);
                }

                previous = mf;
        }

        if (previous) {
                r = metric_family_build_json_one(link, previous, /* more */ false);
                if (r < 0)
                        return log_debug_errno(r, "Failed to describe metric family '%s': %m", previous->name);
        }

        return 0;
}

int metrics_method_list(const MetricFamily metric_family_table[], sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(metric_family_table);
        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        for (const MetricFamily *mf = metric_family_table; mf && mf->name; mf++) {
                assert(mf->iterate_cb);
                r = mf->iterate_cb(link, mf, userdata);
                if (r < 0)
                        return log_debug_errno(r, "Failed to list metrics for metric family '%s': %m", mf->name);
        }

        /* produce last empty metric to notify client about more = false */
        return sd_varlink_reply(link, NULL);
}

int metric_build_full_json_one(sd_varlink *link, const MetricFamily *mf, const char *object, sd_json_variant *value, char **fields) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(mf);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("name", mf->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("object", object),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("value", value));
                        /* TODO JSON_BUILD_PAIR_OBJECT_STRV_NOT_NULL */
        if (r < 0)
                return r;

        if (fields) { /* NULL => no fields object, empty strv => field: {} */
                r = metric_set_fields(&v, fields);
                if (r < 0)
                        return r;
        }

        return sd_varlink_notify(link, v);
}

int metric_build_body_json_one(sd_varlink *link, const MetricFamily *mf, const char *object, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);
        assert(mf);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("name", mf->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("object", object));
        if (r < 0)
                return r;

        r = mf->fill_metric_cb(&v, userdata);
        if (r < 0)
                return log_debug_errno(r, "Failed to call fill_metric_cb for '%s': %m", mf->name);

        return sd_varlink_notify(link, v);
}

int metric_set_value_string(sd_json_variant **v, const char *value) {
        return sd_json_variant_set_field_string(ASSERT_PTR(v), "value", ASSERT_PTR(value));
}

int metric_set_value_unsigned(sd_json_variant **v, uint64_t value) {
        return sd_json_variant_set_field_unsigned(ASSERT_PTR(v), "value", value);
}

int metric_set_fields(sd_json_variant **v, char **fields) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields_v = NULL;
        int r;

        STRV_FOREACH_PAIR(fk, fv, fields) {
                r = sd_json_variant_merge_objectbo(&fields_v, SD_JSON_BUILD_PAIR_STRING(*fk, *fv));
                if (r < 0)
                        return r;
        }

        return sd_json_variant_set_field(ASSERT_PTR(v), "fields", fields_v);
}
