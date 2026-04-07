/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "facts.h"
#include "json-util.h"
#include "log.h"
#include "varlink-io.systemd.Facts.h"

int facts_add_to_varlink_server(
                sd_varlink_server *server,
                sd_varlink_method_t vl_method_list_cb,
                sd_varlink_method_t vl_method_describe_cb) {

        int r;

        assert(server);
        assert(vl_method_list_cb);
        assert(vl_method_describe_cb);

        r = sd_varlink_server_add_interface(server, &vl_interface_io_systemd_Facts);
        if (r < 0)
                return log_debug_errno(r, "Failed to add varlink facts interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        server,
                        "io.systemd.Facts.List",     vl_method_list_cb,
                        "io.systemd.Facts.Describe", vl_method_describe_cb);
        if (r < 0)
                return log_debug_errno(r, "Failed to register varlink facts methods: %m");

        return 0;
}

static int fact_family_build_json(const FactFamily *ff, sd_json_variant **ret) {
        assert(ff);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("name", ff->name),
                        SD_JSON_BUILD_PAIR_STRING("description", ff->description));
}

int facts_method_describe(
                const FactFamily fact_family_table[],
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(fact_family_table);
        assert(link);
        assert(parameters);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Facts.NoSuchFact");
        if (r < 0)
                return r;

        for (const FactFamily *ff = fact_family_table; ff && ff->name; ff++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = fact_family_build_json(ff, &v);
                if (r < 0)
                        return log_debug_errno(r, "Failed to describe fact family '%s': %m", ff->name);

                r = sd_varlink_reply(link, v);
                if (r < 0)
                        return log_debug_errno(r, "Failed to send varlink reply: %m");
        }

        return 0;
}

int facts_method_list(
                const FactFamily fact_family_table[],
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(fact_family_table);
        assert(link);
        assert(parameters);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Facts.NoSuchFact");
        if (r < 0)
                return r;

        FactFamilyContext ctx = { .link = link };
        for (const FactFamily *ff = fact_family_table; ff && ff->name; ff++) {
                assert(ff->generate);

                ctx.fact_family = ff;
                r = ff->generate(&ctx, userdata);
                if (r < 0)
                        return log_debug_errno(
                                        r, "Failed to list facts for fact family '%s': %m", ff->name);
        }

        return 0;
}

static int fact_build_send(FactFamilyContext *context, const char *object, sd_json_variant *value) {
        assert(context);
        assert(value);
        assert(context->link);
        assert(context->fact_family);

        return sd_varlink_replybo(context->link,
                        SD_JSON_BUILD_PAIR_STRING("name", context->fact_family->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("object", object),
                        SD_JSON_BUILD_PAIR_VARIANT("value", value));
}

int fact_build_send_string(FactFamilyContext *context, const char *object, const char *value) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(value);

        r = sd_json_variant_new_string(&v, value);
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate JSON string: %m");

        return fact_build_send(context, object, v);
}

int fact_build_send_unsigned(FactFamilyContext *context, const char *object, uint64_t value) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        r = sd_json_variant_new_unsigned(&v, value);
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate JSON unsigned: %m");

        return fact_build_send(context, object, v);
}
