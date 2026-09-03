/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "constants.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "path-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "sysupdate-provider.h"
#include "sysupdate-util.h"
#include "varlink-util.h"

/* Component providers are queried by connecting to all sockets in VARLINK_DIR_SYSUPDATE_PROVIDER in
 * parallel. Since replies arrive in arbitrary order we collect them first, and then process them sorted by
 * provider name, so that the outcome is deterministic: if multiple providers claim the same component the one
 * whose socket name sorts first wins. */

#define PROVIDER_LIST_TIMEOUT_USEC (15 * USEC_PER_SEC)
#define PROVIDER_DESCRIBE_TIMEOUT_USEC (60 * USEC_PER_SEC)

typedef struct ProviderReply {
        char *provider;              /* Socket name of the provider */
        sd_json_variant *parameters; /* Reply parameters, NULL on error */
        char *error_id;              /* NULL on success */
        bool local;                  /* Error was synthesized locally (timeout, disconnect, …), i.e. the provider didn't actually answer */
} ProviderReply;

typedef struct ProviderCollector {
        ProviderReply *replies;
        size_t n_replies;
        int error;                   /* First error hit while collecting, if any */
} ProviderCollector;

static void provider_reply_done(ProviderReply *reply) {
        assert(reply);

        free(reply->provider);
        sd_json_variant_unref(reply->parameters);
        free(reply->error_id);
}

static void provider_collector_done(ProviderCollector *c) {
        assert(c);

        FOREACH_ARRAY(reply, c->replies, c->n_replies)
                provider_reply_done(reply);

        free(c->replies);
}

static int provider_reply_compare(const ProviderReply *a, const ProviderReply *b) {
        return strcmp(ASSERT_PTR(a)->provider, ASSERT_PTR(b)->provider);
}

static int provider_on_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        ProviderCollector *c = ASSERT_PTR(userdata);
        bool local = FLAGS_SET(flags, SD_VARLINK_REPLY_LOCAL);
        int r;

        assert(link);

        if (c->error < 0) /* Already failed, don't bother */
                return 0;

        _cleanup_free_ char *provider = NULL;
        r = path_extract_filename(ASSERT_PTR(sd_varlink_get_description(link)), &provider);
        if (r < 0) {
                c->error = log_error_errno(r, "Failed to extract provider name from socket path: %m");
                return 0;
        }

        _cleanup_free_ char *e = NULL;
        if (error_id) {
                e = strdup(error_id);
                if (!e) {
                        c->error = log_oom();
                        return 0;
                }
        }

        if (!GREEDY_REALLOC(c->replies, c->n_replies + 1)) {
                c->error = log_oom();
                return 0;
        }

        c->replies[c->n_replies++] = (ProviderReply) {
                .provider = TAKE_PTR(provider),
                .parameters = error_id ? NULL : sd_json_variant_ref(parameters),
                .error_id = TAKE_PTR(e),
                .local = local,
        };

        return 0;
}

static int provider_query(
                const char *method,
                sd_json_variant *parameters,
                usec_t timeout_usec,
                ProviderCollector *c) {

        assert(method);
        assert(c);

        /* Invokes the specified method on all providers, and collects the replies in the collector, sorted
         * by provider name. Returns the number of providers contacted, or -ENOENT if there are none. */

        ssize_t n = varlink_execute_directory(
                        VARLINK_DIR_SYSUPDATE_PROVIDER,
                        method,
                        parameters,
                        /* more= */ false,
                        timeout_usec,
                        provider_on_reply,
                        c);
        if (n == -ENOENT) {
                log_debug("No component provider directory " VARLINK_DIR_SYSUPDATE_PROVIDER ", skipping.");
                return -ENOENT;
        }
        if (n < 0)
                return log_error_errno(n, "Failed to query component providers in " VARLINK_DIR_SYSUPDATE_PROVIDER ": %m");
        if (c->error < 0)
                return c->error;
        if (n == 0) {
                log_debug("No component providers found in " VARLINK_DIR_SYSUPDATE_PROVIDER ".");
                return -ENOENT;
        }

        typesafe_qsort(c->replies, c->n_replies, provider_reply_compare);

        log_debug("Queried %zi component providers via %s(), got %zu replies.", n, method, c->n_replies);
        return (int) n;
}

ProviderComponent* provider_component_free(ProviderComponent *pc) {
        if (!pc)
                return NULL;

        free(pc->name);
        free(pc->provider);
        sd_json_variant_unref(pc->target);
        return mfree(pc);
}

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                provider_component_hash_ops,
                char, string_hash_func, string_compare_func,
                ProviderComponent, provider_component_free);

static int provider_target_get_id(sd_json_variant *target, const char **ret_class, const char **ret_name) {
        int r;

        assert(target);
        assert(ret_class);
        assert(ret_name);

        /* Extracts the identifier of a Target object as returned by a provider. The remaining fields carry
         * the component's metadata, and are ignored here. */

        struct {
                sd_json_variant *id;
        } t = {};

        static const sd_json_dispatch_field target_table[] = {
                { "id", SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, voffsetof(t, id), SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(target, target_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &t);
        if (r < 0)
                return r;

        struct {
                const char *class, *name;
        } id = {};

        static const sd_json_dispatch_field id_table[] = {
                { "class", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(id, class), SD_JSON_MANDATORY },
                { "name",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(id, name),  0 },
                {},
        };

        r = sd_json_dispatch(t.id, id_table, SD_JSON_LOG, &id);
        if (r < 0)
                return r;

        *ret_class = id.class;
        *ret_name = id.name;
        return 0;
}

int provider_list_components(Hashmap **ret) {
        _cleanup_(provider_collector_done) ProviderCollector c = {};
        int r;

        assert(ret);

        /* Queries all providers for the components they offer, and returns them in a hashmap keyed by
         * component name. Providers that fail are logged about and ignored. Returns 0 if there are no
         * providers at all, > 0 otherwise. */

        r = provider_query("io.systemd.SysUpdate.Provider.ListTargets", /* parameters= */ NULL, PROVIDER_LIST_TIMEOUT_USEC, &c);
        if (r == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        _cleanup_hashmap_free_ Hashmap *components = NULL;
        FOREACH_ARRAY(reply, c.replies, c.n_replies) {
                if (reply->error_id) {
                        log_warning("Component provider '%s' failed to list its components, ignoring: %s", reply->provider, reply->error_id);
                        continue;
                }

                struct {
                        sd_json_variant *targets;
                } p = {};

                static const sd_json_dispatch_field dispatch_table[] = {
                { "targets", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_variant_noref, voffsetof(p, targets), SD_JSON_MANDATORY },
                        {},
                };

                r = sd_json_dispatch(reply->parameters, dispatch_table, SD_JSON_LOG, &p);
                if (r < 0) {
                        log_warning_errno(r, "Component provider '%s' returned an invalid list of targets, ignoring: %m", reply->provider);
                        continue;
                }

                sd_json_variant *e;
                JSON_VARIANT_ARRAY_FOREACH(e, p.targets) {
                        const char *class, *name;

                        r = provider_target_get_id(e, &class, &name);
                        if (r < 0) {
                                log_warning_errno(r, "Component provider '%s' returned an invalid target, ignoring: %m", reply->provider);
                                continue;
                        }

                        if (!streq(class, "component")) {
                                log_debug("Component provider '%s' returned a target of class '%s', ignoring.", reply->provider, class);
                                continue;
                        }

                        if (!name || !component_name_valid(name)) {
                                log_warning("Component provider '%s' returned a component with an invalid name, ignoring: %s", reply->provider, strna(name));
                                continue;
                        }

                        ProviderComponent *existing = hashmap_get(components, name);
                        if (existing) {
                                log_notice("Component '%s' is provided by both '%s' and '%s', using the definition of the former.",
                                           name, existing->provider, reply->provider);
                                continue;
                        }

                        _cleanup_(provider_component_freep) ProviderComponent *pc = new(ProviderComponent, 1);
                        if (!pc)
                                return log_oom();

                        *pc = (ProviderComponent) {
                                .target = sd_json_variant_ref(e),
                        };

                        pc->name = strdup(name);
                        if (!pc->name)
                                return log_oom();

                        pc->provider = strdup(reply->provider);
                        if (!pc->provider)
                                return log_oom();

                        r = hashmap_ensure_put(&components, &provider_component_hash_ops, pc->name, pc);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add component '%s' to map: %m", name);
                        TAKE_PTR(pc);

                        log_debug("Component '%s' is provided by '%s'.", name, reply->provider);
                }
        }

        *ret = TAKE_PTR(components);
        return 1;
}

int provider_describe_component(
                const char *name,
                char **ret_provider,
                sd_json_variant **ret_target,
                sd_json_variant **ret_features,
                sd_json_variant **ret_transfers) {

        _cleanup_(provider_collector_done) ProviderCollector c = {};
        int r;

        assert(name);
        assert(ret_provider);
        assert(ret_target);
        assert(ret_features);
        assert(ret_transfers);

        /* Asks all providers for the definition of the specified component. The definition of the provider
         * whose socket name sorts first wins.
         *
         * Returns -ENOENT if no provider offers the component. Returns -EHOSTUNREACH if we cannot be sure
         * about that, because a provider that might have offered it failed to answer properly. The
         * distinction matters for callers that treat a missing component as reason to clean up after it.
         * Components are requested from providers as targets of class 'component'. */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        r = sd_json_buildo(&parameters,
                           SD_JSON_BUILD_PAIR_OBJECT("id",
                                           SD_JSON_BUILD_PAIR_STRING("class", "component"),
                                           SD_JSON_BUILD_PAIR_STRING("name", name)));
        if (r < 0)
                return log_oom();

        r = provider_query("io.systemd.SysUpdate.Provider.DescribeTarget", parameters, PROVIDER_DESCRIBE_TIMEOUT_USEC, &c);
        if (r < 0)
                return r; /* Includes -ENOENT if there are no providers */

        size_t n_contacted = r;
        bool incomplete = false;
        ProviderReply *found = NULL;

        struct {
                sd_json_variant *target, *features, *transfers;
        } d = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "target",    SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, voffsetof(d, target),    SD_JSON_MANDATORY },
                { "features",  SD_JSON_VARIANT_ARRAY,  sd_json_dispatch_variant_noref, voffsetof(d, features),  SD_JSON_MANDATORY },
                { "transfers", SD_JSON_VARIANT_ARRAY,  sd_json_dispatch_variant_noref, voffsetof(d, transfers), SD_JSON_MANDATORY },
                {},
        };

        /* If fewer replies came in than providers were contacted, we lack information */
        if (c.n_replies < n_contacted) {
                log_warning("Got only %zu replies from %zu component providers, provider set incomplete.", c.n_replies, n_contacted);
                incomplete = true;
        }

        FOREACH_ARRAY(reply, c.replies, c.n_replies) {
                if (reply->error_id) {
                        if (streq(reply->error_id, "io.systemd.SysUpdate.Provider.NoSuchTarget")) {
                                log_debug("Component provider '%s' does not provide component '%s'.", reply->provider, name);
                                continue;
                        }

                        log_warning("Component provider '%s' failed to describe component '%s'%s: %s",
                                    reply->provider, name,
                                    reply->local ? "" : ", ignoring",
                                    reply->error_id);

                        /* A failing provider that sorts before the one we found might have claimed the
                         * component too, and would have won. Hence we cannot be sure about the result. */
                        if (!found)
                                incomplete = true;
                        continue;
                }

                if (found) {
                        log_notice("Component '%s' is provided by both '%s' and '%s', using the definition of the former.",
                                   name, found->provider, reply->provider);
                        continue;
                }

                typeof(d) p = {};

                r = sd_json_dispatch(reply->parameters, dispatch_table, SD_JSON_LOG, &p);
                if (r >= 0) {
                        const char *class, *id_name;

                        /* Make sure the returned target is actually the component we asked for */
                        r = provider_target_get_id(p.target, &class, &id_name);
                        if (r >= 0 && (!streq(class, "component") || !streq_ptr(id_name, name)))
                                r = -EBADMSG;
                }
                if (r < 0) {
                        log_warning_errno(r, "Component provider '%s' returned an invalid definition of component '%s', ignoring: %m", reply->provider, name);
                        incomplete = true;
                        continue;
                }

                found = reply;
                d = p;
        }

        if (incomplete)
                return log_error_errno(SYNTHETIC_ERRNO(EHOSTUNREACH),
                                       "Unable to determine reliably whether component '%s' is provided, since not all component providers answered.", name);
        if (!found)
                return -ENOENT;

        log_debug("Component '%s' is provided by '%s'.", name, found->provider);

        _cleanup_free_ char *p = strdup(found->provider);
        if (!p)
                return log_oom();

        *ret_provider = TAKE_PTR(p);
        *ret_target = sd_json_variant_ref(d.target);
        *ret_features = sd_json_variant_ref(d.features);
        *ret_transfers = sd_json_variant_ref(d.transfers);
        return 0;
}
