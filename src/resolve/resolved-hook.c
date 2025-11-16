/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-varlink.h"

#include "dirent-util.h"
#include "dns-domain.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hash-funcs.h"
#include "iovec-util.h"
#include "json-util.h"
#include "ratelimit.h"
#include "resolved-hook.h"
#include "resolved-manager.h"
#include "set.h"
#include "stat-util.h"
#include "varlink-util.h"

/* Controls how many idle connections to keep around at max. This is purely an optimization: an established
 * socket that has gone through connect()/accept() already is just quicker to use. Since we might get a flood
 * of resolution requests we keep multiple connections open thus, but not too many. */
#define HOOK_IDLE_CONNECTIONS_MAX 4U

/* Encapsulates a specific hook, i.e. bound socket in in the /run/systemd/resolve.hook/ directory */
typedef struct Hook {
        unsigned n_ref;

        Manager *manager;
        char *socket_path;

        sd_varlink *filter_link;
        Set *idle_links; /* we retry to recycle varlink connections */

        /* This hook only shall be applied to names matching the following filter parameters */
        Set *filter_domains;          /* if NULL → no filtering; if empty → do not accept anything */
        unsigned filter_labels_min;   /* minimum number of labels */
        unsigned filter_labels_max;   /* maximum number of labels (this is useful to hook only into single-label lookups á la LLMNR) */

        /* timestamp we last saw this in CLOCK_MONOTONIC, for GC handling */
        uint64_t seen_usec;

        /* When a hook never responds correctly, we'll eventually give up trying */
        RateLimit reconnect_ratelimit;
} Hook;

static Hook* hook_free(Hook *h) {
        if (!h)
                return NULL;

        mfree(h->socket_path);
        sd_varlink_unref(h->filter_link);
        set_free(h->idle_links);

        set_free(h->filter_domains);

        return mfree(h);
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(Hook, hook, hook_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hook*, hook_unref);

static Hook *hook_unlink(Hook *h) {
        if (!h)
                return NULL;

        if (!h->manager)
                return NULL;

        if (h->socket_path)
                hashmap_remove(h->manager->hooks, h->socket_path);
        h->manager = NULL;

        return hook_unref(h);
}

static int dispatch_filter_domains(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Hook *h = ASSERT_PTR(userdata);
        int r;

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        /* Let's explicitly allocate the set here, since we want that a NULL set means: let everything
         * through; but an empty set shall mean: let nothing through */
        r = set_ensure_allocated(&h->filter_domains, &dns_name_hash_ops_free);
        if (r < 0)
                return json_log_oom(variant, flags);

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                if (!sd_json_variant_is_string(i))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Element of JSON field '%s' is not a string.", strna(name));

                r = set_put_strdup_full(&h->filter_domains, &dns_name_hash_ops_free, sd_json_variant_string(i));
                if (r < 0 && r != -EEXIST)
                        return json_log_oom(variant, flags);
        }

        return 0;
}

static void hook_reset_filter(Hook *h) {
        assert(h);

        h->filter_domains = set_free(h->filter_domains);
        h->filter_labels_min = UINT_MAX;
        h->filter_labels_max = UINT_MAX;
}

static int hook_acquire_filter(Hook *h);

static int on_filter_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        Hook *h = ASSERT_PTR(userdata);
        int r;

        if (error_id) {
                if (streq(error_id, SD_VARLINK_ERROR_DISCONNECTED)) {
                        /* When we are are disconnected, that's fine, maybe the other side wants to clean up
                         * open connections every now and then, or is being restarted and thus a moment
                         * offline. Try to reconnect immediately to recover. However, a service that
                         * continuously fails should not be able to get us into a busy loop, hence we apply a
                         * ratelimit, and when it is hit we stop reconnecting. */
                        if (ratelimit_below(&h->reconnect_ratelimit)) {
                                log_debug("Connection terminated while querying filter of hook '%s', trying to reconnect.", h->socket_path);

                                h->filter_link = sd_varlink_unref(h->filter_link);

                                r = hook_acquire_filter(h);
                                if (r < 0)
                                        goto terminate;
                        } else
                                log_warning("Connection terminated while querying filter of hook '%s', and reconnection attempts failed too quickly, giving up.", h->socket_path);

                        goto terminate;
                }

                if (streq(error_id, SD_VARLINK_ERROR_METHOD_NOT_FOUND)) {
                        log_debug("Hook '%s' does not implement querying filter.", h->socket_path);
                        goto terminate;
                }

                log_warning("Received error while requesting query filter: %s", error_id);
                goto terminate;
        }

        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES)) {
                log_debug("Final message received while querying filter, terminating connection.");
                goto terminate;
        }

        hook_reset_filter(h);

        static const struct sd_json_dispatch_field dispatch_table[] = {
                { "filterDomains",   SD_JSON_VARIANT_ARRAY,   dispatch_filter_domains, 0,                                 SD_JSON_NULLABLE },
                { "filterLabelsMin", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint,   offsetof(Hook, filter_labels_min), 0                },
                { "filterLabelsMax", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint,   offsetof(Hook, filter_labels_max), 0                },
                {},
        };

        r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, h);
        if (r < 0)
                goto terminate;

        return 1;

terminate:
        h->filter_link = sd_varlink_unref(h->filter_link);
        hook_reset_filter(h);
        return 1;
}

static int hook_varlink_connect(Hook *h, int64_t priority, sd_varlink **ret) {
        int r;

        assert(h);
        assert(ret);

        _cleanup_(sd_varlink_unrefp) sd_varlink *v = NULL;
        r = sd_varlink_connect_address(&v, h->socket_path);
        if (ERRNO_IS_NEG_DISCONNECT(r) || r == -ENOENT) {
                log_debug_errno(r, "Socket '%s' is not connectible, probably stale, ignoring: %m", h->socket_path);
                *ret = NULL;
                return 0; /* dead socket */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to connect to '%s': %m", h->socket_path);

        _cleanup_free_ char *bn = NULL;
        r = path_extract_filename(h->socket_path, &bn);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", h->socket_path);

        _cleanup_free_ char *j = strjoin("hook-", bn);
        if (!j)
                return log_oom();

        (void) sd_varlink_set_description(v, j);

        r = sd_varlink_attach_event(v, h->manager->event, priority);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink connection to event loop: %m");

        *ret = TAKE_PTR(v);
        return 1; /* worked */
}

static int hook_acquire_filter(Hook *h) {
        int r;

        assert(h);
        assert(h->manager);

        if (h->filter_link)
                return 0;

        _cleanup_(sd_varlink_unrefp) sd_varlink *v = NULL;
        r = hook_varlink_connect(h, SD_EVENT_PRIORITY_NORMAL-10, &v); /* Give the querying of the filter a bit of priority */
        if (r <= 0)
                return r;

        /* Turn off timeout, after all we want to continuously monitor filter changes */
        r = sd_varlink_set_relative_timeout(v, UINT64_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to disable timeout on Varlink connection %m");

        sd_varlink_set_userdata(v, h);
        r = sd_varlink_bind_reply(v, on_filter_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to set filter reply callback on Varlink connection: %m");

        r = sd_varlink_observe(
                        v,
                        "io.systemd.Resolve.Hook.QueryFilter",
                        /* parameters= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue QueryFilter() varlink call: %m");

        h->filter_link = TAKE_PTR(v);
        return 0;
}

static int hook_test_filter(Hook *h, DnsQuestion *question) {
        int r;

        assert(h);
        assert(question);

        const char *name = dns_question_first_name(question);
        if (!name)
                return -EINVAL;

        if (h->filter_labels_max != UINT_MAX || h->filter_labels_min != UINT_MAX) {
                int n = dns_name_count_labels(name);
                if (n < 0)
                        return n;

                if (h->filter_labels_max != UINT_MAX && (unsigned) n > h->filter_labels_max)
                        return false;
                if (h->filter_labels_min != UINT_MAX && (unsigned) n < h->filter_labels_min)
                        return false;
        }

        if (h->filter_domains)
                for (const char *p = name;;) {
                        if (set_contains(h->filter_domains, p))
                                break;

                        r = dns_name_parent(&p);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return false;
                }

        return true;
}

static int hook_compare(const Hook *a, const Hook *b) {
        assert(a);

        /* Hooks take preference based on the name of their socket */
        return path_compare(a->socket_path, b->socket_path);
}

static void hook_recycle_varlink(Hook *h, sd_varlink *vl) {
        int r;

        assert(h);
        assert(vl);

        /* Disable any potential callbacks while we are recycling the thing */
        sd_varlink_set_userdata(vl, NULL);
        (void) sd_varlink_bind_reply(vl, NULL);

        if (set_size(h->idle_links) > HOOK_IDLE_CONNECTIONS_MAX)
                return;

        /* If we are done with a lookup don't close the connection right-away, but keep it open so that we
         * can possibly reuse it later, and can save a bit of time on future lookups. We only keep a few
         * around however. */

        r = set_ensure_put(&h->idle_links, &varlink_hash_ops, vl);
        if (r < 0)
                log_debug_errno(r, "Failed to add varlink connection to idle set, ignoring: %m");
        else
                sd_varlink_ref(vl);
}

static void manager_gc_hooks(Manager *m, usec_t seen_usec) {
        assert(m);

        Hook *h;
        HASHMAP_FOREACH(h, m->hooks) {
                /* Keep hooks around that have been seen in this iteration */
                if (h->seen_usec == seen_usec)
                        continue;

                hook_unlink(h);
        }
}

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                hook_hash_ops,
                char, string_hash_func, string_compare_func,
                Hook, hook_unlink);

static int manager_hook_add(Manager *m, const char *p, usec_t seen_usec) {
        int r;

        assert(m);
        assert(p);

        Hook *found = hashmap_get(m->hooks, p);
        if (found) {
                found->seen_usec = seen_usec;
                return 0;
        }

        _cleanup_free_ char *s = strdup(p);
        if (!s)
                return log_oom();

        _cleanup_(hook_unrefp) Hook *h = new(Hook, 1);
        if (!h)
                return log_oom();

        *h = (Hook) {
                .n_ref = 1,
                .socket_path = TAKE_PTR(s),
                .filter_labels_min = UINT_MAX,
                .filter_labels_max = UINT_MAX,
                .reconnect_ratelimit = { 1 * USEC_PER_SEC, 5 },
                .seen_usec = seen_usec,
        };

        if (hashmap_ensure_put(&m->hooks, &hook_hash_ops, h->socket_path, h) < 0)
                return log_oom();

        hook_ref(h);
        h->manager = m;

        r = hook_acquire_filter(h);
        if (r < 0) {
                hook_unlink(h);
                return r;
        }

        return 0;
}

static int manager_hook_discover(Manager *m) {
        /* You might wonder, why is this /run/systemd/resolve.hook/ and not /run/systemd/resolve/hook/?
         * That's because of permissions: resolved runs as "systemd-resolve" user and owns
         * /run/systemd/resolve/, but the hook directory is where other privileged code shall bind a socket
         * in (and where root ownership hence makes sense). Hence we do not nest the directories, but put
         * them side by side, so that they can have different ownership. */
        static const char dp[] = "/run/systemd/resolve.hook";
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(m);

        usec_t seen_usec = now(CLOCK_MONOTONIC);

        struct stat st;
        if (stat(dp, &st) < 0) {
                if (errno == ENOENT)
                        r = 0;
                else
                        r = log_warning_errno(errno, "Failed to stat %s/: %m", dp);

                goto finish;
        }

        if (stat_inode_unmodified(&st, &m->hook_stat))
                return 0;

        d = opendir(dp);
        if (!d) {
                if (errno == ENOENT)
                        r = 0;
                else
                        r = log_warning_errno(errno, "Failed to enumerate %s/ contents: %m", dp);

                goto finish;
        }

        for (;;) {
                errno = 0;
                struct dirent *de = readdir_no_dot(d);
                if (!de) {
                        if (errno == 0) /* EOD */
                                break;

                        r = log_error_errno(errno, "Failed to enumerate %s/: %m", dp);
                        goto finish;
                }

                if (!IN_SET(de->d_type, DT_SOCK, DT_UNKNOWN))
                        continue;

                _cleanup_free_ char *p = path_join(dp, de->d_name);
                if (!p) {
                        r = log_oom();
                        goto finish;
                }

                (void) manager_hook_add(m, p, seen_usec);
        }

        m->hook_stat = st;
        r = 0;

finish:
        manager_gc_hooks(m, seen_usec);
        return r;
}

typedef struct HookQuery HookQuery;
typedef struct HookQueryCandidate HookQueryCandidate;

/* Encapsulates a query currently being processed by various hooks */
struct HookQuery {
        /* Question */
        DnsQuestion *question_idna;
        DnsQuestion *question_utf8;

        /* Selected answer */
        DnsAnswer *answer;
        int answer_rcode;
        Hook *answer_hook;

        /* Candidates for a reply, i.e, one entry for each hook */
        LIST_HEAD(HookQueryCandidate, candidates);

        /* Completion callback to invoke */
        void (*complete)(HookQuery *q, int answer_rcode, DnsAnswer *answer, void *userdata);
        void *userdata;
};

/* Encapsulates the state of a hook query to one specific hook */
struct HookQueryCandidate {
        HookQuery *query;
        Hook *hook;
        sd_varlink *link;
        LIST_FIELDS(HookQueryCandidate, candidates);
};

static HookQueryCandidate* hook_query_candidate_free(HookQueryCandidate *c) {
        if (!c)
                return NULL;

        c->link = sd_varlink_unref(c->link);

        if (c->query)
                LIST_REMOVE(candidates, c->query->candidates, c);

        hook_unref(c->hook);
        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(HookQueryCandidate*, hook_query_candidate_free);

HookQuery* hook_query_free(HookQuery *hq) {
        if (!hq)
                return NULL;

        /* Free candidates as long as there are candidates */
        while (hq->candidates)
                hook_query_candidate_free(hq->candidates);

        dns_question_unref(hq->question_utf8);
        dns_question_unref(hq->question_idna);
        dns_answer_unref(hq->answer);
        hook_unref(hq->answer_hook);

        return mfree(hq);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(HookQuery*, hook_query_free);

static void hook_query_ready(HookQuery *hq) {
        assert(hq);

        bool done = true;
        LIST_FOREACH(candidates, c, hq->candidates)
                if (c->link) { /* ongoing connection? */
                        done = false;
                        break;
                }

        if (!done)
                return;

        /* The complete() callback quite likely will destroy 'hq', which might be what keeps the answer
         * object alive. Let's take an explicit ref here hence, so that it definitely remains alive for the
         * whole callback lifetime */
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = dns_answer_ref(hq->answer);
        hq->complete(hq, hq->answer_rcode, answer, hq->userdata);
}

static int dispatch_rcode(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int *u = ASSERT_PTR(userdata), r;

        assert(variant);

        int rcode;
        r = sd_json_dispatch_int(name, variant, flags, &rcode);
        if (r < 0)
                return r;

        if (rcode < 0 || rcode >= _DNS_RCODE_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' contains an invalid DNS rcode.", strna(name));

        *u = rcode;
        return 0;
}

static int dispatch_answer(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        DnsAnswer **a = ASSERT_PTR(userdata);
        int r;

        assert(variant);

        if (sd_json_variant_is_null(variant)) {
                *a = dns_answer_unref(*a);
                return 0;
        }

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        _cleanup_(dns_answer_unrefp) DnsAnswer *l = NULL;
        sd_json_variant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                if (!sd_json_variant_is_object(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not an object");

                _cleanup_(iovec_done) struct iovec iovec = {};
                static const sd_json_dispatch_field dispatch_table[] = {
                        { "raw", SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec, 0, SD_JSON_MANDATORY },
                        { "rr",  SD_JSON_VARIANT_OBJECT, NULL,                         0, 0                 },
                        {}
                };

                r = sd_json_dispatch(e, dispatch_table, flags|SD_JSON_ALLOW_EXTENSIONS, &iovec);
                if (r < 0)
                        return r;

                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                r = dns_resource_record_new_from_raw(&rr, iovec.iov_base, iovec.iov_len);
                if (r < 0)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "JSON field '%s' contains an invalid resource record.", strna(name));

                if (dns_answer_add_extend(&l, rr, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL) < 0)
                        return json_log_oom(e, flags);
        }

        dns_answer_unref(*a);
        *a = TAKE_PTR(l);

        return 0;
}

typedef struct QueryReplyParameters {
        int rcode;
        DnsAnswer *answer;
} QueryReplyParameters;

static void query_reply_parameters_done(QueryReplyParameters *p) {
        assert(p);

        p->answer = dns_answer_unref(p->answer);
}

static int on_query_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        HookQueryCandidate *qc = ASSERT_PTR(userdata);
        HookQuery *q = ASSERT_PTR(qc->query); /* save early in case we destroy 'qc' half-way through this function */
        int r;

        assert(link);

        _cleanup_(query_reply_parameters_done) QueryReplyParameters p = {
                .rcode = -1,
        };

        if (error_id) {
                log_notice("Query on hook '%s' failed with error '%s', ignoring.", qc->hook->socket_path, error_id);
                r = -EBADR;
                goto destroy;
        }

        static const sd_json_dispatch_field dispatch_table[] = {
                { "rcode",  _SD_JSON_VARIANT_TYPE_INVALID, dispatch_rcode,  offsetof(QueryReplyParameters, rcode),  0 },
                { "answer", SD_JSON_VARIANT_ARRAY,         dispatch_answer, offsetof(QueryReplyParameters, answer), 0 },
                {},
        };

        r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                goto destroy;

        if (p.rcode < 0) {
                /* If no rcode is specified, then this means "continue with regular DNS based resolving" to us */
                log_debug("Query on hook '%s' returned empty reply, skipping.", qc->hook->socket_path);
                r = 0;
                goto destroy;
        }

        bool win = false;
        if (p.rcode == DNS_RCODE_SUCCESS)
                /* if this is a successful lookup, let it win if the so far best lookup was a failure or
                 * empty, or ordered later than us */
                win = q->answer_rcode != DNS_RCODE_SUCCESS ||
                        dns_answer_isempty(q->answer) ||
                        (!dns_answer_isempty(p.answer) &&
                         hook_compare(qc->hook, q->answer_hook) < 0);
        else
                /* if this is a failure lookup, let it win if we so far haven't seen any reply at all, or the
                 * winner so far us ordered later than us. */
                win = q->answer_rcode < 0 ||
                        hook_compare(qc->hook, q->answer_hook) < 0;

        if (win) {
                /* This reply wins over whatever was stored before. Let's track that */
                dns_answer_unref(q->answer);
                q->answer = TAKE_PTR(p.answer);
                q->answer_rcode = p.rcode;
                hook_unref(q->answer_hook);
                q->answer_hook = hook_ref(qc->hook);
        }

        hook_recycle_varlink(qc->hook, qc->link);
        qc->link = sd_varlink_unref(qc->link);

        /* Check if we are ready now, and have processed all hooks on this query (this might destroy our
         * candidate and our hook query!) */
        hook_query_ready(q);
        return 0;

destroy:
        qc = hook_query_candidate_free(qc);
        hook_query_ready(q);
        return r;
}

static int dns_questions_to_json(DnsQuestion *a, DnsQuestion *b, sd_json_variant **ret) {
        int r;

        assert(ret);

        /* Takes both questions and turns them into a JSON array of objects with the key. Note this takes two
         * questions, one in IDNA and one in UTF-8 encoding, and merges them, removing duplicates. */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL;

        DnsResourceKey *key;
        DNS_QUESTION_FOREACH(key, a) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                r = dns_resource_key_to_json(key, &v);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_arraybo(&l, SD_JSON_BUILD_PAIR_VARIANT("key", v));
                if (r < 0)
                        return r;
        }

        if (a != b) {
                DNS_QUESTION_FOREACH(key, b) {
                        if (dns_question_contains_key(a, key))
                                continue;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                        r = dns_resource_key_to_json(key, &v);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_append_arraybo(&l, SD_JSON_BUILD_PAIR_VARIANT("key", v));
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(l);
        return 0;
}

static int hook_query_add_candidate(HookQuery *hq, Hook *h) {
        int r;

        assert(hq);
        assert(h);

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        for (;;) {
                /* Before we create a new connection, let's see if there are still idle connections we can
                 * use. */
                vl = set_steal_first(h->idle_links);
                if (!vl) {
                        /* Nope, there's nothing, let's create a new connection */
                        r = hook_varlink_connect(h, SD_EVENT_PRIORITY_NORMAL, &vl);
                        if (r <= 0)
                                return r;

                        break;
                }

                r = sd_varlink_is_connected(vl);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if varlink connection is connected: %m");
                if (r > 0)
                        break;

                vl = sd_varlink_unref(vl);
        }

        /* Set a short timeout for hooks. Hooks should not be able to cause the DNS part of the lookup to fail. */
        r = sd_varlink_set_relative_timeout(vl, SD_RESOLVED_QUERY_TIMEOUT_USEC/4);
        if (r < 0)
                return log_error_errno(r, "Failed to set Varlink connection timeout: %m");

        r = sd_varlink_bind_reply(vl, on_query_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind reply callback to Varlink connection: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jq = NULL;
        r = dns_questions_to_json(hq->question_idna, hq->question_utf8, &jq);
        if (r < 0)
                return log_error_errno(r, "Failed to convert question to JSON: %m");

        r = sd_varlink_invokebo(
                        vl,
                        "io.systemd.Resolve.Hook.ResolveRecord",
                        SD_JSON_BUILD_PAIR_VARIANT("question", jq));
        if (r < 0)
                return log_error_errno(r, "Failed to enqueue question onto Varlink connection: %m");

        _cleanup_(hook_query_candidate_freep) HookQueryCandidate *qc = new(HookQueryCandidate, 1);
        if (!qc)
                return log_oom();

        qc->query = hq;
        qc->hook = hook_ref(h);
        qc->link = TAKE_PTR(vl);
        LIST_PREPEND(candidates, hq->candidates, qc);

        sd_varlink_set_userdata(qc->link, qc);

        TAKE_PTR(qc);

        return 0;
}

static bool use_hooks(void) {
        static int cache = -1;
        int r;

        if (cache >= 0)
                return cache;

        r = secure_getenv_bool("SYSTEMD_RESOLVED_HOOK");
        if (r < 0) {
                if (r != -ENXIO)
                        log_debug_errno(r, "Failed to parse $SYSTEMD_RESOLVED_HOOK, ignoring: %m");

                return (cache = true);
        }

        return (cache = r);
}

int manager_hook_query(
                Manager *m,
                DnsQuestion *question_idna,
                DnsQuestion *question_utf8,
                HookCompleteCallback complete_cb,
                void *userdata,
                HookQuery **ret) {

        int r;

        assert(m);
        assert(ret);

        if (!use_hooks()) {
                *ret = NULL;
                return 0; /* no relevant hooks, continue immediately */
        }

        /* Let's bring our list of hooks up-to-date */
        (void) manager_hook_discover(m);

        _cleanup_(hook_query_freep) HookQuery *hq = NULL;

        Hook *h;
        HASHMAP_FOREACH(h, m->hooks) {
                r = hook_test_filter(h, question_idna);
                if (r < 0) {
                        log_warning_errno(
                                        r, "Failed to test if hook '%s' matches IDNA  question (%s), assuming not.",
                                        h->socket_path, dns_question_first_name(question_idna));
                        continue;
                }
                if (r == 0) {
                        r = hook_test_filter(h, question_utf8);
                        if (r < 0) {
                                log_warning_errno(
                                                r, "Failed to test if hook '%s' matches UTF-8 question (%s), assuming not.",
                                                h->socket_path, dns_question_first_name(question_utf8));
                                continue;
                        }
                        if (r == 0) {
                                log_debug("Hook %s does not match question, skipping.", h->socket_path);
                                continue;
                        }
                }

                if (!hq) {
                        hq = new(HookQuery, 1);
                        if (!hq)
                                return log_oom();

                        *hq = (HookQuery) {
                                .question_idna = dns_question_ref(question_idna),
                                .question_utf8 = dns_question_ref(question_utf8),
                                .answer_rcode = -1,
                                .complete = complete_cb,
                                .userdata = userdata,
                        };
                }

                r = hook_query_add_candidate(hq, h);
                if (r < 0)
                        return r;
        }

        if (!hq || !hq->candidates) {
                *ret = NULL;
                return 0; /* no relevant hooks, continue immediately */
        }

        *ret = TAKE_PTR(hq);
        return 1; /* please wait for the hooks to reply */
}
