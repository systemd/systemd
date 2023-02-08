/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "strv.h"
#include "user-util.h"

static int check_good_user(sd_bus_message *m, uid_t good_user) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        uid_t sender_uid;
        int r;

        assert(m);

        if (good_user == UID_INVALID)
                return 0;

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        /* Don't trust augmented credentials for authorization */
        assert_return((sd_bus_creds_get_augmented_mask(creds) & SD_BUS_CREDS_EUID) == 0, -EPERM);

        r = sd_bus_creds_get_euid(creds, &sender_uid);
        if (r < 0)
                return r;

        return sender_uid == good_user;
}

#if ENABLE_POLKIT
static int bus_message_append_strv_key_value(
                sd_bus_message *m,
                const char **l) {

        int r;

        assert(m);

        r = sd_bus_message_open_container(m, 'a', "{ss}");
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(k, v, l) {
                r = sd_bus_message_append(m, "{ss}", *k, *v);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        return r;
}
#endif

int bus_test_polkit(
                sd_bus_message *call,
                int capability,
                const char *action,
                const char **details,
                uid_t good_user,
                bool *_challenge,
                sd_bus_error *ret_error) {

        int r;

        assert(call);
        assert(action);

        /* Tests non-interactively! */

        r = check_good_user(call, good_user);
        if (r != 0)
                return r;

        r = sd_bus_query_sender_privilege(call, capability);
        if (r < 0)
                return r;
        else if (r > 0)
                return 1;
#if ENABLE_POLKIT
        else {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                int authorized = false, challenge = false;
                const char *sender;

                sender = sd_bus_message_get_sender(call);
                if (!sender)
                        return -EBADMSG;

                r = sd_bus_message_new_method_call(
                                call->bus,
                                &request,
                                "org.freedesktop.PolicyKit1",
                                "/org/freedesktop/PolicyKit1/Authority",
                                "org.freedesktop.PolicyKit1.Authority",
                                "CheckAuthorization");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(
                                request,
                                "(sa{sv})s",
                                "system-bus-name", 1, "name", "s", sender,
                                action);
                if (r < 0)
                        return r;

                r = bus_message_append_strv_key_value(request, details);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(request, "us", 0, NULL);
                if (r < 0)
                        return r;

                r = sd_bus_call(call->bus, request, 0, ret_error, &reply);
                if (r < 0) {
                        /* Treat no PK available as access denied */
                        if (bus_error_is_unknown_service(ret_error)) {
                                sd_bus_error_free(ret_error);
                                return -EACCES;
                        }

                        return r;
                }

                r = sd_bus_message_enter_container(reply, 'r', "bba{ss}");
                if (r < 0)
                        return r;

                r = sd_bus_message_read(reply, "bb", &authorized, &challenge);
                if (r < 0)
                        return r;

                if (authorized)
                        return 1;

                if (_challenge) {
                        *_challenge = challenge;
                        return 0;
                }
        }
#endif

        return -EACCES;
}

#if ENABLE_POLKIT

struct AsyncPolkitQueries;

typedef struct AsyncPolkitQuery {
        char *action;
        char **details;

        sd_bus_message *request, *reply;
        sd_bus_slot *slot;

        sd_event_source *defer_event_source;

        struct AsyncPolkitQueries *parent;
        LIST_FIELDS(struct AsyncPolkitQuery, item);
} AsyncPolkitQuery;

static AsyncPolkitQuery *async_polkit_query_free(AsyncPolkitQuery *q);

typedef struct AsyncPolkitQueries {
        unsigned n_ref;

        Hashmap *registry;
        sd_bus_message *request;

        LIST_HEAD(AsyncPolkitQuery, items);
} AsyncPolkitQueries;

static int async_polkit_queries_new(sd_bus_message *request, AsyncPolkitQueries **ret) {
        AsyncPolkitQueries *qs;

        assert(request);
        assert(ret);

        qs = new(AsyncPolkitQueries, 1);
        if (!qs)
                return -ENOMEM;

        *qs = (AsyncPolkitQueries) {
                .n_ref = 1,
                .request = sd_bus_message_ref(request),
        };

        *ret = qs;
        return 0;
}

static AsyncPolkitQueries* async_polkit_queries_free(AsyncPolkitQueries *qs) {
        AsyncPolkitQuery *q;

        if (!qs)
                return NULL;

        if (qs->registry && qs->request)
                hashmap_remove(qs->registry, qs->request);

        sd_bus_message_unref(qs->request);

        while ((q = qs->items)) {
                LIST_REMOVE(item, qs->items, q);
                q->parent = NULL;
                async_polkit_query_free(q);
        }

        return mfree(qs);
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(AsyncPolkitQueries, async_polkit_queries, async_polkit_queries_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(AsyncPolkitQueries*, async_polkit_queries_unref);

static AsyncPolkitQuery *async_polkit_query_free(AsyncPolkitQuery *q) {
        if (!q)
                return NULL;

        /* Once initialized, an AsyncPolkitQuery is a part of its parent AsyncPolkitQueries object. Hence
         * calling this is only allowed during initialization and from async_polkit_queries_free(). */
        assert(!q->parent);

        sd_bus_slot_unref(q->slot);

        sd_bus_message_unref(q->request);
        sd_bus_message_unref(q->reply);

        free(q->action);
        strv_free(q->details);

        sd_event_source_disable_unref(q->defer_event_source);

        return mfree(q);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(AsyncPolkitQuery*, async_polkit_query_free);

static int async_polkit_query_new(
                AsyncPolkitQueries *parent,
                sd_bus_message *request,
                const char *action,
                const char **details,
                AsyncPolkitQuery **ret)
{
        AsyncPolkitQuery *q;

        assert(parent);
        assert(request);
        assert(action);
        assert(ret);

        q = new(AsyncPolkitQuery, 1);
        if (!q)
                return -ENOMEM;

        *q = (AsyncPolkitQuery) {
                .request = sd_bus_message_ref(request),
        };

        q->action = strdup(action);
        if (!q->action) {
                async_polkit_query_free(q);
                return -ENOMEM;
        }

        q->details = strv_copy((char**) details);
        if (!q->details) {
                async_polkit_query_free(q);
                return -ENOMEM;
        }

        LIST_PREPEND(item, parent->items, q);

        *ret = q;

        return 0;
}

static int async_polkit_defer(sd_event_source *s, void *userdata) {
        AsyncPolkitQuery *q = ASSERT_PTR(userdata);

        assert(s);

        /* This is called as idle event source after we processed the async polkit reply, hopefully after the
         * method call we re-enqueued has been properly processed. */

        async_polkit_queries_unref(ASSERT_PTR(q->parent));

        return 0;
}

static int async_polkit_callback(sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        AsyncPolkitQuery *q = ASSERT_PTR(userdata);
        int r;

        assert(reply);

        assert(q->slot);
        q->slot = sd_bus_slot_unref(q->slot);

        assert(!q->reply);
        q->reply = sd_bus_message_ref(reply);

        /* Now, let's dispatch the original message a second time be re-enqueing. This will then traverse the
         * whole message processing again, and thus re-validating and re-retrieving the "userdata" field
         * again.
         *
         * We install an idle event loop event to clean-up the PolicyKit request data when we are idle again,
         * i.e. after the last time the message is processed is complete. */

        assert(!q->defer_event_source);
        r = sd_event_add_defer(sd_bus_get_event(sd_bus_message_get_bus(reply)), &q->defer_event_source, async_polkit_defer, q);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(q->defer_event_source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_enabled(q->defer_event_source, SD_EVENT_ONESHOT);
        if (r < 0)
                goto fail;

        r = sd_bus_message_rewind(q->request, true);
        if (r < 0)
                goto fail;

        assert(q->parent);
        assert(q->parent->items); /* There must be at least one query on the list */
        LIST_FOREACH(item, i, q->parent->items)
                if (i != q)
                        sd_bus_message_rewind(i->reply, true);

        r = sd_bus_enqueue_for_read(sd_bus_message_get_bus(q->request), q->request);
        if (r < 0)
                goto fail;

        return 1;

fail:
        log_debug_errno(r, "Processing asynchronous PolicyKit reply failed, ignoring: %m");
        (void) sd_bus_reply_method_errno(q->request, r, NULL);
        async_polkit_queries_unref(q->parent);
        return r;
}

static int process_polkit_response(
                AsyncPolkitQuery *q,
                sd_bus_message *call,
                const char *action,
                const char **details,
                Hashmap **registry,
                sd_bus_error *ret_error) {
        int authorized, challenge, r;

        assert(q);
        assert(call);
        assert(action);
        assert(registry);
        assert(ret_error);

        assert(q->reply);
        assert(streq(q->action, action));

        /* If the details of operation we want to authenticate changed since the previous call(s),
         * let's not use this authentication, it might be out of date as the object and context we
         * operate on might have changed. */
        if (!strv_equal(q->details, (char**) details))
                return -ESTALE;

        if (sd_bus_message_is_method_error(q->reply, NULL)) {
                const sd_bus_error *e;

                e = sd_bus_message_get_error(q->reply);

                /* Treat no PK available as access denied */
                if (bus_error_is_unknown_service(e))
                        return -EACCES;

                /* Copy error from polkit reply */
                sd_bus_error_copy(ret_error, e);
                return -sd_bus_error_get_errno(e);
        }

        r = sd_bus_message_enter_container(q->reply, 'r', "bba{ss}");
        if (r >= 0)
                r = sd_bus_message_read(q->reply, "bb", &authorized, &challenge);
        if (r < 0)
                return r;

        if (authorized)
                return 1;

        if (challenge)
                return sd_bus_error_set(ret_error, SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED, "Interactive authentication required.");

        return -EACCES;
}

static AsyncPolkitQuery *find_query(Hashmap *registry, sd_bus_message *call, const char *action, AsyncPolkitQueries **ret_queries) {
        AsyncPolkitQueries *qs;
        AsyncPolkitQuery *q = NULL;

        assert(call);
        assert(action);
        assert(ret_queries);

        qs = hashmap_get(registry, call);
        if (!qs)
                return NULL;

        LIST_FOREACH(item, i, qs->items)
                if (streq(i->action, action)) {
                        q = i;
                        break;
                }

        *ret_queries = qs;

        return q;
}

#endif

int bus_verify_polkit_async(
                sd_bus_message *call,
                int capability,
                const char *action,
                const char **details,
                bool interactive,
                uid_t good_user,
                Hashmap **registry,
                sd_bus_error *ret_error) {

        const char *sender;
        int r;

        assert(call);
        assert(action);
        assert(registry);

        r = check_good_user(call, good_user);
        if (r != 0)
                return r;

#if ENABLE_POLKIT
        AsyncPolkitQueries *qs = NULL;
        AsyncPolkitQuery *q;

        q = find_query(*registry, call, action, &qs);
        /* This is a repeated invocation of this function, and there's already a response from
         * polkit, let's process it */
        if (q)
                return process_polkit_response(q, call, action, details, registry, ret_error);
#endif

        r = sd_bus_query_sender_privilege(call, capability);
        if (r < 0)
                return r;
        else if (r > 0)
                return 1;

        sender = sd_bus_message_get_sender(call);
        if (!sender)
                return -EBADMSG;

#if ENABLE_POLKIT
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pk = NULL;
        _cleanup_(async_polkit_queries_unrefp) AsyncPolkitQueries *qs_new = NULL;

        int c = sd_bus_message_get_allow_interactive_authorization(call);
        if (c < 0)
                return c;
        if (c > 0)
                interactive = true;

        r = hashmap_ensure_allocated(registry, NULL);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        call->bus,
                        &pk,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization");
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        pk,
                        "(sa{sv})s",
                        "system-bus-name", 1, "name", "s", sender,
                        action);
        if (r < 0)
                return r;

        r = bus_message_append_strv_key_value(pk, details);
        if (r < 0)
                return r;

        r = sd_bus_message_append(pk, "us", interactive, NULL);
        if (r < 0)
                return r;

        if (!qs) {
                r = async_polkit_queries_new(call, &qs_new);
                if (r < 0)
                        return r;

                qs = qs_new;

                r = hashmap_put(*registry, call, qs);
                if (r < 0)
                        return r;

                qs->registry = *registry;
        }

        /* Note: lifetime of the created AsyncPolkitQuery object is bound to its parent AsyncPolkitQueries. */
        r = async_polkit_query_new(qs, call, action, details, &q);
        if (r < 0)
                return r;

        r = sd_bus_call_async(call->bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0)
                return r;

        q->parent = async_polkit_queries_ref(qs);

        return 0;
#endif

        return -EACCES;
}

Hashmap *bus_verify_polkit_async_registry_free(Hashmap *registry) {
#if ENABLE_POLKIT
        return hashmap_free_with_destructor(registry, async_polkit_queries_free);
#else
        assert(hashmap_isempty(registry));
        return hashmap_free(registry);
#endif
}
