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
static int bus_message_append_strv_key_value(sd_bus_message *m, const char **l) {
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

static int bus_message_new_polkit_auth_call(
                sd_bus_message *m,
                const char *action,
                const char **details,
                bool interactive,
                sd_bus_message **ret) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *c = NULL;
        const char *sender;
        int r;

        assert(m);
        assert(action);
        assert(ret);

        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return -EBADMSG;

        r = sd_bus_message_new_method_call(
                        ASSERT_PTR(m->bus),
                        &c,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization");
        if (r < 0)
                return r;

        r = sd_bus_message_append(c, "(sa{sv})s", "system-bus-name", 1, "name", "s", sender, action);
        if (r < 0)
                return r;

        r = bus_message_append_strv_key_value(c, details);
        if (r < 0)
                return r;

        r = sd_bus_message_append(c, "us", interactive, NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
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
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int authorized = false, challenge = false;

        r = bus_message_new_polkit_auth_call(call, action, details, /* interactive = */ false, &request);
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
#endif

        return -EACCES;
}

#if ENABLE_POLKIT

struct AsyncPolkitQueries;

typedef struct AsyncPolkitQuery {
        char *action;
        char **details;

        sd_bus_message *reply;
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
         * calling this is only allowed from async_polkit_queries_new_query() and async_polkit_queries_free(). */
        assert(!q->parent);

        sd_bus_slot_unref(q->slot);
        sd_bus_message_unref(q->reply);

        free(q->action);
        strv_free(q->details);

        sd_event_source_disable_unref(q->defer_event_source);

        return mfree(q);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(AsyncPolkitQuery*, async_polkit_query_free);

static int async_polkit_queries_new_query(
                AsyncPolkitQueries *parent,
                sd_bus_message *request,
                const char *action,
                const char **details,
                AsyncPolkitQuery **ret) {
        _cleanup_(async_polkit_query_freep) AsyncPolkitQuery *q = NULL;

        assert(parent);
        assert(request);
        assert(action);
        assert(ret);

        q = new(AsyncPolkitQuery, 1);
        if (!q)
                return -ENOMEM;

        *q = (AsyncPolkitQuery) {
                .action = strdup(action),
                .details = strv_copy((char**) details),
                .parent = parent,
        };

        if (!q->action || (details && !q->details))
                return -ENOMEM;

        LIST_PREPEND(item, parent->items, q);

        *ret = TAKE_PTR(q);

        return 0;
}

static int async_polkit_defer(sd_event_source *s, void *userdata) {
        AsyncPolkitQueries *qs = ASSERT_PTR(userdata);

        assert(s);

        /* This is called as idle event source after we processed the async polkit reply, hopefully after the
         * method call we re-enqueued has been properly processed. */

        async_polkit_queries_unref(qs);

        return 0;
}

static int async_polkit_callback(sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        AsyncPolkitQuery *q = ASSERT_PTR(userdata);
        int r;

        assert(reply);

        assert(q->parent);

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

        assert(q->parent);
        assert(!q->defer_event_source);
        r = sd_event_add_defer(sd_bus_get_event(sd_bus_message_get_bus(reply)), &q->defer_event_source, async_polkit_defer, q->parent);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(q->defer_event_source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_enabled(q->defer_event_source, SD_EVENT_ONESHOT);
        if (r < 0)
                goto fail;

        r = sd_bus_message_rewind(q->parent->request, true);
        if (r < 0)
                goto fail;

        assert(q->parent->items); /* There must be at least one query on the list */
        LIST_FOREACH(item, i, q->parent->items)
                if (i != q)
                        sd_bus_message_rewind(i->reply, true);

        r = sd_bus_enqueue_for_read(sd_bus_message_get_bus(q->parent->request), q->parent->request);
        if (r < 0)
                goto fail;

        return 1;

fail:
        log_debug_errno(r, "Processing asynchronous PolicyKit reply failed, ignoring: %m");
        (void) sd_bus_reply_method_errno(q->parent->request, r, NULL);
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

        assert(q->action);
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

/* bus_verify_polkit_async() handles verification of D-Bus calls with polkit. Because the polkit API
 * is asynchronous, the whole thing is a bit complex and requires some support the code that uses it.
 * It relies on sd-bus's support for interruption of processing of a message.
 *
 * Requirements:
 *
 * * bus_verify_polkit_async() must be called before any changes to internal state.
 * * If bus_verify_polkit_async() has made a new polkit query() (signalized by return value 0),
 *   processing of the message should be interrupted. This is done by returning 1--which sd-bus
 *   handles specially--and is usually accompanied by a comment. (The message will be queued for
 *   processing again when a reply from polkit is received.)
 * * The code needs to keep a hashmap, here called registry, in which bus_verify_polkit_async()
 *   stores active queries. This hashmap's lifetime must be larger than the method handler's;
 *   e.g., it can be a member of some "manager" object or a global variable.
 *
 * Return value:
 *
 * * 0 - a new polkit call has been made, which means the processing of the message should be
 *   interrupted;
 * * 1 - the action has been authorized;
 * * -EACCES - the action has not been authorized;
 * * <0 - an unspecified error.
 *
 * A step-by-step description how it works:
 *
 *  1. A D-Bus method handler calls bus_verify_polkit_async(), passing it the D-Bus message being
 *     processed and the polkit action to verify.
 *  2. bus_verify_polkit_async() checks registry for the message and action combination. Let's assume
 *     this is the first call, so it finds nothing.
 *  3. A new AsyncPolkitQueries container is created and inserted into the registry for the message.
 *  4. A new AsyncPolkitQuery object is inserted into the container and an async. D-Bus call to
 *     polkit is made. The function then returns 0. The method handler returns 1 to tell sd-bus that
 *     the processing of the message has been interrupted.
 *  5. (Later) A reply from polkit is received and async_polkit_callback() is called.
 *  6. async_polkit_callback() reads the reply and stores result into the passed query.
 *  7. async_polkit_callback() enqueues the original message again.
 *  8. (Later) The same D-Bus method handler is called for the same message. It calls
 *     bus_verify_polkit_async() again.
 *  9. bus_verify_polkit_async() checks registry for the message and action combination. It finds
 *     an existing query and returns its result.
 * 10. The method handler continues processing of the message. If there's another action that needs to be verified:
 * 11. bus_verify_polkit_async() is called again for the new action. The registry already contains an
 *     AsyncPolkitQueries object for the message, but it doesn't contain a query for the action yet,
 *     hence steps 4-8 are repeated.
 * 12. (In the method handler again.) bus_verify_polkit_async() returns query results for both
 *     actions and the processing continues as in step 10.
 *
 * Memory handling:
 *
 * Use of bus_verify_polkit_async() from a method handler results in creation of an AsyncPolkitQueries
 * object (container) and one or more AsyncPolkitQuery objects (query); the number of the latter
 * depends on the number of actions the hanler needs to verify (typically just one). The container is
 * kept in registry; the queries form a linked list and are owned by the container. The container is
 * refcounted: the refcount goes up every time a new query is created and sent to polkit, and down
 * after each async_polkit_callback() call which processes a reply from polkit for a query. For this,
 * async_polkit_callback() registers a deferred call of async_polkit_defer() for the query's parent
 * container. At the last unref the container is removed from the registry. Deferred events are run
 * with idle priority, hence this will happen after processing of the D-Bus message, when the queries
 * are no longer needed.
 *
 * Schematically:
 *
 * (m - D-Bus message, a - polkit action, q - polkit query, qs - parent container of the query)
 *
 * -> foo_method(m)
 *    -> bus_verify_polkit_async(m, a)
 *       -> async_polkit_queries_ref(qs)
 *       -> bus_call_method_async(q)
 *    <- bus_verify_polkit_async(m, a) = 0
 * <- foo_method(m) = 1
 * ...
 * -> async_polkit_callback(q)
 *    -> sd_event_add_defer(async_polkit_defer, qs)
 *    -> sd_bus_enqueue_for_read(m)
 * <- async_polkit_callback(q)
 * ...
 * -> foo_method(m)
 *    -> bus_verify_polkit_async(m, a)
 *    <- bus_verify_polkit_async(m, a) = 1/-EACCES/error
 *    // possibly another call to bus_verify_polkit_async with action a2
 * <- foo_method(m)
 * ...
 * -> async_polkit_defer(qs)
 *    -> async_polkit_queries_unref(qs)
 * <- async_polkit_defer(qs)
 */

int bus_verify_polkit_async(
                sd_bus_message *call,
                int capability,
                const char *action,
                const char **details,
                bool interactive,
                uid_t good_user,
                Hashmap **registry,
                sd_bus_error *ret_error) {

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

        r = bus_message_new_polkit_auth_call(call, action, details, interactive, &pk);
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

        /* The created AsyncPolkitQuery object is owned by its parent AsyncPolkitQueries. */
        r = async_polkit_queries_new_query(qs, call, action, details, &q);
        if (r < 0)
                return r;

        r = sd_bus_call_async(call->bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0)
                return r;

        /* Increment refcount. It'll be decremented again after the above async call has finished. */
        async_polkit_queries_ref(qs);

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
