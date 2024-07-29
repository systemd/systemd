/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "process-util.h"
#include "strv.h"
#include "user-util.h"
#include "varlink-util.h"

static int bus_message_check_good_user(sd_bus_message *m, uid_t good_user) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        uid_t sender_uid;
        int r;

        assert(m);

        if (good_user == UID_INVALID)
                return false;

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

        return sd_bus_message_close_container(m);
}

static int bus_message_new_polkit_auth_call_for_bus(
                sd_bus_message *m,
                const char *action,
                const char **details,
                PolkitFlags flags,
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

        r = sd_bus_message_append(c, "us", (uint32_t) (flags & _POLKIT_MASK_PUBLIC), NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}
#endif

int bus_test_polkit(
                sd_bus_message *call,
                const char *action,
                const char **details,
                uid_t good_user,
                bool *_challenge,
                sd_bus_error *ret_error) {

        int r;

        assert(call);
        assert(action);

        /* Tests non-interactively! */

        r = bus_message_check_good_user(call, good_user);
        if (r != 0)
                return r;

        r = sd_bus_query_sender_privilege(call, -1);
        if (r < 0)
                return r;
        if (r > 0)
                return 1;

#if ENABLE_POLKIT
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL, *reply = NULL;
        int authorized = false, challenge = false;

        r = bus_message_new_polkit_auth_call_for_bus(call, action, details, /* interactive = */ false, &request);
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

typedef struct AsyncPolkitQueryAction {
        char *action;
        char **details;

        LIST_FIELDS(struct AsyncPolkitQueryAction, authorized);
} AsyncPolkitQueryAction;

static AsyncPolkitQueryAction *async_polkit_query_action_free(AsyncPolkitQueryAction *a) {
        if (!a)
                return NULL;

        free(a->action);
        strv_free(a->details);

        return mfree(a);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(AsyncPolkitQueryAction*, async_polkit_query_action_free);

typedef struct AsyncPolkitQuery {
        unsigned n_ref;

        AsyncPolkitQueryAction *action; /* action currently being processed */

        sd_bus *bus;
        sd_bus_message *request;        /* the original bus method call that triggered the polkit auth, NULL in case of varlink */
        sd_bus_slot *slot;
        sd_varlink *link;               /* the original varlink method call that triggered the polkit auth, NULL in case of bus */

        Hashmap *registry;
        sd_event_source *defer_event_source;

        LIST_HEAD(AsyncPolkitQueryAction, authorized_actions);  /* actions we successfully were authorized for */
        AsyncPolkitQueryAction *denied_action;                  /* if we received denial for an action, it's this one */
        AsyncPolkitQueryAction *absent_action;                  /* If polkit was absent for some action, it's this one */
        AsyncPolkitQueryAction *error_action;                   /* if we encountered any other error, it's this one */
        sd_bus_error error;                                     /* the precise error, in case error_action is set */
} AsyncPolkitQuery;

static AsyncPolkitQuery *async_polkit_query_free(AsyncPolkitQuery *q) {
        if (!q)
                return NULL;

        sd_bus_slot_unref(q->slot);

        if (q->registry) {
                if (q->request)
                        hashmap_remove(q->registry, q->request);
                if (q->link)
                        hashmap_remove(q->registry, q->link);
        }

        sd_bus_message_unref(q->request);

        sd_bus_unref(q->bus);
        sd_varlink_unref(q->link);

        async_polkit_query_action_free(q->action);

        sd_event_source_disable_unref(q->defer_event_source);

        LIST_CLEAR(authorized, q->authorized_actions, async_polkit_query_action_free);

        async_polkit_query_action_free(q->denied_action);
        async_polkit_query_action_free(q->absent_action);
        async_polkit_query_action_free(q->error_action);

        sd_bus_error_free(&q->error);

        return mfree(q);
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(AsyncPolkitQuery, async_polkit_query, async_polkit_query_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(AsyncPolkitQuery*, async_polkit_query_unref);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                async_polkit_query_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                AsyncPolkitQuery,
                async_polkit_query_unref);

static int async_polkit_defer(sd_event_source *s, void *userdata) {
        AsyncPolkitQuery *q = ASSERT_PTR(userdata);

        assert(s);

        /* This is called as idle event source after we processed the async polkit reply, hopefully after the
         * method call we re-enqueued has been properly processed. */

        async_polkit_query_unref(q);
        return 0;
}

static int async_polkit_read_reply(sd_bus_message *reply, AsyncPolkitQuery *q) {
        _cleanup_(async_polkit_query_action_freep) AsyncPolkitQueryAction *a = NULL;
        int authorized, challenge, r;

        assert(reply);
        assert(q);

        /* Processing of a PolicyKit checks is canceled on the first auth. error. */
        assert(!q->denied_action);
        assert(!q->absent_action);
        assert(!q->error_action);
        assert(!sd_bus_error_is_set(&q->error));

        a = ASSERT_PTR(TAKE_PTR(q->action));

        if (sd_bus_message_is_method_error(reply, NULL)) {
                const sd_bus_error *e;

                e = sd_bus_message_get_error(reply);

                if (bus_error_is_unknown_service(e)) {
                        /* If PK is absent, then store this away, as it depends on the callers flags whether
                         * this means deny or allow */
                        log_debug("Polkit found to be unavailable while trying to authorize action '%s'.", a->action);
                        q->absent_action = TAKE_PTR(a);
                } else if (sd_bus_error_has_names(
                                           e,
                                           "org.freedesktop.PolicyKit1.Error.Failed",
                                           "org.freedesktop.PolicyKit1.Error.Cancelled",
                                           "org.freedesktop.PolicyKit1.Error.NotAuthorized")) {
                        /* Treat some of the well-known PK errors as denial. */
                        log_debug("Polkit authorization for action '%s' failed with an polkit error: %s", a->action, e->name);
                        q->denied_action = TAKE_PTR(a);
                } else {
                        /* Save error from polkit reply, so it can be returned when the same authorization
                         * is attempted for second time */
                        log_debug("Polkit authorization for action '%s' failed with an unexpected error: %s", a->action, e->name);
                        q->error_action = TAKE_PTR(a);
                        r = sd_bus_error_copy(&q->error, e);
                        if (r == -ENOMEM)
                                return r;
                }

                return 0;
        }

        r = sd_bus_message_enter_container(reply, 'r', "bba{ss}");
        if (r >= 0)
                r = sd_bus_message_read(reply, "bb", &authorized, &challenge);
        if (r < 0)
                return r;

        if (authorized) {
                log_debug("Polkit authorization for action '%s' succeeded.", a->action);
                LIST_PREPEND(authorized, q->authorized_actions, TAKE_PTR(a));
        } else if (challenge) {
                log_debug("Polkit authorization for action requires '%s' interactive authentication, which we didn't allow.", a->action);
                q->error_action = TAKE_PTR(a);
                sd_bus_error_set_const(&q->error, SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED, "Interactive authentication required.");
        } else {
                log_debug("Polkit authorization for action '%s' denied.", a->action);
                q->denied_action = TAKE_PTR(a);
        }

        return 0;
}

static int async_polkit_process_reply(sd_bus_message *reply, AsyncPolkitQuery *q) {
        int r;

        assert(reply);
        assert(q);

        assert(q->slot);
        q->slot = sd_bus_slot_unref(q->slot);

        r = async_polkit_read_reply(reply, q);
        if (r < 0)
                return r;

        /* Now, let's dispatch the original message a second time be re-enqueing. This will then traverse the
         * whole message processing again, and thus re-validating and re-retrieving the "userdata" field
         * again.
         *
         * We install an idle event loop event to clean-up the PolicyKit request data when we are idle again,
         * i.e. after the second time the message is processed is complete. */

        if (!q->defer_event_source) {
                r = sd_event_add_defer(
                                sd_bus_get_event(q->bus),
                                &q->defer_event_source,
                                async_polkit_defer,
                                q);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(q->defer_event_source, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        return r;
        }

        r = sd_event_source_set_enabled(q->defer_event_source, SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        if (q->request) {
                r = sd_bus_message_rewind(q->request, true);
                if (r < 0)
                        return r;

                r = sd_bus_enqueue_for_read(q->bus, q->request);
                if (r < 0)
                        return r;
        }

        if (q->link) {
                r = sd_varlink_dispatch_again(q->link);
                if (r < 0)
                        return r;
        }

        return 1;
}

static int async_polkit_callback(sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        AsyncPolkitQuery *q = ASSERT_PTR(userdata);
        int r;

        assert(reply);

        r = async_polkit_process_reply(reply, q);
        if (r < 0) {
                log_debug_errno(r, "Processing asynchronous PolicyKit reply failed, ignoring: %m");
                if (q->request)
                        (void) sd_bus_reply_method_errno(q->request, r, NULL);
                if (q->link)
                        (void) sd_varlink_error_errno(q->link, r);
                async_polkit_query_unref(q);
        }
        return r;
}

static bool async_polkit_query_have_action(
                AsyncPolkitQuery *q,
                const char *action,
                const char **details) {

        assert(q);
        assert(action);

        LIST_FOREACH(authorized, a, q->authorized_actions)
                if (streq(a->action, action) && strv_equal(a->details, (char**) details))
                        return true;

        return false;
}

static int async_polkit_query_check_action(
                AsyncPolkitQuery *q,
                const char *action,
                const char **details,
                PolkitFlags flags,
                sd_bus_error *ret_error) {

        assert(q);
        assert(action);

        if (async_polkit_query_have_action(q, action, details))
                return 1; /* Allow! */

        if (q->error_action && streq(q->error_action->action, action))
                return sd_bus_error_copy(ret_error, &q->error);

        if (q->denied_action && streq(q->denied_action->action, action))
                return -EACCES; /* Deny! */

        if (q->absent_action)
                return FLAGS_SET(flags, POLKIT_DEFAULT_ALLOW) ? 1 /* Allow! */ : -EACCES /* Deny! */;

        return 0; /* no reply yet */
}
#endif

/* bus_verify_polkit_async() handles verification of D-Bus calls with polkit. Because the polkit API
 * is asynchronous, the whole thing is a bit complex and requires some support in the code that uses
 * it. It relies on sd-bus's support for interrupting the processing of a message.
 *
 * Requirements:
 *
 * * bus_verify_polkit_async() must be called before any changes to internal state.
 * * If bus_verify_polkit_async() has made a new polkit query (signaled by return value 0),
 *   processing of the message should be interrupted. This is done by returning 1--which sd-bus
 *   handles specially--and is usually accompanied by a comment. (The message will be queued for
 *   processing again later when a reply from polkit is received.)
 * * The code needs to keep a hashmap, here called registry, in which bus_verify_polkit_async()
 *   stores active queries. This hashmap's lifetime must be larger than the method handler's;
 *   e.g., it can be a member of some "manager" object or a global variable.
 *
 * Return value:
 *
 * * 0 - a new polkit call has been made, which means the processing of the message should be
 *   interrupted;
 * * 1 - the action has been allowed;
 * * -EACCES - the action has been denied;
 * * < 0 - an unspecified error.
 *
 * A step-by-step description of how it works:
 *
 * 1.  A D-Bus method handler calls bus_verify_polkit_async(), passing it the D-Bus message being
 *     processed and the polkit action to verify.
 * 2.  bus_verify_polkit_async() checks the registry for an existing query object associated with the
 *     message. Let's assume this is the first call, so it finds nothing.
 * 3.  A new AsyncPolkitQuery object is created and an async. D-Bus call to polkit is made. The
 *     function then returns 0. The method handler returns 1 to tell sd-bus that the processing of
 *    the message has been interrupted.
 * 4.  (Later) A reply from polkit is received and async_polkit_callback() is called.
 * 5.  async_polkit_callback() reads the reply and stores its result in the passed query.
 * 6.  async_polkit_callback() enqueues the original message again.
 * 7.  (Later) The same D-Bus method handler is called for the same message. It calls
 *     bus_verify_polkit_async() again.
 * 8.  bus_verify_polkit_async() checks the registry for an existing query object associated with the
 *     message. It finds one and returns the result for the action.
 * 9.  The method handler continues processing of the message. If there's another action that needs
 *     to be verified:
 * 10. bus_verify_polkit_async() is called again for the new action. The registry already contains a
 *     query for the message, but the new action hasn't been seen yet, hence steps 4-8 are repeated.
 * 11. (In the method handler again.) bus_verify_polkit_async() returns query results for both
 *     actions and the processing continues as in step 9.
 *
 * Memory handling:
 *
 * async_polkit_callback() registers a deferred call of async_polkit_defer() for the query, which
 * causes the query to be removed from the registry and freed. Deferred events are run with idle
 * priority, so this will happen after processing of the D-Bus message, when the query is no longer
 * needed.
 *
 * Schematically:
 *
 * (m - D-Bus message, a - polkit action, q - polkit query)
 *
 * -> foo_method(m)
 *    -> bus_verify_polkit_async(m, a)
 *       -> async_polkit_query_ref(q)
 *       -> bus_call_method_async(q)
 *    <- bus_verify_polkit_async(m, a) = 0
 * <- foo_method(m) = 1
 * ...
 * -> async_polkit_callback(q)
 *    -> sd_event_add_defer(async_polkit_defer, q)
 *    -> sd_bus_enqueue_for_read(m)
 * <- async_polkit_callback(q)
 * ...
 * -> foo_method(m)
 *    -> bus_verify_polkit_async(m, a)
 *    <- bus_verify_polkit_async(m, a) = 1/-EACCES/error
 *    ...
 *    // possibly another call to bus_verify_polkit_async with action a2
 * <- foo_method(m)
 * ...
 * -> async_polkit_defer(q)
 *    -> async_polkit_query_unref(q)
 * <- async_polkit_defer(q)
 */

int bus_verify_polkit_async_full(
                sd_bus_message *call,
                const char *action,
                const char **details,
                uid_t good_user,
                PolkitFlags flags,
                Hashmap **registry,
                sd_bus_error *error) {

        int r;

        assert(call);
        assert(action);
        assert(registry);

        log_debug("Trying to acquire polkit authentication for '%s'.", action);

        r = bus_message_check_good_user(call, good_user);
        if (r != 0)
                return r;

#if ENABLE_POLKIT
        _cleanup_(async_polkit_query_unrefp) AsyncPolkitQuery *q = NULL;

        q = async_polkit_query_ref(hashmap_get(*registry, call));
        /* This is a repeated invocation of this function, hence let's check if we've already got
         * a response from polkit for this action */
        if (q) {
                r = async_polkit_query_check_action(q, action, details, flags, error);
                if (r != 0) {
                        log_debug("Found matching previous polkit authentication for '%s'.", action);
                        return r;
                }
        }
#endif

        if (!FLAGS_SET(flags, POLKIT_ALWAYS_QUERY)) {
                /* Don't query PK if client is privileged */
                r = sd_bus_query_sender_privilege(call, /* capability= */ -1);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

#if ENABLE_POLKIT
        int c = sd_bus_message_get_allow_interactive_authorization(call);
        if (c < 0)
                return c;
        if (c > 0)
                flags |= POLKIT_ALLOW_INTERACTIVE;

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pk = NULL;
        r = bus_message_new_polkit_auth_call_for_bus(call, action, details, flags, &pk);
        if (r < 0)
                return r;

        if (!q) {
                q = new(AsyncPolkitQuery, 1);
                if (!q)
                        return -ENOMEM;

                *q = (AsyncPolkitQuery) {
                        .n_ref = 1,
                        .request = sd_bus_message_ref(call),
                        .bus = sd_bus_ref(sd_bus_message_get_bus(call)),
                };
        }

        assert(!q->action);
        q->action = new(AsyncPolkitQueryAction, 1);
        if (!q->action)
                return -ENOMEM;

        *q->action = (AsyncPolkitQueryAction) {
                .action = strdup(action),
                .details = strv_copy((char**) details),
        };
        if (!q->action->action || !q->action->details)
                return -ENOMEM;

        if (!q->registry) {
                r = hashmap_ensure_put(registry, &async_polkit_query_hash_ops, call, q);
                if (r < 0)
                        return r;

                q->registry = *registry;
        }

        r = sd_bus_call_async(call->bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0)
                return r;

        TAKE_PTR(q);

        return 0;
#else
        return FLAGS_SET(flags, POLKIT_DEFAULT_ALLOW) ? 1 : -EACCES;
#endif
}

static int varlink_check_good_user(sd_varlink *link, uid_t good_user) {
        int r;

        assert(link);

        if (good_user == UID_INVALID)
                return false;

        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        return good_user == peer_uid;
}

static int varlink_check_peer_privilege(sd_varlink *link) {
        int r;

        assert(link);

        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        uid_t our_uid = getuid();
        return peer_uid == our_uid ||
                (our_uid != 0 && peer_uid == 0);
}

#if ENABLE_POLKIT
static int bus_message_new_polkit_auth_call_for_varlink(
                sd_bus *bus,
                sd_varlink *link,
                const char *action,
                const char **details,
                PolkitFlags flags,
                sd_bus_message **ret) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *c = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert(bus);
        assert(link);
        assert(action);
        assert(ret);

        r = varlink_get_peer_pidref(link, &pidref);
        if (r < 0)
                return r;
        if (r == 0) /* if we couldn't get a pidfd this returns == 0 */
                return log_debug_errno(SYNTHETIC_ERRNO(EPERM), "Failed to get peer pidfd, cannot securely authenticate.");

        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        bus,
                        &c,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization");
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        c,
                        "(sa{sv})s",
                        "unix-process", 2,
                        "pidfd", "h", (uint32_t) pidref.fd,
                        "uid", "i", (int32_t) uid,
                        action);
        if (r < 0)
                return r;

        r = bus_message_append_strv_key_value(c, details);
        if (r < 0)
                return r;

        r = sd_bus_message_append(c, "us", (uint32_t) (flags & _POLKIT_MASK_PUBLIC), NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

static bool varlink_allow_interactive_authentication(sd_varlink *link) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(link);

        /* We look for the allowInteractiveAuthentication field in the message currently being dispatched,
         * always under the same name. */

        r = sd_varlink_get_current_parameters(link, &v);
        if (r < 0) {
                log_debug_errno(r, "Unable to query current parameters: %m");
                return false;
        }

        sd_json_variant *b;
        b = sd_json_variant_by_key(v, "allowInteractiveAuthentication");
        if (b) {
                if (sd_json_variant_is_boolean(b))
                        return sd_json_variant_boolean(b);

                log_debug("Incoming 'allowInteractiveAuthentication' field is not a boolean, ignoring.");
        }

        return false;
}
#endif

int varlink_verify_polkit_async_full(
                sd_varlink *link,
                sd_bus *bus,
                const char *action,
                const char **details,
                uid_t good_user,
                PolkitFlags flags,
                Hashmap **registry) {

        int r;

        assert(link);
        assert(registry);

        log_debug("Trying to acquire polkit authentication for '%s'.", action);

        /* This is the same as bus_verify_polkit_async_full(), but authenticates the peer of a varlink
         * connection rather than the sender of a bus message. */

        r = varlink_check_good_user(link, good_user);
        if (r != 0)
                return r;

        if (!FLAGS_SET(flags, POLKIT_ALWAYS_QUERY)) {
                r = varlink_check_peer_privilege(link);
                if (r != 0)
                        return r;
        }

#if ENABLE_POLKIT
        _cleanup_(async_polkit_query_unrefp) AsyncPolkitQuery *q = NULL;

        q = async_polkit_query_ref(hashmap_get(*registry, link));
        /* This is a repeated invocation of this function, hence let's check if we've already got
         * a response from polkit for this action */
        if (q) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = async_polkit_query_check_action(q, action, details, flags, &error);
                if (r != 0)
                        log_debug("Found matching previous polkit authentication for '%s'.", action);
                if (r < 0) {
                        if (!FLAGS_SET(flags, POLKIT_DONT_REPLY)) {
                                /* Reply with a nice error */
                                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED))
                                        (void) sd_varlink_error(link, SD_VARLINK_ERROR_INTERACTIVE_AUTHENTICATION_REQUIRED, NULL);
                                else if (ERRNO_IS_NEG_PRIVILEGE(r))
                                        (void) sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);
                        }

                        return r;
                }
                if (r > 0)
                        return r;
        }

        _cleanup_(sd_bus_unrefp) sd_bus *mybus = NULL;
        if (!bus) {
                r = sd_bus_open_system(&mybus);
                if (r < 0)
                        return r;

                r = sd_bus_attach_event(mybus, sd_varlink_get_event(link), 0);
                if (r < 0)
                        return r;

                bus = mybus;
        }

        if (varlink_allow_interactive_authentication(link))
                flags |= POLKIT_ALLOW_INTERACTIVE;

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pk = NULL;
        r = bus_message_new_polkit_auth_call_for_varlink(bus, link, action, details, flags, &pk);
        if (r < 0)
                return r;

        if (!q) {
                q = new(AsyncPolkitQuery, 1);
                if (!q)
                        return -ENOMEM;

                *q = (AsyncPolkitQuery) {
                        .n_ref = 1,
                        .link = sd_varlink_ref(link),
                        .bus = sd_bus_ref(bus),
                };
        }

        assert(!q->action);
        q->action = new(AsyncPolkitQueryAction, 1);
        if (!q->action)
                return -ENOMEM;

        *q->action = (AsyncPolkitQueryAction) {
                .action = strdup(action),
                .details = strv_copy((char**) details),
        };
        if (!q->action->action || !q->action->details)
                return -ENOMEM;

        if (!q->registry) {
                r = hashmap_ensure_put(registry, &async_polkit_query_hash_ops, link, q);
                if (r < 0)
                        return r;

                q->registry = *registry;
        }

        r = sd_bus_call_async(bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0)
                return r;

        TAKE_PTR(q);

        return 0;
#else
        return FLAGS_SET(flags, POLKIT_DEFAULT_ALLOW) ? 1 : -EACCES;
#endif
}

bool varlink_has_polkit_action(sd_varlink *link, const char *action, const char **details, Hashmap **registry) {
        assert(link);
        assert(action);
        assert(registry);

        /* Checks if we already have acquired some action previously */

#if ENABLE_POLKIT
        AsyncPolkitQuery *q = hashmap_get(*registry, link);
        if (!q)
                return false;

        return async_polkit_query_have_action(q, action, details);
#else
        return false;
#endif
}
