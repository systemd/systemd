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

        const char **k, **v;
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

typedef struct AsyncPolkitQuery {
        char *action;
        char **details;

        sd_bus_message *request, *reply;
        sd_bus_slot *slot;

        Hashmap *registry;
        sd_event_source *defer_event_source;
} AsyncPolkitQuery;

static void async_polkit_query_free(AsyncPolkitQuery *q) {
        if (!q)
                return;

        sd_bus_slot_unref(q->slot);

        if (q->registry && q->request)
                hashmap_remove(q->registry, q->request);

        sd_bus_message_unref(q->request);
        sd_bus_message_unref(q->reply);

        free(q->action);
        strv_free(q->details);

        sd_event_source_disable_unref(q->defer_event_source);
        free(q);
}

static int async_polkit_defer(sd_event_source *s, void *userdata) {
        AsyncPolkitQuery *q = userdata;

        assert(s);

        /* This is called as idle event source after we processed the async polkit reply, hopefully after the
         * method call we re-enqueued has been properly processed. */

        async_polkit_query_free(q);
        return 0;
}

static int async_polkit_callback(sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        AsyncPolkitQuery *q = userdata;
        int r;

        assert(reply);
        assert(q);

        assert(q->slot);
        q->slot = sd_bus_slot_unref(q->slot);

        assert(!q->reply);
        q->reply = sd_bus_message_ref(reply);

        /* Now, let's dispatch the original message a second time be re-enqueing. This will then traverse the
         * whole message processing again, and thus re-validating and re-retrieving the "userdata" field
         * again.
         *
         * We install an idle event loop event to clean-up the PolicyKit request data when we are idle again,
         * i.e. after the second time the message is processed is complete. */

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

        r = sd_bus_enqueue_for_read(sd_bus_message_get_bus(q->request), q->request);
        if (r < 0)
                goto fail;

        return 1;

fail:
        log_debug_errno(r, "Processing asynchronous PolicyKit reply failed, ignoring: %m");
        (void) sd_bus_reply_method_errno(q->request, r, NULL);
        async_polkit_query_free(q);
        return r;
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

#if ENABLE_POLKIT
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pk = NULL;
        AsyncPolkitQuery *q;
        int c;
#endif
        const char *sender;
        int r;

        assert(call);
        assert(action);
        assert(registry);

        r = check_good_user(call, good_user);
        if (r != 0)
                return r;

#if ENABLE_POLKIT
        q = hashmap_get(*registry, call);
        if (q) {
                int authorized, challenge;

                /* This is the second invocation of this function, and there's already a response from
                 * polkit, let's process it */
                assert(q->reply);

                /* If the operation we want to authenticate changed between the first and the second time,
                 * let's not use this authentication, it might be out of date as the object and context we
                 * operate on might have changed. */
                if (!streq(q->action, action) ||
                    !strv_equal(q->details, (char**) details))
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
        c = sd_bus_message_get_allow_interactive_authorization(call);
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

        q = new(AsyncPolkitQuery, 1);
        if (!q)
                return -ENOMEM;

        *q = (AsyncPolkitQuery) {
                .request = sd_bus_message_ref(call),
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

        r = hashmap_put(*registry, call, q);
        if (r < 0) {
                async_polkit_query_free(q);
                return r;
        }

        q->registry = *registry;

        r = sd_bus_call_async(call->bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0) {
                async_polkit_query_free(q);
                return r;
        }

        return 0;
#endif

        return -EACCES;
}

void bus_verify_polkit_async_registry_free(Hashmap *registry) {
#if ENABLE_POLKIT
        hashmap_free_with_destructor(registry, async_polkit_query_free);
#endif
}
