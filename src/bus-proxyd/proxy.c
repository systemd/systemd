/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Daniel Mack
  Copyright 2014 Kay Sievers
  Copyright 2014 David Herrmann

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "log.h"
#include "util.h"
#include "sd-daemon.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "strv.h"
#include "bus-control.h"
#include "set.h"
#include "bus-xml-policy.h"
#include "driver.h"
#include "proxy.h"
#include "synthesize.h"
#include "formats-util.h"

static int proxy_create_destination(Proxy *p, const char *destination, const char *local_sec, bool negotiate_fds) {
        _cleanup_bus_flush_close_unref_ sd_bus *b = NULL;
        int r;

        r = sd_bus_new(&b);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate bus: %m");

        r = sd_bus_set_description(b, "sd-proxy");
        if (r < 0)
                return log_error_errno(r, "Failed to set bus name: %m");

        r = sd_bus_set_address(b, destination);
        if (r < 0)
                return log_error_errno(r, "Failed to set address to connect to: %m");

        r = sd_bus_negotiate_fds(b, negotiate_fds);
        if (r < 0)
                return log_error_errno(r, "Failed to set FD negotiation: %m");

        r = sd_bus_negotiate_creds(b, true, SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SELINUX_CONTEXT);
        if (r < 0)
                return log_error_errno(r, "Failed to set credential negotiation: %m");

        if (p->local_creds.pid > 0) {
                b->fake_pids.pid = p->local_creds.pid;
                b->fake_pids_valid = true;

                b->fake_creds.uid = UID_INVALID;
                b->fake_creds.euid = p->local_creds.uid;
                b->fake_creds.suid = UID_INVALID;
                b->fake_creds.fsuid = UID_INVALID;
                b->fake_creds.gid = GID_INVALID;
                b->fake_creds.egid = p->local_creds.gid;
                b->fake_creds.sgid = GID_INVALID;
                b->fake_creds.fsgid = GID_INVALID;
                b->fake_creds_valid = true;
        }

        if (local_sec) {
                b->fake_label = strdup(local_sec);
                if (!b->fake_label)
                        return log_oom();
        }

        b->manual_peer_interface = true;

        r = sd_bus_start(b);
        if (r < 0)
                return log_error_errno(r, "Failed to start bus client: %m");

        p->destination_bus = b;
        b = NULL;
        return 0;
}

static int proxy_create_local(Proxy *p, int in_fd, int out_fd, bool negotiate_fds) {
        _cleanup_bus_flush_close_unref_ sd_bus *b = NULL;
        sd_id128_t server_id;
        int r;

        r = sd_bus_new(&b);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate bus: %m");

        r = sd_bus_set_fd(b, in_fd, out_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to set fds: %m");

        r = sd_bus_get_bus_id(p->destination_bus, &server_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get server ID: %m");

        r = sd_bus_set_server(b, 1, server_id);
        if (r < 0)
                return log_error_errno(r, "Failed to set server mode: %m");

        r = sd_bus_negotiate_fds(b, negotiate_fds);
        if (r < 0)
                return log_error_errno(r, "Failed to set FD negotiation: %m");

        r = sd_bus_negotiate_creds(b, true, SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SELINUX_CONTEXT);
        if (r < 0)
                return log_error_errno(r, "Failed to set credential negotiation: %m");

        r = sd_bus_set_anonymous(b, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set anonymous authentication: %m");

        b->manual_peer_interface = true;

        r = sd_bus_start(b);
        if (r < 0)
                return log_error_errno(r, "Failed to start bus client: %m");

        p->local_bus = b;
        b = NULL;
        return 0;
}

static int proxy_match_synthetic(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Proxy *p = userdata;

        p->synthetic_matched = true;
        return 0; /* make sure to continue processing it in further handlers */
}

/*
 * We always need NameOwnerChanged so we can synthesize NameLost and
 * NameAcquired. Furthermore, dbus-1 always passes unicast-signals through, so
 * subscribe unconditionally.
 */
static int proxy_prepare_matches(Proxy *p) {
        _cleanup_free_ char *match = NULL;
        const char *unique;
        int r;

        if (!p->destination_bus->is_kernel)
                return 0;

        r = sd_bus_get_unique_name(p->destination_bus, &unique);
        if (r < 0)
                return log_error_errno(r, "Failed to get unique name: %m");

        match = strjoin("type='signal',"
                        "sender='org.freedesktop.DBus',"
                        "path='/org/freedesktop/DBus',"
                        "interface='org.freedesktop.DBus',"
                        "member='NameOwnerChanged',"
                        "arg1='",
                        unique,
                        "'",
                        NULL);
        if (!match)
                return log_oom();

        r = sd_bus_add_match(p->destination_bus, NULL, match, proxy_match_synthetic, p);
        if (r < 0)
                return log_error_errno(r, "Failed to add match for NameLost: %m");

        free(match);
        match = strjoin("type='signal',"
                        "sender='org.freedesktop.DBus',"
                        "path='/org/freedesktop/DBus',"
                        "interface='org.freedesktop.DBus',"
                        "member='NameOwnerChanged',"
                        "arg2='",
                        unique,
                        "'",
                        NULL);
        if (!match)
                return log_oom();

        r = sd_bus_add_match(p->destination_bus, NULL, match, proxy_match_synthetic, p);
        if (r < 0)
                return log_error_errno(r, "Failed to add match for NameAcquired: %m");

        free(match);
        match = strjoin("type='signal',"
                        "destination='",
                        unique,
                        "'",
                        NULL);
        if (!match)
                return log_oom();

        r = sd_bus_add_match(p->destination_bus, NULL, match, proxy_match_synthetic, p);
        if (r < 0)
                log_error_errno(r, "Failed to add match for directed signals: %m");
                /* FIXME: temporarily ignore error to support older kdbus versions */

        return 0;
}

int proxy_new(Proxy **out, int in_fd, int out_fd, const char *destination) {
        _cleanup_(proxy_freep) Proxy *p = NULL;
        _cleanup_free_ char *local_sec = NULL;
        bool is_unix;
        int r;

        p = new0(Proxy, 1);
        if (!p)
                return log_oom();

        p->local_in = in_fd;
        p->local_out = out_fd;

        p->owned_names = set_new(&string_hash_ops);
        if (!p->owned_names)
                return log_oom();

        is_unix = sd_is_socket(in_fd, AF_UNIX, 0, 0) > 0 &&
                  sd_is_socket(out_fd, AF_UNIX, 0, 0) > 0;

        if (is_unix) {
                (void) getpeercred(in_fd, &p->local_creds);
                (void) getpeersec(in_fd, &local_sec);
        }

        r = proxy_create_destination(p, destination, local_sec, is_unix);
        if (r < 0)
                return r;

        r = proxy_create_local(p, in_fd, out_fd, is_unix);
        if (r < 0)
                return r;

        r = proxy_prepare_matches(p);
        if (r < 0)
                return r;

        *out = p;
        p = NULL;
        return 0;
}

Proxy *proxy_free(Proxy *p) {
        ProxyActivation *activation;

        if (!p)
                return NULL;

        while ((activation = p->activations)) {
                LIST_REMOVE(activations_by_proxy, p->activations, activation);
                sd_bus_message_unref(activation->request);
                sd_bus_slot_unref(activation->slot);
                free(activation);
        }

        sd_bus_flush_close_unref(p->local_bus);
        sd_bus_flush_close_unref(p->destination_bus);
        set_free_free(p->owned_names);
        free(p);

        return NULL;
}

int proxy_set_policy(Proxy *p, SharedPolicy *sp, char **configuration) {
        _cleanup_strv_free_ char **strv = NULL;
        Policy *policy;
        int r;

        assert(p);
        assert(sp);

        /* no need to load legacy policy if destination is not kdbus */
        if (!p->destination_bus->is_kernel)
                return 0;

        p->policy = sp;

        policy = shared_policy_acquire(sp);
        if (policy) {
                /* policy already pre-loaded */
                shared_policy_release(sp, policy);
                return 0;
        }

        if (!configuration) {
                const char *scope;

                r = sd_bus_get_scope(p->destination_bus, &scope);
                if (r < 0)
                        return log_error_errno(r, "Couldn't determine bus scope: %m");

                if (streq(scope, "system"))
                        strv = strv_new("/usr/share/dbus-1/system.conf",
                                        "/etc/dbus-1/system.conf",
                                        "/usr/share/dbus-1/system.d/",
                                        "/etc/dbus-1/system.d/",
                                        "/etc/dbus-1/system-local.conf",
                                        NULL);
                else if (streq(scope, "user"))
                        strv = strv_new("/usr/share/dbus-1/session.conf",
                                        "/etc/dbus-1/session.conf",
                                        "/usr/share/dbus-1/session.d/",
                                        "/etc/dbus-1/session.d/",
                                        "/etc/dbus-1/session-local.conf",
                                        NULL);
                else
                        return log_error("Unknown scope %s, don't know which policy to load. Refusing.", scope);

                if (!strv)
                        return log_oom();

                configuration = strv;
        }

        return shared_policy_preload(sp, configuration);
}

int proxy_hello_policy(Proxy *p, uid_t original_uid) {
        Policy *policy;
        int r = 0;

        assert(p);

        if (!p->policy)
                return 0;

        policy = shared_policy_acquire(p->policy);

        if (p->local_creds.uid == original_uid)
                log_debug("Permitting access, since bus owner matches bus client.");
        else if (policy_check_hello(policy, p->local_creds.uid, p->local_creds.gid))
                log_debug("Permitting access due to XML policy.");
        else
                r = log_error_errno(EPERM, "Policy denied connection.");

        shared_policy_release(p->policy, policy);

        return r;
}

static int proxy_wait(Proxy *p) {
        uint64_t timeout_destination, timeout_local, t;
        int events_destination, events_local, fd;
        struct timespec _ts, *ts;
        struct pollfd *pollfd;
        int r;

        assert(p);

        fd = sd_bus_get_fd(p->destination_bus);
        if (fd < 0)
                return log_error_errno(fd, "Failed to get fd: %m");

        events_destination = sd_bus_get_events(p->destination_bus);
        if (events_destination < 0)
                return log_error_errno(events_destination, "Failed to get events mask: %m");

        r = sd_bus_get_timeout(p->destination_bus, &timeout_destination);
        if (r < 0)
                return log_error_errno(r, "Failed to get timeout: %m");

        events_local = sd_bus_get_events(p->local_bus);
        if (events_local < 0)
                return log_error_errno(events_local, "Failed to get events mask: %m");

        r = sd_bus_get_timeout(p->local_bus, &timeout_local);
        if (r < 0)
                return log_error_errno(r, "Failed to get timeout: %m");

        t = timeout_destination;
        if (t == (uint64_t) -1 || (timeout_local != (uint64_t) -1 && timeout_local < timeout_destination))
                t = timeout_local;

        if (t == (uint64_t) -1)
                ts = NULL;
        else {
                usec_t nw;

                nw = now(CLOCK_MONOTONIC);
                if (t > nw)
                        t -= nw;
                else
                        t = 0;

                ts = timespec_store(&_ts, t);
        }

        pollfd = (struct pollfd[3]) {
                { .fd = fd,           .events = events_destination,     },
                { .fd = p->local_in,  .events = events_local & POLLIN,  },
                { .fd = p->local_out, .events = events_local & POLLOUT, },
        };

        r = ppoll(pollfd, 3, ts, NULL);
        if (r < 0)
                return log_error_errno(errno, "ppoll() failed: %m");

        return 0;
}

static int handle_policy_error(sd_bus_message *m, int r) {
        if (r == -ESRCH || r == -ENXIO)
                return synthetic_reply_method_errorf(m, SD_BUS_ERROR_NAME_HAS_NO_OWNER, "Name %s is currently not owned by anyone.", m->destination);

        return r;
}

static int process_policy_unlocked(sd_bus *from, sd_bus *to, sd_bus_message *m, Policy *policy, const struct ucred *our_ucred, Set *owned_names) {
        int r;

        assert(from);
        assert(to);
        assert(m);

        if (!policy)
                return 0;

        /*
         * dbus-1 distinguishes expected and non-expected replies by tracking
         * method-calls and timeouts. By default, DENY rules are *NEVER* applied
         * on expected replies, unless explicitly specified. But we dont track
         * method-calls, thus, we cannot know whether a reply is expected.
         * Fortunately, the kdbus forbids non-expected replies, so we can safely
         * ignore any policy on those and let the kernel deal with it.
         *
         * TODO: To be correct, we should only ignore policy-tags that are
         * applied on non-expected replies. However, so far we don't parse those
         * tags so we let everything pass. I haven't seen a DENY policy tag on
         * expected-replies, ever, so don't bother..
         */
        if (m->reply_cookie > 0)
                return 0;

        if (from->is_kernel) {
                uid_t sender_uid = UID_INVALID;
                gid_t sender_gid = GID_INVALID;
                char **sender_names = NULL;

                /* Driver messages are always OK */
                if (streq_ptr(m->sender, "org.freedesktop.DBus"))
                        return 0;

                /* The message came from the kernel, and is sent to our legacy client. */
                (void) sd_bus_creds_get_well_known_names(&m->creds, &sender_names);

                (void) sd_bus_creds_get_euid(&m->creds, &sender_uid);
                (void) sd_bus_creds_get_egid(&m->creds, &sender_gid);

                if (sender_uid == UID_INVALID || sender_gid == GID_INVALID) {
                        _cleanup_bus_creds_unref_ sd_bus_creds *sender_creds = NULL;

                        /* If the message came from another legacy
                         * client, then the message creds will be
                         * missing, simply because on legacy clients
                         * per-message creds were unknown. In this
                         * case, query the creds of the peer
                         * instead. */

                        r = bus_get_name_creds_kdbus(from, m->sender, SD_BUS_CREDS_EUID|SD_BUS_CREDS_EGID, true, &sender_creds);
                        if (r < 0)
                                return handle_policy_error(m, r);

                        (void) sd_bus_creds_get_euid(sender_creds, &sender_uid);
                        (void) sd_bus_creds_get_egid(sender_creds, &sender_gid);
                }

                /* First check whether the sender can send the message to our name */
                if (policy_check_send(policy, sender_uid, sender_gid, m->header->type, owned_names, NULL, m->path, m->interface, m->member, false, NULL) &&
                    policy_check_recv(policy, our_ucred->uid, our_ucred->gid, m->header->type, NULL, sender_names, m->path, m->interface, m->member, false))
                        return 0;

                /* Return an error back to the caller */
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        return synthetic_reply_method_errorf(m, SD_BUS_ERROR_ACCESS_DENIED, "Access prohibited by XML receiver policy.");

                /* Return 1, indicating that the message shall not be processed any further */
                return 1;
        }

        if (to->is_kernel) {
                _cleanup_bus_creds_unref_ sd_bus_creds *destination_creds = NULL;
                uid_t destination_uid = UID_INVALID;
                gid_t destination_gid = GID_INVALID;
                const char *destination_unique = NULL;
                char **destination_names = NULL;
                char *n;

                /* Driver messages are always OK */
                if (streq_ptr(m->destination, "org.freedesktop.DBus"))
                        return 0;

                /* The message came from the legacy client, and is sent to kdbus. */
                if (m->destination) {
                        r = bus_get_name_creds_kdbus(to, m->destination,
                                                     SD_BUS_CREDS_WELL_KNOWN_NAMES|SD_BUS_CREDS_UNIQUE_NAME|
                                                     SD_BUS_CREDS_EUID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_PID,
                                                     true, &destination_creds);
                        if (r < 0)
                                return handle_policy_error(m, r);

                        r = sd_bus_creds_get_unique_name(destination_creds, &destination_unique);
                        if (r < 0)
                                return handle_policy_error(m, r);

                        (void) sd_bus_creds_get_well_known_names(destination_creds, &destination_names);

                        (void) sd_bus_creds_get_euid(destination_creds, &destination_uid);
                        (void) sd_bus_creds_get_egid(destination_creds, &destination_gid);
                }

                /* First check if we (the sender) can send to this name */
                if (sd_bus_message_is_signal(m, NULL, NULL)) {
                        /* If we forward a signal from dbus-1 to kdbus, we have
                         * no idea who the recipient is. Therefore, we cannot
                         * apply any dbus-1 policies that match on receiver
                         * credentials. We know sd-bus always sets
                         * KDBUS_MSG_SIGNAL, so the kernel applies policies to
                         * the message. Therefore, skip policy checks in this
                         * case. */
                        return 0;
                } else if (policy_check_send(policy, our_ucred->uid, our_ucred->gid, m->header->type, NULL, destination_names, m->path, m->interface, m->member, true, &n)) {
                        if (n) {
                                /* If we made a receiver decision, then remember which
                                 * name's policy we used, and to which unique ID it
                                 * mapped when we made the decision. Then, let's pass
                                 * this to the kernel when sending the message, so that
                                 * it refuses the operation should the name and unique
                                 * ID not map to each other anymore. */

                                r = free_and_strdup(&m->destination_ptr, n);
                                if (r < 0)
                                        return r;

                                r = bus_kernel_parse_unique_name(destination_unique, &m->verify_destination_id);
                                if (r < 0)
                                        return r;
                        }

                        if (policy_check_recv(policy, destination_uid, destination_gid, m->header->type, owned_names, NULL, m->path, m->interface, m->member, true))
                                return 0;
                }

                /* Return an error back to the caller */
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        return synthetic_reply_method_errorf(m, SD_BUS_ERROR_ACCESS_DENIED, "Access prohibited by XML sender policy.");

                /* Return 1, indicating that the message shall not be processed any further */
                return 1;
        }

        return 0;
}

static int process_policy(sd_bus *from, sd_bus *to, sd_bus_message *m, SharedPolicy *sp, const struct ucred *our_ucred, Set *owned_names) {
        Policy *policy;
        int r;

        assert(sp);

        policy = shared_policy_acquire(sp);
        r = process_policy_unlocked(from, to, m, policy, our_ucred, owned_names);
        shared_policy_release(sp, policy);

        return r;
}

static int process_hello(Proxy *p, sd_bus_message *m) {
        _cleanup_bus_message_unref_ sd_bus_message *n = NULL;
        bool is_hello;
        int r;

        assert(p);
        assert(m);

        /* As reaction to hello we need to respond with two messages:
         * the callback reply and the NameAcquired for the unique
         * name, since hello is otherwise obsolete on kdbus. */

        is_hello =
                sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "Hello") &&
                streq_ptr(m->destination, "org.freedesktop.DBus");

        if (!is_hello) {
                if (p->got_hello)
                        return 0;

                return log_error_errno(EIO, "First packet isn't hello (it's %s.%s), aborting.", m->interface, m->member);
        }

        if (p->got_hello)
                return log_error_errno(EIO, "Got duplicate hello, aborting.");

        p->got_hello = true;

        if (!p->destination_bus->is_kernel)
                return 0;

        r = sd_bus_message_new_method_return(m, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate HELLO reply: %m");

        r = sd_bus_message_append(n, "s", p->destination_bus->unique_name);
        if (r < 0)
                return log_error_errno(r, "Failed to append unique name to HELLO reply: %m");

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0)
                return log_error_errno(r, "Failed to append sender to HELLO reply: %m");

        r = bus_seal_synthetic_message(p->local_bus, n);
        if (r < 0)
                return log_error_errno(r, "Failed to seal HELLO reply: %m");

        r = sd_bus_send(p->local_bus, n, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to send HELLO reply: %m");

        n = sd_bus_message_unref(n);
        r = sd_bus_message_new_signal(
                        p->local_bus,
                        &n,
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "NameAcquired");
        if (r < 0)
                return log_error_errno(r, "Failed to allocate initial NameAcquired message: %m");

        r = sd_bus_message_append(n, "s", p->destination_bus->unique_name);
        if (r < 0)
                return log_error_errno(r, "Failed to append unique name to NameAcquired message: %m");

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0)
                return log_error_errno(r, "Failed to append sender to NameAcquired message: %m");

        r = sd_bus_message_set_destination(n, p->destination_bus->unique_name);
        if (r < 0)
                return log_error_errno(r, "Failed to set destination for NameAcquired message: %m");

        r = bus_seal_synthetic_message(p->local_bus, n);
        if (r < 0)
                return log_error_errno(r, "Failed to seal NameAcquired message: %m");

        r = sd_bus_send(p->local_bus, n, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to send NameAcquired message: %m");

        return 1;
}

static int patch_sender(sd_bus *a, sd_bus_message *m) {
        char **well_known = NULL;
        sd_bus_creds *c;
        int r;

        assert(a);
        assert(m);

        if (!a->is_kernel)
                return 0;

        /* We will change the sender of messages from the bus driver
         * so that they originate from the bus driver. This is a
         * speciality originating from dbus1, where the bus driver did
         * not have a unique id, but only the well-known name. */

        c = sd_bus_message_get_creds(m);
        if (!c)
                return 0;

        r = sd_bus_creds_get_well_known_names(c, &well_known);
        if (r < 0)
                return r;

        if (strv_contains(well_known, "org.freedesktop.DBus"))
                m->sender = "org.freedesktop.DBus";

        return 0;
}

static int proxy_process_destination_to_local(Proxy *p) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        bool matched, matched_synthetic;
        int r;

        assert(p);

        /*
         * Usually, we would just take any message that the bus passes to us
         * and forward it to the local connection. However, there are actually
         * applications that fail if they receive broadcasts that they didn't
         * subscribe to. Therefore, we actually emulate a real broadcast
         * matching here, and discard any broadcasts that weren't matched. Our
         * match-handlers remembers whether a message was matched by any rule,
         * by marking it in @p->message_matched.
         */

        r = sd_bus_process(p->destination_bus, &m);

        matched = p->message_matched;
        matched_synthetic = p->synthetic_matched;
        p->message_matched = false;
        p->synthetic_matched = false;

        if (r == -ECONNRESET || r == -ENOTCONN) /* Treat 'connection reset by peer' as clean exit condition */
                return r;
        if (r < 0) {
                log_error_errno(r, "Failed to process destination bus: %m");
                return r;
        }
        if (r == 0)
                return 0;
        if (!m)
                return 1;

        /* We officially got EOF, let's quit */
        if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected"))
                return -ECONNRESET;

        r = synthesize_name_acquired(p, p->destination_bus, p->local_bus, m);
        if (r == -ECONNRESET || r == -ENOTCONN)
                return r;
        if (r < 0)
                return log_error_errno(r, "Failed to synthesize message: %m");

        /* discard broadcasts that were not matched by any MATCH rule */
        if (!matched && !sd_bus_message_get_destination(m)) {
                if (!matched_synthetic)
                        log_debug("Dropped unmatched broadcast: uid=" UID_FMT " gid=" GID_FMT " pid=" PID_FMT " message=%s path=%s interface=%s member=%s sender=%s destination=%s",
                                  p->local_creds.uid, p->local_creds.gid, p->local_creds.pid, bus_message_type_to_string(m->header->type),
                                  strna(m->path), strna(m->interface), strna(m->member), strna(m->sender), strna(m->destination));
                return 1;
        }

        patch_sender(p->destination_bus, m);

        if (p->policy) {
                r = process_policy(p->destination_bus, p->local_bus, m, p->policy, &p->local_creds, p->owned_names);
                if (r == -ECONNRESET || r == -ENOTCONN)
                        return r;
                if (r < 0)
                        return log_error_errno(r, "Failed to process policy: %m");
                if (r > 0)
                        return 1;
        }

        r = sd_bus_send(p->local_bus, m, NULL);
        if (r < 0) {
                if (r == -ECONNRESET || r == -ENOTCONN)
                        return r;

                /* If the peer tries to send a reply and it is
                 * rejected with EPERM by the kernel, we ignore the
                 * error. This catches cases where the original
                 * method-call didn't had EXPECT_REPLY set, but the
                 * proxy-peer still sends a reply. This is allowed in
                 * dbus1, but not in kdbus. We don't want to track
                 * reply-windows in the proxy, so we simply ignore
                 * EPERM for all replies. The only downside is, that
                 * callers are no longer notified if their replies are
                 * dropped. However, this is equivalent to the
                 * caller's timeout to expire, so this should be
                 * acceptable. Nobody sane sends replies without a
                 * matching method-call, so nobody should care. */
                if (r == -EPERM && m->reply_cookie > 0)
                        return 1;

                /* Return the error to the client, if we can */
                synthetic_reply_method_errnof(m, r, "Failed to forward message we got from destination: %m");
                if (r == -ENOBUFS) {
                        /* if local dbus1 peer does not dispatch its queue, warn only once */
                        if (!p->queue_overflow)
                                log_error("Dropped messages due to queue overflow of local peer (pid: "PID_FMT" uid: "UID_FMT")", p->local_creds.pid, p->local_creds.uid);
                        p->queue_overflow = true;
                } else
                        log_error_errno(r,
                                 "Failed to forward message we got from destination: uid=" UID_FMT " gid=" GID_FMT" message=%s destination=%s path=%s interface=%s member=%s: %m",
                                 p->local_creds.uid, p->local_creds.gid, bus_message_type_to_string(m->header->type),
                                 strna(m->destination), strna(m->path), strna(m->interface), strna(m->member));

                return 1;
        }

        p->queue_overflow = false;
        return 1;
}

static int proxy_process_local_to_destination(Proxy *p) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(p);

        r = sd_bus_process(p->local_bus, &m);
        if (r == -ECONNRESET || r == -ENOTCONN) /* Treat 'connection reset by peer' as clean exit condition */
                return r;
        if (r < 0) {
                log_error_errno(r, "Failed to process local bus: %m");
                return r;
        }
        if (r == 0)
                return 0;
        if (!m)
                return 1;

        /* We officially got EOF, let's quit */
        if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected"))
                return -ECONNRESET;

        r = process_hello(p, m);
        if (r == -ECONNRESET || r == -ENOTCONN)
                return r;
        if (r < 0)
                return log_error_errno(r, "Failed to process HELLO: %m");
        if (r > 0)
                return 1;

        r = bus_proxy_process_driver(p, p->destination_bus, p->local_bus, m, p->policy, &p->local_creds, p->owned_names);
        if (r == -ECONNRESET || r == -ENOTCONN)
                return r;
        if (r < 0)
                return log_error_errno(r, "Failed to process driver calls: %m");
        if (r > 0)
                return 1;

        for (;;) {
                if (p->policy) {
                        r = process_policy(p->local_bus, p->destination_bus, m, p->policy, &p->local_creds, p->owned_names);
                        if (r == -ECONNRESET || r == -ENOTCONN)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to process policy: %m");
                        if (r > 0)
                                return 1;
                }

                r = sd_bus_send(p->destination_bus, m, NULL);
                if (r < 0) {
                        if (r == -ECONNRESET || r == -ENOTCONN)
                                return r;

                        /* The name database changed since the policy check, hence let's check again */
                        if (r == -EREMCHG)
                                continue;

                        /* see above why EPERM is ignored for replies */
                        if (r == -EPERM && m->reply_cookie > 0)
                                return 1;

                        synthetic_reply_method_errnof(m, r, "Failed to forward message we got from local: %m");
                        log_error_errno(r,
                                 "Failed to forward message we got from local: uid=" UID_FMT " gid=" GID_FMT" message=%s destination=%s path=%s interface=%s member=%s: %m",
                                 p->local_creds.uid, p->local_creds.gid, bus_message_type_to_string(m->header->type),
                                 strna(m->destination), strna(m->path), strna(m->interface), strna(m->member));
                        return 1;
                }

                break;
        }

        return 1;
}

int proxy_match(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Proxy *p = userdata;

        p->message_matched = true;
        return 0; /* make sure to continue processing it in further handlers */
}

int proxy_run(Proxy *p) {
        int r;

        assert(p);

        for (;;) {
                bool busy = false;

                if (p->got_hello) {
                        /* Read messages from bus, to pass them on to our client */
                        r = proxy_process_destination_to_local(p);
                        if (r == -ECONNRESET || r == -ENOTCONN)
                                return 0;
                        if (r < 0)
                                return r;
                        if (r > 0)
                                busy = true;
                }

                /* Read messages from our client, to pass them on to the bus */
                r = proxy_process_local_to_destination(p);
                if (r == -ECONNRESET || r == -ENOTCONN)
                        return 0;
                if (r < 0)
                        return r;
                if (r > 0)
                        busy = true;

                if (!busy) {
                        r = proxy_wait(p);
                        if (r == -ECONNRESET || r == -ENOTCONN)
                                return 0;
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
