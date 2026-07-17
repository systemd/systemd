/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "fd-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "run-polkit.h"
#include "user-util.h"

int polkit_check_authorization(sd_bus *bus, PolkitFlags flags, char **ret_tmpauthz_id) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        pid_t pid;
        _cleanup_close_ int pidfd = -EBADF;
        _cleanup_free_ char *tmpauthz_id = NULL;
        int is_authorized, is_challenge;
        int r;

        assert(bus);

        r = sd_bus_message_new_method_call(bus, &m,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization");
        if (r < 0)
                return bus_log_create_error(r);

        pid = getpid_cached();

        /* Polkit requires pidfd to honor temporary authorizations */
        pidfd = pidfd_open(pid, 0);
        if (pidfd < 0)
                return log_debug_errno(errno, "pidfd_open failed: %m");

        r = sd_bus_message_append(m, "(sa{sv})s", "unix-process", 4, "pid", "u", (uint32_t) pid,
                        "start-time", "t", UINT64_C(0), "uid", "i", (uint32_t) geteuid(), "pidfd", "h", pidfd,
                        "org.freedesktop.systemd1.manage-units");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "a{ss}us", /* details = */ 0, (uint32_t) flags, /* cancel_id = */ NULL);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, /* usec = */ 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to check authorization: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'r', "bba{ss}");
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read(reply, "bb", &is_authorized, &is_challenge);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_enter_container(reply, 'a', "{ss}");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *key, *value;
                r = sd_bus_message_enter_container(reply, 'e', "ss");
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = sd_bus_message_read(reply, "ss", &key, &value);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (streq(key, "polkit.temporary_authorization_id")) {
                        r = free_and_strdup(&tmpauthz_id, value);
                        if (r < 0)
                                return log_oom();
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        r = sd_bus_message_exit_container(reply); /* a{ss} */
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply); /* (bba{ss}) */
        if (r < 0)
                return bus_log_parse_error(r);

        if (ret_tmpauthz_id && is_authorized)
                *ret_tmpauthz_id = TAKE_PTR(tmpauthz_id);

        return is_authorized;
}

int polkit_revoke_temporary_authorization_by_id(sd_bus *bus, const char *id) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(id);

        r = sd_bus_message_new_method_call(bus, &m,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "RevokeTemporaryAuthorizationById");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", id);
        if (r < 0)
                return bus_log_create_error(r);

        log_debug("Revoking temporary authorization %s", id);
        r = sd_bus_call(bus, m, /* usec = */ 0, &error, /* ret_reply= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to revoke temporary authorization %s: %s",
                                id, bus_error_message(&error, r));

        return 0;
}

static int check_polkit_subject_for_uid(sd_bus_message *m) {
        const char *kind = NULL;
        uid_t uid = UID_INVALID;
        int r;

        r = sd_bus_message_enter_container(m, 'r', "sa{sv}");
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read(m, "s", &kind);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_enter_container(m, 'a', "{sv}");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *key, *contents;
                char type;

                r = sd_bus_message_enter_container(m, 'e', "sv");
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = sd_bus_message_read(m, "s", &key);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (streq(key, "pid")) {
                        if (*contents != SD_BUS_TYPE_UINT32)
                                return bus_log_parse_error(SYNTHETIC_ERRNO(EINVAL));
                        r = sd_bus_message_skip(m, "v");
                        if (r < 0)
                                return bus_log_parse_error(r);
                } else if (streq(key, "start-time")) {
                        if (*contents != SD_BUS_TYPE_UINT64)
                                return bus_log_parse_error(SYNTHETIC_ERRNO(EINVAL));
                        r = sd_bus_message_skip(m, "v");
                        if (r < 0)
                                return bus_log_parse_error(r);
                } else if (streq(key, "uid")) {
                        if (*contents != SD_BUS_TYPE_INT32)
                                return bus_log_parse_error(SYNTHETIC_ERRNO(EINVAL));
                        r = sd_bus_message_read(m, "v", "i", &uid);
                        if (r < 0)
                                return bus_log_parse_error(r);
                } else if (streq(key, "pidfd")) {
                        if (*contents != SD_BUS_TYPE_UNIX_FD)
                                return bus_log_parse_error(SYNTHETIC_ERRNO(EINVAL));
                        r = sd_bus_message_skip(m, "v");
                        if (r < 0)
                                return bus_log_parse_error(r);
                } else {
                        r = sd_bus_message_skip(m, "v");
                        if (r < 0)
                                return bus_log_parse_error(r);
                }

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        r = sd_bus_message_exit_container(m); /* a(sa{sv}) */
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(m); /* (a(sa{sv})) */
        if (r < 0)
                return bus_log_parse_error(r);

        return uid_is_valid(uid) && uid == geteuid();
}

int polkit_revoke_temporary_authorizations(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *session_id = NULL;
        int r;

        assert(bus);

        session_id = getenv("XDG_SESSION_ID");
        if (!session_id)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "XDG_SESSION_ID is not set");

        r = sd_bus_message_new_method_call(bus, &m,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "EnumerateTemporaryAuthorizations");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sa{sv})", "unix-session", 1, "session-id", "s", session_id);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, /* usec = */ 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate temporary authorizations: %s",
                                bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "(ss(sa{sv})tt)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *id = NULL, *action_id = NULL;

                r = sd_bus_message_enter_container(reply, 'r', "ss(sa{sv})tt");
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = sd_bus_message_read(reply, "ss", &id, &action_id);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (streq(action_id, "org.freedesktop.systemd1.manage-units")) {
                        r = check_polkit_subject_for_uid(reply);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                r = polkit_revoke_temporary_authorization_by_id(bus, id);
                                if (r < 0)
                                        return r;
                        }
                } else {
                        r = sd_bus_message_skip(reply, "(sa{sv})");
                        if (r < 0)
                                return bus_log_parse_error(r);
                }

                r = sd_bus_message_skip(reply, "tt");
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}
