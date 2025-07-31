/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-control.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "fd-util.h"
#include "log.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

_public_ int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(unique, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!bus->bus_client)
                return -EINVAL;

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        *unique = bus->unique_name;
        return 0;
}

static int validate_request_name_parameters(
                sd_bus *bus,
                const char *name,
                uint64_t flags,
                uint32_t *ret_param) {

        uint32_t param = 0;

        assert(bus);
        assert(name);
        assert(ret_param);

        assert_return(!(flags & ~(SD_BUS_NAME_ALLOW_REPLACEMENT|SD_BUS_NAME_REPLACE_EXISTING|SD_BUS_NAME_QUEUE)), -EINVAL);
        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return(name[0] != ':', -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

        /* Don't allow requesting the special driver and local names */
        if (STR_IN_SET(name, "org.freedesktop.DBus", "org.freedesktop.DBus.Local"))
                return -EINVAL;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (flags & SD_BUS_NAME_ALLOW_REPLACEMENT)
                param |= BUS_NAME_ALLOW_REPLACEMENT;
        if (flags & SD_BUS_NAME_REPLACE_EXISTING)
                param |= BUS_NAME_REPLACE_EXISTING;
        if (!(flags & SD_BUS_NAME_QUEUE))
                param |= BUS_NAME_DO_NOT_QUEUE;

        *ret_param = param;

        return 0;
}

_public_ int sd_bus_request_name(
                sd_bus *bus,
                const char *name,
                uint64_t flags) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        uint32_t ret, param = 0;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(name, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        r = validate_request_name_parameters(bus, name, flags, &param);
        if (r < 0)
                return r;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "RequestName",
                        NULL,
                        &reply,
                        "su",
                        name,
                        param);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "u", &ret);
        if (r < 0)
                return r;

        switch (ret) {

        case BUS_NAME_ALREADY_OWNER:
                return -EALREADY;

        case BUS_NAME_EXISTS:
                return -EEXIST;

        case BUS_NAME_IN_QUEUE:
                return 0;

        case BUS_NAME_PRIMARY_OWNER:
                return 1;
        }

        return -EIO;
}

static int default_request_name_handler(
                sd_bus_message *m,
                void *userdata,
                sd_bus_error *ret_error) {

        uint32_t ret;
        int r;

        assert(m);

        if (sd_bus_message_is_method_error(m, NULL)) {
                log_debug_errno(sd_bus_message_get_errno(m),
                                "Unable to request name, failing connection: %s",
                                sd_bus_message_get_error(m)->message);

                bus_enter_closing(sd_bus_message_get_bus(m));
                return 1;
        }

        r = sd_bus_message_read(m, "u", &ret);
        if (r < 0)
                return r;

        switch (ret) {

        case BUS_NAME_ALREADY_OWNER:
                log_debug("Already owner of requested service name, ignoring.");
                return 1;

        case BUS_NAME_IN_QUEUE:
                log_debug("In queue for requested service name.");
                return 1;

        case BUS_NAME_PRIMARY_OWNER:
                log_debug("Successfully acquired requested service name.");
                return 1;

        case BUS_NAME_EXISTS:
                log_debug("Requested service name already owned, failing connection.");
                bus_enter_closing(sd_bus_message_get_bus(m));
                return 1;
        }

        log_debug("Unexpected response from RequestName(), failing connection.");
        bus_enter_closing(sd_bus_message_get_bus(m));
        return 1;
}

_public_ int sd_bus_request_name_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *name,
                uint64_t flags,
                sd_bus_message_handler_t callback,
                void *userdata) {

        uint32_t param = 0;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(name, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        r = validate_request_name_parameters(bus, name, flags, &param);
        if (r < 0)
                return r;

        return sd_bus_call_method_async(
                        bus,
                        ret_slot,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "RequestName",
                        callback ?: default_request_name_handler,
                        userdata,
                        "su",
                        name,
                        param);
}

static int validate_release_name_parameters(
                sd_bus *bus,
                const char *name) {

        assert(bus);
        assert(name);

        assert_return(service_name_is_valid(name), -EINVAL);
        assert_return(name[0] != ':', -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

        /* Don't allow releasing the special driver and local names */
        if (STR_IN_SET(name, "org.freedesktop.DBus", "org.freedesktop.DBus.Local"))
                return -EINVAL;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        return 0;
}

_public_ int sd_bus_release_name(
                sd_bus *bus,
                const char *name) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        uint32_t ret;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(name, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        r = validate_release_name_parameters(bus, name);
        if (r < 0)
                return r;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "ReleaseName",
                        NULL,
                        &reply,
                        "s",
                        name);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "u", &ret);
        if (r < 0)
                return r;

        switch (ret) {

        case BUS_NAME_NON_EXISTENT:
                return -ESRCH;

        case BUS_NAME_NOT_OWNER:
                return -EADDRINUSE;

        case BUS_NAME_RELEASED:
                return 0;
        }

        return -EIO;
}

static int default_release_name_handler(
                sd_bus_message *m,
                void *userdata,
                sd_bus_error *ret_error) {

        uint32_t ret;
        int r;

        assert(m);

        if (sd_bus_message_is_method_error(m, NULL)) {
                log_debug_errno(sd_bus_message_get_errno(m),
                                "Unable to release name, failing connection: %s",
                                sd_bus_message_get_error(m)->message);

                bus_enter_closing(sd_bus_message_get_bus(m));
                return 1;
        }

        r = sd_bus_message_read(m, "u", &ret);
        if (r < 0)
                return r;

        switch (ret) {

        case BUS_NAME_NON_EXISTENT:
                log_debug("Name asked to release is not taken currently, ignoring.");
                return 1;

        case BUS_NAME_NOT_OWNER:
                log_debug("Name asked to release is owned by somebody else, ignoring.");
                return 1;

        case BUS_NAME_RELEASED:
                log_debug("Name successfully released.");
                return 1;
        }

        log_debug("Unexpected response from ReleaseName(), failing connection.");
        bus_enter_closing(sd_bus_message_get_bus(m));
        return 1;
}

_public_ int sd_bus_release_name_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *name,
                sd_bus_message_handler_t callback,
                void *userdata) {

        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(name, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        r = validate_release_name_parameters(bus, name);
        if (r < 0)
                return r;

        return sd_bus_call_method_async(
                        bus,
                        ret_slot,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "ReleaseName",
                        callback ?: default_release_name_handler,
                        userdata,
                        "s",
                        name);
}

_public_ int sd_bus_list_names(sd_bus *bus, char ***ret_acquired, char ***ret_activatable) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **x = NULL, **y = NULL;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(ret_acquired || ret_activatable, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!bus->bus_client)
                return -EINVAL;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (ret_acquired) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "ListNames",
                                NULL,
                                &reply,
                                NULL);
                if (r < 0)
                        return r;

                r = sd_bus_message_read_strv(reply, &x);
                if (r < 0)
                        return r;

                reply = sd_bus_message_unref(reply);
        }

        if (ret_activatable) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "ListActivatableNames",
                                NULL,
                                &reply,
                                NULL);
                if (r < 0)
                        return r;

                r = sd_bus_message_read_strv(reply, &y);
                if (r < 0)
                        return r;

                *ret_activatable = TAKE_PTR(y);
        }

        if (ret_acquired)
                *ret_acquired = TAKE_PTR(x);

        return 0;
}

_public_ int sd_bus_get_name_creds(
                sd_bus *bus,
                const char *name,
                uint64_t mask,
                sd_bus_creds **ret) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply_unique = NULL, *reply = NULL;
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
        const char *unique;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(name, -EINVAL);
        assert_return((mask & ~SD_BUS_CREDS_AUGMENT) <= _SD_BUS_CREDS_ALL, -EOPNOTSUPP);
        assert_return(mask == 0 || ret, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);
        assert_return(service_name_is_valid(name), -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

        /* Turn off augmenting if this isn't a local connection. If the connection is not local, then /proc is not
         * going to match. */
        if (!bus->is_local)
                mask &= ~SD_BUS_CREDS_AUGMENT;

        if (streq(name, "org.freedesktop.DBus.Local"))
                return -EINVAL;

        if (streq(name, "org.freedesktop.DBus"))
                return sd_bus_get_owner_creds(bus, mask, ret);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        /* If the name is unique anyway, we can use it directly */
        unique = name[0] == ':' ? name : NULL;

        /* Only query the owner if the caller wants to know it and the name is not unique anyway, or if the caller just
         * wants to check whether a name exists */
        if ((FLAGS_SET(mask, SD_BUS_CREDS_UNIQUE_NAME) && !unique) || mask == 0) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.DBus",
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "GetNameOwner",
                                NULL,
                                &reply_unique,
                                "s",
                                name);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(reply_unique, "s", &unique);
                if (r < 0)
                        return r;
        }

        if (mask != 0) {
                bool need_pid, need_uid, need_gids, need_selinux, need_separate_calls, need_pidfd, need_augment;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                c = bus_creds_new();
                if (!c)
                        return -ENOMEM;

                if ((mask & SD_BUS_CREDS_UNIQUE_NAME) && unique) {
                        c->unique_name = strdup(unique);
                        if (!c->unique_name)
                                return -ENOMEM;

                        c->mask |= SD_BUS_CREDS_UNIQUE_NAME;
                }

                need_augment =
                        (mask & SD_BUS_CREDS_AUGMENT) &&
                        (mask & (SD_BUS_CREDS_UID|SD_BUS_CREDS_SUID|SD_BUS_CREDS_FSUID|
                                 SD_BUS_CREDS_GID|SD_BUS_CREDS_EGID|SD_BUS_CREDS_SGID|SD_BUS_CREDS_FSGID|
                                 SD_BUS_CREDS_SUPPLEMENTARY_GIDS|
                                 SD_BUS_CREDS_COMM|SD_BUS_CREDS_EXE|SD_BUS_CREDS_CMDLINE|
                                 SD_BUS_CREDS_CGROUP|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_USER_UNIT|SD_BUS_CREDS_SLICE|SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID|
                                 SD_BUS_CREDS_EFFECTIVE_CAPS|SD_BUS_CREDS_PERMITTED_CAPS|SD_BUS_CREDS_INHERITABLE_CAPS|SD_BUS_CREDS_BOUNDING_CAPS|
                                 SD_BUS_CREDS_SELINUX_CONTEXT|
                                 SD_BUS_CREDS_AUDIT_SESSION_ID|SD_BUS_CREDS_AUDIT_LOGIN_UID|
                                 SD_BUS_CREDS_PIDFD));

                need_pid = (mask & SD_BUS_CREDS_PID) || need_augment;
                need_uid = mask & SD_BUS_CREDS_EUID;
                need_gids = mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
                need_selinux = mask & SD_BUS_CREDS_SELINUX_CONTEXT;
                need_pidfd = (mask & SD_BUS_CREDS_PIDFD) || need_augment;

                if (need_pid + need_uid + need_selinux + need_pidfd + need_gids > 1) {

                        /* If we need more than one of the credentials, then use GetConnectionCredentials() */

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.DBus",
                                        "/org/freedesktop/DBus",
                                        "org.freedesktop.DBus",
                                        "GetConnectionCredentials",
                                        &error,
                                        &reply,
                                        "s",
                                        unique ?: name);

                        if (r < 0) {

                                if (!sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD))
                                        return r;

                                /* If we got an unknown method error, fall back to the individual calls... */
                                need_separate_calls = true;
                                sd_bus_error_free(&error);

                        } else {
                                need_separate_calls = false;

                                r = sd_bus_message_enter_container(reply, 'a', "{sv}");
                                if (r < 0)
                                        return r;

                                for (;;) {
                                        const char *m;

                                        r = sd_bus_message_enter_container(reply, 'e', "sv");
                                        if (r < 0)
                                                return r;
                                        if (r == 0)
                                                break;

                                        r = sd_bus_message_read(reply, "s", &m);
                                        if (r < 0)
                                                return r;

                                        if (need_uid && streq(m, "UnixUserID")) {
                                                uint32_t u;

                                                r = sd_bus_message_read(reply, "v", "u", &u);
                                                if (r < 0)
                                                        return r;

                                                c->euid = u;
                                                c->mask |= SD_BUS_CREDS_EUID;

                                        } else if (need_pid && streq(m, "ProcessID")) {
                                                uint32_t p;

                                                r = sd_bus_message_read(reply, "v", "u", &p);
                                                if (r < 0)
                                                        return r;

                                                if (!pidref_is_set(&pidref))
                                                        pidref = PIDREF_MAKE_FROM_PID(p);

                                                if (mask & SD_BUS_CREDS_PID) {
                                                        c->pid = p;
                                                        c->mask |= SD_BUS_CREDS_PID;
                                                }

                                        } else if (need_selinux && streq(m, "LinuxSecurityLabel")) {
                                                const void *p = NULL;
                                                size_t sz = 0;

                                                r = sd_bus_message_enter_container(reply, 'v', "ay");
                                                if (r < 0)
                                                        return r;

                                                r = sd_bus_message_read_array(reply, 'y', &p, &sz);
                                                if (r < 0)
                                                        return r;

                                                r = free_and_strndup(&c->label, p, sz);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;

                                                r = sd_bus_message_exit_container(reply);
                                                if (r < 0)
                                                        return r;
                                        } else if (need_pidfd && streq(m, "ProcessFD")) {
                                                int fd;

                                                r = sd_bus_message_read(reply, "v", "h", &fd);
                                                if (r < 0)
                                                        return r;

                                                pidref_done(&pidref);
                                                r = pidref_set_pidfd(&pidref, fd);
                                                if (r < 0)
                                                        return r;

                                                if (mask & SD_BUS_CREDS_PIDFD) {
                                                        fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                                                        if (fd < 0)
                                                                return -errno;

                                                        close_and_replace(c->pidfd, fd);
                                                        c->mask |= SD_BUS_CREDS_PIDFD;
                                                }
                                        } else if (need_gids && streq(m, "UnixGroupIDs")) {

                                                /* Note that D-Bus actually only gives us a combined list of
                                                 * primary gid and supplementary gids. And we don't know
                                                 * which one the primary one is. We'll take the whole shebang
                                                 * hence and use it as the supplementary group list, and not
                                                 * initialize the primary gid field. This is slightly
                                                 * incorrect of course, but only slightly, as in effect if
                                                 * the primary gid is also listed in the supplementary gid
                                                 * it has zero effect. */

                                                r = sd_bus_message_enter_container(reply, 'v', "au");
                                                if (r < 0)
                                                        return r;

                                                r = sd_bus_message_enter_container(reply, 'a', "u");
                                                if (r < 0)
                                                        return r;

                                                for (;;) {
                                                        uint32_t u;

                                                        r = sd_bus_message_read(reply, "u", &u);
                                                        if (r < 0)
                                                                return r;
                                                        if (r == 0)
                                                                break;

                                                        if (!GREEDY_REALLOC(c->supplementary_gids, c->n_supplementary_gids+1))
                                                                return -ENOMEM;

                                                        c->supplementary_gids[c->n_supplementary_gids++] = (gid_t) u;
                                                }

                                                r = sd_bus_message_exit_container(reply);
                                                if (r < 0)
                                                        return r;

                                                r = sd_bus_message_exit_container(reply);
                                                if (r < 0)
                                                        return r;

                                                c->mask |= SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
                                        } else {
                                                r = sd_bus_message_skip(reply, "v");
                                                if (r < 0)
                                                        return r;
                                        }

                                        r = sd_bus_message_exit_container(reply);
                                        if (r < 0)
                                                return r;
                                }

                                r = sd_bus_message_exit_container(reply);
                                if (r < 0)
                                        return r;

                                if (need_pid && !pidref_is_set(&pidref))
                                        return -EPROTO;
                        }

                } else /* When we only need a single field, then let's use separate calls */
                        need_separate_calls = true;

                if (need_separate_calls) {
                        if (need_pid) {
                                uint32_t u;

                                r = sd_bus_call_method(
                                                bus,
                                                "org.freedesktop.DBus",
                                                "/org/freedesktop/DBus",
                                                "org.freedesktop.DBus",
                                                "GetConnectionUnixProcessID",
                                                NULL,
                                                &reply,
                                                "s",
                                                unique ?: name);
                                if (r < 0)
                                        return r;

                                r = sd_bus_message_read(reply, "u", &u);
                                if (r < 0)
                                        return r;

                                if (!pidref_is_set(&pidref))
                                        pidref = PIDREF_MAKE_FROM_PID(u);

                                if (mask & SD_BUS_CREDS_PID) {
                                        c->pid = u;
                                        c->mask |= SD_BUS_CREDS_PID;
                                }

                                reply = sd_bus_message_unref(reply);
                        }

                        if (need_uid) {
                                uint32_t u;

                                r = sd_bus_call_method(
                                                bus,
                                                "org.freedesktop.DBus",
                                                "/org/freedesktop/DBus",
                                                "org.freedesktop.DBus",
                                                "GetConnectionUnixUser",
                                                NULL,
                                                &reply,
                                                "s",
                                                unique ?: name);
                                if (r < 0)
                                        return r;

                                r = sd_bus_message_read(reply, "u", &u);
                                if (r < 0)
                                        return r;

                                c->euid = u;
                                c->mask |= SD_BUS_CREDS_EUID;

                                reply = sd_bus_message_unref(reply);
                        }

                        if (need_selinux) {
                                const void *p = NULL;
                                size_t sz = 0;

                                r = sd_bus_call_method(
                                                bus,
                                                "org.freedesktop.DBus",
                                                "/org/freedesktop/DBus",
                                                "org.freedesktop.DBus",
                                                "GetConnectionSELinuxSecurityContext",
                                                &error,
                                                &reply,
                                                "s",
                                                unique ?: name);
                                if (r < 0) {
                                        if (!sd_bus_error_has_name(&error, SD_BUS_ERROR_SELINUX_SECURITY_CONTEXT_UNKNOWN))
                                                return r;

                                        /* no data is fine */
                                } else {
                                        r = sd_bus_message_read_array(reply, 'y', &p, &sz);
                                        if (r < 0)
                                                return r;

                                        c->label = memdup_suffix0(p, sz);
                                        if (!c->label)
                                                return -ENOMEM;

                                        c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
                                }
                        }
                }

                if (pidref_is_set(&pidref)) {
                        r = bus_creds_add_more(c, mask, &pidref, 0);
                        if (r < 0 && r != -ESRCH) /* Return the error, but ignore ESRCH which just means the process is already gone */
                                return r;
                }
        }

        if (ret)
                *ret = TAKE_PTR(c);

        return 0;
}

static int parse_sockaddr_string(const char *t, char **ret_comm, char **ret_description) {
        _cleanup_free_ char *comm = NULL, *description = NULL;
        const char *e, *sl;

        assert(t);
        assert(ret_comm);
        assert(ret_description);

        e = strstrafter(t, "/bus/");
        if (!e) {
                log_debug("Didn't find /bus/ substring in peer socket address, ignoring.");
                goto not_found;
        }

        sl = strchr(e, '/');
        if (!sl) {
                log_debug("Didn't find / substring after /bus/ in peer socket address, ignoring.");
                goto not_found;
        }

        if (sl - e > 0) {
                comm = strndup(e, sl - e);
                if (!comm)
                        return -ENOMEM;
        }

        sl++;
        if (!isempty(sl)) {
                description = strdup(sl);
                if (!description)
                        return -ENOMEM;
        }

        *ret_comm = TAKE_PTR(comm);
        *ret_description = TAKE_PTR(description);
        return 0;

not_found:
        *ret_comm = *ret_description = NULL;
        return 0;
}

_public_ int sd_bus_get_owner_creds(sd_bus *bus, uint64_t mask, sd_bus_creds **ret) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        bool do_label, do_groups, do_sockaddr_peer, do_pidfd;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return((mask & ~SD_BUS_CREDS_AUGMENT) <= _SD_BUS_CREDS_ALL, -EOPNOTSUPP);
        assert_return(ret, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (!bus->is_local)
                mask &= ~SD_BUS_CREDS_AUGMENT;

        do_label = bus->label && (mask & SD_BUS_CREDS_SELINUX_CONTEXT);
        do_groups = bus->n_groups != SIZE_MAX && (mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS);
        do_sockaddr_peer = bus->sockaddr_size_peer >= offsetof(struct sockaddr_un, sun_path) + 1 &&
                bus->sockaddr_peer.sa.sa_family == AF_UNIX &&
                bus->sockaddr_peer.un.sun_path[0] == 0;
        do_pidfd = bus->pidfd >= 0 && (mask & SD_BUS_CREDS_PIDFD);

        /* Avoid allocating anything if we have no chance of returning useful data */
        if (!bus->ucred_valid && !do_label && !do_groups && !do_sockaddr_peer && !do_pidfd)
                return -ENODATA;

        c = bus_creds_new();
        if (!c)
                return -ENOMEM;

        if (bus->ucred_valid) {
                if (pid_is_valid(bus->ucred.pid)) {
                        c->pid = bus->ucred.pid;
                        c->mask |= SD_BUS_CREDS_PID & mask;

                        pidref = PIDREF_MAKE_FROM_PID(c->pid);
                }

                if (uid_is_valid(bus->ucred.uid)) {
                        c->euid = bus->ucred.uid;
                        c->mask |= SD_BUS_CREDS_EUID & mask;
                }

                if (gid_is_valid(bus->ucred.gid)) {
                        c->egid = bus->ucred.gid;
                        c->mask |= SD_BUS_CREDS_EGID & mask;
                }
        }

        if (do_label) {
                c->label = strdup(bus->label);
                if (!c->label)
                        return -ENOMEM;

                c->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
        }

        if (do_groups) {
                c->supplementary_gids = newdup(gid_t, bus->groups, bus->n_groups);
                if (!c->supplementary_gids)
                        return -ENOMEM;

                c->n_supplementary_gids = bus->n_groups;

                c->mask |= SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
        }

        if (do_sockaddr_peer) {
                _cleanup_free_ char *t = NULL;

                assert(bus->sockaddr_size_peer >= offsetof(struct sockaddr_un, sun_path) + 1);
                assert(bus->sockaddr_peer.sa.sa_family == AF_UNIX);
                assert(bus->sockaddr_peer.un.sun_path[0] == 0);

                /* So this is an abstract namespace socket, good. Now let's find the data we are interested in */
                r = make_cstring(bus->sockaddr_peer.un.sun_path + 1,
                                 bus->sockaddr_size_peer - offsetof(struct sockaddr_un, sun_path) - 1,
                                 MAKE_CSTRING_ALLOW_TRAILING_NUL,
                                 &t);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Can't extract string from peer socket address, ignoring: %m");
                else {
                        r = parse_sockaddr_string(t, &c->comm, &c->description);
                        if (r < 0)
                                return r;

                        if (c->comm)
                                c->mask |= SD_BUS_CREDS_COMM & mask;

                        if (c->description)
                                c->mask |= SD_BUS_CREDS_DESCRIPTION & mask;
                }
        }

        if (do_pidfd) {
                c->pidfd = fcntl(bus->pidfd, F_DUPFD_CLOEXEC, 3);
                if (c->pidfd < 0)
                        return -errno;

                pidref_done(&pidref);
                r = pidref_set_pidfd(&pidref, bus->pidfd);
                if (r < 0)
                        return r;

                c->mask |= SD_BUS_CREDS_PIDFD;
        }

        r = bus_creds_add_more(c, mask, &pidref, 0);
        if (r < 0 && r != -ESRCH) /* If the process vanished, then don't complain, just return what we got */
                return r;

        *ret = TAKE_PTR(c);

        return 0;
}

#define append_eavesdrop(bus, m)                                        \
        ((bus)->is_monitor                                              \
         ? (isempty(m) ? "eavesdrop='true'" : strjoina((m), ",eavesdrop='true'")) \
         : (m))

int bus_add_match_internal(
                sd_bus *bus,
                const char *match,
                uint64_t timeout_usec,
                uint64_t *ret_counter) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        const char *e;
        int r;

        assert(bus);

        if (!bus->bus_client)
                return -EINVAL;

        e = append_eavesdrop(bus, match);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "AddMatch");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", e);
        if (r < 0)
                return r;

        r = sd_bus_call(
                        bus,
                        m,
                        timeout_usec,
                        NULL,
                        &reply);
        if (r < 0)
                return r;

        /* If the caller asked for it, return the read counter of the reply */
        if (ret_counter)
                *ret_counter = reply->read_counter;

        return r;
}

int bus_add_match_internal_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *match,
                sd_bus_message_handler_t callback,
                void *userdata,
                uint64_t timeout_usec) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        const char *e;
        int r;

        assert(bus);

        if (!bus->bus_client)
                return -EINVAL;

        e = append_eavesdrop(bus, match);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "AddMatch");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "s", e);
        if (r < 0)
                return r;

        return sd_bus_call_async(
                        bus,
                        ret_slot,
                        m,
                        callback,
                        userdata,
                        timeout_usec);
}

int bus_remove_match_internal(
                sd_bus *bus,
                const char *match) {

        const char *e;

        assert(bus);
        assert(match);

        if (!bus->bus_client)
                return -EINVAL;

        e = append_eavesdrop(bus, match);

        /* Fire and forget */

        return sd_bus_call_method_async(
                        bus,
                        NULL,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "RemoveMatch",
                        NULL,
                        NULL,
                        "s",
                        e);
}

_public_ int sd_bus_get_name_machine_id(sd_bus *bus, const char *name, sd_id128_t *ret) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
        const char *mid;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(name, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);
        assert_return(service_name_is_valid(name), -EINVAL);

        if (!bus->bus_client)
                return -EINVAL;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (streq_ptr(name, bus->unique_name))
                return sd_id128_get_machine(ret);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        name,
                        "/",
                        "org.freedesktop.DBus.Peer",
                        "GetMachineId");
        if (r < 0)
                return r;

        r = sd_bus_message_set_auto_start(m, false);
        if (r < 0)
                return r;

        r = sd_bus_call(bus, m, 0, NULL, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "s", &mid);
        if (r < 0)
                return r;

        return sd_id128_from_string(mid, ret);
}
