/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-id128.h"

#include "bus-common-errors.h"
#include "bus-internal.h"
#include "bus-label.h"
#include "bus-util.h"
#include "capsule-util.h"
#include "chase.h"
#include "daemon-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "memfd-util.h"
#include "memstream-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "uid-classification.h"

static int name_owner_change_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        sd_event *e = ASSERT_PTR(userdata);

        assert(m);

        sd_bus_close(sd_bus_message_get_bus(m));
        sd_event_exit(e, 0);

        return 1;
}

int bus_log_address_error(int r, BusTransport transport) {
        bool hint = transport == BUS_TRANSPORT_LOCAL && r == -ENOMEDIUM;

        return log_error_errno(r,
                               hint ? "Failed to set bus address: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                                      "Failed to set bus address: %m");
}

int bus_log_connect_full(int log_level, int r, BusTransport transport, RuntimeScope scope) {
        bool hint_vars = transport == BUS_TRANSPORT_LOCAL && r == -ENOMEDIUM,
             hint_addr = transport == BUS_TRANSPORT_LOCAL && ERRNO_IS_PRIVILEGE(r);

        return log_full_errno(log_level, r,
                              hint_vars ? "Failed to connect to %s scope bus via %s transport: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                              hint_addr ? "Failed to connect to %s scope bus via %s transport: Operation not permitted (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                                          "Failed to connect to %s scope bus via %s transport: %m", runtime_scope_to_string(scope), bus_transport_to_string(transport));
}

int bus_async_unregister_and_exit(sd_event *e, sd_bus *bus, const char *name) {
        const char *match;
        const char *unique;
        int r;

        assert(e);
        assert(bus);
        assert(name);

        /* We unregister the name here and then wait for the
         * NameOwnerChanged signal for this event to arrive before we
         * quit. We do this in order to make sure that any queued
         * requests are still processed before we really exit. */

        r = sd_bus_get_unique_name(bus, &unique);
        if (r < 0)
                return r;

        match = strjoina(
                        "sender='org.freedesktop.DBus',"
                        "type='signal',"
                        "interface='org.freedesktop.DBus',"
                        "member='NameOwnerChanged',"
                        "path='/org/freedesktop/DBus',"
                        "arg0='", name, "',",
                        "arg1='", unique, "',",
                        "arg2=''");

        r = sd_bus_add_match_async(bus, NULL, match, name_owner_change_callback, NULL, e);
        if (r < 0)
                return r;

        r = sd_bus_release_name_async(bus, NULL, name, NULL, NULL);
        if (r < 0)
                return r;

        return 0;
}

static bool idle_allowed(void) {
        static int allowed = -1;

        if (allowed >= 0)
                return allowed;

        allowed = secure_getenv_bool("SYSTEMD_EXIT_ON_IDLE");
        if (allowed < 0 && allowed != -ENXIO)
                log_debug_errno(allowed, "Failed to parse $SYSTEMD_EXIT_ON_IDLE, ignoring: %m");

        return allowed != 0;
}

int bus_event_loop_with_idle(
                sd_event *e,
                sd_bus *bus,
                const char *name,
                usec_t timeout,
                check_idle_t check_idle,
                void *userdata) {

        bool exiting = false;
        int r, code;

        assert(e);
        assert(bus);
        assert(name);

        for (;;) {
                bool idle;

                r = sd_event_get_state(e);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        break;

                if (!idle_allowed() || sd_bus_pending_method_calls(bus) > 0)
                        idle = false;
                else if (check_idle)
                        idle = check_idle(userdata);
                else
                        idle = true;

                r = sd_event_run(e, exiting || !idle ? UINT64_MAX : timeout);
                if (r < 0)
                        return r;

                if (r == 0 && !exiting && idle) {
                        log_debug("Idle for %s, exiting.", FORMAT_TIMESPAN(timeout, 1));

                        /* Inform the service manager that we are going down, so that it will queue all
                         * further start requests, instead of assuming we are still running. */
                        (void) sd_notify(false, NOTIFY_STOPPING);

                        r = bus_async_unregister_and_exit(e, bus, name);
                        if (r < 0)
                                return r;

                        exiting = true;
                }
        }

        r = sd_event_get_exit_code(e, &code);
        if (r < 0)
                return r;

        return code;
}

int bus_name_has_owner(sd_bus *c, const char *name, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *rep = NULL;
        int r, has_owner = 0;

        assert(c);
        assert(name);

        r = sd_bus_call_method(c,
                               "org.freedesktop.DBus",
                               "/org/freedesktop/dbus",
                               "org.freedesktop.DBus",
                               "NameHasOwner",
                               error,
                               &rep,
                               "s",
                               name);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(rep, 'b', &has_owner);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        return has_owner;
}

bool bus_error_is_unknown_service(const sd_bus_error *error) {
        return sd_bus_error_has_names(error,
                                      SD_BUS_ERROR_SERVICE_UNKNOWN,
                                      SD_BUS_ERROR_NAME_HAS_NO_OWNER,
                                      BUS_ERROR_NO_SUCH_UNIT);
}

int bus_check_peercred(sd_bus *c) {
        struct ucred ucred;
        int fd, r;

        assert(c);

        fd = sd_bus_get_fd(c);
        if (fd < 0)
                return fd;

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        if (ucred.uid != 0 && ucred.uid != geteuid())
                return -EPERM;

        return 1;
}

int bus_connect_system_systemd(sd_bus **ret_bus) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(ret_bus);

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = sd_bus_set_address(bus, "unix:path=/run/systemd/private");
        if (r < 0)
                return r;

        r = sd_bus_start(bus);
        if (r < 0)
                return r;

        r = bus_check_peercred(bus);
        if (r < 0)
                return r;

        *ret_bus = TAKE_PTR(bus);
        return 0;
}

int bus_connect_user_systemd(sd_bus **ret_bus) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *ee = NULL;
        const char *e;
        int r;

        assert(ret_bus);

        e = secure_getenv("XDG_RUNTIME_DIR");
        if (!e)
                return -ENOMEDIUM;

        ee = bus_address_escape(e);
        if (!ee)
                return -ENOMEM;

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        bus->address = strjoin("unix:path=", ee, "/systemd/private");
        if (!bus->address)
                return -ENOMEM;

        r = sd_bus_start(bus);
        if (r < 0)
                return r;

        r = bus_check_peercred(bus);
        if (r < 0)
                return r;

        *ret_bus = TAKE_PTR(bus);
        return 0;
}

static int pin_capsule_socket(const char *capsule, const char *suffix, uid_t *ret_uid, gid_t *ret_gid) {
        _cleanup_close_ int inode_fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        struct stat st;
        int r;

        assert(capsule);
        assert(suffix);
        assert(ret_uid);
        assert(ret_gid);

        p = path_join("/run/capsules", capsule, suffix);
        if (!p)
                return -ENOMEM;

        /* We enter territory owned by the user, hence let's be paranoid about symlinks and ownership */
        r = chase(p, /* root= */ NULL, CHASE_SAFE|CHASE_PROHIBIT_SYMLINKS, /* ret_path= */ NULL, &inode_fd);
        if (r < 0)
                return r;

        if (fstat(inode_fd, &st) < 0)
                return negative_errno();

        /* Paranoid safety check */
        if (uid_is_system(st.st_uid) || gid_is_system(st.st_gid))
                return -EPERM;

        *ret_uid = st.st_uid;
        *ret_gid = st.st_gid;

        return TAKE_FD(inode_fd);
}

static int bus_set_address_capsule(sd_bus *bus, const char *capsule, const char *suffix, int *ret_pin_fd) {
        _cleanup_close_ int inode_fd = -EBADF;
        _cleanup_free_ char *pp = NULL;
        uid_t uid;
        gid_t gid;
        int r;

        assert(bus);
        assert(capsule);
        assert(suffix);
        assert(ret_pin_fd);

        /* Connects to a capsule's user bus. We need to do so under the capsule's UID/GID, otherwise
         * the service manager might refuse our connection. Hence fake it. */

        r = capsule_name_is_valid(capsule);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        inode_fd = pin_capsule_socket(capsule, suffix, &uid, &gid);
        if (inode_fd < 0)
                return inode_fd;

        pp = bus_address_escape(FORMAT_PROC_FD_PATH(inode_fd));
        if (!pp)
                return -ENOMEM;

        if (asprintf(&bus->address, "unix:path=%s,uid=" UID_FMT ",gid=" GID_FMT, pp, uid, gid) < 0)
                return -ENOMEM;

        *ret_pin_fd = TAKE_FD(inode_fd); /* This fd must be kept pinned until the connection has been established */
        return 0;
}

int bus_set_address_capsule_bus(sd_bus *bus, const char *capsule, int *ret_pin_fd) {
        return bus_set_address_capsule(bus, capsule, "bus", ret_pin_fd);
}

int bus_connect_capsule_systemd(const char *capsule, sd_bus **ret_bus) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int inode_fd = -EBADF;
        int r;

        assert(capsule);
        assert(ret_bus);

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = bus_set_address_capsule(bus, capsule, "systemd/private", &inode_fd);
        if (r < 0)
                return r;

        r = sd_bus_start(bus);
        if (r < 0)
                return r;

        *ret_bus = TAKE_PTR(bus);
        return 0;
}

int bus_connect_capsule_bus(const char *capsule, sd_bus **ret_bus) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int inode_fd = -EBADF;
        int r;

        assert(capsule);
        assert(ret_bus);

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = bus_set_address_capsule_bus(bus, capsule, &inode_fd);
        if (r < 0)
                return r;

        r = sd_bus_set_bus_client(bus, true);
        if (r < 0)
                return r;

        r = sd_bus_start(bus);
        if (r < 0)
                return r;

        *ret_bus = TAKE_PTR(bus);
        return 0;
}

int bus_connect_transport(
                BusTransport transport,
                const char *host,
                RuntimeScope runtime_scope,
                sd_bus **ret) {

        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(transport >= 0);
        assert(transport < _BUS_TRANSPORT_MAX);
        assert(ret);

        switch (transport) {

        case BUS_TRANSPORT_LOCAL:
                assert_return(!host, -EINVAL);

                switch (runtime_scope) {

                case RUNTIME_SCOPE_USER:
                        r = sd_bus_default_user(&bus);
                        break;

                case RUNTIME_SCOPE_SYSTEM:
                        if (sd_booted() <= 0)
                                /* Print a friendly message when the local system is actually not running systemd as PID 1. */
                                return log_error_errno(SYNTHETIC_ERRNO(EHOSTDOWN),
                                                       "System has not been booted with systemd as init system (PID 1). Can't operate.");

                        r = sd_bus_default_system(&bus);
                        break;

                default:
                        assert_not_reached();
                }
                break;

        case BUS_TRANSPORT_REMOTE:
                assert_return(runtime_scope == RUNTIME_SCOPE_SYSTEM, -EOPNOTSUPP);

                r = sd_bus_open_system_remote(&bus, host);
                break;

        case BUS_TRANSPORT_MACHINE:
                switch (runtime_scope) {

                case RUNTIME_SCOPE_USER:
                        r = sd_bus_open_user_machine(&bus, host);
                        break;

                case RUNTIME_SCOPE_SYSTEM:
                        r = sd_bus_open_system_machine(&bus, host);
                        break;

                default:
                        assert_not_reached();
                }

                break;

        case BUS_TRANSPORT_CAPSULE:
                assert_return(runtime_scope == RUNTIME_SCOPE_USER, -EINVAL);

                r = bus_connect_capsule_bus(host, &bus);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        r = sd_bus_set_exit_on_disconnect(bus, true);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(bus);
        return 0;
}

int bus_connect_transport_systemd(
                BusTransport transport,
                const char *host,
                RuntimeScope runtime_scope,
                sd_bus **ret_bus) {

        int r;

        assert(transport >= 0);
        assert(transport < _BUS_TRANSPORT_MAX);
        assert(ret_bus);

        switch (transport) {

        case BUS_TRANSPORT_LOCAL:
                assert_return(!host, -EINVAL);

                switch (runtime_scope) {

                case RUNTIME_SCOPE_USER:
                        r = bus_connect_user_systemd(ret_bus);
                        /* We used to always fall back to the user session bus if we couldn't connect to the
                         * private manager bus. To keep compat with existing code that was setting
                         * DBUS_SESSION_BUS_ADDRESS without setting XDG_RUNTIME_DIR, connect to the user
                         * session bus if DBUS_SESSION_BUS_ADDRESS is set and XDG_RUNTIME_DIR isn't. */
                        if (r == -ENOMEDIUM && secure_getenv("DBUS_SESSION_BUS_ADDRESS")) {
                                log_debug_errno(r, "$XDG_RUNTIME_DIR not set, unable to connect to private bus. Falling back to session bus.");
                                r = sd_bus_default_user(ret_bus);
                        }

                        return r;

                case RUNTIME_SCOPE_SYSTEM:
                        if (sd_booted() <= 0)
                                /* Print a friendly message when the local system is actually not running systemd as PID 1. */
                                return log_error_errno(SYNTHETIC_ERRNO(EHOSTDOWN),
                                                       "System has not been booted with systemd as init system (PID 1). Can't operate.");

                        /* If we are root then let's talk directly to the system instance, instead of
                         * going via the bus. */
                        if (geteuid() == 0)
                                return bus_connect_system_systemd(ret_bus);

                        return sd_bus_default_system(ret_bus);

                default:
                        assert_not_reached();
                }

                break;

        case BUS_TRANSPORT_REMOTE:
                assert_return(runtime_scope == RUNTIME_SCOPE_SYSTEM, -EOPNOTSUPP);
                return sd_bus_open_system_remote(ret_bus, host);

        case BUS_TRANSPORT_MACHINE:
                assert_return(runtime_scope == RUNTIME_SCOPE_SYSTEM, -EOPNOTSUPP);
                return sd_bus_open_system_machine(ret_bus, host);

        case BUS_TRANSPORT_CAPSULE:
                assert_return(runtime_scope == RUNTIME_SCOPE_USER, -EINVAL);
                return bus_connect_capsule_systemd(host, ret_bus);

        default:
                assert_not_reached();
        }
}

/**
 * bus_path_encode_unique() - encode unique object path
 * @b: bus connection or NULL
 * @prefix: object path prefix
 * @sender_id: unique-name of client, or NULL
 * @external_id: external ID to be chosen by client, or NULL
 * @ret_path: storage for encoded object path pointer
 *
 * Whenever we provide a bus API that allows clients to create and manage
 * server-side objects, we need to provide a unique name for these objects. If
 * we let the server choose the name, we suffer from a race condition: If a
 * client creates an object asynchronously, it cannot destroy that object until
 * it received the method reply. It cannot know the name of the new object,
 * thus, it cannot destroy it. Furthermore, it enforces a round-trip.
 *
 * Therefore, many APIs allow the client to choose the unique name for newly
 * created objects. There're two problems to solve, though:
 *    1) Object names are usually defined via dbus object paths, which are
 *       usually globally namespaced. Therefore, multiple clients must be able
 *       to choose unique object names without interference.
 *    2) If multiple libraries share the same bus connection, they must be
 *       able to choose unique object names without interference.
 * The first problem is solved easily by prefixing a name with the
 * unique-bus-name of a connection. The server side must enforce this and
 * reject any other name. The second problem is solved by providing unique
 * suffixes from within sd-bus.
 *
 * This helper allows clients to create unique object-paths. It uses the
 * template '/prefix/sender_id/external_id' and returns the new path in
 * @ret_path (must be freed by the caller).
 * If @sender_id is NULL, the unique-name of @b is used. If @external_id is
 * NULL, this function allocates a unique suffix via @b (by requesting a new
 * cookie). If both @sender_id and @external_id are given, @b can be passed as
 * NULL.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int bus_path_encode_unique(sd_bus *b, const char *prefix, const char *sender_id, const char *external_id, char **ret_path) {
        _cleanup_free_ char *sender_label = NULL, *external_label = NULL;
        char external_buf[DECIMAL_STR_MAX(uint64_t)], *p;
        int r;

        assert_return(b || (sender_id && external_id), -EINVAL);
        assert_return(sd_bus_object_path_is_valid(prefix), -EINVAL);
        assert_return(ret_path, -EINVAL);

        if (!sender_id) {
                r = sd_bus_get_unique_name(b, &sender_id);
                if (r < 0)
                        return r;
        }

        if (!external_id) {
                xsprintf(external_buf, "%"PRIu64, ++b->cookie);
                external_id = external_buf;
        }

        sender_label = bus_label_escape(sender_id);
        if (!sender_label)
                return -ENOMEM;

        external_label = bus_label_escape(external_id);
        if (!external_label)
                return -ENOMEM;

        p = path_join(prefix, sender_label, external_label);
        if (!p)
                return -ENOMEM;

        *ret_path = p;
        return 0;
}

/**
 * bus_path_decode_unique() - decode unique object path
 * @path: object path to decode
 * @prefix: object path prefix
 * @ret_sender: output parameter for sender-id label
 * @ret_external: output parameter for external-id label
 *
 * This does the reverse of bus_path_encode_unique() (see its description for
 * details). Both trailing labels, sender-id and external-id, are unescaped and
 * returned in the given output parameters (the caller must free them).
 *
 * Note that this function returns 0 if the path does not match the template
 * (see bus_path_encode_unique()), 1 if it matched.
 *
 * Returns: Negative error code on failure, 0 if the given object path does not
 *          match the template (return parameters are set to NULL), 1 if it was
 *          parsed successfully (return parameters contain allocated labels).
 */
int bus_path_decode_unique(const char *path, const char *prefix, char **ret_sender, char **ret_external) {
        const char *p, *q;
        char *sender, *external;

        assert(sd_bus_object_path_is_valid(path));
        assert(sd_bus_object_path_is_valid(prefix));
        assert(ret_sender);
        assert(ret_external);

        p = object_path_startswith(path, prefix);
        if (!p) {
                *ret_sender = NULL;
                *ret_external = NULL;
                return 0;
        }

        q = strchr(p, '/');
        if (!q) {
                *ret_sender = NULL;
                *ret_external = NULL;
                return 0;
        }

        sender = bus_label_unescape_n(p, q - p);
        external = bus_label_unescape(q + 1);
        if (!sender || !external) {
                free(sender);
                free(external);
                return -ENOMEM;
        }

        *ret_sender = sender;
        *ret_external = external;
        return 1;
}

int bus_track_add_name_many(sd_bus_track *t, char * const *l) {
        int r = 0;

        assert(t);

        /* Continues adding after failure, and returns the first failure. */

        STRV_FOREACH(i, l)
                RET_GATHER(r, sd_bus_track_add_name(t, *i));
        return r;
}

int bus_track_to_strv(sd_bus_track *t, char ***ret) {
        _cleanup_strv_free_ char **subscribed = NULL;
        int r;

        assert(ret);

        for (const char *n = sd_bus_track_first(t); n; n = sd_bus_track_next(t)) {
                int c = sd_bus_track_count_name(t, n);
                assert(c >= 0);

                for (int j = 0; j < c; j++) {
                        r = strv_extend(&subscribed, n);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(subscribed);
        return 0;
}

int bus_open_system_watch_bind_with_description(sd_bus **ret, const char *description) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        const char *e;
        int r;

        assert(ret);

        /* Match like sd_bus_open_system(), but with the "watch_bind" feature and the Connected() signal
         * turned on. */

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        if (description) {
                r = sd_bus_set_description(bus, description);
                if (r < 0)
                        return r;
        }

        e = secure_getenv("DBUS_SYSTEM_BUS_ADDRESS");
        if (!e)
                e = DEFAULT_SYSTEM_BUS_ADDRESS;

        r = sd_bus_set_address(bus, e);
        if (r < 0)
                return r;

        r = sd_bus_set_bus_client(bus, true);
        if (r < 0)
                return r;

        r = sd_bus_negotiate_creds(bus, true, SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS);
        if (r < 0)
                return r;

        r = sd_bus_set_watch_bind(bus, true);
        if (r < 0)
                return r;

        r = sd_bus_set_connected_signal(bus, true);
        if (r < 0)
                return r;

        r = sd_bus_start(bus);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(bus);

        return 0;
}

int bus_reply_pair_array(sd_bus_message *m, char **l) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(m);

        /* Reply to the specified message with a message containing a dictionary put together from the
         * specified strv */

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "{ss}");
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(k, v, l) {
                r = sd_bus_message_append(reply, "{ss}", *k, *v);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_dump_memory_state_by_fd(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_free_ char *dump = NULL;
        _cleanup_close_ int fd = -EBADF;
        size_t dump_size;
        FILE *f;
        int r;

        assert(message);

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        r = RET_NERRNO(malloc_info(/* options= */ 0, f));
        if (r < 0)
                return r;

        r = memstream_finalize(&m, &dump, &dump_size);
        if (r < 0)
                return r;

        fd = memfd_new_and_seal("malloc-info", dump, dump_size);
        if (fd < 0)
                return fd;

        r = sd_bus_reply_method_return(message, "h", fd);
        if (r < 0)
                return r;

        return 1; /* Stop further processing */
}

/* The default install callback will fail and disconnect the bus if it cannot register the match, but this
 * is only a debug method, we definitely don't want to fail in case there's some permission issue. */
static int dummy_install_callback(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        return 1;
}

int bus_register_malloc_status(sd_bus *bus, const char *destination) {
        const char *match;
        int r;

        assert(bus);
        assert(!isempty(destination));

        match = strjoina("type='method_call',"
                         "interface='org.freedesktop.MemoryAllocation1',"
                         "path='/org/freedesktop/MemoryAllocation1',"
                         "destination='", destination, "',",
                         "member='GetMallocInfo'");

        r = sd_bus_add_match_async(bus, NULL, match, method_dump_memory_state_by_fd, dummy_install_callback, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to subscribe to GetMallocInfo() calls on MemoryAllocation1 interface: %m");

        return 0;
}

int bus_creds_get_pidref(
                sd_bus_creds *c,
                PidRef *ret) {

        int pidfd = -EBADF;
        pid_t pid;
        int r;

        assert(c);
        assert(ret);

        r = sd_bus_creds_get_pid(c, &pid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_pidfd_dup(c, &pidfd);
        if (r < 0 && r != -ENODATA)
                return r;

        *ret = (PidRef) {
                .pid = pid,
                .fd = pidfd,
        };

        return 0;
}

int bus_query_sender_pidref(
                sd_bus_message *m,
                PidRef *ret) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        int r;

        assert(m);
        assert(ret);

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_PID|SD_BUS_CREDS_PIDFD, &creds);
        if (r < 0)
                return r;

        return bus_creds_get_pidref(creds, ret);
}

int bus_get_instance_id(sd_bus *bus, sd_id128_t *ret) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(ret);

        r = sd_bus_call_method(bus,
                               "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetId",
                               /* error = */ NULL, &reply,
                               NULL);
        if (r < 0)
                return r;

        const char *id;

        r = sd_bus_message_read_basic(reply, 's', &id);
        if (r < 0)
                return r;

        return sd_id128_from_string(id, ret);
}

static const char* const bus_transport_table[] = {
        [BUS_TRANSPORT_LOCAL]   = "local",
        [BUS_TRANSPORT_REMOTE]  = "remote",
        [BUS_TRANSPORT_MACHINE] = "machine",
        [BUS_TRANSPORT_CAPSULE] = "capsule",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(bus_transport, BusTransport);
