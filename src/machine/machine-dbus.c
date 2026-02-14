/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-label.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "copy.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "machine.h"
#include "machine-dbus.h"
#include "machined.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "operation.h"
#include "path-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_class, machine_class, MachineClass);
static BUS_DEFINE_PROPERTY_GET2(property_get_state, "s", Machine, machine_get_state, machine_state_to_string);

static int property_get_netif(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Machine *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        assert_cc(sizeof(int) == sizeof(int32_t));

        return sd_bus_message_append_array(reply, 'i', m->netif, m->n_netif * sizeof(int));
}

int bus_machine_method_unregister(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (m->manager->runtime_scope != RUNTIME_SCOPE_USER) {
                const char *details[] = {
                        "machine", m->name,
                        "verb", "unregister",
                        NULL
                };

                r = bus_verify_polkit_async_full(
                                message,
                                "org.freedesktop.machine1.manage-machines",
                                details,
                                m->uid,
                                /* flags= */ 0,
                                &m->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        r = machine_finalize(m);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_machine_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (m->manager->runtime_scope != RUNTIME_SCOPE_USER) {
                const char *details[] = {
                        "machine", m->name,
                        "verb", "terminate",
                        NULL
                };

                r = bus_verify_polkit_async_full(
                                message,
                                "org.freedesktop.machine1.manage-machines",
                                details,
                                m->uid,
                                /* flags= */ 0,
                                &m->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        r = machine_stop(m);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_machine_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Machine *m = ASSERT_PTR(userdata);
        const char *swho;
        int32_t signo;
        KillWhom whom;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "si", &swho, &signo);
        if (r < 0)
                return r;

        if (isempty(swho))
                whom = KILL_ALL;
        else {
                whom = kill_whom_from_string(swho);
                if (whom < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid kill parameter '%s'", swho);
        }

        if (!SIGNAL_VALID(signo))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal %i", signo);

        if (m->manager->runtime_scope != RUNTIME_SCOPE_USER) {
                const char *details[] = {
                        "machine", m->name,
                        "verb", "kill",
                        NULL
                };

                r = bus_verify_polkit_async_full(
                                message,
                                "org.freedesktop.machine1.manage-machines",
                                details,
                                m->uid,
                                /* flags= */ 0,
                                &m->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        r = machine_kill(m, whom, signo);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_machine_method_get_addresses(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ struct local_address *addresses = NULL;
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(iay)");
        if (r < 0)
                return r;

        int n = machine_get_addresses(m, &addresses);
        if (n == -ENONET)
                return sd_bus_error_setf(error, BUS_ERROR_NO_PRIVATE_NETWORKING, "Machine %s does not use private networking", m->name);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(n))
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Requesting IP address data is only supported on container machines.");
        if (n < 0)
                return sd_bus_error_set_errnof(error, n, "Failed to get addresses: %m");

        for (int i = 0; i < n; i++) {
                r = sd_bus_message_open_container(reply, 'r', "iay");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "i", addresses[i].family);
                if (r < 0)
                        return r;

                r = sd_bus_message_append_array(reply, 'y', &addresses[i].address, FAMILY_ADDRESS_SIZE(addresses[i].family));
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

int bus_machine_method_get_ssh_info(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        if (!m->ssh_address || !m->ssh_private_key_path)
                return -ENOENT;

        r = sd_bus_message_append(reply, "ss", m->ssh_address, m->ssh_private_key_path);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

int bus_machine_method_get_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = machine_get_os_release(m, &l);
        if (r == -ENONET)
                return sd_bus_error_set(error, SD_BUS_ERROR_FAILED, "Machine does not contain OS release information.");
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Requesting OS release data is only supported on container machines.");
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to get OS release: %m");

        return bus_reply_pair_array(message, l);
}

int bus_machine_method_open_pty(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *pty_name = NULL;
        _cleanup_close_ int master = -EBADF;
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (m->manager->runtime_scope != RUNTIME_SCOPE_USER) {
                const char *details[] = {
                        "machine", m->name,
                        NULL
                };

                r = bus_verify_polkit_async_full(
                                message,
                                m->class == MACHINE_HOST ? "org.freedesktop.machine1.host-open-pty" : "org.freedesktop.machine1.open-pty",
                                details,
                                m->uid,
                                /* flags= */ 0,
                                &m->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        master = machine_openpt(m, O_RDWR|O_NOCTTY|O_CLOEXEC, &pty_name);
        if (master < 0)
                return master;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "hs", master, pty_name);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

int bus_machine_method_open_login(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *pty_name = NULL;
        _cleanup_close_ int master = -EBADF;
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (m->manager->runtime_scope != RUNTIME_SCOPE_USER) {
                const char *details[] = {
                        "machine", m->name,
                        "verb", "login",
                        NULL
                };

                r = bus_verify_polkit_async_full(
                                message,
                                m->class == MACHINE_HOST ? "org.freedesktop.machine1.host-login" : "org.freedesktop.machine1.login",
                                details,
                                m->uid,
                                /* flags= */ 0,
                                &m->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        master = machine_openpt(m, O_RDWR|O_NOCTTY|O_CLOEXEC, &pty_name);
        if (master < 0)
                return master;

        r = machine_start_getty(m, pty_name, error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "hs", master, pty_name);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

int bus_machine_method_open_shell(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *pty_name = NULL;
        _cleanup_close_ int master = -EBADF;
        _cleanup_strv_free_ char **env = NULL, **args_wire = NULL, **args = NULL;
        Machine *m = ASSERT_PTR(userdata);
        const char *user, *path;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "ss", &user, &path);
        if (r < 0)
                return r;
        user = isempty(user) ? "root" : user;

        /* Ensure only root can shell into the root namespace, unless it's specifically the host machine,
         * which is owned by uid 0 anyway and cannot be self-registered. This is to avoid unprivileged
         * users registering a process they own in the root user namespace, and then shelling in as root
         * or another user. Note that the shell operation is privileged and requires 'auth_admin', so we
         * do not need to check the caller's uid, as that will be checked by polkit, and if they machine's
         * and the caller's do not match, authorization will be required. It's only the case where the
         * caller owns the machine that will be shortcut and needs to be checked here. */
        if (m->uid != 0 && m->class != MACHINE_HOST) {
                r = pidref_in_same_namespace(&PIDREF_MAKE_FROM_PID(1), &m->leader, NAMESPACE_USER);
                if (r < 0)
                        return log_debug_errno(
                                        r,
                                        "Failed to check if machine '%s' is running in the root user namespace: %m",
                                        m->name);
                if (r != 0)
                        return sd_bus_error_set(
                                        error,
                                        SD_BUS_ERROR_ACCESS_DENIED,
                                        "Only root may shell into the root user namespace");
        }

        r = sd_bus_message_read_strv(message, &args_wire);
        if (r < 0)
                return r;
        if (isempty(path)) {
                path = machine_default_shell_path();
                args = machine_default_shell_args(user);
                if (!args)
                        return -ENOMEM;
        } else {
                if (!path_is_absolute(path))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified path '%s' is not absolute", path);
                args = TAKE_PTR(args_wire);
                if (strv_isempty(args)) {
                        args = strv_free(args);

                        args = strv_new(path);
                        if (!args)
                                return -ENOMEM;
                }
        }

        r = sd_bus_message_read_strv(message, &env);
        if (r < 0)
                return r;
        if (!strv_env_is_valid(env))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment assignments");

        if (m->manager->runtime_scope != RUNTIME_SCOPE_USER) {
                _cleanup_free_ char *command_line = strv_join(args, " ");
                if (!command_line)
                        return -ENOMEM;

                const char *details[] = {
                        "machine", m->name,
                        "user", user,
                        "program", path,
                        "command_line", command_line,
                        NULL
                };

                r = bus_verify_polkit_async_full(
                                message,
                                m->class == MACHINE_HOST ? "org.freedesktop.machine1.host-shell" : "org.freedesktop.machine1.shell",
                                details,
                                m->uid,
                                /* flags= */ 0,
                                &m->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        master = machine_openpt(m, O_RDWR|O_NOCTTY|O_CLOEXEC, &pty_name);
        if (master < 0)
                return master;

        r = machine_start_shell(m, master, pty_name, user, path, args, env, error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "hs", master, pty_name);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

int bus_machine_method_bind_mount(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        int read_only, make_file_or_directory;
        const char *dest, *src, *propagate_directory;
        Machine *m = ASSERT_PTR(userdata);
        MountInNamespaceFlags flags = 0;
        uid_t uid;
        int r;

        assert(message);

        if (m->class != MACHINE_CONTAINER)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Bind mounting is only supported on container machines.");

        r = sd_bus_message_read(message, "ssbb", &src, &dest, &read_only, &make_file_or_directory);
        if (r < 0)
                return r;

        if (!path_is_absolute(src) || !path_is_normalized(src))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Source path must be absolute and normalized.");

        if (isempty(dest))
                dest = src;
        else if (!path_is_absolute(dest) || !path_is_normalized(dest))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Destination path must be absolute and normalized.");

        if (m->manager->runtime_scope != RUNTIME_SCOPE_USER) {
                const char *details[] = {
                        "machine", m->name,
                        "verb", "bind",
                        "src", src,
                        "dest", dest,
                        NULL
                };

                /* NB: For now not opened up to owner of machine without auth */
                r = bus_verify_polkit_async(
                                message,
                                "org.freedesktop.machine1.manage-machines",
                                details,
                                &m->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        r = machine_get_uid_shift(m, &uid);
        if (r < 0)
                return r;
        if (uid != 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Can't bind mount on container with user namespacing applied.");

        if (read_only)
                flags |= MOUNT_IN_NAMESPACE_READ_ONLY;
        if (make_file_or_directory)
                flags |= MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY;

        propagate_directory = strjoina("/run/systemd/nspawn/propagate/", m->name);
        r = bind_mount_in_namespace(
                        &m->leader,
                        propagate_directory,
                        "/run/host/incoming/",
                        src, dest,
                        flags);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to mount %s on %s in machine's namespace: %m", src, dest);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_machine_method_copy(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *src, *dest, *host_path, *container_path;
        CopyFlags copy_flags = COPY_REFLINK|COPY_MERGE|COPY_HARDLINKS;
        Machine *m = ASSERT_PTR(userdata);
        Manager *manager = m->manager;
        bool copy_from;
        int r;

        assert(message);

        if (m->manager->n_operations >= OPERATIONS_MAX)
                return sd_bus_error_set(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing copies.");

        if (m->class != MACHINE_CONTAINER)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Copying files is only supported on container machines.");

        r = sd_bus_message_read(message, "ss", &src, &dest);
        if (r < 0)
                return r;

        if (endswith(sd_bus_message_get_member(message), "WithFlags")) {
                uint64_t raw_flags;

                r = sd_bus_message_read(message, "t", &raw_flags);
                if (r < 0)
                        return r;

                if ((raw_flags & ~_MACHINE_COPY_FLAGS_MASK_PUBLIC) != 0)
                        return -EINVAL;

                if (raw_flags & MACHINE_COPY_REPLACE)
                        copy_flags |= COPY_REPLACE;
        }

        if (!path_is_absolute(src))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Source path must be absolute.");

        if (isempty(dest))
                dest = src;
        else if (!path_is_absolute(dest))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Destination path must be absolute.");

        if (manager->runtime_scope != RUNTIME_SCOPE_USER) {
                const char *details[] = {
                        "machine", m->name,
                        "verb", "copy",
                        "src", src,
                        "dest", dest,
                        NULL
                };

                /* NB: For now not opened up to owner of machine without auth */
                r = bus_verify_polkit_async(
                                message,
                                "org.freedesktop.machine1.manage-machines",
                                details,
                                &manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        copy_from = strstr(sd_bus_message_get_member(message), "CopyFrom");

        if (copy_from) {
                container_path = src;
                host_path = dest;
        } else {
                host_path = src;
                container_path = dest;
        }

        Operation *op;
        r = machine_copy_from_to_operation(manager, m, host_path, container_path, copy_from, copy_flags, &op);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to copy from/to machine '%s': %m", m->name);

        operation_attach_bus_reply(op, message);
        return 1;
}

int bus_machine_method_open_root_directory(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_close_ int fd = -EBADF;
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        if (m->manager->runtime_scope != RUNTIME_SCOPE_USER) {
                const char *details[] = {
                        "machine", m->name,
                        "verb", "open_root_directory",
                        NULL
                };

                /* NB: For now not opened up to owner of machine without auth */
                r = bus_verify_polkit_async(
                                message,
                                "org.freedesktop.machine1.manage-machines",
                                details,
                                &m->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        fd = machine_open_root_directory(m);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(fd))
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Opening the root directory is only supported on container machines.");
        if (fd < 0)
                return sd_bus_error_set_errnof(error, fd, "Failed to open root directory of machine '%s': %m", m->name);

        return sd_bus_reply_method_return(message, "h", fd);
}

int bus_machine_method_get_uid_shift(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Machine *m = ASSERT_PTR(userdata);
        uid_t shift = 0;
        int r;

        assert(message);

        /* You wonder why this is a method and not a property? Well, properties are not supposed to return errors, but
         * we kinda have to for this. */

        if (m->class == MACHINE_HOST)
                return sd_bus_reply_method_return(message, "u", UINT32_C(0));

        if (m->class != MACHINE_CONTAINER)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "UID/GID shift may only be determined for container machines.");

        r = machine_get_uid_shift(m, &shift);
        if (r == -ENXIO)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Machine %s uses a complex UID/GID mapping, cannot determine shift", m->name);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "u", (uint32_t) shift);
}

static int machine_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Machine *machine;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        if (streq(path, "/org/freedesktop/machine1/machine/self")) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                sd_bus_message *message;

                message = sd_bus_get_current_message(bus);
                if (!message)
                        return 0;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID|SD_BUS_CREDS_PIDFD, &creds);
                if (r < 0)
                        return r;

                r = bus_creds_get_pidref(creds, &pidref);
                if (r < 0)
                        return r;

                r = manager_get_machine_by_pidref(m, &pidref, &machine);
                if (r <= 0)
                        return 0;
        } else {
                _cleanup_free_ char *e = NULL;
                const char *p;

                p = startswith(path, "/org/freedesktop/machine1/machine/");
                if (!p)
                        return 0;

                e = bus_label_unescape(p);
                if (!e)
                        return -ENOMEM;

                machine = hashmap_get(m->machines, e);
                if (!machine)
                        return 0;
        }

        *found = machine;
        return 1;
}

char* machine_bus_path(Machine *m) {
        _cleanup_free_ char *e = NULL;

        assert(m);

        e = bus_label_escape(m->name);
        if (!e)
                return NULL;

        return strjoin("/org/freedesktop/machine1/machine/", e);
}

static int machine_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Machine *machine = NULL;
        Manager *m = userdata;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        HASHMAP_FOREACH(machine, m->machines) {
                char *p;

                p = machine_bus_path(machine);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        *nodes = TAKE_PTR(l);

        return 1;
}

static const sd_bus_vtable machine_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Name", "s", NULL, offsetof(Machine, name), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Id", "ay", bus_property_get_id128, offsetof(Machine, id), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("Timestamp", offsetof(Machine, timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Service", "s", NULL, offsetof(Machine, service), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Unit", "s", NULL, offsetof(Machine, unit), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Scope", "s", NULL, offsetof(Machine, unit), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("Subgroup", "s", NULL, offsetof(Machine, subgroup), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Leader", "u", bus_property_get_pid, offsetof(Machine, leader.pid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LeaderPIDFDId", "t", bus_property_get_pidfdid, offsetof(Machine, leader), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Supervisor", "u", bus_property_get_pid, offsetof(Machine, supervisor.pid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SupervisorPIDFDId", "t", bus_property_get_pidfdid, offsetof(Machine, supervisor), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Class", "s", property_get_class, offsetof(Machine, class), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RootDirectory", "s", NULL, offsetof(Machine, root_directory), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NetworkInterfaces", "ai", property_get_netif, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("VSockCID", "u", NULL, offsetof(Machine, vsock_cid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SSHAddress", "s", NULL, offsetof(Machine, ssh_address), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SSHPrivateKeyPath", "s", NULL, offsetof(Machine, ssh_private_key_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("State", "s", property_get_state, 0, 0),
        SD_BUS_PROPERTY("UID", "u", bus_property_get_uid, offsetof(Machine, uid), SD_BUS_VTABLE_PROPERTY_CONST),

        SD_BUS_METHOD("Terminate",
                      NULL,
                      NULL,
                      bus_machine_method_terminate,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Kill",
                                SD_BUS_ARGS("s", whom, "i", signal),
                                SD_BUS_NO_RESULT,
                                bus_machine_method_kill,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetAddresses",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(iay)", addresses),
                                bus_machine_method_get_addresses,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetSSHInfo",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", ssh_address, "s", ssh_private_key_path),
                                bus_machine_method_get_ssh_info,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetOSRelease",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a{ss}", fields),
                                bus_machine_method_get_os_release,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUIDShift",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("u", shift),
                                bus_machine_method_get_uid_shift,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("OpenPTY",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("h", pty, "s", pty_path),
                                bus_machine_method_open_pty,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("OpenLogin",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("h", pty, "s", pty_path),
                                bus_machine_method_open_login,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("OpenShell",
                                SD_BUS_ARGS("s", user, "s", path, "as", args, "as", environment),
                                SD_BUS_RESULT("h", pty, "s", pty_path),
                                bus_machine_method_open_shell,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("BindMount",
                                SD_BUS_ARGS("s", source, "s", destination, "b", read_only, "b", mkdir),
                                SD_BUS_NO_RESULT,
                                bus_machine_method_bind_mount,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CopyFrom",
                                SD_BUS_ARGS("s", source, "s", destination),
                                SD_BUS_NO_RESULT,
                                bus_machine_method_copy,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CopyTo",
                                SD_BUS_ARGS("s", source, "s", destination),
                                SD_BUS_NO_RESULT,
                                bus_machine_method_copy,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CopyFromWithFlags",
                                SD_BUS_ARGS("s", source, "s", destination, "t", flags),
                                SD_BUS_NO_RESULT,
                                bus_machine_method_copy,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CopyToWithFlags",
                                SD_BUS_ARGS("s", source, "s", destination, "t", flags),
                                SD_BUS_NO_RESULT,
                                bus_machine_method_copy,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("OpenRootDirectory",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("h", fd),
                                bus_machine_method_open_root_directory,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation machine_object = {
        "/org/freedesktop/machine1/machine",
        "org.freedesktop.machine1.Machine",
        .fallback_vtables = BUS_FALLBACK_VTABLES({machine_vtable, machine_object_find}),
        .node_enumerator = machine_node_enumerator,
};

int machine_send_signal(Machine *m, const char *signal_name) {
        assert(m);
        assert(signal_name);

        _cleanup_free_ char *p = machine_bus_path(m);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_signal(
                        m->manager->api_bus,
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        signal_name,
                        "so", m->name, p);
}

int machine_send_create_reply(Machine *m, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *c = NULL;
        _cleanup_free_ char *p = NULL;

        assert(m);

        if (!m->create_message)
                return 0;

        c = TAKE_PTR(m->create_message);

        if (error)
                return sd_bus_reply_method_error(c, error);

        /* Update the machine state file before we notify the client
         * about the result. */
        machine_save(m);

        p = machine_bus_path(m);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(c, "o", p);
}
