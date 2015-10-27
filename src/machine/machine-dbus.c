/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <errno.h>
#include <string.h>
#include <sys/mount.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the POSIX
 * version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-internal.h"
#include "bus-label.h"
#include "bus-util.h"
#include "copy.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "fs-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "machine-dbus.h"
#include "machine.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"

static int property_get_id(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Machine *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        return sd_bus_message_append_array(reply, 'y', &m->id, 16);
}

static int property_get_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Machine *m = userdata;
        const char *state;
        int r;

        assert(bus);
        assert(reply);
        assert(m);

        state = machine_state_to_string(machine_get_state(m));

        r = sd_bus_message_append_basic(reply, 's', state);
        if (r < 0)
                return r;

        return 1;
}

static int property_get_netif(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Machine *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        assert_cc(sizeof(int) == sizeof(int32_t));

        return sd_bus_message_append_array(reply, 'i', m->netif, m->n_netif * sizeof(int));
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_class, machine_class, MachineClass);

int bus_machine_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Machine *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = bus_verify_polkit_async(
                        message,
                        CAP_KILL,
                        "org.freedesktop.machine1.manage-machines",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = machine_stop(m);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_machine_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Machine *m = userdata;
        const char *swho;
        int32_t signo;
        KillWho who;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "si", &swho, &signo);
        if (r < 0)
                return r;

        if (isempty(swho))
                who = KILL_ALL;
        else {
                who = kill_who_from_string(swho);
                if (who < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid kill parameter '%s'", swho);
        }

        if (signo <= 0 || signo >= _NSIG)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal %i", signo);

        r = bus_verify_polkit_async(
                        message,
                        CAP_KILL,
                        "org.freedesktop.machine1.manage-machines",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = machine_kill(m, who, signo);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_machine_method_get_addresses(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Machine *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(iay)");
        if (r < 0)
                return r;

        switch (m->class) {

        case MACHINE_HOST: {
                _cleanup_free_ struct local_address *addresses = NULL;
                struct local_address *a;
                int n, i;

                n = local_addresses(NULL, 0, AF_UNSPEC, &addresses);
                if (n < 0)
                        return n;

                for (a = addresses, i = 0; i < n; a++, i++) {

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

                break;
        }

        case MACHINE_CONTAINER: {
                _cleanup_close_pair_ int pair[2] = { -1, -1 };
                _cleanup_free_ char *us = NULL, *them = NULL;
                _cleanup_close_ int netns_fd = -1;
                const char *p;
                siginfo_t si;
                pid_t child;

                r = readlink_malloc("/proc/self/ns/net", &us);
                if (r < 0)
                        return r;

                p = procfs_file_alloca(m->leader, "ns/net");
                r = readlink_malloc(p, &them);
                if (r < 0)
                        return r;

                if (streq(us, them))
                        return sd_bus_error_setf(error, BUS_ERROR_NO_PRIVATE_NETWORKING, "Machine %s does not use private networking", m->name);

                r = namespace_open(m->leader, NULL, NULL, &netns_fd, NULL, NULL);
                if (r < 0)
                        return r;

                if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0)
                        return -errno;

                child = fork();
                if (child < 0)
                        return sd_bus_error_set_errnof(error, errno, "Failed to fork(): %m");

                if (child == 0) {
                        _cleanup_free_ struct local_address *addresses = NULL;
                        struct local_address *a;
                        int i, n;

                        pair[0] = safe_close(pair[0]);

                        r = namespace_enter(-1, -1, netns_fd, -1, -1);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        n = local_addresses(NULL, 0, AF_UNSPEC, &addresses);
                        if (n < 0)
                                _exit(EXIT_FAILURE);

                        for (a = addresses, i = 0; i < n; a++, i++) {
                                struct iovec iov[2] = {
                                        { .iov_base = &a->family, .iov_len = sizeof(a->family) },
                                        { .iov_base = &a->address, .iov_len = FAMILY_ADDRESS_SIZE(a->family) },
                                };

                                r = writev(pair[1], iov, 2);
                                if (r < 0)
                                        _exit(EXIT_FAILURE);
                        }

                        pair[1] = safe_close(pair[1]);

                        _exit(EXIT_SUCCESS);
                }

                pair[1] = safe_close(pair[1]);

                for (;;) {
                        int family;
                        ssize_t n;
                        union in_addr_union in_addr;
                        struct iovec iov[2];
                        struct msghdr mh = {
                                .msg_iov = iov,
                                .msg_iovlen = 2,
                        };

                        iov[0] = (struct iovec) { .iov_base = &family, .iov_len = sizeof(family) };
                        iov[1] = (struct iovec) { .iov_base = &in_addr, .iov_len = sizeof(in_addr) };

                        n = recvmsg(pair[0], &mh, 0);
                        if (n < 0)
                                return -errno;
                        if ((size_t) n < sizeof(family))
                                break;

                        r = sd_bus_message_open_container(reply, 'r', "iay");
                        if (r < 0)
                                return r;

                        r = sd_bus_message_append(reply, "i", family);
                        if (r < 0)
                                return r;

                        switch (family) {

                        case AF_INET:
                                if (n != sizeof(struct in_addr) + sizeof(family))
                                        return -EIO;

                                r = sd_bus_message_append_array(reply, 'y', &in_addr.in, sizeof(in_addr.in));
                                break;

                        case AF_INET6:
                                if (n != sizeof(struct in6_addr) + sizeof(family))
                                        return -EIO;

                                r = sd_bus_message_append_array(reply, 'y', &in_addr.in6, sizeof(in_addr.in6));
                                break;
                        }
                        if (r < 0)
                                return r;

                        r = sd_bus_message_close_container(reply);
                        if (r < 0)
                                return r;
                }

                r = wait_for_terminate(child, &si);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to wait for child: %m");
                if (si.si_code != CLD_EXITED || si.si_status != EXIT_SUCCESS)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Child died abnormally.");
                break;
        }

        default:
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Requesting IP address data is only supported on container machines.");
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

int bus_machine_method_get_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **l = NULL;
        Machine *m = userdata;
        char **k, **v;
        int r;

        assert(message);
        assert(m);

        switch (m->class) {

        case MACHINE_HOST:
                r = load_env_file_pairs(NULL, "/etc/os-release", NULL, &l);
                if (r < 0)
                        return r;

                break;

        case MACHINE_CONTAINER: {
                _cleanup_close_ int mntns_fd = -1, root_fd = -1;
                _cleanup_close_pair_ int pair[2] = { -1, -1 };
                _cleanup_fclose_ FILE *f = NULL;
                siginfo_t si;
                pid_t child;

                r = namespace_open(m->leader, NULL, &mntns_fd, NULL, NULL, &root_fd);
                if (r < 0)
                        return r;

                if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0)
                        return -errno;

                child = fork();
                if (child < 0)
                        return sd_bus_error_set_errnof(error, errno, "Failed to fork(): %m");

                if (child == 0) {
                        _cleanup_close_ int fd = -1;

                        pair[0] = safe_close(pair[0]);

                        r = namespace_enter(-1, mntns_fd, -1, -1, root_fd);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        fd = open("/etc/os-release", O_RDONLY|O_CLOEXEC);
                        if (fd < 0) {
                                fd = open("/usr/lib/os-release", O_RDONLY|O_CLOEXEC);
                                if (fd < 0)
                                        _exit(EXIT_FAILURE);
                        }

                        r = copy_bytes(fd, pair[1], (uint64_t) -1, false);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        _exit(EXIT_SUCCESS);
                }

                pair[1] = safe_close(pair[1]);

                f = fdopen(pair[0], "re");
                if (!f)
                        return -errno;

                pair[0] = -1;

                r = load_env_file_pairs(f, "/etc/os-release", NULL, &l);
                if (r < 0)
                        return r;

                r = wait_for_terminate(child, &si);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to wait for child: %m");
                if (si.si_code != CLD_EXITED || si.si_status != EXIT_SUCCESS)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Child died abnormally.");

                break;
        }

        default:
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Requesting OS release data is only supported on container machines.");
        }

        r = sd_bus_message_new_method_return(message, &reply);
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

int bus_machine_method_open_pty(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ char *pty_name = NULL;
        _cleanup_close_ int master = -1;
        Machine *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        m->class == MACHINE_HOST ? "org.freedesktop.machine1.host-open-pty" : "org.freedesktop.machine1.open-pty",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        master = machine_openpt(m, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (master < 0)
                return master;

        r = ptsname_namespace(master, &pty_name);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "hs", master, pty_name);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int container_bus_new(Machine *m, sd_bus_error *error, sd_bus **ret) {
        int r;

        assert(m);
        assert(ret);

        switch (m->class) {

        case MACHINE_HOST:
                *ret = NULL;
                break;

        case MACHINE_CONTAINER: {
                _cleanup_bus_unref_ sd_bus *bus = NULL;
                char *address;

                r = sd_bus_new(&bus);
                if (r < 0)
                        return r;

                if (asprintf(&address, "x-machine-kernel:pid=%1$" PID_PRI ";x-machine-unix:pid=%1$" PID_PRI, m->leader) < 0)
                        return -ENOMEM;

                bus->address = address;
                bus->bus_client = true;
                bus->trusted = false;
                bus->is_system = true;

                r = sd_bus_start(bus);
                if (r == -ENOENT)
                        return sd_bus_error_set_errnof(error, r, "There is no system bus in container %s.", m->name);
                if (r < 0)
                        return r;

                *ret = bus;
                bus = NULL;
                break;
        }

        default:
                return -EOPNOTSUPP;
        }

        return 0;
}

int bus_machine_method_open_login(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ char *pty_name = NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *allocated_bus = NULL;
        _cleanup_close_ int master = -1;
        sd_bus *container_bus = NULL;
        Machine *m = userdata;
        const char *p, *getty;
        int r;

        assert(message);
        assert(m);

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        m->class == MACHINE_HOST ? "org.freedesktop.machine1.host-login" : "org.freedesktop.machine1.login",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        master = machine_openpt(m, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (master < 0)
                return master;

        r = ptsname_namespace(master, &pty_name);
        if (r < 0)
                return r;

        p = path_startswith(pty_name, "/dev/pts/");
        if (!p)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "PTS name %s is invalid", pty_name);

        r = container_bus_new(m, error, &allocated_bus);
        if (r < 0)
                return r;

        container_bus = allocated_bus ?: m->manager->bus;

        getty = strjoina("container-getty@", p, ".service");

        r = sd_bus_call_method(
                        container_bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        error, NULL,
                        "ss", getty, "replace");
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "hs", master, pty_name);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

int bus_machine_method_open_shell(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL, *tm = NULL;
        _cleanup_free_ char *pty_name = NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *allocated_bus = NULL;
        sd_bus *container_bus = NULL;
        _cleanup_close_ int master = -1, slave = -1;
        _cleanup_strv_free_ char **env = NULL, **args = NULL;
        Machine *m = userdata;
        const char *p, *unit, *user, *path, *description, *utmp_id;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "ss", &user, &path);
        if (r < 0)
                return r;
        if (isempty(user))
                user = NULL;
        if (isempty(path))
                path = "/bin/sh";
        if (!path_is_absolute(path))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified path '%s' is not absolute", path);

        r = sd_bus_message_read_strv(message, &args);
        if (r < 0)
                return r;
        if (strv_isempty(args)) {
                args = strv_free(args);

                args = strv_new(path, NULL);
                if (!args)
                        return -ENOMEM;

                args[0][0] = '-'; /* Tell /bin/sh that this shall be a login shell */
        }

        r = sd_bus_message_read_strv(message, &env);
        if (r < 0)
                return r;
        if (!strv_env_is_valid(env))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment assignments");

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        m->class == MACHINE_HOST ? "org.freedesktop.machine1.host-shell" : "org.freedesktop.machine1.shell",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        master = machine_openpt(m, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (master < 0)
                return master;

        r = ptsname_namespace(master, &pty_name);
        if (r < 0)
                return r;

        p = path_startswith(pty_name, "/dev/pts/");
        assert(p);

        slave = machine_open_terminal(m, pty_name, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (slave < 0)
                return slave;

        utmp_id = path_startswith(pty_name, "/dev/");
        assert(utmp_id);

        r = container_bus_new(m, error, &allocated_bus);
        if (r < 0)
                return r;

        container_bus = allocated_bus ?: m->manager->bus;

        r = sd_bus_message_new_method_call(
                        container_bus,
                        &tm,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (r < 0)
                return r;

        /* Name and mode */
        unit = strjoina("container-shell@", p, ".service", NULL);
        r = sd_bus_message_append(tm, "ss", unit, "fail");
        if (r < 0)
                return r;

        /* Properties */
        r = sd_bus_message_open_container(tm, 'a', "(sv)");
        if (r < 0)
                return r;

        description = strjoina("Shell for User ", isempty(user) ? "root" : user);
        r = sd_bus_message_append(tm,
                                  "(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)",
                                  "Description", "s", description,
                                  "StandardInputFileDescriptor", "h", slave,
                                  "StandardOutputFileDescriptor", "h", slave,
                                  "StandardErrorFileDescriptor", "h", slave,
                                  "SendSIGHUP", "b", true,
                                  "IgnoreSIGPIPE", "b", false,
                                  "KillMode", "s", "mixed",
                                  "TTYReset", "b", true,
                                  "UtmpIdentifier", "s", utmp_id,
                                  "UtmpMode", "s", "user",
                                  "PAMName", "s", "login",
                                  "WorkingDirectory", "s", "-~");
        if (r < 0)
                return r;

        r = sd_bus_message_append(tm, "(sv)", "User", "s", isempty(user) ? "root" : user);
        if (r < 0)
                return r;

        if (!strv_isempty(env)) {
                r = sd_bus_message_open_container(tm, 'r', "sv");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(tm, "s", "Environment");
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(tm, 'v', "as");
                if (r < 0)
                        return r;

                r = sd_bus_message_append_strv(tm, env);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(tm);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(tm);
                if (r < 0)
                        return r;
        }

        /* Exec container */
        r = sd_bus_message_open_container(tm, 'r', "sv");
        if (r < 0)
                return r;

        r = sd_bus_message_append(tm, "s", "ExecStart");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(tm, 'v', "a(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(tm, 'a', "(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(tm, 'r', "sasb");
        if (r < 0)
                return r;

        r = sd_bus_message_append(tm, "s", path);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(tm, args);
        if (r < 0)
                return r;

        r = sd_bus_message_append(tm, "b", true);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        /* Auxiliary units */
        r = sd_bus_message_append(tm, "a(sa(sv))", 0);
        if (r < 0)
                return r;

        r = sd_bus_call(container_bus, tm, 0, error, NULL);
        if (r < 0)
                return r;

        slave = safe_close(slave);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "hs", master, pty_name);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

int bus_machine_method_bind_mount(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        char mount_slave[] = "/tmp/propagate.XXXXXX", *mount_tmp, *mount_outside, *p;
        bool mount_slave_created = false, mount_slave_mounted = false,
                mount_tmp_created = false, mount_tmp_mounted = false,
                mount_outside_created = false, mount_outside_mounted = false;
        const char *dest, *src;
        Machine *m = userdata;
        int read_only, make_directory;
        pid_t child;
        siginfo_t si;
        int r;

        assert(message);
        assert(m);

        if (m->class != MACHINE_CONTAINER)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Bind mounting is only supported on container machines.");

        r = sd_bus_message_read(message, "ssbb", &src, &dest, &read_only, &make_directory);
        if (r < 0)
                return r;

        if (!path_is_absolute(src) || !path_is_safe(src))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Source path must be absolute and not contain ../.");

        if (isempty(dest))
                dest = src;
        else if (!path_is_absolute(dest) || !path_is_safe(dest))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Destination path must be absolute and not contain ../.");

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-machines",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        /* One day, when bind mounting /proc/self/fd/n works across
         * namespace boundaries we should rework this logic to make
         * use of it... */

        p = strjoina("/run/systemd/nspawn/propagate/", m->name, "/");
        if (laccess(p, F_OK) < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Container does not allow propagation of mount points.");

        /* Our goal is to install a new bind mount into the container,
           possibly read-only. This is irritatingly complex
           unfortunately, currently.

           First, we start by creating a private playground in /tmp,
           that we can mount MS_SLAVE. (Which is necessary, since
           MS_MOUNT cannot be applied to mounts with MS_SHARED parent
           mounts.) */

        if (!mkdtemp(mount_slave))
                return sd_bus_error_set_errnof(error, errno, "Failed to create playground %s: %m", mount_slave);

        mount_slave_created = true;

        if (mount(mount_slave, mount_slave, NULL, MS_BIND, NULL) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to make bind mount %s: %m", mount_slave);
                goto finish;
        }

        mount_slave_mounted = true;

        if (mount(NULL, mount_slave, NULL, MS_SLAVE, NULL) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to remount slave %s: %m", mount_slave);
                goto finish;
        }

        /* Second, we mount the source directory to a directory inside
           of our MS_SLAVE playground. */
        mount_tmp = strjoina(mount_slave, "/mount");
        if (mkdir(mount_tmp, 0700) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to create temporary mount point %s: %m", mount_tmp);
                goto finish;
        }

        mount_tmp_created = true;

        if (mount(src, mount_tmp, NULL, MS_BIND, NULL) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to overmount %s: %m", mount_tmp);
                goto finish;
        }

        mount_tmp_mounted = true;

        /* Third, we remount the new bind mount read-only if requested. */
        if (read_only)
                if (mount(NULL, mount_tmp, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) < 0) {
                        r = sd_bus_error_set_errnof(error, errno, "Failed to remount read-only %s: %m", mount_tmp);
                        goto finish;
                }

        /* Fourth, we move the new bind mount into the propagation
         * directory. This way it will appear there read-only
         * right-away. */

        mount_outside = strjoina("/run/systemd/nspawn/propagate/", m->name, "/XXXXXX");
        if (!mkdtemp(mount_outside)) {
                r = sd_bus_error_set_errnof(error, errno, "Cannot create propagation directory %s: %m", mount_outside);
                goto finish;
        }

        mount_outside_created = true;

        if (mount(mount_tmp, mount_outside, NULL, MS_MOVE, NULL) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to move %s to %s: %m", mount_tmp, mount_outside);
                goto finish;
        }

        mount_outside_mounted = true;
        mount_tmp_mounted = false;

        (void) rmdir(mount_tmp);
        mount_tmp_created = false;

        (void) umount(mount_slave);
        mount_slave_mounted = false;

        (void) rmdir(mount_slave);
        mount_slave_created = false;

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to create pipe: %m");
                goto finish;
        }

        child = fork();
        if (child < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to fork(): %m");
                goto finish;
        }

        if (child == 0) {
                const char *mount_inside;
                int mntfd;
                const char *q;

                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                q = procfs_file_alloca(m->leader, "ns/mnt");
                mntfd = open(q, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntfd < 0) {
                        r = log_error_errno(errno, "Failed to open mount namespace of leader: %m");
                        goto child_fail;
                }

                if (setns(mntfd, CLONE_NEWNS) < 0) {
                        r = log_error_errno(errno, "Failed to join namespace of leader: %m");
                        goto child_fail;
                }

                if (make_directory)
                        (void) mkdir_p(dest, 0755);

                /* Fifth, move the mount to the right place inside */
                mount_inside = strjoina("/run/systemd/nspawn/incoming/", basename(mount_outside));
                if (mount(mount_inside, dest, NULL, MS_MOVE, NULL) < 0) {
                        r = log_error_errno(errno, "Failed to mount: %m");
                        goto child_fail;
                }

                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(errno_pipe_fd[1], &r, sizeof(r));
                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                _exit(EXIT_FAILURE);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = wait_for_terminate(child, &si);
        if (r < 0) {
                r = sd_bus_error_set_errnof(error, r, "Failed to wait for child: %m");
                goto finish;
        }
        if (si.si_code != CLD_EXITED) {
                r = sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Child died abnormally.");
                goto finish;
        }
        if (si.si_status != EXIT_SUCCESS) {

                if (read(errno_pipe_fd[0], &r, sizeof(r)) == sizeof(r))
                        r = sd_bus_error_set_errnof(error, r, "Failed to mount: %m");
                else
                        r = sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Child failed.");
                goto finish;
        }

        r = sd_bus_reply_method_return(message, NULL);

finish:
        if (mount_outside_mounted)
                umount(mount_outside);
        if (mount_outside_created)
                rmdir(mount_outside);

        if (mount_tmp_mounted)
                umount(mount_tmp);
        if (mount_tmp_created)
                rmdir(mount_tmp);

        if (mount_slave_mounted)
                umount(mount_slave);
        if (mount_slave_created)
                rmdir(mount_slave);

        return r;
}

static int machine_operation_done(sd_event_source *s, const siginfo_t *si, void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        MachineOperation *o = userdata;
        int r;

        assert(o);
        assert(si);

        o->pid = 0;

        if (si->si_code != CLD_EXITED) {
                r = sd_bus_error_setf(&error, SD_BUS_ERROR_FAILED, "Child died abnormally.");
                goto fail;
        }

        if (si->si_status != EXIT_SUCCESS) {
                if (read(o->errno_fd, &r, sizeof(r)) == sizeof(r))
                        r = sd_bus_error_set_errnof(&error, r, "%m");
                else
                        r = sd_bus_error_setf(&error, SD_BUS_ERROR_FAILED, "Child failed.");

                goto fail;
        }

        r = sd_bus_reply_method_return(o->message, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to reply to message: %m");

        machine_operation_unref(o);
        return 0;

fail:
        r = sd_bus_reply_method_error(o->message, &error);
        if (r < 0)
                log_error_errno(r, "Failed to reply to message: %m");

        machine_operation_unref(o);
        return 0;
}

int bus_machine_method_copy(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *src, *dest, *host_path, *container_path, *host_basename, *host_dirname, *container_basename, *container_dirname;
        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        _cleanup_close_ int hostfd = -1;
        Machine *m = userdata;
        MachineOperation *o;
        bool copy_from;
        pid_t child;
        char *t;
        int r;

        assert(message);
        assert(m);

        if (m->n_operations >= MACHINE_OPERATIONS_MAX)
                return sd_bus_error_setf(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing copies.");

        if (m->class != MACHINE_CONTAINER)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Copying files is only supported on container machines.");

        r = sd_bus_message_read(message, "ss", &src, &dest);
        if (r < 0)
                return r;

        if (!path_is_absolute(src))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Source path must be absolute.");

        if (isempty(dest))
                dest = src;
        else if (!path_is_absolute(dest))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Destination path must be absolute.");

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-machines",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        copy_from = strstr(sd_bus_message_get_member(message), "CopyFrom");

        if (copy_from) {
                container_path = src;
                host_path = dest;
        } else {
                host_path = src;
                container_path = dest;
        }

        host_basename = basename(host_path);
        t = strdupa(host_path);
        host_dirname = dirname(t);

        container_basename = basename(container_path);
        t = strdupa(container_path);
        container_dirname = dirname(t);

        hostfd = open(host_dirname, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_DIRECTORY);
        if (hostfd < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to open host directory %s: %m", host_dirname);

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to create pipe: %m");

        child = fork();
        if (child < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to fork(): %m");

        if (child == 0) {
                int containerfd;
                const char *q;
                int mntfd;

                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                q = procfs_file_alloca(m->leader, "ns/mnt");
                mntfd = open(q, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntfd < 0) {
                        r = log_error_errno(errno, "Failed to open mount namespace of leader: %m");
                        goto child_fail;
                }

                if (setns(mntfd, CLONE_NEWNS) < 0) {
                        r = log_error_errno(errno, "Failed to join namespace of leader: %m");
                        goto child_fail;
                }

                containerfd = open(container_dirname, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_DIRECTORY);
                if (containerfd < 0) {
                        r = log_error_errno(errno, "Failed top open destination directory: %m");
                        goto child_fail;
                }

                if (copy_from)
                        r = copy_tree_at(containerfd, container_basename, hostfd, host_basename, true);
                else
                        r = copy_tree_at(hostfd, host_basename, containerfd, container_basename, true);

                hostfd = safe_close(hostfd);
                containerfd = safe_close(containerfd);

                if (r < 0) {
                        r = log_error_errno(r, "Failed to copy tree: %m");
                        goto child_fail;
                }

                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(errno_pipe_fd[1], &r, sizeof(r));
                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                _exit(EXIT_FAILURE);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        /* Copying might take a while, hence install a watch the
         * child, and return */

        o = new0(MachineOperation, 1);
        if (!o)
                return log_oom();

        o->pid = child;
        o->message = sd_bus_message_ref(message);
        o->errno_fd = errno_pipe_fd[0];
        errno_pipe_fd[0] = -1;

        r = sd_event_add_child(m->manager->event, &o->event_source, child, WEXITED, machine_operation_done, o);
        if (r < 0) {
                machine_operation_unref(o);
                return log_oom();
        }

        LIST_PREPEND(operations, m->operations, o);
        m->n_operations++;
        o->machine = m;

        return 1;
}

const sd_bus_vtable machine_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Name", "s", NULL, offsetof(Machine, name), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Id", "ay", property_get_id, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("Timestamp", offsetof(Machine, timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Service", "s", NULL, offsetof(Machine, service), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Unit", "s", NULL, offsetof(Machine, unit), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Scope", "s", NULL, offsetof(Machine, unit), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("Leader", "u", NULL, offsetof(Machine, leader), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Class", "s", property_get_class, offsetof(Machine, class), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RootDirectory", "s", NULL, offsetof(Machine, root_directory), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NetworkInterfaces", "ai", property_get_netif, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("State", "s", property_get_state, 0, 0),
        SD_BUS_METHOD("Terminate", NULL, NULL, bus_machine_method_terminate, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Kill", "si", NULL, bus_machine_method_kill, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetAddresses", NULL, "a(iay)", bus_machine_method_get_addresses, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetOSRelease", NULL, "a{ss}", bus_machine_method_get_os_release, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("OpenPTY", NULL, "hs", bus_machine_method_open_pty, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("OpenLogin", NULL, "hs", bus_machine_method_open_login, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("OpenShell", "ssasas", "hs", bus_machine_method_open_shell, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("BindMount", "ssbb", NULL, bus_machine_method_bind_mount, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CopyFrom", "ss", NULL, bus_machine_method_copy, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CopyTo", "ss", NULL, bus_machine_method_copy, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

int machine_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        if (streq(path, "/org/freedesktop/machine1/machine/self")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                sd_bus_message *message;
                pid_t pid;

                message = sd_bus_get_current_message(bus);
                if (!message)
                        return 0;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;

                r = manager_get_machine_by_pid(m, pid, &machine);
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

char *machine_bus_path(Machine *m) {
        _cleanup_free_ char *e = NULL;

        assert(m);

        e = bus_label_escape(m->name);
        if (!e)
                return NULL;

        return strappend("/org/freedesktop/machine1/machine/", e);
}

int machine_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Machine *machine = NULL;
        Manager *m = userdata;
        Iterator i;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        HASHMAP_FOREACH(machine, m->machines, i) {
                char *p;

                p = machine_bus_path(machine);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        *nodes = l;
        l = NULL;

        return 1;
}

int machine_send_signal(Machine *m, bool new_machine) {
        _cleanup_free_ char *p = NULL;

        assert(m);

        p = machine_bus_path(m);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_signal(
                        m->manager->bus,
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        new_machine ? "MachineNew" : "MachineRemoved",
                        "so", m->name, p);
}

int machine_send_create_reply(Machine *m, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *c = NULL;
        _cleanup_free_ char *p = NULL;

        assert(m);

        if (!m->create_message)
                return 0;

        c = m->create_message;
        m->create_message = NULL;

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
