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
#include <sys/capability.h>
#include <arpa/inet.h>

#include "bus-util.h"
#include "bus-label.h"
#include "strv.h"
#include "bus-errors.h"
#include "copy.h"
#include "fileio.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "machine.h"

static int property_get_id(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Machine *m = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(m);

        r = sd_bus_message_append_array(reply, 'y', &m->id, 16);
        if (r < 0)
                return r;

        return 1;
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
        int r;

        assert(bus);
        assert(reply);
        assert(m);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_append_array(reply, 'i', m->netif, m->n_netif * sizeof(int));
        if (r < 0)
                return r;

        return 1;
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_class, machine_class, MachineClass);

int bus_machine_method_terminate(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Machine *m = userdata;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = machine_stop(m);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_machine_method_kill(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Machine *m = userdata;
        const char *swho;
        int32_t signo;
        KillWho who;
        int r;

        assert(bus);
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

        r = machine_kill(m, who, signo);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_machine_method_get_addresses(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        _cleanup_free_ char *us = NULL, *them = NULL;
        _cleanup_close_ int netns_fd = -1;
        Machine *m = userdata;
        const char *p;
        siginfo_t si;
        pid_t child;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = readlink_malloc("/proc/self/ns/net", &us);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        p = procfs_file_alloca(m->leader, "ns/net");
        r = readlink_malloc(p, &them);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        if (streq(us, them))
                return sd_bus_error_setf(error, BUS_ERROR_NO_PRIVATE_NETWORKING, "Machine %s does not use private networking", m->name);

        r = namespace_open(m->leader, NULL, NULL, &netns_fd, NULL);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0)
                return sd_bus_error_set_errno(error, -errno);

        child = fork();
        if (child < 0)
                return sd_bus_error_set_errno(error, -errno);

        if (child == 0) {
                _cleanup_free_ struct local_address *addresses = NULL;
                struct local_address *a;
                int i, n;

                pair[0] = safe_close(pair[0]);

                r = namespace_enter(-1, -1, netns_fd, -1);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                n = local_addresses(NULL, 0, &addresses);
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

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        r = sd_bus_message_open_container(reply, 'a', "(iay)");
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

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
                        return sd_bus_error_set_errno(error, -errno);
                if ((size_t) n < sizeof(family))
                        break;

                r = sd_bus_message_open_container(reply, 'r', "iay");
                if (r < 0)
                        return sd_bus_error_set_errno(error, r);

                r = sd_bus_message_append(reply, "i", family);
                if (r < 0)
                        return sd_bus_error_set_errno(error, r);

                switch (family) {

                case AF_INET:
                        if (n != sizeof(struct in_addr) + sizeof(family))
                                return sd_bus_error_set_errno(error, EIO);

                        r = sd_bus_message_append_array(reply, 'y', &in_addr.in, sizeof(in_addr.in));
                        break;

                case AF_INET6:
                        if (n != sizeof(struct in6_addr) + sizeof(family))
                                return sd_bus_error_set_errno(error, EIO);

                        r = sd_bus_message_append_array(reply, 'y', &in_addr.in6, sizeof(in_addr.in6));
                        break;
                }
                if (r < 0)
                        return sd_bus_error_set_errno(error, r);

                r = sd_bus_message_close_container(reply);
                if (r < 0)
                        return sd_bus_error_set_errno(error, r);
        }

        r = wait_for_terminate(child, &si);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);
        if (si.si_code != CLD_EXITED || si.si_status != EXIT_SUCCESS)
                return sd_bus_error_set_errno(error, EIO);

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        return sd_bus_send(bus, reply, NULL);
}

int bus_machine_method_get_os_release(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_close_ int mntns_fd = -1, root_fd = -1;
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        Machine *m = userdata;
        char **k, **v;
        siginfo_t si;
        pid_t child;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = namespace_open(m->leader, NULL, &mntns_fd, NULL, &root_fd);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0)
                return sd_bus_error_set_errno(error, -errno);

        child = fork();
        if (child < 0)
                return sd_bus_error_set_errno(error, -errno);

        if (child == 0) {
                _cleanup_close_ int fd = -1;

                pair[0] = safe_close(pair[0]);

                r = namespace_enter(-1, mntns_fd, -1, root_fd);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                fd = open("/etc/os-release", O_RDONLY|O_CLOEXEC);
                if (fd < 0) {
                        fd = open("/usr/lib/os-release", O_RDONLY|O_CLOEXEC);
                        if (fd < 0)
                                _exit(EXIT_FAILURE);
                }

                r = copy_bytes(fd, pair[1], (off_t) -1);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        f = fdopen(pair[0], "re");
        if (!f)
                return sd_bus_error_set_errno(error, -errno);

        pair[0] = -1;

        r = load_env_file_pairs(f, "/etc/os-release", NULL, &l);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        r = wait_for_terminate(child, &si);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);
        if (si.si_code != CLD_EXITED || si.si_status != EXIT_SUCCESS)
                return sd_bus_error_set_errno(error, EIO);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        r = sd_bus_message_open_container(reply, 'a', "{ss}");
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        STRV_FOREACH_PAIR(k, v, l) {
                r = sd_bus_message_append(reply, "{ss}", *k, *v);
                if (r < 0)
                        return sd_bus_error_set_errno(error, r);
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        return sd_bus_send(bus, reply, NULL);
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
        SD_BUS_METHOD("Terminate", NULL, NULL, bus_machine_method_terminate, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("Kill", "si", NULL, bus_machine_method_kill, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("GetAddresses", NULL, "a(iay)", bus_machine_method_get_addresses, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetOSRelease", NULL, "a{ss}", bus_machine_method_get_os_release, SD_BUS_VTABLE_UNPRIVILEGED),
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
