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
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "bus-common-errors.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "formats-util.h"
#include "hostname-util.h"
#include "image-dbus.h"
#include "machine-dbus.h"
#include "machine-image.h"
#include "machine-pool.h"
#include "machined.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "unit-name.h"
#include "user-util.h"

static int property_get_pool_path(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", "/var/lib/machines");
}

static int property_get_pool_usage(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_ int fd = -1;
        uint64_t usage = (uint64_t) -1;
        struct stat st;

        assert(bus);
        assert(reply);

        /* We try to read the quota info from /var/lib/machines, as
         * well as the usage of the loopback file
         * /var/lib/machines.raw, and pick the larger value. */

        fd = open("/var/lib/machines", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd >= 0) {
                BtrfsQuotaInfo q;

                if (btrfs_subvol_get_subtree_quota_fd(fd, 0, &q) >= 0)
                        usage = q.referenced;
        }

        if (stat("/var/lib/machines.raw", &st) >= 0) {
                if (usage == (uint64_t) -1 || st.st_blocks * 512ULL > usage)
                        usage = st.st_blocks * 512ULL;
        }

        return sd_bus_message_append(reply, "t", usage);
}

static int property_get_pool_limit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_ int fd = -1;
        uint64_t size = (uint64_t) -1;
        struct stat st;

        assert(bus);
        assert(reply);

        /* We try to read the quota limit from /var/lib/machines, as
         * well as the size of the loopback file
         * /var/lib/machines.raw, and pick the smaller value. */

        fd = open("/var/lib/machines", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd >= 0) {
                BtrfsQuotaInfo q;

                if (btrfs_subvol_get_subtree_quota_fd(fd, 0, &q) >= 0)
                        size = q.referenced_max;
        }

        if (stat("/var/lib/machines.raw", &st) >= 0) {
                if (size == (uint64_t) -1 || (uint64_t) st.st_size < size)
                        size = st.st_size;
        }

        return sd_bus_message_append(reply, "t", size);
}

static int method_get_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        p = machine_bus_path(machine);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = image_find(name, NULL);
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "No image '%s' known", name);
        if (r < 0)
                return r;

        p = image_bus_path(name);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_machine_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        Machine *machine = NULL;
        pid_t pid;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;

        if (pid < 0)
                return -EINVAL;

        if (pid == 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;
        }

        r = manager_get_machine_by_pid(m, pid, &machine);
        if (r < 0)
                return r;
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_MACHINE_FOR_PID, "PID "PID_FMT" does not belong to any known machine", pid);

        p = machine_bus_path(machine);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_list_machines(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Machine *machine;
        Iterator i;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        r = sd_bus_message_open_container(reply, 'a', "(ssso)");
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        HASHMAP_FOREACH(machine, m->machines, i) {
                _cleanup_free_ char *p = NULL;

                p = machine_bus_path(machine);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(ssso)",
                                          machine->name,
                                          strempty(machine_class_to_string(machine->class)),
                                          machine->service,
                                          p);
                if (r < 0)
                        return sd_bus_error_set_errno(error, r);
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        return sd_bus_send(NULL, reply, NULL);
}

static int method_create_or_register_machine(Manager *manager, sd_bus_message *message, bool read_network, Machine **_m, sd_bus_error *error) {
        const char *name, *service, *class, *root_directory;
        const int32_t *netif = NULL;
        MachineClass c;
        uint32_t leader;
        sd_id128_t id;
        const void *v;
        Machine *m;
        size_t n, n_netif = 0;
        int r;

        assert(manager);
        assert(message);
        assert(_m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;
        if (!machine_name_is_valid(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine name");

        r = sd_bus_message_read_array(message, 'y', &v, &n);
        if (r < 0)
                return r;
        if (n == 0)
                id = SD_ID128_NULL;
        else if (n == 16)
                memcpy(&id, v, n);
        else
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine ID parameter");

        r = sd_bus_message_read(message, "ssus", &service, &class, &leader, &root_directory);
        if (r < 0)
                return r;

        if (read_network) {
                size_t i;

                r = sd_bus_message_read_array(message, 'i', (const void**) &netif, &n_netif);
                if (r < 0)
                        return r;

                n_netif /= sizeof(int32_t);

                for (i = 0; i < n_netif; i++) {
                        if (netif[i] <= 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid network interface index %i", netif[i]);
                }
        }

        if (isempty(class))
                c = _MACHINE_CLASS_INVALID;
        else {
                c = machine_class_from_string(class);
                if (c < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine class parameter");
        }

        if (leader == 1)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid leader PID");

        if (!isempty(root_directory) && !path_is_absolute(root_directory))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Root directory must be empty or an absolute path");

        if (leader == 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                assert_cc(sizeof(uint32_t) == sizeof(pid_t));

                r = sd_bus_creds_get_pid(creds, (pid_t*) &leader);
                if (r < 0)
                        return r;
        }

        if (hashmap_get(manager->machines, name))
                return sd_bus_error_setf(error, BUS_ERROR_MACHINE_EXISTS, "Machine '%s' already exists", name);

        r = manager_add_machine(manager, name, &m);
        if (r < 0)
                return r;

        m->leader = leader;
        m->class = c;
        m->id = id;

        if (!isempty(service)) {
                m->service = strdup(service);
                if (!m->service) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (!isempty(root_directory)) {
                m->root_directory = strdup(root_directory);
                if (!m->root_directory) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (n_netif > 0) {
                assert_cc(sizeof(int32_t) == sizeof(int));
                m->netif = memdup(netif, sizeof(int32_t) * n_netif);
                if (!m->netif) {
                        r = -ENOMEM;
                        goto fail;
                }

                m->n_netif = n_netif;
        }

        *_m = m;

        return 1;

fail:
        machine_add_to_gc_queue(m);
        return r;
}

static int method_create_machine_internal(sd_bus_message *message, bool read_network, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        Machine *m = NULL;
        int r;

        assert(message);
        assert(manager);

        r = method_create_or_register_machine(manager, message, read_network, &m, error);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(message, 'a', "(sv)");
        if (r < 0)
                goto fail;

        r = machine_start(m, message, error);
        if (r < 0)
                goto fail;

        m->create_message = sd_bus_message_ref(message);
        return 1;

fail:
        machine_add_to_gc_queue(m);
        return r;
}

static int method_create_machine_with_network(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_create_machine_internal(message, true, userdata, error);
}

static int method_create_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_create_machine_internal(message, false, userdata, error);
}

static int method_register_machine_internal(sd_bus_message *message, bool read_network, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        _cleanup_free_ char *p = NULL;
        Machine *m = NULL;
        int r;

        assert(message);
        assert(manager);

        r = method_create_or_register_machine(manager, message, read_network, &m, error);
        if (r < 0)
                return r;

        r = cg_pid_get_unit(m->leader, &m->unit);
        if (r < 0) {
                r = sd_bus_error_set_errnof(error, r, "Failed to determine unit of process "PID_FMT" : %s", m->leader, strerror(-r));
                goto fail;
        }

        r = machine_start(m, NULL, error);
        if (r < 0)
                goto fail;

        p = machine_bus_path(m);
        if (!p) {
                r = -ENOMEM;
                goto fail;
        }

        return sd_bus_reply_method_return(message, "o", p);

fail:
        machine_add_to_gc_queue(m);
        return r;
}

static int method_register_machine_with_network(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_register_machine_internal(message, true, userdata, error);
}

static int method_register_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_register_machine_internal(message, false, userdata, error);
}

static int method_terminate_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_terminate(message, machine, error);
}

static int method_kill_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_kill(message, machine, error);
}

static int method_get_machine_addresses(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_get_addresses(message, machine, error);
}

static int method_get_machine_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_get_os_release(message, machine, error);
}

static int method_list_images(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_(image_hashmap_freep) Hashmap *images = NULL;
        Manager *m = userdata;
        Image *image;
        Iterator i;
        int r;

        assert(message);
        assert(m);

        images = hashmap_new(&string_hash_ops);
        if (!images)
                return -ENOMEM;

        r = image_discover(images);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssbttto)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images, i) {
                _cleanup_free_ char *p = NULL;

                p = image_bus_path(image->name);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(ssbttto)",
                                          image->name,
                                          image_type_to_string(image->type),
                                          image->read_only,
                                          image->crtime,
                                          image->mtime,
                                          image->usage,
                                          p);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_open_machine_pty(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_open_pty(message, machine, error);
}

static int method_open_machine_login(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_open_login(message, machine, error);
}

static int method_open_machine_shell(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;

        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_open_shell(message, machine, error);
}

static int method_bind_mount_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_bind_mount(message, machine, error);
}

static int method_copy_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_copy(message, machine, error);
}

static int method_remove_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(image_unrefp) Image* i = NULL;
        const char *name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", name);

        r = image_find(name, &i);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "No image '%s' known", name);

        i->userdata = userdata;
        return bus_image_method_remove(message, i, error);
}

static int method_rename_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(image_unrefp) Image* i = NULL;
        const char *old_name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &old_name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(old_name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", old_name);

        r = image_find(old_name, &i);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "No image '%s' known", old_name);

        i->userdata = userdata;
        return bus_image_method_rename(message, i, error);
}

static int method_clone_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(image_unrefp) Image *i = NULL;
        const char *old_name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &old_name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(old_name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", old_name);

        r = image_find(old_name, &i);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "No image '%s' known", old_name);

        i->userdata = userdata;
        return bus_image_method_clone(message, i, error);
}

static int method_mark_image_read_only(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(image_unrefp) Image *i = NULL;
        const char *name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", name);

        r = image_find(name, &i);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "No image '%s' known", name);

        i->userdata = userdata;
        return bus_image_method_mark_read_only(message, i, error);
}

static int method_set_pool_limit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint64_t limit;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "t", &limit);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.machine1.manage-machines",
                        NULL,
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        /* Set up the machine directory if necessary */
        r = setup_machine_directory(limit, error);
        if (r < 0)
                return r;

        r = btrfs_resize_loopback("/var/lib/machines", limit, false);
        if (r == -ENOTTY)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Quota is only supported on btrfs.");
        if (r < 0 && r != -ENODEV) /* ignore ENODEV, as that's what is returned if the file system is not on loopback */
                return sd_bus_error_set_errnof(error, r, "Failed to adjust loopback limit: %m");

        (void) btrfs_qgroup_set_limit("/var/lib/machines", 0, limit);

        r = btrfs_subvol_set_subtree_quota_limit("/var/lib/machines", 0, limit);
        if (r == -ENOTTY)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Quota is only supported on btrfs.");
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to adjust quota limit: %m");

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_image_limit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(image_unrefp) Image *i = NULL;
        const char *name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", name);

        r = image_find(name, &i);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "No image '%s' known", name);

        i->userdata = userdata;
        return bus_image_method_set_limit(message, i, error);
}

static int method_map_from_machine_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_fclose_ FILE *f = NULL;
        Manager *m = userdata;
        const char *name, *p;
        Machine *machine;
        uint32_t uid;
        int r;

        r = sd_bus_message_read(message, "su", &name, &uid);
        if (r < 0)
                return r;

        if (!uid_is_valid(uid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid user ID " UID_FMT, uid);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        if (machine->class != MACHINE_CONTAINER)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Not supported for non-container machines.");

        p = procfs_file_alloca(machine->leader, "uid_map");
        f = fopen(p, "re");
        if (!f)
                return -errno;

        for (;;) {
                uid_t uid_base, uid_shift, uid_range, converted;
                int k;

                errno = 0;
                k = fscanf(f, UID_FMT " " UID_FMT " " UID_FMT, &uid_base, &uid_shift, &uid_range);
                if (k < 0 && feof(f))
                        break;
                if (k != 3) {
                        if (ferror(f) && errno != 0)
                                return -errno;

                        return -EIO;
                }

                if (uid < uid_base || uid >= uid_base + uid_range)
                        continue;

                converted = uid - uid_base + uid_shift;
                if (!uid_is_valid(converted))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid user ID " UID_FMT, uid);

                return sd_bus_reply_method_return(message, "u", (uint32_t) converted);
        }

        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER_MAPPING, "Machine '%s' has no matching user mappings.", name);
}

static int method_map_to_machine_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        uid_t uid;
        Iterator i;
        int r;

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;
        if (!uid_is_valid(uid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid user ID " UID_FMT, uid);
        if (uid < 0x10000)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER_MAPPING, "User " UID_FMT " belongs to host UID range", uid);

        HASHMAP_FOREACH(machine, m->machines, i) {
                _cleanup_fclose_ FILE *f = NULL;
                char p[strlen("/proc//uid_map") + DECIMAL_STR_MAX(pid_t) + 1];

                if (machine->class != MACHINE_CONTAINER)
                        continue;

                xsprintf(p, "/proc/" UID_FMT "/uid_map", machine->leader);
                f = fopen(p, "re");
                if (!f) {
                        log_warning_errno(errno, "Failed top open %s, ignoring,", p);
                        continue;
                }

                for (;;) {
                        _cleanup_free_ char *o = NULL;
                        uid_t uid_base, uid_shift, uid_range, converted;
                        int k;

                        errno = 0;
                        k = fscanf(f, UID_FMT " " UID_FMT " " UID_FMT, &uid_base, &uid_shift, &uid_range);
                        if (k < 0 && feof(f))
                                break;
                        if (k != 3) {
                                if (ferror(f) && errno != 0)
                                        return -errno;

                                return -EIO;
                        }

                        if (uid < uid_shift || uid >= uid_shift + uid_range)
                                continue;

                        converted = (uid - uid_shift + uid_base);
                        if (!uid_is_valid(converted))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid user ID " UID_FMT, uid);

                        o = machine_bus_path(machine);
                        if (!o)
                                return -ENOMEM;

                        return sd_bus_reply_method_return(message, "sou", machine->name, o, (uint32_t) converted);
                }
        }

        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER_MAPPING, "No matching user mapping for " UID_FMT ".", uid);
}

static int method_map_from_machine_group(sd_bus_message *message, void *groupdata, sd_bus_error *error) {
        _cleanup_fclose_ FILE *f = NULL;
        Manager *m = groupdata;
        const char *name, *p;
        Machine *machine;
        uint32_t gid;
        int r;

        r = sd_bus_message_read(message, "su", &name, &gid);
        if (r < 0)
                return r;

        if (!gid_is_valid(gid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid group ID " GID_FMT, gid);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        if (machine->class != MACHINE_CONTAINER)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Not supported for non-container machines.");

        p = procfs_file_alloca(machine->leader, "gid_map");
        f = fopen(p, "re");
        if (!f)
                return -errno;

        for (;;) {
                gid_t gid_base, gid_shift, gid_range, converted;
                int k;

                errno = 0;
                k = fscanf(f, GID_FMT " " GID_FMT " " GID_FMT, &gid_base, &gid_shift, &gid_range);
                if (k < 0 && feof(f))
                        break;
                if (k != 3) {
                        if (ferror(f) && errno != 0)
                                return -errno;

                        return -EIO;
                }

                if (gid < gid_base || gid >= gid_base + gid_range)
                        continue;

                converted = gid - gid_base + gid_shift;
                if (!gid_is_valid(converted))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid group ID " GID_FMT, gid);

                return sd_bus_reply_method_return(message, "u", (uint32_t) converted);
        }

        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_GROUP_MAPPING, "Machine '%s' has no matching group mappings.", name);
}

static int method_map_to_machine_group(sd_bus_message *message, void *groupdata, sd_bus_error *error) {
        Manager *m = groupdata;
        Machine *machine;
        gid_t gid;
        Iterator i;
        int r;

        r = sd_bus_message_read(message, "u", &gid);
        if (r < 0)
                return r;
        if (!gid_is_valid(gid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid group ID " GID_FMT, gid);
        if (gid < 0x10000)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_GROUP_MAPPING, "Group " GID_FMT " belongs to host GID range", gid);

        HASHMAP_FOREACH(machine, m->machines, i) {
                _cleanup_fclose_ FILE *f = NULL;
                char p[strlen("/proc//gid_map") + DECIMAL_STR_MAX(pid_t) + 1];

                if (machine->class != MACHINE_CONTAINER)
                        continue;

                xsprintf(p, "/proc/" GID_FMT "/gid_map", machine->leader);
                f = fopen(p, "re");
                if (!f) {
                        log_warning_errno(errno, "Failed top open %s, ignoring,", p);
                        continue;
                }

                for (;;) {
                        _cleanup_free_ char *o = NULL;
                        gid_t gid_base, gid_shift, gid_range, converted;
                        int k;

                        errno = 0;
                        k = fscanf(f, GID_FMT " " GID_FMT " " GID_FMT, &gid_base, &gid_shift, &gid_range);
                        if (k < 0 && feof(f))
                                break;
                        if (k != 3) {
                                if (ferror(f) && errno != 0)
                                        return -errno;

                                return -EIO;
                        }

                        if (gid < gid_shift || gid >= gid_shift + gid_range)
                                continue;

                        converted = (gid - gid_shift + gid_base);
                        if (!gid_is_valid(converted))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid group ID " GID_FMT, gid);

                        o = machine_bus_path(machine);
                        if (!o)
                                return -ENOMEM;

                        return sd_bus_reply_method_return(message, "sou", machine->name, o, (uint32_t) converted);
                }
        }

        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_GROUP_MAPPING, "No matching group mapping for " GID_FMT ".", gid);
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("PoolPath", "s", property_get_pool_path, 0, 0),
        SD_BUS_PROPERTY("PoolUsage", "t", property_get_pool_usage, 0, 0),
        SD_BUS_PROPERTY("PoolLimit", "t", property_get_pool_limit, 0, 0),
        SD_BUS_METHOD("GetMachine", "s", "o", method_get_machine, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetImage", "s", "o", method_get_image, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetMachineByPID", "u", "o", method_get_machine_by_pid, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListMachines", NULL, "a(ssso)", method_list_machines, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListImages", NULL, "a(ssbttto)", method_list_images, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CreateMachine", "sayssusa(sv)", "o", method_create_machine, 0),
        SD_BUS_METHOD("CreateMachineWithNetwork", "sayssusaia(sv)", "o", method_create_machine_with_network, 0),
        SD_BUS_METHOD("RegisterMachine", "sayssus", "o", method_register_machine, 0),
        SD_BUS_METHOD("RegisterMachineWithNetwork", "sayssusai", "o", method_register_machine_with_network, 0),
        SD_BUS_METHOD("TerminateMachine", "s", NULL, method_terminate_machine, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("KillMachine", "ssi", NULL, method_kill_machine, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetMachineAddresses", "s", "a(iay)", method_get_machine_addresses, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetMachineOSRelease", "s", "a{ss}", method_get_machine_os_release, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("OpenMachinePTY", "s", "hs", method_open_machine_pty, 0),
        SD_BUS_METHOD("OpenMachineLogin", "s", "hs", method_open_machine_login, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("OpenMachineShell", "sssasas", "hs", method_open_machine_shell, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("BindMountMachine", "sssbb", NULL, method_bind_mount_machine, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CopyFromMachine", "sss", NULL, method_copy_machine, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CopyToMachine", "sss", NULL, method_copy_machine, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RemoveImage", "s", NULL, method_remove_image, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RenameImage", "ss", NULL, method_rename_image, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CloneImage", "ssb", NULL, method_clone_image, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MarkImageReadOnly", "sb", NULL, method_mark_image_read_only, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetPoolLimit", "t", NULL, method_set_pool_limit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetImageLimit", "st", NULL, method_set_image_limit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MapFromMachineUser", "su", "u", method_map_from_machine_user, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MapToMachineUser", "u", "sou", method_map_to_machine_user, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MapFromMachineGroup", "su", "u", method_map_from_machine_group, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MapToMachineGroup", "u", "sou", method_map_to_machine_group, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("MachineNew", "so", 0),
        SD_BUS_SIGNAL("MachineRemoved", "so", 0),
        SD_BUS_VTABLE_END
};

int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *result, *unit;
        Manager *m = userdata;
        Machine *machine;
        uint32_t id;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        machine = hashmap_get(m->machine_units, unit);
        if (!machine)
                return 0;

        if (streq_ptr(path, machine->scope_job)) {
                machine->scope_job = mfree(machine->scope_job);

                if (machine->started) {
                        if (streq(result, "done"))
                                machine_send_create_reply(machine, NULL);
                        else {
                                _cleanup_bus_error_free_ sd_bus_error e = SD_BUS_ERROR_NULL;

                                sd_bus_error_setf(&e, BUS_ERROR_JOB_FAILED, "Start job for unit %s failed with '%s'", unit, result);

                                machine_send_create_reply(machine, &e);
                        }
                }

                machine_save(machine);
        }

        machine_add_to_gc_queue(machine);
        return 0;
}

int match_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *unit = NULL;
        const char *path;
        Manager *m = userdata;
        Machine *machine;
        int r;

        assert(message);
        assert(m);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        r = unit_name_from_dbus_path(path, &unit);
        if (r == -EINVAL) /* not for a unit */
                return 0;
        if (r < 0){
                log_oom();
                return 0;
        }

        machine = hashmap_get(m->machine_units, unit);
        if (!machine)
                return 0;

        machine_add_to_gc_queue(machine);
        return 0;
}

int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *unit;
        Manager *m = userdata;
        Machine *machine;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "so", &unit, &path);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        machine = hashmap_get(m->machine_units, unit);
        if (!machine)
                return 0;

        machine_add_to_gc_queue(machine);
        return 0;
}

int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        Iterator i;
        int b, r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }
        if (b)
                return 0;

        /* systemd finished reloading, let's recheck all our machines */
        log_debug("System manager has been reloaded, rechecking machines...");

        HASHMAP_FOREACH(machine, m->machines, i)
                machine_add_to_gc_queue(machine);

        return 0;
}

int manager_start_scope(
                Manager *manager,
                const char *scope,
                pid_t pid,
                const char *slice,
                const char *description,
                sd_bus_message *more_properties,
                sd_bus_error *error,
                char **job) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        int r;

        assert(manager);
        assert(scope);
        assert(pid > 1);

        r = sd_bus_message_new_method_call(
                        manager->bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", strempty(scope), "fail");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

        if (!isempty(slice)) {
                r = sd_bus_message_append(m, "(sv)", "Slice", "s", slice);
                if (r < 0)
                        return r;
        }

        if (!isempty(description)) {
                r = sd_bus_message_append(m, "(sv)", "Description", "s", description);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, pid);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "(sv)", "Delegate", "b", 1);
        if (r < 0)
                return r;

        if (more_properties) {
                r = sd_bus_message_copy(m, more_properties, true);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return r;

        r = sd_bus_call(manager->bus, m, 0, error, &reply);
        if (r < 0)
                return r;

        if (job) {
                const char *j;
                char *copy;

                r = sd_bus_message_read(reply, "o", &j);
                if (r < 0)
                        return r;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_stop_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(unit);

        r = sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StopUnit",
                        error,
                        &reply,
                        "ss", unit, "fail");
        if (r < 0) {
                if (sd_bus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT) ||
                    sd_bus_error_has_name(error, BUS_ERROR_LOAD_FAILED)) {

                        if (job)
                                *job = NULL;

                        sd_bus_error_free(error);
                        return 0;
                }

                return r;
        }

        if (job) {
                const char *j;
                char *copy;

                r = sd_bus_message_read(reply, "o", &j);
                if (r < 0)
                        return r;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_kill_unit(Manager *manager, const char *unit, int signo, sd_bus_error *error) {
        assert(manager);
        assert(unit);

        return sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "KillUnit",
                        error,
                        NULL,
                        "ssi", unit, "all", signo);
}

int manager_unit_is_active(Manager *manager, const char *unit) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ char *path = NULL;
        const char *state;
        int r;

        assert(manager);
        assert(unit);

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return -ENOMEM;

        r = sd_bus_get_property(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "ActiveState",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_NO_REPLY) ||
                    sd_bus_error_has_name(&error, SD_BUS_ERROR_DISCONNECTED))
                        return true;

                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_UNIT) ||
                    sd_bus_error_has_name(&error, BUS_ERROR_LOAD_FAILED))
                        return false;

                return r;
        }

        r = sd_bus_message_read(reply, "s", &state);
        if (r < 0)
                return -EINVAL;

        return !STR_IN_SET(state, "inactive", "failed");
}

int manager_job_is_active(Manager *manager, const char *path) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(path);

        r = sd_bus_get_property(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Job",
                        "State",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_NO_REPLY) ||
                    sd_bus_error_has_name(&error, SD_BUS_ERROR_DISCONNECTED))
                        return true;

                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_OBJECT))
                        return false;

                return r;
        }

        /* We don't actually care about the state really. The fact
         * that we could read the job state is enough for us */

        return true;
}

int manager_get_machine_by_pid(Manager *m, pid_t pid, Machine **machine) {
        Machine *mm;
        int r;

        assert(m);
        assert(pid >= 1);
        assert(machine);

        mm = hashmap_get(m->machine_leaders, PID_TO_PTR(pid));
        if (!mm) {
                _cleanup_free_ char *unit = NULL;

                r = cg_pid_get_unit(pid, &unit);
                if (r >= 0)
                        mm = hashmap_get(m->machine_units, unit);
        }
        if (!mm)
                return 0;

        *machine = mm;
        return 1;
}

int manager_add_machine(Manager *m, const char *name, Machine **_machine) {
        Machine *machine;

        assert(m);
        assert(name);

        machine = hashmap_get(m->machines, name);
        if (!machine) {
                machine = machine_new(m, _MACHINE_CLASS_INVALID, name);
                if (!machine)
                        return -ENOMEM;
        }

        if (_machine)
                *_machine = machine;

        return 0;
}
