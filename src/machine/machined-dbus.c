/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-locator.h"
#include "bus-message-util.h"
#include "bus-polkit.h"
#include "cgroup-util.h"
#include "discover-image.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hostname-util.h"
#include "image-dbus.h"
#include "io-util.h"
#include "machine-dbus.h"
#include "machine-pool.h"
#include "machined.h"
#include "missing_capability.h"
#include "os-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "unit-name.h"
#include "user-util.h"

static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_pool_path, "s", "/var/lib/machines");

static int property_get_pool_usage(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_ int fd = -EBADF;
        uint64_t usage = UINT64_MAX;

        assert(bus);
        assert(reply);

        fd = open("/var/lib/machines", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd >= 0) {
                BtrfsQuotaInfo q;

                if (btrfs_subvol_get_subtree_quota_fd(fd, 0, &q) >= 0)
                        usage = q.referenced;
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

        _cleanup_close_ int fd = -EBADF;
        uint64_t size = UINT64_MAX;

        assert(bus);
        assert(reply);

        fd = open("/var/lib/machines", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd >= 0) {
                BtrfsQuotaInfo q;

                if (btrfs_subvol_get_subtree_quota_fd(fd, 0, &q) >= 0)
                        size = q.referenced_max;
        }

        return sd_bus_message_append(reply, "t", size);
}

static int method_get_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Machine *machine;
        const char *name;
        int r;

        assert(message);

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
        _unused_ Manager *m = ASSERT_PTR(userdata);
        const char *name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = image_find(m->runtime_scope, IMAGE_MACHINE, name, NULL, NULL);
        if (r == -ENOENT)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "No image '%s' known", name);
        if (r < 0)
                return r;

        p = image_bus_path(name);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_machine_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *p = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Machine *machine = NULL;
        pid_t pid;
        int r;

        assert(message);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;

        if (pid < 0)
                return -EINVAL;

        pidref = PIDREF_MAKE_FROM_PID(pid);

        if (pid == 0) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID|SD_BUS_CREDS_PIDFD, &creds);
                if (r < 0)
                        return r;

                r = bus_creds_get_pidref(creds, &pidref);
                if (r < 0)
                        return r;
        }

        r = manager_get_machine_by_pidref(m, &pidref, &machine);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_MACHINE_FOR_PID, "PID "PID_FMT" does not belong to any known machine", pid);

        p = machine_bus_path(machine);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_list_machines(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Machine *machine;
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        r = sd_bus_message_open_container(reply, 'a', "(ssso)");
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        HASHMAP_FOREACH(machine, m->machines) {
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

static int method_create_or_register_machine(
                Manager *manager,
                sd_bus_message *message,
                bool read_network,
                Machine **ret,
                sd_bus_error *error) {

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        const char *name, *service, *class, *root_directory;
        const int32_t *netif = NULL;
        MachineClass c;
        uint32_t leader;
        sd_id128_t id;
        Machine *m;
        size_t n_netif = 0;
        int r;

        assert(manager);
        assert(message);
        assert(ret);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;
        if (!hostname_is_valid(name, 0))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine name");

        r = bus_message_read_id128(message, &id);
        if (r < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine ID parameter");

        r = sd_bus_message_read(message, "ssus", &service, &class, &leader, &root_directory);
        if (r < 0)
                return r;

        if (read_network) {
                r = sd_bus_message_read_array(message, 'i', (const void**) &netif, &n_netif);
                if (r < 0)
                        return r;

                n_netif /= sizeof(int32_t);

                for (size_t i = 0; i < n_netif; i++) {
                        if (netif[i] <= 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid network interface index %i", netif[i]);
                }
        }

        if (isempty(class))
                c = _MACHINE_CLASS_INVALID;
        else {
                c = machine_class_from_string(class);
                if (c < 0)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine class parameter");
        }

        if (leader == 1)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid leader PID");

        if (!isempty(root_directory) && !path_is_absolute(root_directory))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Root directory must be empty or an absolute path");

        if (leader == 0) {
                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to pin client process: %m");
        } else {
                r = pidref_set_pid(&pidref, leader);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to pin process " PID_FMT ": %m", (pid_t) leader);
        }

        if (hashmap_get(manager->machines, name))
                return sd_bus_error_setf(error, BUS_ERROR_MACHINE_EXISTS, "Machine '%s' already exists", name);

        r = manager_add_machine(manager, name, &m);
        if (r < 0)
                return r;

        m->leader = TAKE_PIDREF(pidref);
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

        *ret = m;
        return 1;

fail:
        machine_add_to_gc_queue(m);
        return r;
}

static int method_create_machine_internal(sd_bus_message *message, bool read_network, void *userdata, sd_bus_error *error) {
        Manager *manager = ASSERT_PTR(userdata);
        Machine *m = NULL;
        int r;

        assert(message);

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
        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_free_ char *p = NULL;
        Machine *m = NULL;
        int r;

        assert(message);

        r = method_create_or_register_machine(manager, message, read_network, &m, error);
        if (r < 0)
                return r;

        r = cg_pidref_get_unit(&m->leader, &m->unit);
        if (r < 0) {
                r = sd_bus_error_set_errnof(error, r,
                                            "Failed to determine unit of process "PID_FMT" : %m",
                                            m->leader.pid);
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

static int redirect_method_to_machine(sd_bus_message *message, Manager *m, sd_bus_error *error, sd_bus_message_handler_t method) {
        Machine *machine;
        const char *name;
        int r;

        assert(message);
        assert(m);
        assert(method);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return method(message, machine, error);
}

static int method_unregister_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_unregister);
}

static int method_terminate_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_terminate);
}

static int method_kill_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_kill);
}

static int method_get_machine_addresses(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_get_addresses);
}

static int method_get_machine_ssh_info(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_get_ssh_info);
}

static int method_get_machine_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_get_os_release);
}

static int method_list_images(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        _unused_ Manager *m = ASSERT_PTR(userdata);
        Image *image;
        int r;

        assert(message);

        images = hashmap_new(&image_hash_ops);
        if (!images)
                return -ENOMEM;

        r = image_discover(m->runtime_scope, IMAGE_MACHINE, NULL, images);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssbttto)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images) {
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
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_open_pty);
}

static int method_open_machine_login(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_open_login);
}

static int method_open_machine_shell(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_open_shell);
}

static int method_bind_mount_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_bind_mount);
}

static int method_copy_machine(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_copy);
}

static int method_open_machine_root_directory(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_open_root_directory);
}

static int method_get_machine_uid_shift(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_machine(message, userdata, error, bus_machine_method_get_uid_shift);
}

static int redirect_method_to_image(sd_bus_message *message, Manager *m, sd_bus_error *error, sd_bus_message_handler_t method) {
        const char *name;
        Image *i;
        int r;

        assert(message);
        assert(m);
        assert(method);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (!image_name_is_valid(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Image name '%s' is invalid.", name);

        r = manager_acquire_image(m, name, &i);
        if (r == -ENOENT)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_IMAGE, "No image '%s' known", name);
        if (r < 0)
                return r;

        return method(message, i, error);
}

static int method_remove_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_remove);
}

static int method_rename_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_rename);
}

static int method_clone_image(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_clone);
}

static int method_mark_image_read_only(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_mark_read_only);
}

static int method_get_image_hostname(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_get_hostname);
}

static int method_get_image_machine_id(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_get_machine_id);
}

static int method_get_image_machine_info(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_get_machine_info);
}

static int method_get_image_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_get_os_release);
}

static int clean_pool_done(Operation *operation, int ret, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        bool success;
        size_t n;
        int r;

        assert(operation);
        assert(operation->extra_fd >= 0);

        if (lseek(operation->extra_fd, 0, SEEK_SET) < 0)
                return -errno;

        f = take_fdopen(&operation->extra_fd, "r");
        if (!f)
                return -errno;

        /* The resulting temporary file starts with a boolean value that indicates success or not. */
        errno = 0;
        n = fread(&success, 1, sizeof(success), f);
        if (n != sizeof(success))
                return ret < 0 ? ret : errno_or_else(EIO);

        if (ret < 0) {
                _cleanup_free_ char *name = NULL;

                /* The clean-up operation failed. In this case the resulting temporary file should contain a boolean
                 * set to false followed by the name of the failed image. Let's try to read this and use it for the
                 * error message. If we can't read it, don't mind, and return the naked error. */

                if (success) /* The resulting temporary file could not be updated, ignore it. */
                        return ret;

                r = read_nul_string(f, LONG_LINE_MAX, &name);
                if (r <= 0) /* Same here... */
                        return ret;

                return sd_bus_error_set_errnof(error, ret, "Failed to remove image %s: %m", name);
        }

        assert(success);

        r = sd_bus_message_new_method_return(operation->message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(st)");
        if (r < 0)
                return r;

        /* On success the resulting temporary file will contain a list of image names that were removed followed by
         * their size on disk. Let's read that and turn it into a bus message. */
        for (;;) {
                _cleanup_free_ char *name = NULL;
                uint64_t size;

                r = read_nul_string(f, LONG_LINE_MAX, &name);
                if (r < 0)
                        return r;
                if (r == 0) /* reached the end */
                        break;

                errno = 0;
                n = fread(&size, 1, sizeof(size), f);
                if (n != sizeof(size))
                        return errno_or_else(EIO);

                r = sd_bus_message_append(reply, "(st)", name, size);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_clean_pool(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        enum {
                REMOVE_ALL,
                REMOVE_HIDDEN,
        } mode;

        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        _cleanup_close_ int result_fd = -EBADF;
        Manager *m = userdata;
        Operation *operation;
        const char *mm;
        pid_t child;
        int r;

        assert(message);

        if (m->n_operations >= OPERATIONS_MAX)
                return sd_bus_error_set(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Too many ongoing operations.");

        r = sd_bus_message_read(message, "s", &mm);
        if (r < 0)
                return r;

        if (streq(mm, "all"))
                mode = REMOVE_ALL;
        else if (streq(mm, "hidden"))
                mode = REMOVE_HIDDEN;
        else
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown mode '%s'.", mm);

        const char *details[] = {
                "verb", "clean_pool",
                "mode", mm,
                NULL
        };

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.machine1.manage-machines",
                        details,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to create pipe: %m");

        /* Create a temporary file we can dump information about deleted images into. We use a temporary file for this
         * instead of a pipe or so, since this might grow quit large in theory and we don't want to process this
         * continuously */
        result_fd = open_tmpfile_unlinkable(NULL, O_RDWR|O_CLOEXEC);
        if (result_fd < 0)
                return -errno;

        /* This might be a slow operation, run it asynchronously in a background process */
        r = safe_fork("(sd-clean)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to fork(): %m");
        if (r == 0) {
                _cleanup_hashmap_free_ Hashmap *images = NULL;
                bool success = true;
                Image *image;
                ssize_t l;

                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                images = hashmap_new(&image_hash_ops);
                if (!images) {
                        r = -ENOMEM;
                        goto child_fail;
                }

                r = image_discover(m->runtime_scope, IMAGE_MACHINE, NULL, images);
                if (r < 0)
                        goto child_fail;

                l = write(result_fd, &success, sizeof(success));
                if (l < 0) {
                        r = -errno;
                        goto child_fail;
                }

                HASHMAP_FOREACH(image, images) {

                        /* We can't remove vendor images (i.e. those in /usr) */
                        if (IMAGE_IS_VENDOR(image))
                                continue;

                        if (IMAGE_IS_HOST(image))
                                continue;

                        if (mode == REMOVE_HIDDEN && !IMAGE_IS_HIDDEN(image))
                                continue;

                        r = image_remove(image);
                        if (r == -EBUSY) /* keep images that are currently being used. */
                                continue;
                        if (r < 0) {
                                /* If the operation failed, let's override everything we wrote, and instead write there at which image we failed. */
                                success = false;
                                (void) ftruncate(result_fd, 0);
                                (void) lseek(result_fd, 0, SEEK_SET);
                                (void) write(result_fd, &success, sizeof(success));
                                (void) write(result_fd, image->name, strlen(image->name)+1);
                                goto child_fail;
                        }

                        l = write(result_fd, image->name, strlen(image->name)+1);
                        if (l < 0) {
                                r = -errno;
                                goto child_fail;
                        }

                        l = write(result_fd, &image->usage_exclusive, sizeof(image->usage_exclusive));
                        if (l < 0) {
                                r = -errno;
                                goto child_fail;
                        }
                }

                result_fd = safe_close(result_fd);
                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(errno_pipe_fd[1], &r, sizeof(r));
                _exit(EXIT_FAILURE);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        /* The clean-up might take a while, hence install a watch on the child and return */

        r = operation_new_with_bus_reply(m, /* machine= */ NULL, child, message, errno_pipe_fd[0], &operation);
        if (r < 0) {
                (void) sigkill_wait(child);
                return r;
        }

        operation->extra_fd = result_fd;
        operation->done = clean_pool_done;

        result_fd = -EBADF;
        errno_pipe_fd[0] = -EBADF;

        return 1;
}

static int method_set_pool_limit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint64_t limit;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "t", &limit);
        if (r < 0)
                return r;
        if (!FILE_SIZE_VALID_OR_INFINITY(limit))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "New limit out of range");

        const char *details[] = {
                "verb", "set_pool_limit",
                NULL
        };

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.machine1.manage-machines",
                        details,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        /* Set up the machine directory if necessary */
        r = setup_machine_directory(error, /* use_btrfs_subvol= */ true, /* use_btrfs_quota= */ true);
        if (r < 0)
                return r;

        r = image_set_pool_limit(IMAGE_MACHINE, limit);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Quota is only supported on btrfs.");
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to adjust quota limit: %m");

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_image_limit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return redirect_method_to_image(message, userdata, error, bus_image_method_set_limit);
}

static int method_map_from_machine_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Machine *machine;
        uint32_t uid;
        uid_t converted;
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
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Not supported for non-container machines.");

        r = machine_translate_uid(machine, uid, &converted);
        if (r == -ESRCH)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER_MAPPING, "Machine '%s' has no matching user mappings.", name);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "u", (uint32_t) converted);
}

static int method_map_to_machine_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *o = NULL;
        Manager *m = userdata;
        Machine *machine;
        uid_t uid, converted;
        int r;

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;
        if (!uid_is_valid(uid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid user ID " UID_FMT, uid);
        if (uid < 0x10000)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER_MAPPING, "User " UID_FMT " belongs to host UID range", uid);

        r = manager_find_machine_for_uid(m, uid, &machine, &converted);
        if (r < 0)
                return r;
        if (!r)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER_MAPPING, "No matching user mapping for " UID_FMT ".", uid);

        o = machine_bus_path(machine);
        if (!o)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "sou", machine->name, o, (uint32_t) converted);
}

static int method_map_from_machine_group(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Machine *machine;
        gid_t converted;
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
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Not supported for non-container machines.");

        r = machine_translate_gid(machine, gid, &converted);
        if (r == -ESRCH)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER_MAPPING, "Machine '%s' has no matching group mappings.", name);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "u", (uint32_t) converted);
}

static int method_map_to_machine_group(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *o = NULL;
        Manager *m = userdata;
        Machine *machine;
        gid_t gid, converted;
        int r;

        r = sd_bus_message_read(message, "u", &gid);
        if (r < 0)
                return r;
        if (!gid_is_valid(gid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid group ID " GID_FMT, gid);
        if (gid < 0x10000)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_GROUP_MAPPING, "Group " GID_FMT " belongs to host GID range", gid);

        r = manager_find_machine_for_gid(m, gid, &machine, &converted);
        if (r < 0)
                return r;
        if (!r)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_GROUP_MAPPING, "No matching group mapping for " GID_FMT ".", gid);

        o = machine_bus_path(machine);
        if (!o)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "sou", machine->name, o, (uint32_t) converted);
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("PoolPath", "s", property_get_pool_path, 0, 0),
        SD_BUS_PROPERTY("PoolUsage", "t", property_get_pool_usage, 0, 0),
        SD_BUS_PROPERTY("PoolLimit", "t", property_get_pool_limit, 0, 0),

        SD_BUS_METHOD_WITH_ARGS("GetMachine",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("o", machine),
                                method_get_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImage",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("o", image),
                                method_get_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetMachineByPID",
                                SD_BUS_ARGS("u", pid),
                                SD_BUS_RESULT("o", machine),
                                method_get_machine_by_pid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListMachines",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(ssso)", machines),
                                method_list_machines,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListImages",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(ssbttto)", images),
                                method_list_images,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CreateMachine",
                                SD_BUS_ARGS("s", name, "ay", id, "s", service, "s", class, "u", leader, "s", root_directory, "a(sv)", scope_properties),
                                SD_BUS_RESULT("o", path),
                                method_create_machine, 0),
        SD_BUS_METHOD_WITH_ARGS("CreateMachineWithNetwork",
                                SD_BUS_ARGS("s", name, "ay", id, "s", service, "s", class, "u", leader, "s", root_directory, "ai", ifindices, "a(sv)", scope_properties),
                                SD_BUS_RESULT("o", path),
                                method_create_machine_with_network, 0),
        SD_BUS_METHOD_WITH_ARGS("RegisterMachine",
                                SD_BUS_ARGS("s", name, "ay", id, "s", service, "s", class, "u", leader, "s", root_directory),
                                SD_BUS_RESULT("o", path),
                                method_register_machine, 0),
        SD_BUS_METHOD_WITH_ARGS("RegisterMachineWithNetwork",
                                SD_BUS_ARGS("s", name, "ay", id, "s", service, "s", class, "u", leader, "s", root_directory, "ai", ifindices),
                                SD_BUS_RESULT("o", path),
                                method_register_machine_with_network, 0),
        SD_BUS_METHOD_WITH_ARGS("UnregisterMachine",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_unregister_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("TerminateMachine",
                                SD_BUS_ARGS("s", id),
                                SD_BUS_NO_RESULT,
                                method_terminate_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("KillMachine",
                                SD_BUS_ARGS("s", name, "s", whom, "i", signal),
                                SD_BUS_NO_RESULT,
                                method_kill_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetMachineAddresses",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("a(iay)", addresses),
                                method_get_machine_addresses,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetMachineSSHInfo",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("s", ssh_address, "s", ssh_private_key_path),
                                method_get_machine_ssh_info,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetMachineOSRelease",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("a{ss}", fields),
                                method_get_machine_os_release,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("OpenMachinePTY",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("h", pty, "s", pty_path),
                                method_open_machine_pty,
                                0),
        SD_BUS_METHOD_WITH_ARGS("OpenMachineLogin",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("h", pty, "s", pty_path),
                                method_open_machine_login,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("OpenMachineShell",
                                SD_BUS_ARGS("s", name, "s", user, "s", path, "as", args, "as", environment),
                                SD_BUS_RESULT("h", pty, "s", pty_path),
                                method_open_machine_shell,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("BindMountMachine",
                                SD_BUS_ARGS("s", name, "s", source, "s", destination, "b", read_only, "b", mkdir),
                                SD_BUS_NO_RESULT,
                                method_bind_mount_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CopyFromMachine",
                                SD_BUS_ARGS("s", name, "s", source, "s", destination),
                                SD_BUS_NO_RESULT,
                                method_copy_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CopyToMachine",
                                SD_BUS_ARGS("s", name, "s", source, "s", destination),
                                SD_BUS_NO_RESULT,
                                method_copy_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CopyFromMachineWithFlags",
                                SD_BUS_ARGS("s", name, "s", source, "s", destination, "t", flags),
                                SD_BUS_NO_RESULT,
                                method_copy_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CopyToMachineWithFlags",
                                SD_BUS_ARGS("s", name, "s", source, "s", destination, "t", flags),
                                SD_BUS_NO_RESULT,
                                method_copy_machine,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("OpenMachineRootDirectory",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("h", fd),
                                method_open_machine_root_directory,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetMachineUIDShift",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("u", shift),
                                method_get_machine_uid_shift,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RemoveImage",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_NO_RESULT,
                                method_remove_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RenameImage",
                                SD_BUS_ARGS("s", name, "s", new_name),
                                SD_BUS_NO_RESULT,
                                method_rename_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CloneImage",
                                SD_BUS_ARGS("s", name, "s", new_name, "b", read_only),
                                SD_BUS_NO_RESULT,
                                method_clone_image,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MarkImageReadOnly",
                                SD_BUS_ARGS("s", name, "b", read_only),
                                SD_BUS_NO_RESULT,
                                method_mark_image_read_only,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageHostname",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("s", hostname),
                                method_get_image_hostname,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageMachineID",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("ay", id),
                                method_get_image_machine_id,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageMachineInfo",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("a{ss}", machine_info),
                                method_get_image_machine_info,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetImageOSRelease",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("a{ss}", os_release),
                                method_get_image_os_release,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetPoolLimit",
                                SD_BUS_ARGS("t", size),
                                SD_BUS_NO_RESULT,
                                method_set_pool_limit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetImageLimit",
                                SD_BUS_ARGS("s", name, "t", size),
                                SD_BUS_NO_RESULT,
                                method_set_image_limit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CleanPool",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_RESULT("a(st)",images),
                                method_clean_pool,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MapFromMachineUser",
                                SD_BUS_ARGS("s", name, "u", uid_inner),
                                SD_BUS_RESULT("u", uid_outer),
                                method_map_from_machine_user,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MapToMachineUser",
                                SD_BUS_ARGS("u", uid_outer),
                                SD_BUS_RESULT("s", machine_name, "o", machine_path, "u", uid_inner),
                                method_map_to_machine_user,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MapFromMachineGroup",
                                SD_BUS_ARGS("s", name, "u", gid_inner),
                                SD_BUS_RESULT("u", gid_outer),
                                method_map_from_machine_group,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MapToMachineGroup",
                                SD_BUS_ARGS("u", gid_outer),
                                SD_BUS_RESULT("s", machine_name, "o", machine_path, "u", gid_inner),
                                method_map_to_machine_group,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL_WITH_ARGS("MachineNew",
                                SD_BUS_ARGS("s", machine, "o", path),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("MachineRemoved",
                                SD_BUS_ARGS("s", machine, "o", path),
                                0),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation manager_object = {
        "/org/freedesktop/machine1",
        "org.freedesktop.machine1.Manager",
        .vtables = BUS_VTABLES(manager_vtable),
        .children = BUS_IMPLEMENTATIONS( &machine_object,
                                         &image_object ),
};

int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *result, *unit;
        Manager *m = ASSERT_PTR(userdata);
        Machine *machine;
        uint32_t id;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        machine = hashmap_get(m->machines_by_unit, unit);
        if (!machine)
                return 0;

        if (streq_ptr(path, machine->scope_job)) {
                machine->scope_job = mfree(machine->scope_job);

                if (machine->started) {
                        if (streq(result, "done"))
                                machine_send_create_reply(machine, NULL);
                        else {
                                _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;

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
        Manager *m = ASSERT_PTR(userdata);
        Machine *machine;
        int r;

        assert(message);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        r = unit_name_from_dbus_path(path, &unit);
        if (r == -EINVAL) /* not for a unit */
                return 0;
        if (r < 0) {
                log_oom();
                return 0;
        }

        machine = hashmap_get(m->machines_by_unit, unit);
        if (!machine)
                return 0;

        machine_add_to_gc_queue(machine);
        return 0;
}

int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *unit;
        Manager *m = ASSERT_PTR(userdata);
        Machine *machine;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "so", &unit, &path);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        machine = hashmap_get(m->machines_by_unit, unit);
        if (!machine)
                return 0;

        machine_add_to_gc_queue(machine);
        return 0;
}

int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Machine *machine;
        int b, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }
        if (b)
                return 0;

        /* systemd finished reloading, let's recheck all our machines */
        log_debug("System manager has been reloaded, rechecking machines...");

        HASHMAP_FOREACH(machine, m->machines)
                machine_add_to_gc_queue(machine);

        return 0;
}

int manager_unref_unit(
                Manager *m,
                const char *unit,
                sd_bus_error *error) {

        assert(m);
        assert(unit);

        return bus_call_method(m->bus, bus_systemd_mgr, "UnrefUnit", error, NULL, "s", unit);
}

int manager_stop_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(unit);

        r = bus_call_method(manager->bus, bus_systemd_mgr, "StopUnit", error, &reply, "ss", unit, "fail");
        if (r < 0) {
                if (sd_bus_error_has_names(error, BUS_ERROR_NO_SUCH_UNIT,
                                                  BUS_ERROR_LOAD_FAILED)) {

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

        return bus_call_method(manager->bus, bus_systemd_mgr, "KillUnit", error, NULL, "ssi", unit, "all", signo);
}

int manager_unit_is_active(Manager *manager, const char *unit) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
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
                if (sd_bus_error_has_names(&error, SD_BUS_ERROR_NO_REPLY,
                                                   SD_BUS_ERROR_DISCONNECTED))
                        return true;

                if (sd_bus_error_has_names(&error, BUS_ERROR_NO_SUCH_UNIT,
                                                   BUS_ERROR_LOAD_FAILED))
                        return false;

                return r;
        }

        r = sd_bus_message_read(reply, "s", &state);
        if (r < 0)
                return -EINVAL;

        return !STR_IN_SET(state, "inactive", "failed");
}

int manager_job_is_active(Manager *manager, const char *path) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
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
                if (sd_bus_error_has_names(&error, SD_BUS_ERROR_NO_REPLY,
                                                   SD_BUS_ERROR_DISCONNECTED))
                        return true;

                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_OBJECT))
                        return false;

                return r;
        }

        /* We don't actually care about the state really. The fact
         * that we could read the job state is enough for us */

        return true;
}
