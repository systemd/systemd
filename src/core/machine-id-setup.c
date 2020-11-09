/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "id128-util.h"
#include "io-util.h"
#include "log.h"
#include "machine-id-setup.h"
#include "macro.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "umask-util.h"
#include "util.h"
#include "virt.h"

static int generate_machine_id(const char *root, sd_id128_t *ret) {
        const char *dbus_machine_id;
        _cleanup_close_ int fd = -1;
        int r;

        assert(ret);

        /* First, try reading the D-Bus machine id, unless it is a symlink */
        dbus_machine_id = prefix_roota(root, "/var/lib/dbus/machine-id");
        fd = open(dbus_machine_id, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd >= 0) {
                if (id128_read_fd(fd, ID128_PLAIN, ret) >= 0) {
                        log_info("Initializing machine ID from D-Bus machine ID.");
                        return 0;
                }

                fd = safe_close(fd);
        }

        if (isempty(root) && running_in_chroot() <= 0) {
                /* If that didn't work, see if we are running in a container,
                 * and a machine ID was passed in via $container_uuid the way
                 * libvirt/LXC does it */

                if (detect_container() > 0) {
                        _cleanup_free_ char *e = NULL;

                        if (getenv_for_pid(1, "container_uuid", &e) > 0 &&
                            sd_id128_from_string(e, ret) >= 0) {
                                log_info("Initializing machine ID from container UUID.");
                                return 0;
                        }

                } else if (detect_vm() == VIRTUALIZATION_KVM) {

                        /* If we are not running in a container, see if we are
                         * running in qemu/kvm and a machine ID was passed in
                         * via -uuid on the qemu/kvm command line */

                        if (id128_read("/sys/class/dmi/id/product_uuid", ID128_UUID, ret) >= 0) {
                                log_info("Initializing machine ID from KVM UUID.");
                                return 0;
                        }
                        /* on POWER, it's exported here instead */
                        if (id128_read("/sys/firmware/devicetree/base/vm,uuid", ID128_UUID, ret) >= 0) {
                                log_info("Initializing machine ID from KVM UUID.");
                                return 0;
                        }
                }
        }

        /* If that didn't work, generate a random machine id */
        r = sd_id128_randomize(ret);
        if (r < 0)
                return log_error_errno(r, "Failed to generate randomized machine ID: %m");

        log_info("Initializing machine ID from random generator.");
        return 0;
}

int machine_id_setup(const char *root, bool force_transient, sd_id128_t machine_id, sd_id128_t *ret) {
        const char *etc_machine_id, *run_machine_id;
        _cleanup_close_ int fd = -1;
        bool writable;
        int r;

        etc_machine_id = prefix_roota(root, "/etc/machine-id");

        RUN_WITH_UMASK(0000) {
                /* We create this 0444, to indicate that this isn't really
                 * something you should ever modify. Of course, since the file
                 * will be owned by root it doesn't matter much, but maybe
                 * people look. */

                (void) mkdir_parents(etc_machine_id, 0755);
                fd = open(etc_machine_id, O_RDWR|O_CREAT|O_CLOEXEC|O_NOCTTY, 0444);
                if (fd < 0) {
                        int old_errno = errno;

                        fd = open(etc_machine_id, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                        if (fd < 0) {
                                if (old_errno == EROFS && errno == ENOENT)
                                        return log_error_errno(errno,
                                                  "System cannot boot: Missing /etc/machine-id and /etc is mounted read-only.\n"
                                                  "Booting up is supported only when:\n"
                                                  "1) /etc/machine-id exists and is populated.\n"
                                                  "2) /etc/machine-id exists and is empty.\n"
                                                  "3) /etc/machine-id is missing and /etc is writable.\n");
                                else
                                        return log_error_errno(errno, "Cannot open %s: %m", etc_machine_id);
                        }

                        writable = false;
                } else
                        writable = true;
        }

        /* A we got a valid machine ID argument, that's what counts */
        if (sd_id128_is_null(machine_id)) {

                /* Try to read any existing machine ID */
                if (id128_read_fd(fd, ID128_PLAIN, ret) >= 0)
                        return 0;

                /* Hmm, so, the id currently stored is not useful, then let's generate one */
                r = generate_machine_id(root, &machine_id);
                if (r < 0)
                        return r;
        }

        if (writable) {
                if (lseek(fd, 0, SEEK_SET) == (off_t) -1)
                        return log_error_errno(errno, "Failed to seek %s: %m", etc_machine_id);

                if (ftruncate(fd, 0) < 0)
                        return log_error_errno(errno, "Failed to truncate %s: %m", etc_machine_id);

                /* If the caller requested a transient machine-id, write the string "uninitialized\n" to
                 * disk and overmount it with a transient file.
                 *
                 * Otherwise write the machine-id directly to disk. */
                if (force_transient) {
                        r = loop_write(fd, "uninitialized\n", strlen("uninitialized\n"), false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write uninitialized %s: %m", etc_machine_id);

                        r = fsync_full(fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to sync %s: %m", etc_machine_id);
                } else {
                        r = id128_write_fd(fd, ID128_PLAIN, machine_id, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write %s: %m", etc_machine_id);
                        else
                                goto finish;
                }
        }

        fd = safe_close(fd);

        /* Hmm, we couldn't or shouldn't write the machine-id to /etc?
         * So let's write it to /run/machine-id as a replacement */

        run_machine_id = prefix_roota(root, "/run/machine-id");

        RUN_WITH_UMASK(0022)
                r = id128_write(run_machine_id, ID128_PLAIN, machine_id, false);
        if (r < 0) {
                (void) unlink(run_machine_id);
                return log_error_errno(r, "Cannot write %s: %m", run_machine_id);
        }

        /* And now, let's mount it over */
        r = mount_follow_verbose(LOG_ERR, run_machine_id, etc_machine_id, NULL, MS_BIND, NULL);
        if (r < 0) {
                (void) unlink(run_machine_id);
                return r;
        }

        log_full(force_transient ? LOG_DEBUG : LOG_INFO, "Installed transient %s file.", etc_machine_id);

        /* Mark the mount read-only */
        r = mount_follow_verbose(LOG_WARNING, NULL, etc_machine_id, NULL, MS_BIND|MS_RDONLY|MS_REMOUNT, NULL);
        if (r < 0)
                return r;

finish:
        if (ret)
                *ret = machine_id;

        return 0;
}

int machine_id_commit(const char *root) {
        _cleanup_close_ int fd = -1, initial_mntns_fd = -1;
        const char *etc_machine_id, *sync_path;
        sd_id128_t id;
        int r;

        /* Before doing anything, sync everything to ensure any changes by first-boot units are persisted.
         *
         * First, explicitly sync the file systems we care about and check if it worked. */
        FOREACH_STRING(sync_path, "/etc/", "/var/") {
                r = syncfs_path(AT_FDCWD, sync_path);
                if (r < 0)
                        return log_error_errno(r, "Cannot sync %s: %m", sync_path);
        }

        /* Afterwards, sync() the rest too, but we can't check the return value for these. */
        sync();

        /* Replaces a tmpfs bind mount of /etc/machine-id by a proper file, atomically. For this, the umount is removed
         * in a mount namespace, a new file is created at the right place. Afterwards the mount is also removed in the
         * original mount namespace, thus revealing the file that was just created. */

        etc_machine_id = prefix_roota(root, "/etc/machine-id");

        r = path_is_mount_point(etc_machine_id, NULL, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether %s is a mount point: %m", etc_machine_id);
        if (r == 0) {
                log_debug("%s is not a mount point. Nothing to do.", etc_machine_id);
                return 0;
        }

        /* Read existing machine-id */
        fd = open(etc_machine_id, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(errno, "Cannot open %s: %m", etc_machine_id);

        r = fd_is_temporary_fs(fd);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether %s is on a temporary file system: %m", etc_machine_id);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EROFS),
                                       "%s is not on a temporary file system.",
                                       etc_machine_id);

        r = id128_read_fd(fd, ID128_PLAIN, &id);
        if (r < 0)
                return log_error_errno(r, "We didn't find a valid machine ID in %s: %m", etc_machine_id);

        fd = safe_close(fd);

        /* Store current mount namespace */
        r = namespace_open(0, NULL, &initial_mntns_fd, NULL, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Can't fetch current mount namespace: %m");

        /* Switch to a new mount namespace, isolate ourself and unmount etc_machine_id in our new namespace */
        r = detach_mount_namespace();
        if (r < 0)
                return log_error_errno(r, "Failed to set up new mount namespace: %m");

        r = umount_verbose(LOG_ERR, etc_machine_id, 0);
        if (r < 0)
                return r;

        /* Update a persistent version of etc_machine_id */
        r = id128_write(etc_machine_id, ID128_PLAIN, id, true);
        if (r < 0)
                return log_error_errno(r, "Cannot write %s. This is mandatory to get a persistent machine ID: %m", etc_machine_id);

        /* Return to initial namespace and proceed a lazy tmpfs unmount */
        r = namespace_enter(-1, initial_mntns_fd, -1, -1, -1);
        if (r < 0)
                return log_warning_errno(r, "Failed to switch back to initial mount namespace: %m.\nWe'll keep transient %s file until next reboot.", etc_machine_id);

        if (umount2(etc_machine_id, MNT_DETACH) < 0)
                return log_warning_errno(errno, "Failed to unmount transient %s file: %m.\nWe keep that mount until next reboot.", etc_machine_id);

        return 0;
}
