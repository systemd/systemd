/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <linux/loop.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <unistd.h>

#include "capability-util.h"
#include "chase-symlinks.h"
#include "devnum-util.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "env-util.h"
#include "escape.h"
#include "extension-release.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "main-func.h"
#include "missing_magic.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "sort-util.h"
#include "terminal-util.h"
#include "user-util.h"
#include "verbs.h"

static char **arg_hierarchies = NULL; /* "/usr" + "/opt" by default */
static char *arg_root = NULL;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_force = false;

STATIC_DESTRUCTOR_REGISTER(arg_hierarchies, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int is_our_mount_point(const char *p) {
        _cleanup_free_ char *buf = NULL, *f = NULL;
        struct stat st;
        dev_t dev;
        int r;

        r = path_is_mount_point(p, NULL, 0);
        if (r == -ENOENT) {
                log_debug_errno(r, "Hierarchy '%s' doesn't exist.", p);
                return false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is a mount point: %m", p);
        if (r == 0) {
                log_debug("Hierarchy '%s' is not a mount point, skipping.", p);
                return false;
        }

        /* So we know now that it's a mount point. Now let's check if it's one of ours, so that we don't
         * accidentally unmount the user's own /usr/ but just the mounts we established ourselves. We do this
         * check by looking into the metadata directory we place in merged mounts: if the file
         * .systemd-sysext/dev contains the major/minor device pair of the mount we have a good reason to
         * believe this is one of our mounts. This thorough check has the benefit that we aren't easily
         * confused if people tar up one of our merged trees and untar them elsewhere where we might mistake
         * them for a live sysext tree. */

        f = path_join(p, ".systemd-sysext/dev");
        if (!f)
                return log_oom();

        r = read_one_line_file(f, &buf);
        if (r == -ENOENT) {
                log_debug("Hierarchy '%s' does not carry a .systemd-sysext/dev file, not a sysext merged tree.", p);
                return false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether hierarchy '%s' contains '.systemd-sysext/dev': %m", p);

        r = parse_devnum(buf, &dev);
        if (r < 0)
                return log_error_errno(r, "Failed to parse device major/minor stored in '.systemd-sysext/dev' file on '%s': %m", p);

        if (lstat(p, &st) < 0)
                return log_error_errno(r, "Failed to stat %s: %m", p);

        if (st.st_dev != dev) {
                log_debug("Hierarchy '%s' reports a different device major/minor than what we are seeing, assuming offline copy.", p);
                return false;
        }

        return true;
}

static int unmerge_hierarchy(const char *p) {
        int r;

        for (;;) {
                /* We only unmount /usr/ if it is a mount point and really one of ours, in order not to break
                 * systems where /usr/ is a mount point of its own already. */

                r = is_our_mount_point(p);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = umount_verbose(LOG_ERR, p, MNT_DETACH|UMOUNT_NOFOLLOW);
                if (r < 0)
                        return log_error_errno(r, "Failed to unmount file system '%s': %m", p);

                log_info("Unmerged '%s'.", p);
        }

        return 0;
}

static int unmerge(void) {
        int r, ret = 0;

        STRV_FOREACH(p, arg_hierarchies) {
                _cleanup_free_ char *resolved = NULL;

                r = chase_symlinks(*p, arg_root, CHASE_PREFIX_ROOT, &resolved, NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Hierarchy '%s%s' does not exist, ignoring.", strempty(arg_root), *p);
                        continue;
                }
                if (r < 0) {
                        log_error_errno(r, "Failed to resolve path to hierarchy '%s%s': %m", strempty(arg_root), *p);
                        if (ret == 0)
                                ret = r;

                        continue;
                }

                r = unmerge_hierarchy(resolved);
                if (r < 0 && ret == 0)
                        ret = r;
        }

        return ret;
}

static int verb_unmerge(int argc, char **argv, void *userdata) {

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Need to be privileged.");

        return unmerge();
}

static int verb_status(int argc, char **argv, void *userdata) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r, ret = 0;

        t = table_new("hierarchy", "extensions", "since");
        if (!t)
                return log_oom();

        (void) table_set_empty_string(t, "-");

        STRV_FOREACH(p, arg_hierarchies) {
                _cleanup_free_ char *resolved = NULL, *f = NULL, *buf = NULL;
                _cleanup_strv_free_ char **l = NULL;
                struct stat st;

                r = chase_symlinks(*p, arg_root, CHASE_PREFIX_ROOT, &resolved, NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Hierarchy '%s%s' does not exist, ignoring.", strempty(arg_root), *p);
                        continue;
                }
                if (r < 0) {
                        log_error_errno(r, "Failed to resolve path to hierarchy '%s%s': %m", strempty(arg_root), *p);
                        goto inner_fail;
                }

                r = is_our_mount_point(resolved);
                if (r < 0)
                        goto inner_fail;
                if (r == 0) {
                        r = table_add_many(
                                        t,
                                        TABLE_PATH, *p,
                                        TABLE_STRING, "none",
                                        TABLE_SET_COLOR, ansi_grey(),
                                        TABLE_EMPTY);
                        if (r < 0)
                                return table_log_add_error(r);

                        continue;
                }

                f = path_join(*p, ".systemd-sysext/extensions");
                if (!f)
                        return log_oom();

                r = read_full_file(f, &buf, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to open '%s': %m", f);

                l = strv_split_newlines(buf);
                if (!l)
                        return log_oom();

                if (stat(*p, &st) < 0)
                        return log_error_errno(r, "Failed to stat() '%s': %m", *p);

                r = table_add_many(
                                t,
                                TABLE_PATH, *p,
                                TABLE_STRV, l,
                                TABLE_TIMESTAMP, timespec_load(&st.st_mtim));
                if (r < 0)
                        return table_log_add_error(r);

                continue;

        inner_fail:
                if (ret == 0)
                        ret = r;
        }

        (void) table_set_sort(t, (size_t) 0);

        r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
        if (r < 0)
                return r;

        return ret;
}

static int mount_overlayfs(
                const char *where,
                char **layers) {

        _cleanup_free_ char *options = NULL;
        bool separator = false;
        int r;

        assert(where);

        options = strdup("lowerdir=");
        if (!options)
                return log_oom();

        STRV_FOREACH(l, layers) {
                _cleanup_free_ char *escaped = NULL;

                escaped = shell_escape(*l, ",:");
                if (!escaped)
                        return log_oom();

                if (!strextend(&options, separator ? ":" : "", escaped))
                        return log_oom();

                separator = true;
        }

        /* Now mount the actual overlayfs */
        r = mount_nofollow_verbose(LOG_ERR, "sysext", where, "overlay", MS_RDONLY, options);
        if (r < 0)
                return r;

        return 0;
}

static int merge_hierarchy(
                const char *hierarchy,
                char **extensions,
                char **paths,
                const char *meta_path,
                const char *overlay_path) {

        _cleanup_free_ char *resolved_hierarchy = NULL, *f = NULL, *buf = NULL;
        _cleanup_strv_free_ char **layers = NULL;
        struct stat st;
        int r;

        assert(hierarchy);
        assert(meta_path);
        assert(overlay_path);

        /* Resolve the path of the host's version of the hierarchy, i.e. what we want to use as lowest layer
         * in the overlayfs stack. */
        r = chase_symlinks(hierarchy, arg_root, CHASE_PREFIX_ROOT, &resolved_hierarchy, NULL);
        if (r == -ENOENT)
                log_debug_errno(r, "Hierarchy '%s' on host doesn't exist, not merging.", hierarchy);
        else if (r < 0)
                return log_error_errno(r, "Failed to resolve host hierarchy '%s': %m", hierarchy);
        else {
                r = dir_is_empty(resolved_hierarchy, /* ignore_hidden_or_backup= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if host hierarchy '%s' is empty: %m", resolved_hierarchy);
                if (r > 0) {
                        log_debug("Host hierarchy '%s' is empty, not merging.", resolved_hierarchy);
                        resolved_hierarchy = mfree(resolved_hierarchy);
                }
        }

        /* Let's generate a metadata file that lists all extensions we took into account for this
         * hierarchy. We include this in the final fs, to make things nicely discoverable and
         * recognizable. */
        f = path_join(meta_path, ".systemd-sysext/extensions");
        if (!f)
                return log_oom();

        buf = strv_join(extensions, "\n");
        if (!buf)
                return log_oom();

        r = write_string_file(f, buf, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write extension meta file '%s': %m", f);

        /* Put the meta path (i.e. our synthesized stuff) at the top of the layer stack */
        layers = strv_new(meta_path);
        if (!layers)
                return log_oom();

        /* Put the extensions in the middle */
        STRV_FOREACH(p, paths) {
                _cleanup_free_ char *resolved = NULL;

                r = chase_symlinks(hierarchy, *p, CHASE_PREFIX_ROOT, &resolved, NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Hierarchy '%s' in extension '%s' doesn't exist, not merging.", hierarchy, *p);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve hierarchy '%s' in extension '%s': %m", hierarchy, *p);

                r = dir_is_empty(resolved, /* ignore_hidden_or_backup= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if hierarchy '%s' in extension '%s' is empty: %m", resolved, *p);
                if (r > 0) {
                        log_debug("Hierarchy '%s' in extension '%s' is empty, not merging.", hierarchy, *p);
                        continue;
                }

                r = strv_consume(&layers, TAKE_PTR(resolved));
                if (r < 0)
                        return log_oom();
        }

        if (!layers[1]) /* No extension with files in this hierarchy? Then don't do anything. */
                return 0;

        if (resolved_hierarchy) {
                /* Add the host hierarchy as last (lowest) layer in the stack */
                r = strv_consume(&layers, TAKE_PTR(resolved_hierarchy));
                if (r < 0)
                        return log_oom();
        }

        r = mkdir_p(overlay_path, 0700);
        if (r < 0)
                return log_error_errno(r, "Failed to make directory '%s': %m", overlay_path);

        r = mount_overlayfs(overlay_path, layers);
        if (r < 0)
                return r;

        /* The overlayfs superblock is read-only. Let's also mark the bind mount read-only. Extra turbo safety 😎 */
        r = bind_remount_recursive(overlay_path, MS_RDONLY, MS_RDONLY, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to make bind mount '%s' read-only: %m", overlay_path);

        /* Now we have mounted the new file system. Let's now figure out its .st_dev field, and make that
         * available in the metadata directory. This is useful to detect whether the metadata dir actually
         * belongs to the fs it is found on: if .st_dev of the top-level mount matches it, it's pretty likely
         * we are looking at a live sysext tree, and not an unpacked tar or so of one. */
        if (stat(overlay_path, &st) < 0)
                return log_error_errno(r, "Failed to stat mount '%s': %m", overlay_path);

        free(f);
        f = path_join(meta_path, ".systemd-sysext/dev");
        if (!f)
                return log_oom();

        r = write_string_filef(f, WRITE_STRING_FILE_CREATE, "%u:%u", major(st.st_dev), minor(st.st_dev));
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s': %m", f);

        /* Make sure the top-level dir has an mtime marking the point we established the merge */
        if (utimensat(AT_FDCWD, meta_path, NULL, AT_SYMLINK_NOFOLLOW) < 0)
                return log_error_errno(r, "Failed fix mtime of '%s': %m", meta_path);

        return 1;
}

static int strverscmp_improvedp(char *const* a, char *const* b) {
        /* usable in qsort() for sorting a string array with strverscmp_improved() */
        return strverscmp_improved(*a, *b);
}

static int validate_version(
                const char *root,
                const Image *img,
                const char *host_os_release_id,
                const char *host_os_release_version_id,
                const char *host_os_release_sysext_level) {

        int r;

        assert(root);
        assert(img);

        if (arg_force) {
                log_debug("Force mode enabled, skipping version validation.");
                return 1;
        }

        /* Insist that extension images do not overwrite the underlying OS release file (it's fine if
         * they place one in /etc/os-release, i.e. where things don't matter, as they aren't
         * merged.) */
        r = chase_symlinks("/usr/lib/os-release", root, CHASE_PREFIX_ROOT, NULL, NULL);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to determine whether /usr/lib/os-release exists in the extension image: %m");
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extension image contains /usr/lib/os-release file, which is not allowed (it may carry /etc/os-release), refusing.");

        r = extension_release_validate(
                        img->name,
                        host_os_release_id,
                        host_os_release_version_id,
                        host_os_release_sysext_level,
                        in_initrd() ? "initrd" : "system",
                        img->extension_release);
        if (r < 0)
                return log_error_errno(r, "Failed to validate extension release information: %m");

        return r;
}

static int merge_subprocess(Hashmap *images, const char *workspace) {
        _cleanup_free_ char *host_os_release_id = NULL, *host_os_release_version_id = NULL, *host_os_release_sysext_level = NULL,
                *buf = NULL;
        _cleanup_strv_free_ char **extensions = NULL, **paths = NULL;
        size_t n_extensions = 0;
        unsigned n_ignored = 0;
        Image *img;
        int r;

        /* Mark the whole of /run as MS_SLAVE, so that we can mount stuff below it that doesn't show up on
         * the host otherwise. */
        r = mount_nofollow_verbose(LOG_ERR, NULL, "/run", NULL, MS_SLAVE|MS_REC, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to remount /run/ MS_SLAVE: %m");

        /* Let's create the workspace if it's missing */
        r = mkdir_p(workspace, 0700);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd/sysext: %m");

        /* Let's mount a tmpfs to our workspace. This way we don't need to clean up the inodes we mount over,
         * but let the kernel do that entirely automatically, once our namespace dies. Note that this file
         * system won't be visible to anyone but us, since we opened our own namespace and then made the
         * /run/ hierarchy (which our workspace is contained in) MS_SLAVE, see above. */
        r = mount_nofollow_verbose(LOG_ERR, "sysext", workspace, "tmpfs", 0, "mode=0700");
        if (r < 0)
                return r;

        /* Acquire host OS release info, so that we can compare it with the extension's data */
        r = parse_os_release(
                        arg_root,
                        "ID", &host_os_release_id,
                        "VERSION_ID", &host_os_release_version_id,
                        "SYSEXT_LEVEL", &host_os_release_sysext_level);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire 'os-release' data of OS tree '%s': %m", empty_to_root(arg_root));
        if (isempty(host_os_release_id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'ID' field not found or empty in 'os-release' data of OS tree '%s': %m",
                                       empty_to_root(arg_root));

        /* Let's now mount all images */
        HASHMAP_FOREACH(img, images) {
                _cleanup_free_ char *p = NULL;

                p = path_join(workspace, "extensions", img->name);
                if (!p)
                        return log_oom();

                r = mkdir_p(p, 0700);
                if (r < 0)
                        return log_error_errno(r, "Failed to create %s: %m", p);

                switch (img->type) {
                case IMAGE_DIRECTORY:
                case IMAGE_SUBVOLUME:
                        r = mount_nofollow_verbose(LOG_ERR, img->path, p, NULL, MS_BIND, NULL);
                        if (r < 0)
                                return r;

                        /* Make this a read-only bind mount */
                        r = bind_remount_recursive(p, MS_RDONLY, MS_RDONLY, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make bind mount '%s' read-only: %m", p);

                        break;

                case IMAGE_RAW:
                case IMAGE_BLOCK: {
                        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
                        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
                        _cleanup_(decrypted_image_unrefp) DecryptedImage *di = NULL;
                        _cleanup_(verity_settings_done) VeritySettings verity_settings = VERITY_SETTINGS_DEFAULT;
                        DissectImageFlags flags =
                                DISSECT_IMAGE_READ_ONLY |
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_MOUNT_ROOT_ONLY |
                                DISSECT_IMAGE_USR_NO_ROOT;

                        r = verity_settings_load(&verity_settings, img->path, NULL, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read verity artifacts for %s: %m", img->path);

                        if (verity_settings.data_path)
                                flags |= DISSECT_IMAGE_NO_PARTITION_TABLE;

                        r = loop_device_make_by_path(
                                        img->path,
                                        O_RDONLY,
                                        FLAGS_SET(flags, DISSECT_IMAGE_NO_PARTITION_TABLE) ? 0 : LO_FLAGS_PARTSCAN,
                                        &d);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set up loopback device for %s: %m", img->path);

                        r = loop_device_flock(d, LOCK_SH);
                        if (r < 0)
                                return log_error_errno(r, "Failed to lock loopback device: %m");

                        r = dissect_image_and_warn(
                                        d->fd,
                                        img->path,
                                        &verity_settings,
                                        NULL,
                                        d->diskseq,
                                        d->uevent_seqnum_not_before,
                                        d->timestamp_not_before,
                                        flags,
                                        &m);
                        if (r < 0)
                                return r;

                        r = dissected_image_load_verity_sig_partition(
                                        m,
                                        d->fd,
                                        &verity_settings);
                        if (r < 0)
                                return r;

                        r = dissected_image_decrypt_interactively(
                                        m, NULL,
                                        &verity_settings,
                                        flags,
                                        &di);
                        if (r < 0)
                                return r;

                        r = dissected_image_mount_and_warn(
                                        m,
                                        p,
                                        UID_INVALID,
                                        UID_INVALID,
                                        flags);
                        if (r < 0)
                                return r;

                        if (di) {
                                r = decrypted_image_relinquish(di);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to relinquish DM devices: %m");
                        }

                        loop_device_relinquish(d);
                        break;
                }
                default:
                        assert_not_reached();
                }

                r = validate_version(
                                p,
                                img,
                                host_os_release_id,
                                host_os_release_version_id,
                                host_os_release_sysext_level);
                if (r < 0)
                        return r;
                if (r == 0) {
                        n_ignored++;
                        continue;
                }

                /* Nice! This one is an extension we want. */
                r = strv_extend(&extensions, img->name);
                if (r < 0)
                        return log_oom();

                n_extensions ++;
        }

        /* Nothing left? Then shortcut things */
        if (n_extensions == 0) {
                if (n_ignored > 0)
                        log_info("No suitable extensions found (%u ignored due to incompatible version).", n_ignored);
                else
                        log_info("No extensions found.");
                return 0;
        }

        /* Order by version sort with strverscmp_improved() */
        typesafe_qsort(extensions, n_extensions, strverscmp_improvedp);

        buf = strv_join(extensions, "', '");
        if (!buf)
                return log_oom();

        log_info("Using extensions '%s'.", buf);

        /* Build table of extension paths (in reverse order) */
        paths = new0(char*, n_extensions + 1);
        if (!paths)
                return log_oom();

        for (size_t k = 0; k < n_extensions; k++) {
                _cleanup_free_ char *p = NULL;

                assert_se(img = hashmap_get(images, extensions[n_extensions - 1 - k]));

                p = path_join(workspace, "extensions", img->name);
                if (!p)
                        return log_oom();

                paths[k] = TAKE_PTR(p);
        }

        /* Let's now unmerge the status quo ante, since to build the new overlayfs we need a reference to the
         * underlying fs. */
        STRV_FOREACH(h, arg_hierarchies) {
                _cleanup_free_ char *resolved = NULL;

                r = chase_symlinks(*h, arg_root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &resolved, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve hierarchy '%s%s': %m", strempty(arg_root), *h);

                r = unmerge_hierarchy(resolved);
                if (r < 0)
                        return r;
        }

        /* Create overlayfs mounts for all hierarchies */
        STRV_FOREACH(h, arg_hierarchies) {
                _cleanup_free_ char *meta_path = NULL, *overlay_path = NULL;

                meta_path = path_join(workspace, "meta", *h); /* The place where to store metadata about this instance */
                if (!meta_path)
                        return log_oom();

                overlay_path = path_join(workspace, "overlay", *h); /* The resulting overlayfs instance */
                if (!overlay_path)
                        return log_oom();

                r = merge_hierarchy(*h, extensions, paths, meta_path, overlay_path);
                if (r < 0)
                        return r;
        }

        /* And move them all into place. This is where things appear in the host namespace */
        STRV_FOREACH(h, arg_hierarchies) {
                _cleanup_free_ char *p = NULL, *resolved = NULL;

                p = path_join(workspace, "overlay", *h);
                if (!p)
                        return log_oom();

                if (laccess(p, F_OK) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to check if '%s' exists: %m", p);

                        /* Hierarchy apparently was empty in all extensions, and wasn't mounted, ignoring. */
                        continue;
                }

                r = chase_symlinks(*h, arg_root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &resolved, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve hierarchy '%s%s': %m", strempty(arg_root), *h);

                r = mkdir_p(resolved, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create hierarchy mount point '%s': %m", resolved);

                r = mount_nofollow_verbose(LOG_ERR, p, resolved, NULL, MS_BIND, NULL);
                if (r < 0)
                        return r;

                log_info("Merged extensions into '%s'.", resolved);
        }

        return 1;
}

static int merge(Hashmap *images) {
        pid_t pid;
        int r;

        r = safe_fork("(sd-sysext)", FORK_DEATHSIG|FORK_LOG|FORK_NEW_MOUNTNS, &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to fork off child: %m");
        if (r == 0) {
                /* Child with its own mount namespace */

                r = merge_subprocess(images, "/run/systemd/sysext");
                if (r < 0)
                        _exit(EXIT_FAILURE);

                /* Our namespace ceases to exist here, also implicitly detaching all temporary mounts we
                 * created below /run. Nice! */

                _exit(r > 0 ? EXIT_SUCCESS : 123); /* 123 means: didn't find any extensions */
        }

        r = wait_for_terminate_and_check("(sd-sysext)", pid, WAIT_LOG_ABNORMAL);
        if (r < 0)
                return r;

        return r != 123; /* exit code 123 means: didn't do anything */
}

static int image_discover_and_read_metadata(Hashmap **ret_images) {
        _cleanup_(hashmap_freep) Hashmap *images = NULL;
        Image *img;
        int r;

        assert(ret_images);

        images = hashmap_new(&image_hash_ops);
        if (!images)
                return log_oom();

        r = image_discover(IMAGE_EXTENSION, arg_root, images);
        if (r < 0)
                return log_error_errno(r, "Failed to discover extension images: %m");

        HASHMAP_FOREACH(img, images) {
                r = image_read_metadata(img);
                if (r < 0)
                        return log_error_errno(r, "Failed to read metadata for image %s: %m", img->name);
        }

        *ret_images = TAKE_PTR(images);

        return 0;
}

static int verb_merge(int argc, char **argv, void *userdata) {
        _cleanup_(hashmap_freep) Hashmap *images = NULL;
        int r;

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Need to be privileged.");

        r = image_discover_and_read_metadata(&images);
        if (r < 0)
                return r;

        /* In merge mode fail if things are already merged. (In --refresh mode below we'll unmerge if we find
         * things are already merged...) */
        STRV_FOREACH(p, arg_hierarchies) {
                _cleanup_free_ char *resolved = NULL;

                r = chase_symlinks(*p, arg_root, CHASE_PREFIX_ROOT, &resolved, NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Hierarchy '%s%s' does not exist, ignoring.", strempty(arg_root), *p);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path to hierarchy '%s%s': %m", strempty(arg_root), *p);

                r = is_our_mount_point(resolved);
                if (r < 0)
                        return r;
                if (r > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                               "Hierarchy '%s' is already merged.", *p);
        }

        return merge(images);
}

static int verb_refresh(int argc, char **argv, void *userdata) {
        _cleanup_(hashmap_freep) Hashmap *images = NULL;
        int r;

        if (!have_effective_cap(CAP_SYS_ADMIN))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Need to be privileged.");

        r = image_discover_and_read_metadata(&images);
        if (r < 0)
                return r;

        r = merge(images); /* Returns > 0 if it did something, i.e. a new overlayfs is mounted now. When it
                            * does so it implicitly unmounts any overlayfs placed there before. Returns == 0
                            * if it did nothing, i.e. no extension images found. In this case the old
                            * overlayfs remains in place if there was one. */
        if (r < 0)
                return r;
        if (r == 0) /* No images found? Then unmerge. The goal of --refresh is after all that after having
                     * called there's a guarantee that the merge status matches the installed extensions. */
                r = unmerge();

        /* Net result here is that:
         *
         * 1. If an overlayfs was mounted before and no extensions exist anymore, we'll have unmerged things.
         *
         * 2. If an overlayfs was mounted before, and there are still extensions installed' we'll have
         *    unmerged and then merged things again.
         *
         * 3. If an overlayfs so far wasn't mounted, and there are extensions installed, we'll have it
         *    mounted now.
         *
         * 4. If there was no overlayfs mount so far, and no extensions installed, we implement a NOP.
         */

        return 0;
}

static int verb_list(int argc, char **argv, void *userdata) {
        _cleanup_(hashmap_freep) Hashmap *images = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        Image *img;
        int r;

        images = hashmap_new(&image_hash_ops);
        if (!images)
                return log_oom();

        r = image_discover(IMAGE_EXTENSION, arg_root, images);
        if (r < 0)
                return log_error_errno(r, "Failed to discover extension images: %m");

        if ((arg_json_format_flags & JSON_FORMAT_OFF) && hashmap_isempty(images)) {
                log_info("No OS extensions found.");
                return 0;
        }

        t = table_new("name", "type", "path", "time");
        if (!t)
                return log_oom();

        HASHMAP_FOREACH(img, images) {
                r = table_add_many(
                                t,
                                TABLE_STRING, img->name,
                                TABLE_STRING, image_type_to_string(img->type),
                                TABLE_PATH, img->path,
                                TABLE_TIMESTAMP, img->mtime != 0 ? img->mtime : img->crtime);
                if (r < 0)
                        return table_log_add_error(r);
        }

        (void) table_set_sort(t, (size_t) 0);

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int verb_help(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysext", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND\n"
               "\n%5$sMerge extension images into /usr/ and /opt/ hierarchies.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  status                  Show current merge status (default)\n"
               "  merge                   Merge extensions into /usr/ and /opt/\n"
               "  unmerge                 Unmerge extensions from /usr/ and /opt/\n"
               "  refresh                 Unmerge/merge extensions again\n"
               "  list                    List installed extensions\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --root=PATH          Operate relative to root path\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "     --force              Ignore version incompatibilities\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_ROOT,
                ARG_JSON,
                ARG_FORCE,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
                { "no-legend", no_argument,       NULL, ARG_NO_LEGEND },
                { "root",      required_argument, NULL, ARG_ROOT      },
                { "json",      required_argument, NULL, ARG_JSON      },
                { "force",     no_argument,       NULL, ARG_FORCE     },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return verb_help(argc, argv, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int sysext_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "status",   VERB_ANY, 1, VERB_DEFAULT, verb_status  },
                { "merge",    VERB_ANY, 1, 0,            verb_merge   },
                { "unmerge",  VERB_ANY, 1, 0,            verb_unmerge },
                { "refresh",  VERB_ANY, 1, 0,            verb_refresh },
                { "list",     VERB_ANY, 1, 0,            verb_list    },
                { "help",     VERB_ANY, 1, 0,            verb_help    },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* For debugging purposes it might make sense to do this for other hierarchies than /usr/ and
         * /opt/, but let's make that a hacker/debugging feature, i.e. env var instead of cmdline
         * switch. */
        r = parse_env_extension_hierarchies(&arg_hierarchies);
        if (r < 0)
                return log_error_errno(r, "Failed to parse $SYSTEMD_SYSEXT_HIERARCHIES environment variable: %m");

        return sysext_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
