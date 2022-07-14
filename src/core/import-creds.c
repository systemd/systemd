/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "copy.h"
#include "creds-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "import-creds.h"
#include "io-util.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "recurse-dir.h"
#include "strv.h"

/* This imports credentials passed in from environments higher up (VM manager, boot loader, …) and rearranges
 * them so that later code can access them using our regular credential protocol
 * (i.e. $CREDENTIALS_DIRECTORY). It's supposed to be minimal glue to unify behaviour how PID 1 (and
 * generators invoked by it) can acquire credentials from outside, to mimic how we support it for containers,
 * but on VM/physical environments.
 *
 * This does three things:
 *
 * 1. It imports credentials picked up by sd-boot (and placed in the /.extra/credentials/ dir in the initrd)
 *    and puts them in /run/credentials/@encrypted/. Note that during the initrd→host transition the initrd root
 *    file system is cleaned out, thus it is essential we pick up these files before they are deleted. Note
 *    that these credentials originate from an untrusted source, i.e. the ESP and are not
 *    pre-authenticated. They still have to be authenticated before use.
 *
 * 2. It imports credentials from /proc/cmdline and puts them in /run/credentials/@system/. These come from a
 *    trusted environment (i.e. the boot loader), and are typically authenticated (if authentication is done
 *    at all). However, they are world-readable, which might be less than ideal. Hence only use this for data
 *    that doesn't require trust.
 *
 * 3. It imports credentials passed in through qemu's fw_cfg logic. Specifically, credential data passed in
 *    /sys/firmware/qemu_fw_cfg/by_name/opt/io.systemd.credentials/ is picked up and also placed in
 *    /run/credentials/@system/.
 *
 * If it picked up any credentials it will set the $CREDENTIALS_DIRECTORY and
 * $ENCRYPTED_CREDENTIALS_DIRECTORY environment variables to point to these directories, so that processes
 * can find them there later on. If "ramfs" is available $CREDENTIALS_DIRECTORY will be backed by it (but
 * $ENCRYPTED_CREDENTIALS_DIRECTORY is just a regular tmpfs).
 *
 * Net result: the service manager can pick up trusted credentials from $CREDENTIALS_DIRECTORY afterwards,
 * and untrusted ones from $ENCRYPTED_CREDENTIALS_DIRECTORY. */

typedef struct ImportCredentialContext {
        int target_dir_fd;
        size_t size_sum;
        unsigned n_credentials;
} ImportCredentialContext;

static void import_credentials_context_free(ImportCredentialContext *c) {
        assert(c);

        c->target_dir_fd = safe_close(c->target_dir_fd);
}

static int acquire_encrypted_credential_directory(ImportCredentialContext *c) {
        int r;

        assert(c);

        if (c->target_dir_fd >= 0)
                return c->target_dir_fd;

        r = mkdir_safe_label(ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY, 0700, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                return log_error_errno(r, "Failed to create " ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY ": %m");

        c->target_dir_fd = open(ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (c->target_dir_fd < 0)
                return log_error_errno(errno, "Failed to open " ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY ": %m");

        return c->target_dir_fd;
}

static int open_credential_file_for_write(int target_dir_fd, const char *dir_name, const char *n) {
        int fd;

        assert(target_dir_fd >= 0);
        assert(dir_name);
        assert(n);

        fd = openat(target_dir_fd, n, O_WRONLY|O_CLOEXEC|O_CREAT|O_EXCL|O_NOFOLLOW, 0400);
        if (fd < 0) {
                if (errno == EEXIST) /* In case of EEXIST we'll only debug log! */
                        return log_debug_errno(errno, "Credential '%s' set twice, ignoring.", n);

                return log_error_errno(errno, "Failed to create %s/%s: %m", dir_name, n);
        }

        return fd;
}

static bool credential_size_ok(ImportCredentialContext *c, const char *name, uint64_t size) {
        assert(c);
        assert(name);

        if (size > CREDENTIAL_SIZE_MAX) {
                log_warning("Credential '%s' is larger than allowed limit (%s > %s), skipping.", name, FORMAT_BYTES(size), FORMAT_BYTES(CREDENTIAL_SIZE_MAX));
                return false;
        }

        if (size > CREDENTIALS_TOTAL_SIZE_MAX - c->size_sum) {
                log_warning("Accumulated credential size would be above allowed limit (%s+%s > %s), skipping '%s'.",
                            FORMAT_BYTES(c->size_sum), FORMAT_BYTES(size), FORMAT_BYTES(CREDENTIALS_TOTAL_SIZE_MAX), name);
                return false;
        }

        return true;
}

static int finalize_credentials_dir(const char *dir, const char *envvar) {
        int r;

        assert(dir);
        assert(envvar);

        /* Try to make the credentials directory read-only now */

        r = make_mount_point(dir);
        if (r < 0)
                log_warning_errno(r, "Failed to make '%s' a mount point, ignoring: %m", dir);
        else
                (void) mount_nofollow_verbose(LOG_WARNING, NULL, dir, NULL, MS_BIND|MS_NODEV|MS_NOEXEC|MS_NOSUID|MS_RDONLY|MS_REMOUNT, NULL);

        if (setenv(envvar, dir, /* overwrite= */ true) < 0)
                return log_error_errno(errno, "Failed to set $%s environment variable: %m", envvar);

        return 0;
}

static int import_credentials_boot(void) {
        _cleanup_(import_credentials_context_free) ImportCredentialContext context = {
                .target_dir_fd = -1,
        };
        int r;

        /* systemd-stub will wrap sidecar *.cred files from the UEFI kernel image directory into initrd
         * cpios, so that they unpack into /.extra/. We'll pick them up from there and copy them into /run/
         * so that we can access them during the entire runtime (note that the initrd file system is erased
         * during the initrd → host transition). Note that these credentials originate from an untrusted
         * source (i.e. the ESP typically) and thus need to be authenticated later. We thus put them in a
         * directory separate from the usual credentials which are from a trusted source. */

        if (!in_initrd())
                return 0;

        FOREACH_STRING(p,
                       "/.extra/credentials/", /* specific to this boot menu */
                       "/.extra/global_credentials/") { /* boot partition wide */

                _cleanup_free_ DirectoryEntries *de = NULL;
                _cleanup_close_ int source_dir_fd = -1;

                source_dir_fd = open(p, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                if (source_dir_fd < 0) {
                        if (errno == ENOENT) {
                                log_debug("No credentials passed via %s.", p);
                                continue;
                        }

                        log_warning_errno(errno, "Failed to open '%s', ignoring: %m", p);
                        continue;
                }

                r = readdir_all(source_dir_fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT, &de);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read '%s' contents, ignoring: %m", p);
                        continue;
                }

                for (size_t i = 0; i < de->n_entries; i++) {
                        const struct dirent *d = de->entries[i];
                        _cleanup_close_ int cfd = -1, nfd = -1;
                        _cleanup_free_ char *n = NULL;
                        const char *e;
                        struct stat st;

                        e = endswith(d->d_name, ".cred");
                        if (!e)
                                continue;

                        /* drop .cred suffix (which we want in the ESP sidecar dir, but not for our internal
                         * processing) */
                        n = strndup(d->d_name, e - d->d_name);
                        if (!n)
                                return log_oom();

                        if (!credential_name_valid(n)) {
                                log_warning("Credential '%s' has invalid name, ignoring.", d->d_name);
                                continue;
                        }

                        cfd = openat(source_dir_fd, d->d_name, O_RDONLY|O_CLOEXEC);
                        if (cfd < 0) {
                                log_warning_errno(errno, "Failed to open %s, ignoring: %m", d->d_name);
                                continue;
                        }

                        if (fstat(cfd, &st) < 0) {
                                log_warning_errno(errno, "Failed to stat %s, ignoring: %m", d->d_name);
                                continue;
                        }

                        r = stat_verify_regular(&st);
                        if (r < 0) {
                                log_warning_errno(r, "Credential file %s is not a regular file, ignoring: %m", d->d_name);
                                continue;
                        }

                        if (!credential_size_ok(&context, n, st.st_size))
                                continue;

                        r = acquire_encrypted_credential_directory(&context);
                        if (r < 0)
                                return r;

                        nfd = open_credential_file_for_write(context.target_dir_fd, ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY, n);
                        if (nfd == -EEXIST)
                                continue;
                        if (nfd < 0)
                                return nfd;

                        r = copy_bytes(cfd, nfd, st.st_size, 0);
                        if (r < 0) {
                                (void) unlinkat(context.target_dir_fd, n, 0);
                                return log_error_errno(r, "Failed to create credential '%s': %m", n);
                        }

                        context.size_sum += st.st_size;
                        context.n_credentials++;

                        log_debug("Successfully copied boot credential '%s'.", n);
                }
        }

        if (context.n_credentials > 0) {
                log_debug("Imported %u credentials from boot loader.", context.n_credentials);

                r = finalize_credentials_dir(ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY, "ENCRYPTED_CREDENTIALS_DIRECTORY");
                if (r < 0)
                        return r;
        }

        return 0;
}

static int acquire_credential_directory(ImportCredentialContext *c) {
        int r;

        assert(c);

        if (c->target_dir_fd >= 0)
                return c->target_dir_fd;

        r = path_is_mount_point(SYSTEM_CREDENTIALS_DIRECTORY, NULL, 0);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to determine if " SYSTEM_CREDENTIALS_DIRECTORY " is a mount point: %m");

                r = mkdir_safe_label(SYSTEM_CREDENTIALS_DIRECTORY, 0700, 0, 0, MKDIR_WARN_MODE);
                if (r < 0)
                        return log_error_errno(r, "Failed to create " SYSTEM_CREDENTIALS_DIRECTORY " mount point: %m");

                r = 0; /* Now it exists and is not a mount point */
        }
        if (r == 0)
                /* If not a mountpoint yet, try to mount a ramfs there (so that this stuff isn't swapped
                 * out), but if that doesn't work, let's just use the regular tmpfs it already is. */
                (void) mount_nofollow_verbose(LOG_WARNING, "ramfs", SYSTEM_CREDENTIALS_DIRECTORY, "ramfs", MS_NODEV|MS_NOEXEC|MS_NOSUID, "mode=0700");

        c->target_dir_fd = open(SYSTEM_CREDENTIALS_DIRECTORY, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (c->target_dir_fd < 0)
                return log_error_errno(errno, "Failed to open " SYSTEM_CREDENTIALS_DIRECTORY ": %m");

        return c->target_dir_fd;
}

static int proc_cmdline_callback(const char *key, const char *value, void *data) {
        ImportCredentialContext *c = ASSERT_PTR(data);
        _cleanup_free_ char *n = NULL;
        _cleanup_close_ int nfd = -1;
        const char *colon;
        size_t l;
        int r;

        assert(key);

        if (!proc_cmdline_key_streq(key, "systemd.set_credential"))
                return 0;

        colon = value ? strchr(value, ':') : NULL;
        if (!colon) {
                log_warning("Credential assignment through kernel command line lacks ':' character, ignoring: %s", value);
                return 0;
        }

        n = strndup(value, colon - value);
        if (!n)
                return log_oom();

        if (!credential_name_valid(n)) {
                log_warning("Credential name '%s' is invalid, ignoring.", n);
                return 0;
        }

        colon++;
        l = strlen(colon);

        if (!credential_size_ok(c, n, l))
                return 0;

        r = acquire_credential_directory(c);
        if (r < 0)
                return r;

        nfd = open_credential_file_for_write(c->target_dir_fd, SYSTEM_CREDENTIALS_DIRECTORY, n);
        if (nfd == -EEXIST)
                return 0;
        if (nfd < 0)
                return nfd;

        r = loop_write(nfd, colon, l, /* do_poll= */ false);
        if (r < 0) {
                (void) unlinkat(c->target_dir_fd, n, 0);
                return log_error_errno(r, "Failed to write credential: %m");
        }

        c->size_sum += l;
        c->n_credentials++;

        log_debug("Successfully processed kernel command line credential '%s'.", n);

        return 0;
}

static int import_credentials_proc_cmdline(ImportCredentialContext *c) {
        int r;

        assert(c);

        r = proc_cmdline_parse(proc_cmdline_callback, c, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /proc/cmdline: %m");

        return 0;
}

#define QEMU_FWCFG_PATH "/sys/firmware/qemu_fw_cfg/by_name/opt/io.systemd.credentials"

static int import_credentials_qemu(ImportCredentialContext *c) {
        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_close_ int source_dir_fd = -1;
        int r;

        assert(c);

        source_dir_fd = open(QEMU_FWCFG_PATH, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (source_dir_fd < 0) {
                if (errno == ENOENT) {
                        log_debug("No credentials passed via fw_cfg.");
                        return 0;
                }

                log_warning_errno(errno, "Failed to open '" QEMU_FWCFG_PATH "', ignoring: %m");
                return 0;
        }

        r = readdir_all(source_dir_fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0) {
                log_warning_errno(r, "Failed to read '" QEMU_FWCFG_PATH "' contents, ignoring: %m");
                return 0;
        }

        for (size_t i = 0; i < de->n_entries; i++) {
                const struct dirent *d = de->entries[i];
                _cleanup_close_ int vfd = -1, rfd = -1, nfd = -1;
                _cleanup_free_ char *szs = NULL;
                uint64_t sz;

                if (!credential_name_valid(d->d_name)) {
                        log_warning("Credential '%s' has invalid name, ignoring.", d->d_name);
                        continue;
                }

                vfd = openat(source_dir_fd, d->d_name, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (vfd < 0) {
                        log_warning_errno(errno, "Failed to open '" QEMU_FWCFG_PATH "'/%s/, ignoring: %m", d->d_name);
                        continue;
                }

                r = read_virtual_file_at(vfd, "size", LINE_MAX, &szs, NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read '" QEMU_FWCFG_PATH "'/%s/size, ignoring: %m", d->d_name);
                        continue;
                }

                r = safe_atou64(strstrip(szs), &sz);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse size of credential '%s', ignoring: %s", d->d_name, szs);
                        continue;
                }

                if (!credential_size_ok(c, d->d_name, sz))
                        continue;

                /* Ideally we'd just symlink the data here. Alas the kernel driver exports the raw file as
                 * having size zero, and we'd rather not have applications support such credential
                 * files. Let's hence copy the files to make them regular. */

                rfd = openat(vfd, "raw", O_RDONLY|O_CLOEXEC);
                if (rfd < 0) {
                        log_warning_errno(errno, "Failed to open '" QEMU_FWCFG_PATH "'/%s/raw, ignoring: %m", d->d_name);
                        continue;
                }

                r = acquire_credential_directory(c);
                if (r < 0)
                        return r;

                nfd = open_credential_file_for_write(c->target_dir_fd, SYSTEM_CREDENTIALS_DIRECTORY, d->d_name);
                if (nfd == -EEXIST)
                        continue;
                if (nfd < 0)
                        return nfd;

                r = copy_bytes(rfd, nfd, sz, 0);
                if (r < 0) {
                        (void) unlinkat(c->target_dir_fd, d->d_name, 0);
                        return log_error_errno(r, "Failed to create credential '%s': %m", d->d_name);
                }

                c->size_sum += sz;
                c->n_credentials++;

                log_debug("Successfully copied qemu fw_cfg credential '%s'.", d->d_name);
        }

        return 0;
}

static int import_credentials_trusted(void) {
        _cleanup_(import_credentials_context_free) ImportCredentialContext c = {
                .target_dir_fd = -1,
        };
        int q, r;

        r = import_credentials_qemu(&c);
        q = import_credentials_proc_cmdline(&c);

        if (c.n_credentials > 0) {
                int z;

                log_debug("Imported %u credentials from kernel command line/fw_cfg.", c.n_credentials);

                z = finalize_credentials_dir(SYSTEM_CREDENTIALS_DIRECTORY, "CREDENTIALS_DIRECTORY");
                if (z < 0)
                        return z;
        }

        return r < 0 ? r : q;
}

static int symlink_credential_dir(const char *envvar, const char *path, const char *where) {
        int r;

        assert(envvar);
        assert(path);
        assert(where);

        if (!path_is_valid(path) || !path_is_absolute(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "String specified via $%s is not a valid absolute path, refusing: %s", envvar, path);

        /* If the env var already points to where we intend to create the symlink, then most likely we
         * already imported some creds earlier, and thus set the env var, and hence don't need to do
         * anything. */
        if (path_equal(path, where))
                return 0;

        r = symlink_idempotent(path, where, /* make_relative= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to link $%s to %s: %m", envvar, where);

        return 0;
}

int import_credentials(void) {
        const char *received_creds_dir = NULL, *received_encrypted_creds_dir = NULL;
        bool envvar_set = false;
        int r, q;

        r = get_credentials_dir(&received_creds_dir);
        if (r < 0 && r != -ENXIO) /* ENXIO → env var not set yet */
                log_warning_errno(r, "Failed to determine credentials directory, ignoring: %m");

        envvar_set = r >= 0;

        r = get_encrypted_credentials_dir(&received_encrypted_creds_dir);
        if (r < 0 && r != -ENXIO) /* ENXIO → env var not set yet */
                log_warning_errno(r, "Failed to determine encrypted credentials directory, ignoring: %m");

        envvar_set = envvar_set || r >= 0;

        if (envvar_set) {
                /* Maybe an earlier stage initrd already set this up? If so, don't try to import anything again. */
                log_debug("Not importing credentials, $CREDENTIALS_DIRECTORY or $ENCRYPTED_CREDENTIALS_DIRECTORY already set.");

                /* But, let's make sure the creds are available from our regular paths. */
                if (received_creds_dir)
                        r = symlink_credential_dir("CREDENTIALS_DIRECTORY", received_creds_dir, SYSTEM_CREDENTIALS_DIRECTORY);
                else
                        r = 0;

                if (received_encrypted_creds_dir) {
                        q = symlink_credential_dir("ENCRYPTED_CREDENTIALS_DIRECTORY", received_encrypted_creds_dir, ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY);
                        if (r >= 0)
                                r = q;
                }

        } else {
                _cleanup_free_ char *v = NULL;

                r = proc_cmdline_get_key("systemd.import_credentials", PROC_CMDLINE_STRIP_RD_PREFIX, &v);
                if (r < 0)
                        log_debug_errno(r, "Failed to check if 'systemd.import_credentials=' kernel command line option is set, ignoring: %m");
                else if (r > 0) {
                        r = parse_boolean(v);
                        if (r < 0)
                                log_debug_errno(r, "Failed to parse 'systemd.import_credentials=' parameter, ignoring: %m");
                        else if (r == 0) {
                                log_notice("systemd.import_credentials=no is set, skipping importing of credentials.");
                                return 0;
                        }
                }

                r = import_credentials_boot();

                q = import_credentials_trusted();
                if (r >= 0)
                        r = q;
        }

        return r;
}
