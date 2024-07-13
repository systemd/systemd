/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "confidential-virt.h"
#include "copy.h"
#include "creds-util.h"
#include "escape.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "import-creds.h"
#include "initrd-util.h"
#include "io-util.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "recurse-dir.h"
#include "smbios11.h"
#include "strv.h"
#include "virt.h"

/* This imports credentials passed in from environments higher up (VM manager, boot loader, …) and rearranges
 * them so that later code can access them using our regular credential protocol
 * (i.e. $CREDENTIALS_DIRECTORY). It's supposed to be minimal glue to unify behaviour how PID 1 (and
 * generators invoked by it) can acquire credentials from outside, to mimic how we support it for containers,
 * but on VM/physical environments.
 *
 * This does four things:
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
 * 4. It imports credentials passed in via the DMI/SMBIOS OEM string tables, quite similar to fw_cfg. It
 *    looks for strings starting with "io.systemd.credential:" and "io.systemd.credential.binary:". Both
 *    expect a key=value assignment, but in the latter case the value is Base64 decoded, allowing binary
 *    credentials to be passed in.
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

static int acquire_credential_directory(ImportCredentialContext *c, const char *path, bool with_mount) {
        int r;

        assert(c);
        assert(path);

        if (c->target_dir_fd >= 0)
                return c->target_dir_fd;

        r = path_is_mount_point(path);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to determine if %s is a mount point: %m", path);

                r = mkdir_safe_label(path, 0700, 0, 0, MKDIR_WARN_MODE);
                if (r < 0)
                        return log_error_errno(r, "Failed to create %s mount point: %m", path);

                r = 0; /* Now it exists and is not a mount point */
        }
        if (r > 0)
                /* If already a mount point, then remount writable */
                (void) mount_nofollow_verbose(LOG_WARNING, NULL, path, NULL, MS_BIND|MS_REMOUNT|credentials_fs_mount_flags(/* ro= */ false), NULL);
        else if (with_mount)
                /* If not a mount point yet, and the credentials are not encrypted, then let's try to mount a no-swap fs there */
                (void) mount_credentials_fs(path, CREDENTIALS_TOTAL_SIZE_MAX, /* ro= */ false);

        c->target_dir_fd = open(path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (c->target_dir_fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

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
                (void) mount_nofollow_verbose(LOG_WARNING, NULL, dir, NULL, MS_BIND|MS_REMOUNT|credentials_fs_mount_flags(/* ro= */ true), NULL);

        if (setenv(envvar, dir, /* overwrite= */ true) < 0)
                return log_error_errno(errno, "Failed to set $%s environment variable: %m", envvar);

        return 0;
}

static int import_credentials_boot(void) {
        _cleanup_(import_credentials_context_free) ImportCredentialContext context = {
                .target_dir_fd = -EBADF,
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
                _cleanup_close_ int source_dir_fd = -EBADF;

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

                FOREACH_ARRAY(i, de->entries, de->n_entries) {
                        const struct dirent *d = *i;
                        _cleanup_close_ int cfd = -EBADF, nfd = -EBADF;
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

                        r = acquire_credential_directory(&context, ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY, /* with_mount= */ false);
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

static int proc_cmdline_callback(const char *key, const char *value, void *data) {
        ImportCredentialContext *c = ASSERT_PTR(data);
        _cleanup_free_ void *binary = NULL;
        _cleanup_free_ char *n = NULL;
        _cleanup_close_ int nfd = -EBADF;
        const char *colon, *d;
        bool base64;
        size_t l;
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "systemd.set_credential"))
                base64 = false;
        else if (proc_cmdline_key_streq(key, "systemd.set_credential_binary"))
                base64 = true;
        else
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

        if (base64) {
                r = unbase64mem(colon, &binary, &l);
                if (r < 0) {
                        log_warning_errno(r, "Failed to decode binary credential '%s' data, ignoring: %m", n);
                        return 0;
                }

                d = binary;
        } else {
                d = colon;
                l = strlen(colon);
        }

        if (!credential_size_ok(c, n, l))
                return 0;

        r = acquire_credential_directory(c, SYSTEM_CREDENTIALS_DIRECTORY, /* with_mount= */ true);
        if (r < 0)
                return r;

        nfd = open_credential_file_for_write(c->target_dir_fd, SYSTEM_CREDENTIALS_DIRECTORY, n);
        if (nfd == -EEXIST)
                return 0;
        if (nfd < 0)
                return nfd;

        r = loop_write(nfd, d, l);
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
        _cleanup_close_ int source_dir_fd = -EBADF;
        int r;

        assert(c);

        if (detect_container() > 0) /* don't access /sys/ in a container */
                return 0;

        if (detect_confidential_virtualization() > 0) /* don't trust firmware if confidential VMs */
                return 0;

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
                _cleanup_close_ int vfd = -EBADF, rfd = -EBADF, nfd = -EBADF;
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

                r = acquire_credential_directory(c, SYSTEM_CREDENTIALS_DIRECTORY, /* with_mount= */ true);
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

static int parse_smbios_strings(ImportCredentialContext *c, const char *data, size_t size) {
        size_t left, skip;
        const char *p;
        int r;

        assert(c);
        assert(data || size == 0);

        /* Unpacks a packed series of SMBIOS OEM vendor strings. These are a series of NUL terminated
         * strings, one after the other. */

        for (p = data, left = size; left > 0; p += skip, left -= skip) {
                _cleanup_free_ void *buf = NULL;
                _cleanup_free_ char *cn = NULL;
                _cleanup_close_ int nfd = -EBADF;
                const char *nul, *n, *eq;
                const void *cdata;
                size_t buflen, cdata_len;
                bool unbase64;

                nul = memchr(p, 0, left);
                if (nul)
                        skip = (nul - p) + 1;
                else {
                        nul = p + left;
                        skip = left;
                }

                if (nul - p == 0) /* Skip empty strings */
                        continue;

                /* Only care about strings starting with either of these two prefixes */
                if ((n = memory_startswith(p, nul - p, "io.systemd.credential:")))
                        unbase64 = false;
                else if ((n = memory_startswith(p, nul - p, "io.systemd.credential.binary:")))
                        unbase64 = true;
                else {
                        _cleanup_free_ char *escaped = NULL;

                        escaped = cescape_length(p, nul - p);
                        log_debug("Ignoring OEM string: %s", strnull(escaped));
                        continue;
                }

                eq = memchr(n, '=', nul - n);
                if (!eq) {
                        log_warning("SMBIOS OEM string lacks '=' character, ignoring.");
                        continue;
                }

                cn = memdup_suffix0(n, eq - n);
                if (!cn)
                        return log_oom();

                if (!credential_name_valid(cn)) {
                        log_warning("SMBIOS credential name '%s' is not valid, ignoring.", cn);
                        continue;
                }

                /* Optionally base64 decode the data, if requested, to allow binary credentials */
                if (unbase64) {
                        r = unbase64mem_full(eq + 1, nul - (eq + 1), /* secure = */ false, &buf, &buflen);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to base64 decode credential '%s', ignoring: %m", cn);
                                continue;
                        }

                        cdata = buf;
                        cdata_len = buflen;
                } else {
                        cdata = eq + 1;
                        cdata_len = nul - (eq + 1);
                }

                if (!credential_size_ok(c, cn, cdata_len))
                        continue;

                r = acquire_credential_directory(c, SYSTEM_CREDENTIALS_DIRECTORY, /* with_mount= */ true);
                if (r < 0)
                        return r;

                nfd = open_credential_file_for_write(c->target_dir_fd, SYSTEM_CREDENTIALS_DIRECTORY, cn);
                if (nfd == -EEXIST)
                        continue;
                if (nfd < 0)
                        return nfd;

                r = loop_write(nfd, cdata, cdata_len);
                if (r < 0) {
                        (void) unlinkat(c->target_dir_fd, cn, 0);
                        return log_error_errno(r, "Failed to write credential: %m");
                }

                c->size_sum += cdata_len;
                c->n_credentials++;

                log_debug("Successfully processed SMBIOS credential '%s'.", cn);
        }

        return 0;
}

static int import_credentials_smbios(ImportCredentialContext *c) {
        int r;

        /* Parses DMI OEM strings fields (SMBIOS type 11), as settable with qemu's -smbios type=11,value=… switch. */

        if (detect_container() > 0) /* don't access /sys/ in a container */
                return 0;

        if (detect_confidential_virtualization() > 0) /* don't trust firmware if confidential VMs */
                return 0;

        for (unsigned i = 0;; i++) {
                _cleanup_free_ char *data = NULL;
                size_t size;

                r = read_smbios11_field(i, CREDENTIALS_TOTAL_SIZE_MAX, &data, &size);
                if (r == -ENOENT) /* Once we reach ENOENT there are no more DMI Type 11 fields around. */
                        break;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read SMBIOS type #11 object %u, ignoring: %m", i);
                        break;
                }

                r = parse_smbios_strings(c, data, size);
                if (r < 0)
                        return r;

                if (i == UINT_MAX) /* Prevent overflow */
                        break;
        }

        return 0;
}

static int import_credentials_initrd(ImportCredentialContext *c) {
        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_close_ int source_dir_fd = -EBADF;
        int r;

        assert(c);

        /* This imports credentials from /run/credentials/@initrd/ into our credentials directory and deletes
         * the source directory afterwards. This is run once after the initrd → host transition. This is
         * supposed to establish a well-defined avenue for initrd-based host configurators to pass
         * credentials into the main system. */

        if (in_initrd())
                return 0;

        source_dir_fd = open("/run/credentials/@initrd", O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (source_dir_fd < 0) {
                if (errno == ENOENT)
                        log_debug_errno(errno, "No credentials passed from initrd.");
                else
                        log_warning_errno(errno, "Failed to open '/run/credentials/@initrd', ignoring: %m");
                return 0;
        }

        r = readdir_all(source_dir_fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0) {
                log_warning_errno(r, "Failed to read '/run/credentials/@initrd' contents, ignoring: %m");
                return 0;
        }

        FOREACH_ARRAY(entry, de->entries, de->n_entries) {
                _cleanup_close_ int cfd = -EBADF, nfd = -EBADF;
                const struct dirent *d = *entry;
                struct stat st;

                if (!credential_name_valid(d->d_name)) {
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

                if (!credential_size_ok(c, d->d_name, st.st_size))
                        continue;

                r = acquire_credential_directory(c, SYSTEM_CREDENTIALS_DIRECTORY, /* with_mount= */ true);
                if (r < 0)
                        return r;

                nfd = open_credential_file_for_write(c->target_dir_fd, SYSTEM_CREDENTIALS_DIRECTORY, d->d_name);
                if (nfd == -EEXIST)
                        continue;
                if (nfd < 0)
                        return nfd;

                r = copy_bytes(cfd, nfd, st.st_size, 0);
                if (r < 0) {
                        (void) unlinkat(c->target_dir_fd, d->d_name, 0);
                        return log_error_errno(r, "Failed to create credential '%s': %m", d->d_name);
                }

                c->size_sum += st.st_size;
                c->n_credentials++;

                log_debug("Successfully copied initrd credential '%s'.", d->d_name);

                (void) unlinkat(source_dir_fd, d->d_name, 0);
        }

        source_dir_fd = safe_close(source_dir_fd);

        if (rmdir("/run/credentials/@initrd") < 0)
                log_warning_errno(errno, "Failed to remove /run/credentials/@initrd after import, ignoring: %m");

        return 0;
}

static int import_credentials_trusted(void) {
        _cleanup_(import_credentials_context_free) ImportCredentialContext c = {
                .target_dir_fd = -EBADF,
        };
        int q, w, r, y;

        /* This is invoked during early boot when no credentials have been imported so far. (Specifically, if
         * the $CREDENTIALS_DIRECTORY or $ENCRYPTED_CREDENTIALS_DIRECTORY environment variables are not set
         * yet.) */

        r = import_credentials_qemu(&c);
        w = import_credentials_smbios(&c);
        q = import_credentials_proc_cmdline(&c);
        y = import_credentials_initrd(&c);

        if (c.n_credentials > 0) {
                int z;

                log_debug("Imported %u credentials from kernel command line/smbios/fw_cfg/initrd.", c.n_credentials);

                z = finalize_credentials_dir(SYSTEM_CREDENTIALS_DIRECTORY, "CREDENTIALS_DIRECTORY");
                if (z < 0)
                        return z;
        }

        return r < 0 ? r : w < 0 ? w : q < 0 ? q : y;
}

static int merge_credentials_trusted(const char *creds_dir) {
        _cleanup_(import_credentials_context_free) ImportCredentialContext c = {
                .target_dir_fd = -EBADF,
        };
        int r;

        /* This is invoked after the initrd → host transitions, when credentials already have been imported,
         * but we might want to import some more from the initrd. */

        if (in_initrd())
                return 0;

        /* Do not try to merge initrd credentials into foreign credentials directories */
        if (!path_equal(creds_dir, SYSTEM_CREDENTIALS_DIRECTORY)) {
                log_debug("Not importing initrd credentials, as foreign $CREDENTIALS_DIRECTORY has been set.");
                return 0;
        }

        r = import_credentials_initrd(&c);

        if (c.n_credentials > 0) {
                int z;

                log_debug("Merged %u credentials from initrd.", c.n_credentials);

                z = finalize_credentials_dir(SYSTEM_CREDENTIALS_DIRECTORY, "CREDENTIALS_DIRECTORY");
                if (z < 0)
                        return z;
        }

        return r;
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

static int setenv_notify_socket(void) {
        _cleanup_free_ char *address = NULL;
        int r;

        r = read_credential_with_decryption("vmm.notify_socket", (void **)&address, /* ret_size= */ NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to read 'vmm.notify_socket' credential, ignoring: %m");

        if (isempty(address))
                return 0;

        if (setenv("NOTIFY_SOCKET", address, /* replace= */ 1) < 0)
                return log_warning_errno(errno, "Failed to set $NOTIFY_SOCKET environment variable, ignoring: %m");

        return 1;
}

static int report_credentials_per_func(const char *title, int (*get_directory_func)(const char **ret)) {
        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_free_ char *ll = NULL;
        const char *d = NULL;
        int r, c = 0;

        assert(title);
        assert(get_directory_func);

        r = get_directory_func(&d);
        if (r < 0) {
                if (r == -ENXIO) /* Env var not set */
                        return 0;

                return log_warning_errno(r, "Failed to determine %s directory: %m", title);
        }

        r = readdir_all_at(AT_FDCWD, d, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0)
                return log_warning_errno(r, "Failed to enumerate credentials directory %s: %m", d);

        FOREACH_ARRAY(entry, de->entries, de->n_entries) {
                const struct dirent *e = *entry;

                if (!credential_name_valid(e->d_name))
                        continue;

                if (!strextend_with_separator(&ll, ", ", e->d_name))
                        return log_oom();

                c++;
        }

        if (ll)
                log_info("Received %s: %s", title, ll);

        return c;
}

static void report_credentials(void) {
        int p, q;

        p = report_credentials_per_func("regular credentials", get_credentials_dir);
        q = report_credentials_per_func("untrusted credentials", get_encrypted_credentials_dir);

        log_full(p > 0 || q > 0 ? LOG_INFO : LOG_DEBUG,
                 "Acquired %i regular credentials, %i untrusted credentials.",
                 p > 0 ? p : 0,
                 q > 0 ? q : 0);
}

int import_credentials(void) {
        const char *received_creds_dir = NULL, *received_encrypted_creds_dir = NULL;
        bool envvar_set = false;
        int r;

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

                if (received_encrypted_creds_dir)
                        RET_GATHER(r, symlink_credential_dir("ENCRYPTED_CREDENTIALS_DIRECTORY",
                                                             received_encrypted_creds_dir,
                                                             ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY));

                RET_GATHER(r, merge_credentials_trusted(received_creds_dir));

        } else {
                bool import;

                r = proc_cmdline_get_bool("systemd.import_credentials", PROC_CMDLINE_STRIP_RD_PREFIX|PROC_CMDLINE_TRUE_WHEN_MISSING, &import);
                if (r < 0)
                        log_debug_errno(r, "Failed to check systemd.import_credentials= kernel command line option, proceeding: %m");
                else if (!import) {
                        log_notice("systemd.import_credentials=no is set, skipping importing of credentials.");
                        return 0;
                }

                r = import_credentials_boot();
                RET_GATHER(r, import_credentials_trusted());
        }

        report_credentials();

        /* Propagate vmm_notify_socket credential → $NOTIFY_SOCKET env var */
        (void) setenv_notify_socket();

        return r;
}
