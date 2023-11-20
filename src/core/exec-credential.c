/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "acl-util.h"
#include "creds-util.h"
#include "exec-credential.h"
#include "execute.h"
#include "fileio.h"
#include "glob-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "label-util.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mount.h"
#include "mountpoint-util.h"
#include "process-util.h"
#include "random-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "tmpfile-util.h"

ExecSetCredential *exec_set_credential_free(ExecSetCredential *sc) {
        if (!sc)
                return NULL;

        free(sc->id);
        free(sc->data);
        return mfree(sc);
}

ExecLoadCredential *exec_load_credential_free(ExecLoadCredential *lc) {
        if (!lc)
                return NULL;

        free(lc->id);
        free(lc->path);
        return mfree(lc);
}

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        exec_set_credential_hash_ops,
        char, string_hash_func, string_compare_func,
        ExecSetCredential, exec_set_credential_free);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        exec_load_credential_hash_ops,
        char, string_hash_func, string_compare_func,
        ExecLoadCredential, exec_load_credential_free);

bool exec_context_has_credentials(const ExecContext *c) {
        assert(c);

        return !hashmap_isempty(c->set_credentials) ||
                !hashmap_isempty(c->load_credentials) ||
                !set_isempty(c->import_credentials);
}

bool exec_context_has_encrypted_credentials(ExecContext *c) {
        ExecLoadCredential *load_cred;
        ExecSetCredential *set_cred;

        assert(c);

        HASHMAP_FOREACH(load_cred, c->load_credentials)
                if (load_cred->encrypted)
                        return true;

        HASHMAP_FOREACH(set_cred, c->set_credentials)
                if (set_cred->encrypted)
                        return true;

        return false;
}

static int get_credential_directory(
                const char *runtime_prefix,
                const char *unit,
                char **ret) {

        char *p;

        assert(ret);

        if (!runtime_prefix || !unit) {
                *ret = NULL;
                return 0;
        }

        p = path_join(runtime_prefix, "credentials", unit);
        if (!p)
                return -ENOMEM;

        *ret = p;
        return 1;
}

int exec_context_get_credential_directory(
                const ExecContext *context,
                const ExecParameters *params,
                const char *unit,
                char **ret) {

        assert(context);
        assert(params);
        assert(unit);
        assert(ret);

        if (!exec_context_has_credentials(context)) {
                *ret = NULL;
                return 0;
        }

        return get_credential_directory(params->prefix[EXEC_DIRECTORY_RUNTIME], unit, ret);
}

int unit_add_default_credential_dependencies(Unit *u, const ExecContext *c) {
        _cleanup_free_ char *p = NULL, *m = NULL;
        int r;

        assert(u);
        assert(c);

        if (!exec_context_has_credentials(c))
                return 0;

        /* Let's make sure the credentials directory of this service is unmounted *after* the service itself
         * shuts down. This only matters if mount namespacing is not used for the service, and hence the
         * credentials mount appears on the host. */

        r = get_credential_directory(u->manager->prefix[EXEC_DIRECTORY_RUNTIME], u->id, &p);
        if (r <= 0)
                return r;

        r = unit_name_from_path(p, ".mount", &m);
        if (r < 0)
                return r;

        return unit_add_dependency_by_name(u, UNIT_AFTER, m, /* add_reference= */ true, UNIT_DEPENDENCY_FILE);
}

int exec_context_destroy_credentials(Unit *u) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(u);

        r = get_credential_directory(u->manager->prefix[EXEC_DIRECTORY_RUNTIME], u->id, &p);
        if (r <= 0)
                return r;

        /* This is either a tmpfs/ramfs of its own, or a plain directory. Either way, let's first try to
         * unmount it, and afterwards remove the mount point */
        if (umount2(p, MNT_DETACH|UMOUNT_NOFOLLOW) >= 0)
                (void) mount_invalidate_state_by_path(u->manager, p);

        (void) rm_rf(p, REMOVE_ROOT|REMOVE_CHMOD);

        return 0;
}

static int write_credential(
                int dfd,
                const char *id,
                const void *data,
                size_t size,
                uid_t uid,
                gid_t gid,
                bool ownership_ok) {

        _cleanup_(unlink_and_freep) char *tmp = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        r = tempfn_random_child("", "cred", &tmp);
        if (r < 0)
                return r;

        fd = openat(dfd, tmp, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL|O_NOFOLLOW|O_NOCTTY, 0600);
        if (fd < 0) {
                tmp = mfree(tmp);
                return -errno;
        }

        r = loop_write(fd, data, size);
        if (r < 0)
                return r;

        if (fchmod(fd, 0400) < 0) /* Take away "w" bit */
                return -errno;

        if (uid_is_valid(uid) && uid != getuid()) {
                r = fd_add_uid_acl_permission(fd, uid, ACL_READ);
                if (r < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(r) && !ERRNO_IS_PRIVILEGE(r))
                                return r;

                        if (!ownership_ok) /* Ideally we use ACLs, since we can neatly express what we want
                                            * to express: that the user gets read access and nothing
                                            * else. But if the backing fs can't support that (e.g. ramfs)
                                            * then we can use file ownership instead. But that's only safe if
                                            * we can then re-mount the whole thing read-only, so that the
                                            * user can no longer chmod() the file to gain write access. */
                                return r;

                        if (fchown(fd, uid, gid) < 0)
                                return -errno;
                }
        }

        if (renameat(dfd, tmp, dfd, id) < 0)
                return -errno;

        tmp = mfree(tmp);
        return 0;
}

typedef enum CredentialSearchPath {
        CREDENTIAL_SEARCH_PATH_TRUSTED,
        CREDENTIAL_SEARCH_PATH_ENCRYPTED,
        CREDENTIAL_SEARCH_PATH_ALL,
        _CREDENTIAL_SEARCH_PATH_MAX,
        _CREDENTIAL_SEARCH_PATH_INVALID = -EINVAL,
} CredentialSearchPath;

static char **credential_search_path(const ExecParameters *params, CredentialSearchPath path) {

        _cleanup_strv_free_ char **l = NULL;

        assert(params);
        assert(path >= 0 && path < _CREDENTIAL_SEARCH_PATH_MAX);

        /* Assemble a search path to find credentials in. For non-encrypted credentials, We'll look in
         * /etc/credstore/ (and similar directories in /usr/lib/ + /run/). If we're looking for encrypted
         * credentials, we'll look in /etc/credstore.encrypted/ (and similar dirs). */

        if (IN_SET(path, CREDENTIAL_SEARCH_PATH_ENCRYPTED, CREDENTIAL_SEARCH_PATH_ALL)) {
                if (strv_extend(&l, params->received_encrypted_credentials_directory) < 0)
                        return NULL;

                if (strv_extend_strv(&l, CONF_PATHS_STRV("credstore.encrypted"), /* filter_duplicates= */ true) < 0)
                        return NULL;
        }

        if (IN_SET(path, CREDENTIAL_SEARCH_PATH_TRUSTED, CREDENTIAL_SEARCH_PATH_ALL)) {
                if (params->received_credentials_directory)
                        if (strv_extend(&l, params->received_credentials_directory) < 0)
                                return NULL;

                if (strv_extend_strv(&l, CONF_PATHS_STRV("credstore"), /* filter_duplicates= */ true) < 0)
                        return NULL;
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *t = strv_join(l, ":");

                log_debug("Credential search path is: %s", strempty(t));
        }

        return TAKE_PTR(l);
}

static int maybe_decrypt_and_write_credential(
                int dir_fd,
                const char *id,
                bool encrypted,
                uid_t uid,
                gid_t gid,
                bool ownership_ok,
                const char *data,
                size_t size,
                uint64_t *left) {

        _cleanup_(iovec_done_erase) struct iovec plaintext = {};
        size_t add;
        int r;

        if (encrypted) {
                r = decrypt_credential_and_warn(
                                id,
                                now(CLOCK_REALTIME),
                                /* tpm2_device= */ NULL,
                                /* tpm2_signature_path= */ NULL,
                                &IOVEC_MAKE(data, size),
                                /* flags= */ 0,
                                &plaintext);
                if (r < 0)
                        return r;

                data = plaintext.iov_base;
                size = plaintext.iov_len;
        }

        add = strlen(id) + size;
        if (add > *left)
                return -E2BIG;

        r = write_credential(dir_fd, id, data, size, uid, gid, ownership_ok);
        if (r < 0)
                return log_debug_errno(r, "Failed to write credential '%s': %m", id);

        *left -= add;
        return 0;
}

static int load_credential_glob(
                const char *path,
                bool encrypted,
                char **search_path,
                ReadFullFileFlags flags,
                int write_dfd,
                uid_t uid,
                gid_t gid,
                bool ownership_ok,
                uint64_t *left) {

        int r;

        STRV_FOREACH(d, search_path) {
                _cleanup_globfree_ glob_t pglob = {};
                _cleanup_free_ char *j = NULL;

                j = path_join(*d, path);
                if (!j)
                        return -ENOMEM;

                r = safe_glob(j, 0, &pglob);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                for (size_t n = 0; n < pglob.gl_pathc; n++) {
                        _cleanup_free_ char *fn = NULL;
                        _cleanup_(erase_and_freep) char *data = NULL;
                        size_t size;

                        /* path is absolute, hence pass AT_FDCWD as nop dir fd here */
                        r = read_full_file_full(
                                AT_FDCWD,
                                pglob.gl_pathv[n],
                                UINT64_MAX,
                                encrypted ? CREDENTIAL_ENCRYPTED_SIZE_MAX : CREDENTIAL_SIZE_MAX,
                                flags,
                                NULL,
                                &data, &size);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to read credential '%s': %m",
                                                        pglob.gl_pathv[n]);

                        r = path_extract_filename(pglob.gl_pathv[n], &fn);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extract filename from '%s': %m",
                                                        pglob.gl_pathv[n]);

                        r = maybe_decrypt_and_write_credential(
                                write_dfd,
                                fn,
                                encrypted,
                                uid,
                                gid,
                                ownership_ok,
                                data, size,
                                left);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int load_credential(
                const ExecContext *context,
                const ExecParameters *params,
                const char *id,
                const char *path,
                bool encrypted,
                const char *unit,
                int read_dfd,
                int write_dfd,
                uid_t uid,
                gid_t gid,
                bool ownership_ok,
                uint64_t *left) {

        ReadFullFileFlags flags = READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER;
        _cleanup_strv_free_ char **search_path = NULL;
        _cleanup_(erase_and_freep) char *data = NULL;
        _cleanup_free_ char *bindname = NULL;
        const char *source = NULL;
        bool missing_ok = true;
        size_t size, maxsz;
        int r;

        assert(context);
        assert(params);
        assert(id);
        assert(path);
        assert(unit);
        assert(read_dfd >= 0 || read_dfd == AT_FDCWD);
        assert(write_dfd >= 0);
        assert(left);

        if (read_dfd >= 0) {
                /* If a directory fd is specified, then read the file directly from that dir. In this case we
                 * won't do AF_UNIX stuff (we simply don't want to recursively iterate down a tree of AF_UNIX
                 * IPC sockets). It's OK if a file vanishes here in the time we enumerate it and intend to
                 * open it. */

                if (!filename_is_valid(path)) /* safety check */
                        return -EINVAL;

                missing_ok = true;
                source = path;

        } else if (path_is_absolute(path)) {
                /* If this is an absolute path, read the data directly from it, and support AF_UNIX
                 * sockets */

                if (!path_is_valid(path)) /* safety check */
                        return -EINVAL;

                flags |= READ_FULL_FILE_CONNECT_SOCKET;

                /* Pass some minimal info about the unit and the credential name we are looking to acquire
                 * via the source socket address in case we read off an AF_UNIX socket. */
                if (asprintf(&bindname, "@%" PRIx64"/unit/%s/%s", random_u64(), unit, id) < 0)
                        return -ENOMEM;

                missing_ok = false;
                source = path;

        } else if (credential_name_valid(path)) {
                /* If this is a relative path, take it as credential name relative to the credentials
                 * directory we received ourselves. We don't support the AF_UNIX stuff in this mode, since we
                 * are operating on a credential store, i.e. this is guaranteed to be regular files. */

                search_path = credential_search_path(params, CREDENTIAL_SEARCH_PATH_ALL);
                if (!search_path)
                        return -ENOMEM;

                missing_ok = true;
        } else
                source = NULL;

        if (encrypted)
                flags |= READ_FULL_FILE_UNBASE64;

        maxsz = encrypted ? CREDENTIAL_ENCRYPTED_SIZE_MAX : CREDENTIAL_SIZE_MAX;

        if (search_path) {
                STRV_FOREACH(d, search_path) {
                        _cleanup_free_ char *j = NULL;

                        j = path_join(*d, path);
                        if (!j)
                                return -ENOMEM;

                        r = read_full_file_full(
                                        AT_FDCWD, j, /* path is absolute, hence pass AT_FDCWD as nop dir fd here */
                                        UINT64_MAX,
                                        maxsz,
                                        flags,
                                        NULL,
                                        &data, &size);
                        if (r != -ENOENT)
                                break;
                }
        } else if (source)
                r = read_full_file_full(
                                read_dfd, source,
                                UINT64_MAX,
                                maxsz,
                                flags,
                                bindname,
                                &data, &size);
        else
                r = -ENOENT;

        if (r == -ENOENT && (missing_ok || hashmap_contains(context->set_credentials, id))) {
                /* Make a missing inherited credential non-fatal, let's just continue. After all apps
                 * will get clear errors if we don't pass such a missing credential on as they
                 * themselves will get ENOENT when trying to read them, which should not be much
                 * worse than when we handle the error here and make it fatal.
                 *
                 * Also, if the source file doesn't exist, but a fallback is set via SetCredentials=
                 * we are fine, too. */
                log_debug_errno(r, "Couldn't read inherited credential '%s', skipping: %m", path);
                return 0;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to read credential '%s': %m", path);

        return maybe_decrypt_and_write_credential(write_dfd, id, encrypted, uid, gid, ownership_ok, data, size, left);
}

struct load_cred_args {
        const ExecContext *context;
        const ExecParameters *params;
        bool encrypted;
        const char *unit;
        int dfd;
        uid_t uid;
        gid_t gid;
        bool ownership_ok;
        uint64_t *left;
};

static int load_cred_recurse_dir_cb(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        struct load_cred_args *args = ASSERT_PTR(userdata);
        _cleanup_free_ char *sub_id = NULL;
        int r;

        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        if (!IN_SET(de->d_type, DT_REG, DT_SOCK))
                return RECURSE_DIR_CONTINUE;

        sub_id = strreplace(path, "/", "_");
        if (!sub_id)
                return -ENOMEM;

        if (!credential_name_valid(sub_id))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Credential would get ID %s, which is not valid, refusing", sub_id);

        if (faccessat(args->dfd, sub_id, F_OK, AT_SYMLINK_NOFOLLOW) >= 0) {
                log_debug("Skipping credential with duplicated ID %s at %s", sub_id, path);
                return RECURSE_DIR_CONTINUE;
        }
        if (errno != ENOENT)
                return log_debug_errno(errno, "Failed to test if credential %s exists: %m", sub_id);

        r = load_credential(
                        args->context,
                        args->params,
                        sub_id,
                        de->d_name,
                        args->encrypted,
                        args->unit,
                        dir_fd,
                        args->dfd,
                        args->uid,
                        args->gid,
                        args->ownership_ok,
                        args->left);
        if (r < 0)
                return r;

        return RECURSE_DIR_CONTINUE;
}

static int acquire_credentials(
                const ExecContext *context,
                const ExecParameters *params,
                const char *unit,
                const char *p,
                uid_t uid,
                gid_t gid,
                bool ownership_ok) {

        uint64_t left = CREDENTIALS_TOTAL_SIZE_MAX;
        _cleanup_close_ int dfd = -EBADF;
        const char *ic;
        ExecLoadCredential *lc;
        ExecSetCredential *sc;
        int r;

        assert(context);
        assert(p);

        dfd = open(p, O_DIRECTORY|O_CLOEXEC);
        if (dfd < 0)
                return -errno;

        r = fd_acl_make_writable(dfd); /* Add the "w" bit, if we are reusing an already set up credentials dir where it was unset */
        if (r < 0)
                return r;

        /* First, load credentials off disk (or acquire via AF_UNIX socket) */
        HASHMAP_FOREACH(lc, context->load_credentials) {
                _cleanup_close_ int sub_fd = -EBADF;

                /* If this is an absolute path, then try to open it as a directory. If that works, then we'll
                 * recurse into it. If it is an absolute path but it isn't a directory, then we'll open it as
                 * a regular file. Finally, if it's a relative path we will use it as a credential name to
                 * propagate a credential passed to us from further up. */

                if (path_is_absolute(lc->path)) {
                        sub_fd = open(lc->path, O_DIRECTORY|O_CLOEXEC|O_RDONLY);
                        if (sub_fd < 0 && !IN_SET(errno,
                                                  ENOTDIR,  /* Not a directory */
                                                  ENOENT))  /* Doesn't exist? */
                                return log_debug_errno(errno, "Failed to open '%s': %m", lc->path);
                }

                if (sub_fd < 0)
                        /* Regular file (incl. a credential passed in from higher up) */
                        r = load_credential(
                                        context,
                                        params,
                                        lc->id,
                                        lc->path,
                                        lc->encrypted,
                                        unit,
                                        AT_FDCWD,
                                        dfd,
                                        uid,
                                        gid,
                                        ownership_ok,
                                        &left);
                else
                        /* Directory */
                        r = recurse_dir(
                                        sub_fd,
                                        /* path= */ lc->id, /* recurse_dir() will suffix the subdir paths from here to the top-level id */
                                        /* statx_mask= */ 0,
                                        /* n_depth_max= */ UINT_MAX,
                                        RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE,
                                        load_cred_recurse_dir_cb,
                                        &(struct load_cred_args) {
                                                .context = context,
                                                .params = params,
                                                .encrypted = lc->encrypted,
                                                .unit = unit,
                                                .dfd = dfd,
                                                .uid = uid,
                                                .gid = gid,
                                                .ownership_ok = ownership_ok,
                                                .left = &left,
                                        });
                if (r < 0)
                        return r;
        }

        /* Next, look for system credentials and credentials in the credentials store. Note that these do not
         * override any credentials found earlier. */
        SET_FOREACH(ic, context->import_credentials) {
                _cleanup_free_ char **search_path = NULL;

                search_path = credential_search_path(params, CREDENTIAL_SEARCH_PATH_TRUSTED);
                if (!search_path)
                        return -ENOMEM;

                r = load_credential_glob(
                                ic,
                                /* encrypted = */ false,
                                search_path,
                                READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER,
                                dfd,
                                uid,
                                gid,
                                ownership_ok,
                                &left);
                if (r < 0)
                        return r;

                search_path = strv_free(search_path);
                search_path = credential_search_path(params, CREDENTIAL_SEARCH_PATH_ENCRYPTED);
                if (!search_path)
                        return -ENOMEM;

                r = load_credential_glob(
                                ic,
                                /* encrypted = */ true,
                                search_path,
                                READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER|READ_FULL_FILE_UNBASE64,
                                dfd,
                                uid,
                                gid,
                                ownership_ok,
                                &left);
                if (r < 0)
                        return r;
        }

        /* Finally, we add in literally specified credentials. If the credentials already exist, we'll not
         * add them, so that they can act as a "default" if the same credential is specified multiple times. */
        HASHMAP_FOREACH(sc, context->set_credentials) {
                _cleanup_(iovec_done_erase) struct iovec plaintext = {};
                const char *data;
                size_t size, add;

                /* Note that we check ahead of time here instead of relying on O_EXCL|O_CREAT later to return
                 * EEXIST if the credential already exists. That's because the TPM2-based decryption is kinda
                 * slow and involved, hence it's nice to be able to skip that if the credential already
                 * exists anyway. */
                if (faccessat(dfd, sc->id, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                        continue;
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to test if credential %s exists: %m", sc->id);

                if (sc->encrypted) {
                        r = decrypt_credential_and_warn(
                                        sc->id,
                                        now(CLOCK_REALTIME),
                                        /* tpm2_device= */ NULL,
                                        /* tpm2_signature_path= */ NULL,
                                        &IOVEC_MAKE(sc->data, sc->size),
                                        /* flags= */ 0,
                                        &plaintext);
                        if (r < 0)
                                return r;

                        data = plaintext.iov_base;
                        size = plaintext.iov_len;
                } else {
                        data = sc->data;
                        size = sc->size;
                }

                add = strlen(sc->id) + size;
                if (add > left)
                        return -E2BIG;

                r = write_credential(dfd, sc->id, data, size, uid, gid, ownership_ok);
                if (r < 0)
                        return r;

                left -= add;
        }

        r = fd_acl_make_read_only(dfd); /* Now take away the "w" bit */
        if (r < 0)
                return r;

        /* After we created all keys with the right perms, also make sure the credential store as a whole is
         * accessible */

        if (uid_is_valid(uid) && uid != getuid()) {
                r = fd_add_uid_acl_permission(dfd, uid, ACL_READ | ACL_EXECUTE);
                if (r < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(r) && !ERRNO_IS_PRIVILEGE(r))
                                return r;

                        if (!ownership_ok)
                                return r;

                        if (fchown(dfd, uid, gid) < 0)
                                return -errno;
                }
        }

        return 0;
}

static int setup_credentials_internal(
                const ExecContext *context,
                const ExecParameters *params,
                const char *unit,
                const char *final,        /* This is where the credential store shall eventually end up at */
                const char *workspace,    /* This is where we can prepare it before moving it to the final place */
                bool reuse_workspace,     /* Whether to reuse any existing workspace mount if it already is a mount */
                bool must_mount,          /* Whether to require that we mount something, it's not OK to use the plain directory fall back */
                uid_t uid,
                gid_t gid) {

        int r, workspace_mounted; /* negative if we don't know yet whether we have/can mount something; true
                                   * if we mounted something; false if we definitely can't mount anything */
        bool final_mounted;
        const char *where;

        assert(context);
        assert(final);
        assert(workspace);

        if (reuse_workspace) {
                r = path_is_mount_point(workspace, NULL, 0);
                if (r < 0)
                        return r;
                if (r > 0)
                        workspace_mounted = true; /* If this is already a mount, and we are supposed to reuse
                                                   * it, let's keep this in mind */
                else
                        workspace_mounted = -1; /* We need to figure out if we can mount something to the workspace */
        } else
                workspace_mounted = -1; /* ditto */

        r = path_is_mount_point(final, NULL, 0);
        if (r < 0)
                return r;
        if (r > 0) {
                /* If the final place already has something mounted, we use that. If the workspace also has
                 * something mounted we assume it's actually the same mount (but with MS_RDONLY
                 * different). */
                final_mounted = true;

                if (workspace_mounted < 0) {
                        /* If the final place is mounted, but the workspace isn't, then let's bind mount
                         * the final version to the workspace, and make it writable, so that we can make
                         * changes */

                        r = mount_nofollow_verbose(LOG_DEBUG, final, workspace, NULL, MS_BIND|MS_REC, NULL);
                        if (r < 0)
                                return r;

                        r = mount_nofollow_verbose(LOG_DEBUG, NULL, workspace, NULL, MS_BIND|MS_REMOUNT|credentials_fs_mount_flags(/* ro= */ false), NULL);
                        if (r < 0)
                                return r;

                        workspace_mounted = true;
                }
        } else
                final_mounted = false;

        if (workspace_mounted < 0) {
                /* Nothing is mounted on the workspace yet, let's try to mount something now */

                r = mount_credentials_fs(workspace, CREDENTIALS_TOTAL_SIZE_MAX, /* ro= */ false);
                if (r < 0) {
                        /* If that didn't work, try to make a bind mount from the final to the workspace, so
                         * that we can make it writable there. */
                        r = mount_nofollow_verbose(LOG_DEBUG, final, workspace, NULL, MS_BIND|MS_REC, NULL);
                        if (r < 0) {
                                if (!ERRNO_IS_PRIVILEGE(r))
                                        /* Propagate anything that isn't a permission problem. */
                                        return r;

                                if (must_mount)
                                        /* If it's not OK to use the plain directory fallback, propagate all
                                         * errors too. */
                                        return r;

                                /* If we lack privileges to bind mount stuff, then let's gracefully proceed
                                 * for compat with container envs, and just use the final dir as is. */

                                workspace_mounted = false;
                        } else {
                                /* Make the new bind mount writable (i.e. drop MS_RDONLY) */
                                r = mount_nofollow_verbose(LOG_DEBUG, NULL, workspace, NULL, MS_BIND|MS_REMOUNT|credentials_fs_mount_flags(/* ro= */ false), NULL);
                                if (r < 0)
                                        return r;

                                workspace_mounted = true;
                        }
                } else
                        workspace_mounted = true;
        }

        assert(!must_mount || workspace_mounted > 0);
        where = workspace_mounted ? workspace : final;

        (void) label_fix_full(AT_FDCWD, where, final, 0);

        r = acquire_credentials(context, params, unit, where, uid, gid, workspace_mounted);
        if (r < 0)
                return r;

        if (workspace_mounted) {
                bool install;

                /* Determine if we should actually install the prepared mount in the final location by bind
                 * mounting it there. We do so only if the mount is not established there already, and if the
                 * mount is actually non-empty (i.e. carries at least one credential). Not that in the best
                 * case we are doing all this in a mount namespace, thus no one else will see that we
                 * allocated a file system we are getting rid of again here. */
                if (final_mounted)
                        install = false; /* already installed */
                else {
                        r = dir_is_empty(where, /* ignore_hidden_or_backup= */ false);
                        if (r < 0)
                                return r;

                        install = r == 0; /* install only if non-empty */
                }

                if (install) {
                        /* Make workspace read-only now, so that any bind mount we make from it defaults to
                         * read-only too */
                        r = mount_nofollow_verbose(LOG_DEBUG, NULL, workspace, NULL, MS_BIND|MS_REMOUNT|credentials_fs_mount_flags(/* ro= */ true), NULL);
                        if (r < 0)
                                return r;

                        /* And mount it to the final place, read-only */
                        r = mount_nofollow_verbose(LOG_DEBUG, workspace, final, NULL, MS_MOVE, NULL);
                } else
                        /* Otherwise get rid of it */
                        r = umount_verbose(LOG_DEBUG, workspace, MNT_DETACH|UMOUNT_NOFOLLOW);
                if (r < 0)
                        return r;
        } else {
                _cleanup_free_ char *parent = NULL;

                /* If we do not have our own mount put used the plain directory fallback, then we need to
                 * open access to the top-level credential directory and the per-service directory now */

                r = path_extract_directory(final, &parent);
                if (r < 0)
                        return r;
                if (chmod(parent, 0755) < 0)
                        return -errno;
        }

        return 0;
}

int exec_setup_credentials(
                const ExecContext *context,
                const ExecParameters *params,
                const char *unit,
                uid_t uid,
                gid_t gid) {

        _cleanup_free_ char *p = NULL, *q = NULL;
        int r;

        assert(context);
        assert(params);

        if (!exec_context_has_credentials(context))
                return 0;

        if (!params->prefix[EXEC_DIRECTORY_RUNTIME])
                return -EINVAL;

        /* This where we'll place stuff when we are done; this main credentials directory is world-readable,
         * and the subdir we mount over with a read-only file system readable by the service's user */
        q = path_join(params->prefix[EXEC_DIRECTORY_RUNTIME], "credentials");
        if (!q)
                return -ENOMEM;

        r = mkdir_label(q, 0755); /* top-level dir: world readable/searchable */
        if (r < 0 && r != -EEXIST)
                return r;

        p = path_join(q, unit);
        if (!p)
                return -ENOMEM;

        r = mkdir_label(p, 0700); /* per-unit dir: private to user */
        if (r < 0 && r != -EEXIST)
                return r;

        r = safe_fork("(sd-mkdcreds)", FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_NEW_MOUNTNS, NULL);
        if (r < 0) {
                _cleanup_(rmdir_and_freep) char *u = NULL; /* remove the temporary workspace if we can */
                _cleanup_free_ char *t = NULL;

                /* If this is not a privilege or support issue then propagate the error */
                if (!ERRNO_IS_NOT_SUPPORTED(r) && !ERRNO_IS_PRIVILEGE(r))
                        return r;

                /* Temporary workspace, that remains inaccessible all the time. We prepare stuff there before moving
                 * it into place, so that users can't access half-initialized credential stores. */
                t = path_join(params->prefix[EXEC_DIRECTORY_RUNTIME], "systemd/temporary-credentials");
                if (!t)
                        return -ENOMEM;

                /* We can't set up a mount namespace. In that case operate on a fixed, inaccessible per-unit
                 * directory outside of /run/credentials/ first, and then move it over to /run/credentials/
                 * after it is fully set up */
                u = path_join(t, unit);
                if (!u)
                        return -ENOMEM;

                FOREACH_STRING(i, t, u) {
                        r = mkdir_label(i, 0700);
                        if (r < 0 && r != -EEXIST)
                                return r;
                }

                r = setup_credentials_internal(
                                context,
                                params,
                                unit,
                                p,       /* final mount point */
                                u,       /* temporary workspace to overmount */
                                true,    /* reuse the workspace if it is already a mount */
                                false,   /* it's OK to fall back to a plain directory if we can't mount anything */
                                uid,
                                gid);
                if (r < 0)
                        return r;

        } else if (r == 0) {

                /* We managed to set up a mount namespace, and are now in a child. That's great. In this case
                 * we can use the same directory for all cases, after turning off propagation. Question
                 * though is: where do we turn off propagation exactly, and where do we place the workspace
                 * directory? We need some place that is guaranteed to be a mount point in the host, and
                 * which is guaranteed to have a subdir we can mount over. /run/ is not suitable for this,
                 * since we ultimately want to move the resulting file system there, i.e. we need propagation
                 * for /run/ eventually. We could use our own /run/systemd/bind mount on itself, but that
                 * would be visible in the host mount table all the time, which we want to avoid. Hence, what
                 * we do here instead we use /dev/ and /dev/shm/ for our purposes. We know for sure that
                 * /dev/ is a mount point and we now for sure that /dev/shm/ exists. Hence we can turn off
                 * propagation on the former, and then overmount the latter.
                 *
                 * Yes it's nasty playing games with /dev/ and /dev/shm/ like this, since it does not exist
                 * for this purpose, but there are few other candidates that work equally well for us, and
                 * given that we do this in a privately namespaced short-lived single-threaded process that
                 * no one else sees this should be OK to do. */

                /* Turn off propagation from our namespace to host */
                r = mount_nofollow_verbose(LOG_DEBUG, NULL, "/dev", NULL, MS_SLAVE|MS_REC, NULL);
                if (r < 0)
                        goto child_fail;

                r = setup_credentials_internal(
                                context,
                                params,
                                unit,
                                p,           /* final mount point */
                                "/dev/shm",  /* temporary workspace to overmount */
                                false,       /* do not reuse /dev/shm if it is already a mount, under no circumstances */
                                true,        /* insist that something is mounted, do not allow fallback to plain directory */
                                uid,
                                gid);
                if (r < 0)
                        goto child_fail;

                _exit(EXIT_SUCCESS);

        child_fail:
                _exit(EXIT_FAILURE);
        }

        /* If the credentials dir is empty and not a mount point, then there's no point in having it. Let's
         * try to remove it. This matters in particular if we created the dir as mount point but then didn't
         * actually end up mounting anything on it. In that case we'd rather have ENOENT than EACCESS being
         * seen by users when trying access this inode. */
        (void) rmdir(p);
        return 0;
}
