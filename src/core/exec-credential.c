/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <unistd.h>

#include "acl-util.h"
#include "cgroup.h"
#include "creds-util.h"
#include "errno-util.h"
#include "exec-credential.h"
#include "execute.h"
#include "fileio.h"
#include "fs-util.h"
#include "glob-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "label-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "ordered-set.h"
#include "path-lookup.h"
#include "path-util.h"
#include "random-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "siphash24.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

ExecSetCredential* exec_set_credential_free(ExecSetCredential *sc) {
        if (!sc)
                return NULL;

        free(sc->id);
        free(sc->data);
        return mfree(sc);
}

ExecLoadCredential* exec_load_credential_free(ExecLoadCredential *lc) {
        if (!lc)
                return NULL;

        free(lc->id);
        free(lc->path);
        return mfree(lc);
}

ExecImportCredential* exec_import_credential_free(ExecImportCredential *ic) {
        if (!ic)
                return NULL;

        free(ic->glob);
        free(ic->rename);
        return mfree(ic);
}

static void exec_import_credential_hash_func(const ExecImportCredential *ic, struct siphash *state) {
        assert(ic);
        assert(state);

        siphash24_compress_string(ic->glob, state);
        if (ic->rename)
                siphash24_compress_string(ic->rename, state);
}

static int exec_import_credential_compare_func(const ExecImportCredential *a, const ExecImportCredential *b) {
        int r;

        assert(a);
        assert(b);

        r = strcmp(a->glob, b->glob);
        if (r != 0)
                return r;

        return strcmp_ptr(a->rename, b->rename);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        exec_set_credential_hash_ops,
        char, string_hash_func, string_compare_func,
        ExecSetCredential, exec_set_credential_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        exec_load_credential_hash_ops,
        char, string_hash_func, string_compare_func,
        ExecLoadCredential, exec_load_credential_free);

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        exec_import_credential_hash_ops,
        ExecImportCredential,
        exec_import_credential_hash_func,
        exec_import_credential_compare_func,
        exec_import_credential_free);

int exec_context_put_load_credential(ExecContext *c, const char *id, const char *path, bool encrypted) {
        ExecLoadCredential *old;
        int r;

        assert(c);
        assert(id);
        assert(path);

        old = hashmap_get(c->load_credentials, id);
        if (old) {
                r = free_and_strdup(&old->path, path);
                if (r < 0)
                        return r;

                old->encrypted = encrypted;
        } else {
                _cleanup_(exec_load_credential_freep) ExecLoadCredential *lc = NULL;

                lc = new(ExecLoadCredential, 1);
                if (!lc)
                        return -ENOMEM;

                *lc = (ExecLoadCredential) {
                        .id = strdup(id),
                        .path = strdup(path),
                        .encrypted = encrypted,
                };
                if (!lc->id || !lc->path)
                        return -ENOMEM;

                r = hashmap_ensure_put(&c->load_credentials, &exec_load_credential_hash_ops, lc->id, lc);
                assert(r != -EEXIST);
                if (r < 0)
                        return r;

                TAKE_PTR(lc);
        }

        return 0;
}

int exec_context_put_set_credential(
                ExecContext *c,
                const char *id,
                void *data_consume,
                size_t size,
                bool encrypted) {

        _cleanup_free_ void *data = data_consume;
        ExecSetCredential *old;
        int r;

        /* Takes the ownership of data both on success and failure */

        assert(c);
        assert(id);
        assert(data || size == 0);

        old = hashmap_get(c->set_credentials, id);
        if (old) {
                free_and_replace(old->data, data);
                old->size = size;
                old->encrypted = encrypted;
        } else {
                _cleanup_(exec_set_credential_freep) ExecSetCredential *sc = NULL;

                sc = new(ExecSetCredential, 1);
                if (!sc)
                        return -ENOMEM;

                *sc = (ExecSetCredential) {
                        .id = strdup(id),
                        .data = TAKE_PTR(data),
                        .size = size,
                        .encrypted = encrypted,
                };
                if (!sc->id)
                        return -ENOMEM;

                r = hashmap_ensure_put(&c->set_credentials, &exec_set_credential_hash_ops, sc->id, sc);
                assert(r != -EEXIST);
                if (r < 0)
                        return r;

                TAKE_PTR(sc);
        }

        return 0;
}

int exec_context_put_import_credential(ExecContext *c, const char *glob, const char *rename) {
        _cleanup_(exec_import_credential_freep) ExecImportCredential *ic = NULL;
        int r;

        assert(c);
        assert(glob);

        rename = empty_to_null(rename);

        ic = new(ExecImportCredential, 1);
        if (!ic)
                return -ENOMEM;

        *ic = (ExecImportCredential) {
                .glob = strdup(glob),
        };
        if (!ic->glob)
                return -ENOMEM;
        if (rename) {
                ic->rename = strdup(rename);
                if (!ic->rename)
                        return -ENOMEM;
        }

        if (ordered_set_contains(c->import_credentials, ic))
                return 0;

        r = ordered_set_ensure_put(&c->import_credentials, &exec_import_credential_hash_ops, ic);
        assert(r != -EEXIST);
        if (r < 0)
                return r;

        TAKE_PTR(ic);

        return 0;
}

bool exec_params_need_credentials(const ExecParameters *p) {
        assert(p);

        return p->flags & (EXEC_SETUP_CREDENTIALS|EXEC_SETUP_CREDENTIALS_FRESH);
}

bool exec_context_has_credentials(const ExecContext *c) {
        assert(c);

        return !hashmap_isempty(c->set_credentials) ||
                !hashmap_isempty(c->load_credentials) ||
                !ordered_set_isempty(c->import_credentials);
}

bool mount_point_is_credentials(const char *runtime_prefix, const char *path) {
        const char *e;

        assert(runtime_prefix);
        assert(path);

        e = path_startswith(path, runtime_prefix);
        if (!e)
                return false;

        return path_startswith(e, "credentials");
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

        if (!exec_params_need_credentials(params) || !exec_context_has_credentials(context)) {
                *ret = NULL;
                return 0;
        }

        return get_credential_directory(params->prefix[EXEC_DIRECTORY_RUNTIME], unit, ret);
}

int exec_context_destroy_credentials(const ExecContext *c, const char *runtime_prefix, const char *unit) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(c);

        r = get_credential_directory(runtime_prefix, unit, &p);
        if (r <= 0)
                return r;

        /* This is either a tmpfs/ramfs of its own, or a plain directory. Either way, let's first try to
         * unmount it, and afterwards remove the mount point */
        (void) umount2(p, MNT_DETACH|UMOUNT_NOFOLLOW);
        (void) rm_rf(p, REMOVE_ROOT|REMOVE_CHMOD);

        return 0;
}

typedef enum CredentialSearchPath {
        CREDENTIAL_SEARCH_PATH_TRUSTED,
        CREDENTIAL_SEARCH_PATH_ENCRYPTED,
        CREDENTIAL_SEARCH_PATH_ALL,
        _CREDENTIAL_SEARCH_PATH_MAX,
        _CREDENTIAL_SEARCH_PATH_INVALID = -EINVAL,
} CredentialSearchPath;

static int credential_search_path(const ExecParameters *params, CredentialSearchPath path, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(params);
        assert(path >= 0 && path < _CREDENTIAL_SEARCH_PATH_MAX);
        assert(ret);

        /* Assemble a search path to find credentials in. For non-encrypted credentials, We'll look in
         * /etc/credstore/ (and similar directories in /usr/lib/ + /run/). If we're looking for encrypted
         * credentials, we'll look in /etc/credstore.encrypted/ (and similar dirs). */

        if (IN_SET(path, CREDENTIAL_SEARCH_PATH_ENCRYPTED, CREDENTIAL_SEARCH_PATH_ALL)) {
                r = strv_extend(&l, params->received_encrypted_credentials_directory);
                if (r < 0)
                        return r;

                _cleanup_strv_free_ char **add = NULL;
                r = credential_store_path_encrypted(params->runtime_scope, &add);
                if (r < 0)
                        return r;

                r = strv_extend_strv_consume(&l, TAKE_PTR(add), /* filter_duplicates= */ false);
                if (r < 0)
                        return r;
        }

        if (IN_SET(path, CREDENTIAL_SEARCH_PATH_TRUSTED, CREDENTIAL_SEARCH_PATH_ALL)) {
                r = strv_extend(&l, params->received_credentials_directory);
                if (r < 0)
                        return r;

                _cleanup_strv_free_ char **add = NULL;
                r = credential_store_path(params->runtime_scope, &add);
                if (r < 0)
                        return r;

                r = strv_extend_strv_consume(&l, TAKE_PTR(add), /* filter_duplicates= */ false);
                if (r < 0)
                        return r;
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *t = strv_join(l, ":");
                log_debug("Credential search path is: %s", strempty(t));
        }

        *ret = TAKE_PTR(l);
        return 0;
}

struct load_cred_args {
        const ExecContext *context;
        const ExecParameters *params;
        const char *unit;

        bool always_ipc;

        bool encrypted;

        int write_dfd;
        uid_t uid;
        gid_t gid;
        bool ownership_ok;

        uint64_t left;
};

static int write_credential(
                int dfd,
                const char *id,
                const void *data,
                size_t size,
                uid_t uid,
                gid_t gid,
                bool ownership_ok) {

        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(dfd >= 0);
        assert(id);
        assert(data || size == 0);

        fd = openat(dfd, id, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0600);
        if (fd < 0)
                return -errno;

        r = loop_write(fd, data, size);
        if (r < 0)
                return r;

        r = RET_NERRNO(fchmod(fd, 0400)); /* Take away "w" bit */
        if (r < 0)
                return r;

        if (uid_is_valid(uid) && uid != getuid()) {
                r = fd_add_uid_acl_permission(fd, uid, ACL_READ);
                /* Ideally we use ACLs, since we can neatly express what we want to express:
                 * the user gets read access and nothing else. But if the backing fs can't
                 * support that (e.g. ramfs), then we can use file ownership instead. But that's
                 * only safe if we can then re-mount the whole thing read-only, so that the user
                 * can no longer chmod() the file to gain write access. */
                if ((ERRNO_IS_NEG_NOT_SUPPORTED(r) || ERRNO_IS_NEG_PRIVILEGE(r)) && ownership_ok)
                        r = RET_NERRNO(fchown(fd, uid, gid));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int maybe_decrypt_and_write_credential(
                struct load_cred_args *args,
                const char *id,
                const char *data,
                size_t size,
                bool graceful) {

        _cleanup_(iovec_done_erase) struct iovec plaintext = {};
        size_t add;
        int r;

        assert(args);
        assert(args->write_dfd >= 0);
        assert(id);
        assert(data || size == 0);

        if (args->encrypted) {
                CredentialFlags flags = 0; /* only allow user creds in user scope */

                switch (args->params->runtime_scope) {

                case RUNTIME_SCOPE_SYSTEM:
                        /* In system mode talk directly to the TPM – unless we live in a device sandbox
                         * which might block TPM device access. */

                        flags |= CREDENTIAL_ANY_SCOPE;

                        if (!args->always_ipc) {
                                r = decrypt_credential_and_warn(
                                                id,
                                                now(CLOCK_REALTIME),
                                                /* tpm2_device= */ NULL,
                                                /* tpm2_signature_path= */ NULL,
                                                getuid(),
                                                &IOVEC_MAKE(data, size),
                                                flags,
                                                &plaintext);
                                break;
                        }

                        _fallthrough_;

                case RUNTIME_SCOPE_USER:
                        /* In per user mode we'll not have access to the machine secret, nor to the TPM (most
                         * likely), hence go via the IPC service instead. Do this if we are run in root's
                         * per-user invocation too, to minimize differences and because isolating this logic
                         * into a separate process is generally a good thing anyway. */
                        r = ipc_decrypt_credential(
                                        id,
                                        now(CLOCK_REALTIME),
                                        getuid(),
                                        &IOVEC_MAKE(data, size),
                                        flags,
                                        &plaintext);
                        break;

                default:
                        assert_not_reached();
                }
                if (r < 0) {
                        if (graceful) {
                                log_warning_errno(r, "Unable to decrypt credential '%s', skipping: %m", id);
                                return 0;
                        }

                        return r;
                }

                data = plaintext.iov_base;
                size = plaintext.iov_len;
        }

        add = strlen(id) + size;
        if (add > args->left)
                return -E2BIG;

        r = write_credential(args->write_dfd, id, data, size, args->uid, args->gid, args->ownership_ok);
        if (r < 0)
                return log_debug_errno(r, "Failed to write credential '%s': %m", id);

        args->left -= add;

        return 0;
}

static int load_credential_glob(
                struct load_cred_args *args,
                const ExecImportCredential *ic,
                char * const *search_path,
                ReadFullFileFlags flags) {

        int r;

        assert(args);
        assert(args->write_dfd >= 0);
        assert(ic);
        assert(search_path);

        STRV_FOREACH(d, search_path) {
                _cleanup_strv_free_ char **paths = NULL;
                _cleanup_free_ char *j = NULL;

                j = path_join(*d, ic->glob);
                if (!j)
                        return -ENOMEM;

                r = safe_glob(j, /* flags= */ 0, &paths);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                STRV_FOREACH(p, paths) {
                        _cleanup_free_ char *fn = NULL;
                        _cleanup_(erase_and_freep) char *data = NULL;
                        size_t size;

                        r = path_extract_filename(*p, &fn);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extract filename from '%s': %m", *p);

                        if (ic->rename) {
                                _cleanup_free_ char *renamed = NULL;

                                renamed = strjoin(ic->rename, fn + strlen(ic->glob) - !!endswith(ic->glob, "*"));
                                if (!renamed)
                                        return log_oom_debug();

                                free_and_replace(fn, renamed);
                        }

                        if (!credential_name_valid(fn)) {
                                log_debug("Skipping credential with invalid name: %s", fn);
                                continue;
                        }

                        if (faccessat(args->write_dfd, fn, F_OK, AT_SYMLINK_NOFOLLOW) >= 0) {
                                log_debug("Skipping credential with duplicated ID %s at %s", fn, *p);
                                continue;
                        }
                        if (errno != ENOENT)
                                return log_debug_errno(errno, "Failed to test if credential %s exists: %m", fn);

                        /* path is absolute, hence pass AT_FDCWD as nop dir fd here */
                        r = read_full_file_full(
                                        AT_FDCWD,
                                        *p,
                                        UINT64_MAX,
                                        args->encrypted ? CREDENTIAL_ENCRYPTED_SIZE_MAX : CREDENTIAL_SIZE_MAX,
                                        flags,
                                        NULL,
                                        &data, &size);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to read credential '%s': %m", *p);

                        r = maybe_decrypt_and_write_credential(args, fn, data, size, /* graceful= */ true);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int load_credential(
                struct load_cred_args *args,
                const char *id,
                int read_dfd,
                const char *path) {

        ReadFullFileFlags flags = READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER;
        _cleanup_strv_free_ char **search_path = NULL;
        _cleanup_free_ char *bindname = NULL;
        const char *source = NULL;
        bool missing_ok;
        _cleanup_(erase_and_freep) char *data = NULL;
        size_t size, maxsz;
        int r;

        assert(args);
        assert(args->context);
        assert(args->params);
        assert(args->unit);
        assert(args->write_dfd >= 0);
        assert(id);
        assert(read_dfd >= 0 || read_dfd == AT_FDCWD);
        assert(path);

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
                if (asprintf(&bindname, "@%" PRIx64 "/unit/%s/%s", random_u64(), args->unit, id) < 0)
                        return -ENOMEM;

                missing_ok = false;
                source = path;

        } else if (credential_name_valid(path)) {
                /* If this is a relative path, take it as credential name relative to the credentials
                 * directory we received ourselves. We don't support the AF_UNIX stuff in this mode, since we
                 * are operating on a credential store, i.e. this is guaranteed to be regular files. */

                r = credential_search_path(args->params, CREDENTIAL_SEARCH_PATH_ALL, &search_path);
                if (r < 0)
                        return r;

                missing_ok = true;
        } else
                return -EINVAL;

        if (args->encrypted) {
                flags |= READ_FULL_FILE_UNBASE64;
                maxsz = CREDENTIAL_ENCRYPTED_SIZE_MAX;
        } else
                maxsz = CREDENTIAL_SIZE_MAX;

        if (search_path)
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
        else if (source)
                r = read_full_file_full(
                                read_dfd, source,
                                UINT64_MAX,
                                maxsz,
                                flags,
                                bindname,
                                &data, &size);
        else
                assert_not_reached();

        if (r == -ENOENT && (missing_ok || hashmap_contains(args->context->set_credentials, id))) {
                /* Make a missing inherited credential non-fatal, let's just continue. After all apps
                 * will get clear errors if we don't pass such a missing credential on as they
                 * themselves will get ENOENT when trying to read them, which should not be much
                 * worse than when we handle the error here and make it fatal.
                 *
                 * Also, if the source file doesn't exist, but a fallback is set via SetCredentials=
                 * we are fine, too. */
                log_full_errno(hashmap_contains(args->context->set_credentials, id) ? LOG_DEBUG : LOG_INFO,
                               r, "Couldn't read inherited credential '%s', skipping: %m", path);
                return 0;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to read credential '%s': %m", path);

        return maybe_decrypt_and_write_credential(args, id, data, size, /* graceful= */ false);
}

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

        assert(path);
        assert(de);

        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        if (!IN_SET(de->d_type, DT_REG, DT_SOCK))
                return RECURSE_DIR_CONTINUE;

        sub_id = strreplace(path, "/", "_");
        if (!sub_id)
                return -ENOMEM;

        if (!credential_name_valid(sub_id))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Credential would get ID '%s', which is not valid, refusing.", sub_id);

        if (faccessat(args->write_dfd, sub_id, F_OK, AT_SYMLINK_NOFOLLOW) >= 0) {
                log_debug("Skipping credential with duplicated ID %s at %s", sub_id, path);
                return RECURSE_DIR_CONTINUE;
        }
        if (errno != ENOENT)
                return log_debug_errno(errno, "Failed to test if credential %s exists: %m", sub_id);

        r = load_credential(args,
                            sub_id,
                            dir_fd, de->d_name);
        if (r < 0)
                return r;

        return RECURSE_DIR_CONTINUE;
}

static bool device_nodes_restricted(
                const ExecContext *c,
                const CGroupContext *cgroup_context) {

        assert(c);
        assert(cgroup_context);

        /* Returns true if we have any reason to believe we might not be able to access the TPM device
         * directly, even if we run as root/PID 1. This could be because /dev/ is replaced by a private
         * version, or because a device node access list is configured. */

        if (c->private_devices)
                return true;

        if (cgroup_context_has_device_policy(cgroup_context))
                return true;

        return false;
}

static int acquire_credentials(
                const ExecContext *context,
                const CGroupContext *cgroup_context,
                const ExecParameters *params,
                const char *unit,
                int dfd,
                uid_t uid,
                gid_t gid,
                bool ownership_ok) {

        int r;

        assert(context);
        assert(cgroup_context);
        assert(params);
        assert(unit);
        assert(dfd >= 0);

        struct load_cred_args args = {
                .context = context,
                .params = params,
                .unit = unit,
                .always_ipc = device_nodes_restricted(context, cgroup_context),
                .write_dfd = dfd,
                .uid = uid,
                .gid = gid,
                .ownership_ok = ownership_ok,
                .left = CREDENTIALS_TOTAL_SIZE_MAX,
        };

        /* First, load credentials off disk (or acquire via AF_UNIX socket) */
        ExecLoadCredential *lc;
        HASHMAP_FOREACH(lc, context->load_credentials) {
                _cleanup_close_ int sub_fd = -EBADF;

                args.encrypted = lc->encrypted;

                /* If this is an absolute path, then try to open it as a directory. If that works, then we'll
                 * recurse into it. If it is an absolute path but it isn't a directory, then we'll open it as
                 * a regular file. Finally, if it's a relative path we will use it as a credential name to
                 * propagate a credential passed to us from further up. */

                if (path_is_absolute(lc->path)) {
                        sub_fd = open(lc->path, O_DIRECTORY|O_CLOEXEC);
                        if (sub_fd < 0 && !IN_SET(errno,
                                                  ENOTDIR,  /* Not a directory */
                                                  ENOENT))  /* Doesn't exist? */
                                return log_debug_errno(errno, "Failed to open credential source '%s': %m", lc->path);
                }

                if (sub_fd < 0)
                        /* Regular file (incl. a credential passed in from higher up) */
                        r = load_credential(&args,
                                            lc->id,
                                            AT_FDCWD, lc->path);
                else
                        /* Directory */
                        r = recurse_dir(sub_fd,
                                        /* path= */ lc->id, /* recurse_dir() will suffix the subdir paths from here to the top-level id */
                                        /* statx_mask= */ 0,
                                        /* n_depth_max= */ UINT_MAX,
                                        RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE,
                                        load_cred_recurse_dir_cb,
                                        &args);
                if (r < 0)
                        return r;
        }

        /* Next, look for system credentials and credentials in the credentials store. Note that these do not
         * override any credentials found earlier. */
        ExecImportCredential *ic;
        ORDERED_SET_FOREACH(ic, context->import_credentials) {
                _cleanup_free_ char **search_path = NULL;

                r = credential_search_path(params, CREDENTIAL_SEARCH_PATH_TRUSTED, &search_path);
                if (r < 0)
                        return r;

                args.encrypted = false;

                r = load_credential_glob(
                                &args,
                                ic,
                                search_path,
                                READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER);
                if (r < 0)
                        return r;

                search_path = strv_free(search_path);

                r = credential_search_path(params, CREDENTIAL_SEARCH_PATH_ENCRYPTED, &search_path);
                if (r < 0)
                        return r;

                args.encrypted = true;

                r = load_credential_glob(
                                &args,
                                ic,
                                search_path,
                                READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER|READ_FULL_FILE_UNBASE64);
                if (r < 0)
                        return r;
        }

        /* Finally, we add in literally specified credentials. If the credentials already exist, we'll not
         * add them, so that they can act as a "default" if the same credential is specified multiple times. */
        ExecSetCredential *sc;
        HASHMAP_FOREACH(sc, context->set_credentials) {
                args.encrypted = sc->encrypted;

                if (faccessat(dfd, sc->id, F_OK, AT_SYMLINK_NOFOLLOW) >= 0) {
                        log_debug("Skipping credential with duplicated ID %s", sc->id);
                        continue;
                }
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to test if credential %s exists: %m", sc->id);

                r = maybe_decrypt_and_write_credential(&args, sc->id, sc->data, sc->size, /* graceful= */ false);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int credentials_dir_finalize_permissions(int dfd, uid_t uid, gid_t gid, bool ownership_ok) {
        int r;

        assert(dfd >= 0);

        r = fd_acl_make_read_only(dfd); /* Take away the "w" bit */
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

static int setup_credentials_plain_dir(
                const ExecContext *context,
                const CGroupContext *cgroup_context,
                const ExecParameters *params,
                const char *unit,
                const char *cred_dir,
                uid_t uid,
                gid_t gid) {

        _cleanup_free_ char *t = NULL, *workspace = NULL;
        _cleanup_(rm_rf_safep) const char *workspace_rm = NULL;
        _cleanup_close_ int dfd = -EBADF;
        int r;

        assert(context);
        assert(params);
        assert(unit);
        assert(cred_dir);

        /* Temporary workspace, that remains inaccessible all the time. We prepare stuff there before moving
         * it into place, so that users can't access half-initialized credential stores. */
        t = path_join(params->prefix[EXEC_DIRECTORY_RUNTIME], "systemd/temporary-credentials");
        if (!t)
                return -ENOMEM;

        r = mkdir_label(t, 0700);
        if (r < 0 && r != -EEXIST)
                return r;

        workspace = path_join(t, unit);
        if (!workspace)
                return -ENOMEM;

        dfd = open_mkdir(workspace, O_CLOEXEC|O_EXCL, 0700);
        if (dfd < 0)
                return log_debug_errno(dfd, "Failed to create workspace for credentials: %m");
        workspace_rm = workspace;

        (void) label_fix_full(dfd, /* inode_path= */ NULL, cred_dir, /* flags= */ 0);

        r = acquire_credentials(context, cgroup_context, params, unit, dfd, uid, gid, /* ownership_ok= */ false);
        if (r < 0)
                return r;

        r = RET_NERRNO(rename(workspace, cred_dir));
        if (r >= 0)
                workspace_rm = NULL;
        if (IN_SET(r, -ENOTEMPTY, -EEXIST)) {
                _cleanup_close_ int old_dfd = open(cred_dir, O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                if (old_dfd < 0)
                        return log_debug_errno(errno, "Failed to open credentials dir '%s': %m", cred_dir);

                (void) fd_acl_make_writable(old_dfd);

                log_debug_errno(r, "Credential dir '%s' already populated, exchanging with workspace.", cred_dir);
                r = RET_NERRNO(renameat2(AT_FDCWD, workspace, AT_FDCWD, cred_dir, RENAME_EXCHANGE));
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to move credentials workspace into place: %m");

        /* rename() requires both the source and target to be writable, hence lock down write permission
         * as last step. */
        r = credentials_dir_finalize_permissions(dfd, uid, gid, /* ownership_ok= */ false);
        if (r < 0)
                return log_debug_errno(r, "Failed to adjust ACLs of credentials dir: %m");

        return 0;
}

static int setup_credentials_internal(
                const ExecContext *context,
                const CGroupContext *cgroup_context,
                const ExecParameters *params,
                const char *unit,
                const char *cred_dir,
                uid_t uid,
                gid_t gid) {

        _cleanup_close_ int fs_fd = -EBADF, mfd = -EBADF, dfd = -EBADF;
        bool dir_mounted;
        int r;

        assert(context);
        assert(params);
        assert(unit);
        assert(cred_dir);

        r = path_is_mount_point(cred_dir);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if '%s' is a mountpoint: %m", cred_dir);
        dir_mounted = r > 0;

        if (!FLAGS_SET(params->flags, EXEC_SETUP_CREDENTIALS_FRESH)) {
                bool populated;

                /* If the cred dir is a mount, let's treat it as populated, and only look at the contents
                 * if it's a plain dir, where we can't reasonably differentiate populated yet empty vs
                 * not set up. */

                if (dir_mounted)
                        populated = true;
                else {
                        r = dir_is_empty(cred_dir, /* ignore_hidden_or_backup= */ false);
                        if (r < 0)
                                return r;
                        populated = r == 0;
                }
                if (populated) {
                        log_debug("Credential dir for unit '%s' already set up, skipping.", unit);
                        return 0;
                }
        }

        mfd = fsmount_credentials_fs(&fs_fd);
        if (ERRNO_IS_NEG_PRIVILEGE(mfd) && !dir_mounted) {
                log_debug_errno(mfd, "Lacking privilege to mount credentials fs, falling back to plain directory.");
                return setup_credentials_plain_dir(context, cgroup_context, params, unit, cred_dir, uid, gid);
        }
        if (mfd < 0)
                return log_debug_errno(mfd, "Failed to mount credentials fs: %m");

        dfd = fd_reopen(mfd, O_DIRECTORY|O_CLOEXEC);
        if (dfd < 0)
                return dfd;

        (void) label_fix_full(dfd, /* inode_path= */ NULL, cred_dir, /* flags= */ 0);

        r = acquire_credentials(context, cgroup_context, params, unit, dfd, uid, gid, /* ownership_ok= */ true);
        if (r < 0)
                return r;

        r = credentials_dir_finalize_permissions(dfd, uid, gid, /* ownership_ok= */ true);
        if (r < 0)
                return log_debug_errno(r, "Failed to adjust ACLs of credentials dir: %m");

        // Work around a kernel bug that results in tmpfs reconfiguration failure.
        // FIXME: drop this once https://lore.kernel.org/linux-fsdevel/20251108190930.440685-1-me@yhndnzj.com/
        // is merged and hits the distro kernels.
        (void) fsconfig(fs_fd, FSCONFIG_SET_FLAG, "noswap", NULL, 0);

        if (fsconfig(fs_fd, FSCONFIG_SET_FLAG, "ro", NULL, 0) < 0)
                return -errno;

        if (fsconfig(fs_fd, FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0) < 0)
                return -errno;

        log_debug("Successfully reconfigured credentials fs to be read only.");

        if (dir_mounted) {
                /* Firstly, try to move beneath the existing mount, which guarantees strictly atomic replacement
                 * (needs kernel >= 6.5) */
                r = move_mount(mfd, "", AT_FDCWD, cred_dir, MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_BENEATH);
                if (r >= 0)
                        return umount_verbose(LOG_DEBUG, cred_dir, MNT_DETACH|UMOUNT_NOFOLLOW);
                if (errno != EINVAL)
                        return log_debug_errno(errno, "Failed to move credentials fs into place: %m");

                log_debug_errno(errno, "Unable to move credentials fs beneath existing mount '%s', unmounting instead: %m",
                                cred_dir);

                r = umount_verbose(LOG_DEBUG, cred_dir, MNT_DETACH|UMOUNT_NOFOLLOW);
                if (r < 0)
                        return r;
        }

        r = move_mount(mfd, "", AT_FDCWD, cred_dir, MOVE_MOUNT_F_EMPTY_PATH);
        if (r < 0)
                return log_debug_errno(errno, "Failed to move credentials fs into place: %m");

        return 0;
}

int exec_setup_credentials(
                const ExecContext *context,
                const CGroupContext *cgroup_context,
                const ExecParameters *params,
                const char *unit,
                uid_t uid,
                gid_t gid) {

        _cleanup_free_ char *p = NULL, *q = NULL;
        int r;

        assert(context);
        assert(params);
        assert(unit);

        if (!exec_params_need_credentials(params) || !exec_context_has_credentials(context))
                return 0;

        if (!params->prefix[EXEC_DIRECTORY_RUNTIME])
                return -EINVAL;

        /* This is where we'll place stuff when we are done; the main credentials directory is world-readable,
         * and the subdir we mount over with a read-only file system readable by the service's user. */
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

        r = setup_credentials_internal(context, cgroup_context, params, unit, p, uid, gid);

        /* If the credentials dir is empty and not a mount point, then there's no point in having it. Let's
         * try to remove it. This matters in particular if we created the dir as mount point but then didn't
         * actually end up mounting anything on it. In that case we'd rather have ENOENT than EACCESS being
         * seen by users when trying access this inode. */
        (void) rmdir(p);
        return r;
}
