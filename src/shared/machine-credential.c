/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "creds-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fileio.h"
#include "iovec-util.h"
#include "log.h"
#include "machine-credential.h"
#include "memory-util.h"
#include "path-util.h"
#include "string-util.h"

static void machine_credential_done(MachineCredential *cred) {
        assert(cred);

        cred->id = mfree(cred->id);
        cred->data = erase_and_free(cred->data);
        cred->size = 0;
}

void machine_credential_context_done(MachineCredentialContext *ctx) {
        assert(ctx);

        FOREACH_ARRAY(cred, ctx->credentials, ctx->n_credentials)
                machine_credential_done(cred);

        free(ctx->credentials);
}

MachineCredential* machine_credential_find(MachineCredentialContext *ctx, const char *id) {
        assert(ctx);
        assert(id);

        FOREACH_ARRAY(cred, ctx->credentials, ctx->n_credentials)
                if (streq(cred->id, id))
                        return cred;

        return NULL;
}

int machine_credential_add(
                MachineCredentialContext *ctx,
                const char *id,
                const char *value,
                size_t size) {

        assert(ctx);
        assert(id);
        assert(value || size == 0);

        if (!credential_name_valid(id))
                return -EINVAL;

        if (machine_credential_find(ctx, id))
                return -EEXIST;

        if (size == SIZE_MAX)
                size = strlen_ptr(value);

        _cleanup_(machine_credential_done) MachineCredential cred = {};
        cred.id = strdup(id);
        if (!cred.id)
                return -ENOMEM;

        cred.data = memdup(value, size);
        if (!cred.data)
                return -ENOMEM;

        cred.size = size;

        if (!GREEDY_REALLOC(ctx->credentials, ctx->n_credentials + 1))
                return -ENOMEM;

        ctx->credentials[ctx->n_credentials++] = TAKE_STRUCT(cred);
        return 0;
}

static int machine_credential_add_and_log(
                MachineCredentialContext *ctx,
                const char *id,
                const char *value,
                size_t size) {

        int r;

        assert(ctx);
        assert(id);
        assert(value || size == 0);

        r = machine_credential_add(ctx, id, value, size);
        if (r == -EEXIST)
                return log_error_errno(r, "Duplicated credential '%s', refusing.", id);
        if (r == -EINVAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential name is not valid: %s", id);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to add credential '%s': %m", id);

        return 0;
}

int machine_credential_split(const char *s, char **ret_id, const char **ret_value) {
        _cleanup_free_ char *id = NULL;
        const char *p = ASSERT_PTR(s);
        int r;

        assert(ret_id);
        assert(ret_value);

        /* Splits "ID:VALUE" at the first ':'. Doesn't validate the ID, so that callers can log it. Returns
         * -EBADMSG if there's no separator. */

        r = extract_first_word(&p, &id, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0 || !p)
                return -EBADMSG;

        *ret_id = TAKE_PTR(id);
        *ret_value = p;
        return 0;
}

static bool machine_credential_source_valid(const char *source) {
        assert(source);

        return (is_path(source) && path_is_valid(source)) || credential_name_valid(source);
}

int machine_credential_read(const char *source, struct iovec *ret) {
        ReadFullFileFlags flags = READ_FULL_FILE_SECURE;
        _cleanup_free_ char *path_alloc = NULL;
        int r;

        assert(source);
        assert(ret);

        /* Reads a credential from a path (which may refer to an AF_UNIX socket), or from a credential passed
         * to us, if the source is a credential name. Returns -ENXIO in the latter case if we didn't receive
         * any credentials. Doesn't log. */

        if (is_path(source) && path_is_valid(source))
                flags |= READ_FULL_FILE_CONNECT_SOCKET;
        else if (credential_name_valid(source)) {
                const char *e;

                r = get_credentials_dir(&e);
                if (r < 0)
                        return r;

                path_alloc = path_join(e, source);
                if (!path_alloc)
                        return -ENOMEM;

                source = path_alloc;
        } else
                return -EINVAL;

        return read_full_file_full(
                        AT_FDCWD, source,
                        /* offset= */ UINT64_MAX,
                        /* size= */ SIZE_MAX,
                        flags,
                        /* bind_name= */ NULL,
                        (char**) &ret->iov_base, &ret->iov_len);
}

int machine_credential_set(MachineCredentialContext *ctx, const char *cred_str) {
        _cleanup_free_ char *id = NULL;
        const char *p;
        int r;

        assert(ctx);
        assert(cred_str);

        /* Don't log the argument or the data on failure, they might be secret. */

        r = machine_credential_split(cred_str, &id, &p);
        if (r == -EBADMSG)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing ':' separator in --set-credential= argument.");
        if (r < 0)
                return log_error_errno(r, "Failed to parse --set-credential= parameter: %m");

        _cleanup_(erase_and_freep) char *data = NULL;
        ssize_t l;
        l = cunescape(p, UNESCAPE_ACCEPT_NUL, &data);
        if (l < 0)
                return log_error_errno(l, "Failed to unescape data of credential '%s': %m", id);

        return machine_credential_add_and_log(ctx, id, data, l);
}

int machine_credential_load(MachineCredentialContext *ctx, const char *cred_path) {
        _cleanup_free_ char *id = NULL;
        const char *p;
        int r;

        assert(ctx);
        assert(cred_path);

        r = machine_credential_split(cred_path, &id, &p);
        if (r == -EBADMSG)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --load-credential=: %s", cred_path);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --load-credential= parameter: %m");

        if (!machine_credential_source_valid(p))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Credential source appears to be neither a valid path nor a credential name: %s", p);

        _cleanup_(iovec_done_erase) struct iovec iov = {};
        r = machine_credential_read(p, &iov);
        if (r == -ENXIO && !is_path(p))
                return log_error_errno(r, "Credential not available (no credentials passed at all): %s", p);
        if (r < 0)
                return log_error_errno(r, "Failed to read credential '%s': %m", p);

        return machine_credential_add_and_log(ctx, id, iov.iov_base, iov.iov_len);
}
