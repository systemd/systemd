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


int machine_credential_set(MachineCredentialContext *ctx, const char *cred_str) {
        int r;

        assert(ctx);

        const char *p = ASSERT_PTR(cred_str);
        _cleanup_free_ char *id = NULL;
        r = extract_first_word(&p, &id, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --set-credential= parameter: %m");
        if (r == 0 || !p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Missing value for --set-credential=: %s", cred_str);

        _cleanup_free_ char *data = NULL;
        ssize_t l;
        l = cunescape(p, UNESCAPE_ACCEPT_NUL, &data);
        if (l < 0)
                return log_error_errno(l, "Failed to unescape credential data: %s", p);

        return machine_credential_add_and_log(ctx, id, data, l);
}

int machine_credential_load(MachineCredentialContext *ctx, const char *cred_path) {
        int r;

        assert(ctx);

        const char *p = ASSERT_PTR(cred_path);
        _cleanup_free_ char *id = NULL;
        r = extract_first_word(&p, &id, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --load-credential= parameter: %m");
        if (r == 0 || !p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --load-credential=: %s", cred_path);

        ReadFullFileFlags flags = READ_FULL_FILE_SECURE;
        _cleanup_free_ char *path_alloc = NULL;
        if (is_path(p) && path_is_valid(p))
                flags |= READ_FULL_FILE_CONNECT_SOCKET;
        else if (credential_name_valid(p)) {
                const char *e;

                r = get_credentials_dir(&e);
                if (r < 0)
                        return log_error_errno(r, "Credential not available (no credentials passed at all): %s", p);

                path_alloc = path_join(e, p);
                if (!path_alloc)
                        return log_oom();

                p = path_alloc;
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Credential source appears to be neither a valid path nor a credential name: %s", p);

        _cleanup_(iovec_done_erase) struct iovec iov = {};
        r = read_full_file_full(
                        AT_FDCWD, p,
                        /* offset= */ UINT64_MAX,
                        /* size= */ SIZE_MAX,
                        flags,
                        /* bind_name= */ NULL,
                        (char**) &iov.iov_base, &iov.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to read credential '%s': %m", p);

        return machine_credential_add_and_log(ctx, id, iov.iov_base, iov.iov_len);
}
