/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "creds-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"
#include "machine-credential.h"
#include "path-util.h"
#include "string-util-fundamental.h"

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

bool machine_credentials_contains(const MachineCredentialContext *ctx, const char *id) {
        assert(ctx);
        assert(id);

        FOREACH_ARRAY(cred, ctx->credentials, ctx->n_credentials)
                if (streq(cred->id, id))
                        return true;

        return false;
}

int machine_credential_set(MachineCredentialContext *ctx, const char *cred_str) {
        _cleanup_(machine_credential_done) MachineCredential cred = {};
        int r;

        assert(ctx);

        const char *p = ASSERT_PTR(cred_str);

        r = extract_first_word(&p, &cred.id, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --set-credential= parameter: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Missing value for --set-credential=: %s", cred_str);

        if (!credential_name_valid(cred.id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential name is not valid: %s", cred.id);

        if (machine_credentials_contains(ctx, cred.id))
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Duplicate credential '%s', refusing.", cred.id);

        cred.size = cunescape(p, UNESCAPE_ACCEPT_NUL, (char **) &cred.data);
        if (cred.size < 0)
                return log_error_errno(l, "Failed to unescape credential data: %s", p);

        if (!GREEDY_REALLOC(ctx->credentials, ctx->n_credentials + 1))
                return log_oom();

        ctx->credentials[ctx->n_credentials++] = TAKE_STRUCT(cred);

        return 0;
}

int machine_credential_load(MachineCredentialContext *ctx, const char *cred_path) {
        _cleanup_(machine_credential_done) MachineCredential cred = {};
        _cleanup_free_ char *path_alloc = NULL;
        ReadFullFileFlags flags = READ_FULL_FILE_SECURE;
        int r;

        assert(ctx);

        const char *p = ASSERT_PTR(cred_path);

        r = extract_first_word(&p, &cred.id, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --load-credential= parameter: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --load-credential=: %s", cred_path);

        if (!credential_name_valid(cred.id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential name is not valid: %s", cred.id);

        if (machine_credentials_contains(ctx, cred.id))
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Duplicate credential '%s', refusing.", cred.id);

        if (is_path(p) && path_is_valid(p))
                flags |= READ_FULL_FILE_CONNECT_SOCKET;
        else if (credential_name_valid(p)) {
                const char *e;

                r = get_credentials_dir(&e);
                if (r < 0)
                        return log_error_errno(r,
                                               "Credential not available (no credentials passed at all): %s", cred.id);

                path_alloc = path_join(e, p);
                if (!path_alloc)
                        return log_oom();

                p = path_alloc;
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Credential source appears to be neither a valid path nor a credential name: %s", p);

        r = read_full_file_full(AT_FDCWD, p, UINT64_MAX, SIZE_MAX,
                                flags,
                                NULL,
                                &cred.data, &cred.size);
        if (r < 0)
                return log_error_errno(r, "Failed to read credential '%s': %m", p);

        if (!GREEDY_REALLOC(ctx->credentials, ctx->n_credentials + 1))
                return log_oom();

        ctx->credentials[ctx->n_credentials++] = TAKE_STRUCT(cred);

        return 0;
}
