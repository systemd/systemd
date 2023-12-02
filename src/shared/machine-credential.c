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

void machine_credential_free_all(MachineCredential *creds, size_t n) {
        assert(creds || n == 0);

        FOREACH_ARRAY(cred, creds, n)
                machine_credential_done(cred);

        free(creds);
}

int machine_credential_set(MachineCredential **credentials, size_t *n_credentials, const char *cred_string) {
        _cleanup_free_ char *word = NULL, *data = NULL;
        ssize_t l;
        int r;
        const char *p = ASSERT_PTR(cred_string);

        assert(credentials && n_credentials);
        assert(*credentials || *n_credentials == 0);

        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --set-credential= parameter: %m");
        if (r == 0 || !p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --set-credential=: %s", cred_string);

        if (!credential_name_valid(word))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential name is not valid: %s", word);

        FOREACH_ARRAY(cred, *credentials, *n_credentials)
                if (streq(cred->id, word))
                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Duplicate credential '%s', refusing.", word);

        l = cunescape(p, UNESCAPE_ACCEPT_NUL, &data);
        if (l < 0)
                return log_error_errno(l, "Failed to unescape credential data: %s", p);

        if (!GREEDY_REALLOC(*credentials, *n_credentials + 1))
                return log_oom();

        (*credentials)[(*n_credentials)++] = (MachineCredential) {
                .id = TAKE_PTR(word),
                .data = TAKE_PTR(data),
                .size = l,
        };

        return 0;
}

int machine_credential_load(MachineCredential **credentials, size_t *n_credentials, const char *cred_path) {
        ReadFullFileFlags flags = READ_FULL_FILE_SECURE;
        _cleanup_(erase_and_freep) char *data = NULL;
        _cleanup_free_ char *word = NULL, *j = NULL;
        const char *p = ASSERT_PTR(cred_path);
        size_t size;
        int r;

        assert(credentials && n_credentials);
        assert(*credentials || *n_credentials == 0);

        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --load-credential= parameter: %m");
        if (r == 0 || !p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --load-credential=: %s", cred_path);

        if (!credential_name_valid(word))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential name is not valid: %s", word);

        FOREACH_ARRAY(cred, *credentials, *n_credentials)
                if (streq(cred->id, word))
                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Duplicate credential '%s', refusing.", word);

        if (is_path(p) && path_is_valid(p))
                flags |= READ_FULL_FILE_CONNECT_SOCKET;
        else if (credential_name_valid(p)) {
                const char *e;

                r = get_credentials_dir(&e);
                if (r < 0)
                        return log_error_errno(r, "Credential not available (no credentials passed at all): %s", word);

                j = path_join(e, p);
                if (!j)
                        return log_oom();

                p = j;
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential source appears to be neither a valid path nor a credential name: %s", p);

        r = read_full_file_full(AT_FDCWD, p, UINT64_MAX, SIZE_MAX,
                                flags,
                                NULL,
                                &data, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read credential '%s': %m", p);

        if (!GREEDY_REALLOC(*credentials, *n_credentials + 1))
                return log_oom();

        (*credentials)[(*n_credentials)++] = (MachineCredential) {
                .id = TAKE_PTR(word),
                .data = TAKE_PTR(data),
                .size = size,
        };

        return 0;
}
