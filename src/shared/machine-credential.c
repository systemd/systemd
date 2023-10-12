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
        MachineCredential *creds = *ASSERT_PTR(credentials);
        ssize_t l;
        size_t n_creds = *ASSERT_PTR(n_credentials);
        int r;
        const char *p = ASSERT_PTR(cred_string);

        assert(creds || n_creds == 0);

        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r == -ENOMEM)
                return r;
        if (r < 0)
                return log_error_errno(r, "Failed to parse --set-credential= parameter: %m");
        if (r == 0 || !p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --set-credential=: %s", cred_string);

        if (!credential_name_valid(word))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "MachineCredential name is not valid: %s", word);

        FOREACH_ARRAY(cred, creds, n_creds)
                if (streq(cred->id, word))
                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Duplicate credential '%s', refusing.", word);

        l = cunescape(p, UNESCAPE_ACCEPT_NUL, &data);
        if (l < 0)
                return log_error_errno(l, "Failed to unescape credential data: %s", p);

        GREEDY_REALLOC(creds, n_creds + 1);
        if (!creds)
                return -ENOMEM;

        creds[n_creds++] = (MachineCredential) {
                .id = TAKE_PTR(word),
                .data = TAKE_PTR(data),
                .size = l,
        };

        *credentials = creds;
        *n_credentials = n_creds;

        return 0;
}

int machine_credential_load(MachineCredential **credentials, size_t *n_credentials, const char *cred_path) {
        ReadFullFileFlags flags = READ_FULL_FILE_SECURE;
        _cleanup_(erase_and_freep) char *data = NULL;
        _cleanup_free_ char *word = NULL, *j = NULL;
        MachineCredential *creds = *ASSERT_PTR(credentials);
        size_t size, n_creds = *ASSERT_PTR(n_credentials);
        int r;
        const char *p = ASSERT_PTR(cred_path);

        assert(creds || n_creds == 0);

        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r == -ENOMEM)
                return -ENOMEM;
        if (r < 0)
                return log_error_errno(r, "Failed to parse --load-credential= parameter: %m");
        if (r == 0 || !p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --load-credential=: %s", cred_path);

        if (!credential_name_valid(word))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "MachineCredential name is not valid: %s", word);

        FOREACH_ARRAY(cred, creds, n_creds)
                if (streq(cred->id, word))
                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Duplicate credential '%s', refusing.", word);

        if (path_is_absolute(p))
                flags |= READ_FULL_FILE_CONNECT_SOCKET;
        else {
                const char *e;

                r = get_credentials_dir(&e);
                if (r < 0)
                        return log_error_errno(r, "MachineCredential not available (no credentials passed at all): %s", word);

                j = path_join(e, p);
                if (!j)
                        return -ENOMEM;
        }

        r = read_full_file_full(AT_FDCWD, j ?: p, UINT64_MAX, SIZE_MAX,
                                flags,
                                NULL,
                                &data, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read credential '%s': %m", j ?: p);

        GREEDY_REALLOC(creds, n_creds + 1);
        if (!creds)
                return -ENOMEM;

        creds[n_creds++] = (MachineCredential) {
                .id = TAKE_PTR(word),
                .data = TAKE_PTR(data),
                .size = size,
        };

        *credentials = creds;
        *n_credentials = n_creds;

        return 0;
}
