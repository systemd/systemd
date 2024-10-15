/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-srk.h"
#include "fileio.h"
#include "tpm2-util.h"

int verb_srk(int argc, char *argv[], void *userdata) {
#if HAVE_TPM2
        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        _cleanup_(Esys_Freep) TPM2B_PUBLIC *public = NULL;
        int r;

        r = tpm2_context_new_or_warn(/* device= */ NULL, &c);
        if (r < 0)
                return r;

        r = tpm2_get_srk(
                        c,
                        /* session= */ NULL,
                        &public,
                        /* ret_name= */ NULL,
                        /* ret_qname= */ NULL,
                        /* ret_handle= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to get SRK: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No SRK stored so far.");

        _cleanup_free_ void *marshalled = NULL;
        size_t marshalled_size = 0;
        r = tpm2_marshal_public(public, &marshalled, &marshalled_size);
        if (r < 0)
                return log_error_errno(r, "Failed to marshal SRK: %m");

        if (isatty_safe(STDOUT_FILENO))
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Refusing to write binary data to TTY, please redirect output to file.");

        if (fwrite(marshalled, 1, marshalled_size, stdout) != marshalled_size)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write SRK to stdout.");

        r = fflush_and_check(stdout);
        if (r < 0)
                return log_error_errno(r, "Failed to write SRK to stdout: %m");

        return EXIT_SUCCESS;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 support not available.");
#endif
}
