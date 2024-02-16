/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-def.h"
#include "dns-domain.h"
#include "hostname-util.h"
#include "idn-util.h"
#include "resolved-util.h"
#include "utf8.h"

int resolve_system_hostname(char **full_hostname, char **first_label) {
        _cleanup_free_ char *h = NULL, *n = NULL;
#if HAVE_LIBIDN2
        _cleanup_free_ char *utf8 = NULL;
#elif HAVE_LIBIDN
        int k;
#endif
        char label[DNS_LABEL_MAX+1];
        const char *p, *decoded;
        int r;

        /* Return the full hostname in *full_hostname, if nonnull.
         *
         * Extract and normalize the first label of the locally configured hostname, check it's not
         * "localhost", and return it in *first_label, if nonnull. */

        r = gethostname_strict(&h);
        if (r < 0)
                return log_debug_errno(r, "Can't determine system hostname: %m");

        p = h;
        r = dns_label_unescape(&p, label, sizeof label, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to unescape hostname: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Couldn't find a single label in hostname.");

#if HAVE_LIBIDN || HAVE_LIBIDN2
        r = dlopen_idn();
        if (r < 0) {
                log_debug_errno(r, "Failed to initialize IDN support, ignoring: %m");
                decoded = label; /* no decoding */
        } else
#endif
        {
#if HAVE_LIBIDN2
                r = sym_idn2_to_unicode_8z8z(label, &utf8, 0);
                if (r != IDN2_OK)
                        return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                               "Failed to undo IDNA: %s", sym_idn2_strerror(r));
                assert(utf8_is_valid(utf8));

                r = strlen(utf8);
                decoded = utf8;
#elif HAVE_LIBIDN
                k = dns_label_undo_idna(label, r, label, sizeof label);
                if (k < 0)
                        return log_debug_errno(k, "Failed to undo IDNA: %m");
                if (k > 0)
                        r = k;

                if (!utf8_is_valid(label))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "System hostname is not UTF-8 clean.");
                decoded = label;
#else
                decoded = label; /* no decoding */
#endif
        }

        r = dns_label_escape_new(decoded, r, &n);
        if (r < 0)
                return log_debug_errno(r, "Failed to escape hostname: %m");

        if (is_localhost(n))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "System hostname is 'localhost', ignoring.");

        if (full_hostname)
                *full_hostname = TAKE_PTR(h);
        if (first_label)
                *first_label = TAKE_PTR(n);
        return 0;
}
