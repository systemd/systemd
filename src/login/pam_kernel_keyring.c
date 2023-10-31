/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include "keyring-util.h"
#include "macro.h"
#include "missing_syscall.h"
#include "nulstr-util.h"
#include "pam-util.h"
#include "strv.h"

/* By default, this module retieves the key stored by systemd-cryptsetup.
 * This can be overridden by the keyname= parameter. */
static const char* DEFAULT_KEYNAME = "cryptsetup";

_public_ int pam_sm_authenticate(
                pam_handle_t  *handle,
                int            flags,
                int            argc, const char   **argv) {

        assert(handle);

        /* Parse argv. */

        assert(argc >= 0);
        assert(argc == 0 || argv);

        const char *keyname = DEFAULT_KEYNAME;
        bool debug = false;

        for (int i = 0; i < argc; i++) {
                const char *p;

                if ((p = startswith(argv[i], "keyname=")))
                        keyname = p;
                else if (streq(argv[i], "debug"))
                        debug = true;
                else
                        pam_syslog(handle, LOG_WARNING, "Unknown parameter '%s', ignoring.", argv[i]);
        }

        pam_debug_syslog(handle, debug, "pam-kernel-keyring initializing");

        /* Retrive the key. */

        key_serial_t serial;
        serial = request_key("user", keyname, NULL, 0);
        if (serial < 0) {
                if (errno == ENOKEY) {
                        pam_debug_syslog(handle, debug, "Key not found: %s", keyname);
                        return PAM_AUTHINFO_UNAVAIL;
                } else if (errno == EKEYEXPIRED) {
                        pam_debug_syslog(handle, debug, "Key expired: %s", keyname);
                        return PAM_AUTHINFO_UNAVAIL;
                } else {
                        return pam_syslog_errno(handle, LOG_ERR, errno, "Failed to look up the key: %m");
                }
        }

        _cleanup_(erase_and_freep) void *p = NULL;
        _cleanup_(strv_free_erasep) char **passwords = NULL;
        size_t n;
        int r;

        r = keyring_read(serial, &p, &n);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to read the key: %m");

        /* Split the key by NUL. Set the last item as authtok. */

        passwords = strv_parse_nulstr(p, n);
        if (!passwords) {
                pam_debug_syslog(handle, debug, "Failed to split the key by NUL");
                return PAM_AUTHINFO_UNAVAIL;
        }

        size_t passwords_len = strv_length(passwords);
        if (passwords_len == 0) {
                pam_debug_syslog(handle, debug, "Key is empty");
                return PAM_AUTHINFO_UNAVAIL;
        }

        r = pam_set_item(handle, PAM_AUTHTOK, passwords[passwords_len - 1]);

        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to set authtoken: %m");
        else
                return PAM_SUCCESS;
}

_public_ int pam_sm_setcred(
                pam_handle_t  *handle,
                int            flags,
                int            argc, const char   **argv) {

        return PAM_SUCCESS;
}
