/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <security/pam_ext.h>
#include <syslog.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "macro.h"
#include "pam-util.h"
#include "stdio-util.h"
#include "string-util.h"

int pam_syslog_errno(pam_handle_t *handle, int level, int error, const char *format, ...) {
        va_list ap;

        LOCAL_ERRNO(error);

        va_start(ap, format);
        pam_vsyslog(handle, LOG_ERR, format, ap);
        va_end(ap);

        return error == -ENOMEM ? PAM_BUF_ERR : PAM_SERVICE_ERR;
}

int pam_syslog_pam_error(pam_handle_t *handle, int level, int error, const char *format, ...) {
        /* This wraps pam_syslog() but will replace @PAMERR@ with a string from pam_strerror().
         * @PAMERR@ must be at the very end. */

        va_list ap;
        va_start(ap, format);

        const char *p = endswith(format, "@PAMERR@");
        if (p) {
                const char *pamerr = pam_strerror(handle, error);
                if (strchr(pamerr, '%'))
                        pamerr = "n/a";  /* We cannot have any formatting chars */

                char buf[p - format + strlen(pamerr) + 1];
                xsprintf(buf, "%*s%s", (int)(p - format), format, pamerr);
                DISABLE_WARNING_FORMAT_NONLITERAL;
                pam_vsyslog(handle, level, buf, ap);
                REENABLE_WARNING;
        } else
                pam_vsyslog(handle, level, format, ap);

        va_end(ap);

        return error;
}

static void cleanup_system_bus(pam_handle_t *handle, void *data, int error_status) {
        /* The PAM_DATA_SILENT flag is the way that pam_end() communicates to the module stack that this
         * invocation of pam_end() is not the final one, but in the process that is going to directly exec
         * the child. This means we are being called after a fork(), and we do not want to try and clean
         * up the sd-bus object, as it would affect the parent too and we'll hit an assertion. */
        if (error_status & PAM_DATA_SILENT)
                return (void) pam_syslog_pam_error(
                                handle,
                                LOG_ERR,
                                SYNTHETIC_ERRNO(EUCLEAN),
                                "Attempted to close sd-bus after fork, this should not happen.");

        sd_bus_flush_close_unref(data);
}

int pam_acquire_bus_connection(pam_handle_t *handle, const char *module_name, sd_bus **ret) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *cache_id = NULL;
        int r;

        assert(handle);
        assert(module_name);
        assert(ret);

        cache_id = strjoin("system-bus-", module_name);
        if (!cache_id)
                return pam_log_oom(handle);

        /* We cache the bus connection so that we can share it between the session and the authentication hooks */
        r = pam_get_data(handle, cache_id, (const void**) &bus);
        if (r == PAM_SUCCESS && bus) {
                *ret = sd_bus_ref(TAKE_PTR(bus)); /* Increase the reference counter, so that the PAM data stays valid */
                return PAM_SUCCESS;
        }
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get bus connection: @PAMERR@");

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to connect to system bus: %m");

        r = pam_set_data(handle, cache_id, bus, cleanup_system_bus);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to set PAM bus data: @PAMERR@");

        sd_bus_ref(bus);
        *ret = TAKE_PTR(bus);

        return PAM_SUCCESS;
}

int pam_release_bus_connection(pam_handle_t *handle, const char *module_name) {
        _cleanup_free_ char *cache_id = NULL;
        int r;

        assert(module_name);

        cache_id = strjoin("system-bus-", module_name);
        if (!cache_id)
                return pam_log_oom(handle);

        r = pam_set_data(handle, cache_id, NULL, NULL);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to release PAM user record data: @PAMERR@");

        return PAM_SUCCESS;
}

void pam_cleanup_free(pam_handle_t *handle, void *data, int error_status) {
        /* A generic destructor for pam_set_data() that just frees the specified data */
        free(data);
}
