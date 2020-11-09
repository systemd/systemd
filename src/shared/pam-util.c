/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <security/pam_ext.h>
#include <syslog.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "macro.h"
#include "pam-util.h"

int pam_log_oom(pam_handle_t *handle) {
        /* This is like log_oom(), but uses PAM logging */
        pam_syslog(handle, LOG_ERR, "Out of memory.");
        return PAM_BUF_ERR;
}

int pam_bus_log_create_error(pam_handle_t *handle, int r) {
        /* This is like bus_log_create_error(), but uses PAM logging */
        pam_syslog(handle, LOG_ERR, "Failed to create bus message: %s", strerror_safe(r));
        return PAM_BUF_ERR;
}

int pam_bus_log_parse_error(pam_handle_t *handle, int r) {
        /* This is like bus_log_parse_error(), but uses PAM logging */
        pam_syslog(handle, LOG_ERR, "Failed to parse bus message: %s", strerror_safe(r));
        return PAM_BUF_ERR;
}

static void cleanup_system_bus(pam_handle_t *handle, void *data, int error_status) {
        sd_bus_flush_close_unref(data);
}

int pam_acquire_bus_connection(pam_handle_t *handle, sd_bus **ret) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int r;

        assert(handle);
        assert(ret);

        /* We cache the bus connection so that we can share it between the session and the authentication hooks */
        r = pam_get_data(handle, "systemd-system-bus", (const void**) &bus);
        if (r == PAM_SUCCESS && bus) {
                *ret = sd_bus_ref(TAKE_PTR(bus)); /* Increase the reference counter, so that the PAM data stays valid */
                return PAM_SUCCESS;
        }
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA)) {
                pam_syslog(handle, LOG_ERR, "Failed to get bus connection: %s", pam_strerror(handle, r));
                return r;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to connect to system bus: %s", strerror_safe(r));
                return PAM_SERVICE_ERR;
        }

        r = pam_set_data(handle, "systemd-system-bus", bus, cleanup_system_bus);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set PAM bus data: %s", pam_strerror(handle, r));
                return r;
        }

        sd_bus_ref(bus);
        *ret = TAKE_PTR(bus);

        return PAM_SUCCESS;
}

int pam_release_bus_connection(pam_handle_t *handle) {
        int r;

        r = pam_set_data(handle, "systemd-system-bus", NULL, NULL);
        if (r != PAM_SUCCESS)
                pam_syslog(handle, LOG_ERR, "Failed to release PAM user record data: %s", pam_strerror(handle, r));

        return r;
}

void pam_cleanup_free(pam_handle_t *handle, void *data, int error_status) {
        /* A generic destructor for pam_set_data() that just frees the specified data */
        free(data);
}
