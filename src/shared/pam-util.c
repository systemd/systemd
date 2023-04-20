/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <security/pam_ext.h>
#include <syslog.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "macro.h"
#include "pam-util.h"
#include "process-util.h"
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

struct PamBusData {
        pid_t original_pid;
        sd_bus *bus;
        pam_handle_t *pam_handle;
        char *id;
};

static PamBusData *pam_bus_data_free(PamBusData *d) {
        /* The actual destructor */
        if (!d)
                return NULL;

        if (d->original_pid != getpid_cached())
                return NULL;

        sd_bus_flush_close_unref(d->bus);
        free(d->id);

        /* Note: we don't destroy pam_handle here, because this object is pinned by the handle, and not vice versa! */

        return mfree(d);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(PamBusData*, pam_bus_data_free);

static void pam_bus_data_destroy(pam_handle_t *handle, void *data, int error_status) {
        /* Destructor when called from PAM */
        pam_bus_data_free(data);
}

static char* make_bus_data_field_id(const char *module) {
        char *id;

        /* We want to cache bus connections between hooks. But we don't want to allow them to be reused in
         * child processes (because sd-bus doesn't support that). We also don't want them to be reused
         * between our own PAM modules, because they might be linked against different versions of our
         * utility functions and share different state. Hence include both a module ID and a PID in the data
         * field ID. */

        if (asprintf(&id, "systemd-system-bus-%s-" PID_FMT, module, getpid_cached()) < 0)
                return NULL;

        return id;
}

void pam_bus_data_disconnectp(PamBusData **d) {
        int r;

        assert(d);

        /* Disconnects the connection explicitly (for use via _cleanup_()) */

        if (!*d)
                return;

        if ((*d)->original_pid != getpid_cached())
                return;

        if (!(*d)->pam_handle)
                return;

        r = pam_set_data(ASSERT_PTR((*d)->pam_handle), ASSERT_PTR((*d)->id), NULL, NULL);
        if (r != PAM_SUCCESS)
                pam_syslog_pam_error((*d)->pam_handle, LOG_ERR, r, "Failed to release PAM user record data, ignoring: @PAMERR@");

        /* Note, the pam_set_data() call will invalidate 'd', don't access here anymore */
}

int pam_acquire_bus_connection(
                pam_handle_t *handle,
                const char *module,
                sd_bus **ret_bus,
                PamBusData **ret_pam_bus_data) {

        _cleanup_(pam_bus_data_freep) PamBusData *d = NULL;
        _cleanup_free_ char *id = NULL;
        int r;

        assert(handle);
        assert(module);
        assert(ret_bus);

        id = make_bus_data_field_id(module);
        if (!id)
                return pam_log_oom(handle);

        /* We cache the bus connection so that we can share it between the session and the authentication hooks */
        r = pam_get_data(handle, id, (const void**) &d);
        if (r == PAM_SUCCESS && d) {
                if (d->original_pid != getpid_cached()) { /* Refuse reusing a bus from a different process */
                        TAKE_PTR(d); /* don't delete */
                        return PAM_SERVICE_ERR;
                }

                goto success;
        }
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get bus connection: @PAMERR@");

        d = new(PamBusData, 1);
        if (!d)
                return pam_log_oom(handle);

        *d = (PamBusData) {
                .original_pid = getpid_cached(),
                .id = TAKE_PTR(id),
                .pam_handle = handle,
        };

        r = sd_bus_open_system(&d->bus);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to connect to system bus: %m");

        r = pam_set_data(handle, d->id, d, pam_bus_data_destroy);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to set PAM bus data: @PAMERR@");

success:
        *ret_bus = sd_bus_ref(d->bus);

        if (ret_pam_bus_data)
                *ret_pam_bus_data = d;

        TAKE_PTR(d); /* don't auto-destroy anymore, it's installed now */

        return PAM_SUCCESS;
}

int pam_release_bus_connection(pam_handle_t *handle, const char *module) {
        _cleanup_free_ char *id = NULL;
        int r;

        id = make_bus_data_field_id(module);
        if (!id)
                return PAM_BUF_ERR;

        r = pam_set_data(handle, id, NULL, NULL);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to release PAM user record data: @PAMERR@");

        return PAM_SUCCESS;
}

void pam_cleanup_free(pam_handle_t *handle, void *data, int error_status) {
        /* A generic destructor for pam_set_data() that just frees the specified data */
        free(data);
}
