/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <security/pam_ext.h>
#include <syslog.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "format-util.h"
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
                xsprintf(buf, "%.*s%s", (int)(p - format), format, pamerr);

                DISABLE_WARNING_FORMAT_NONLITERAL;
                pam_vsyslog(handle, level, buf, ap);
                REENABLE_WARNING;
        } else
                pam_vsyslog(handle, level, format, ap);

        va_end(ap);

        return error;
}

/* A small structure we store inside the PAM session object, that allows us to reuse bus connections but pins
 * it to the process thoroughly. */
struct PamBusData {
        sd_bus *bus;
        pam_handle_t *pam_handle;
        char *cache_id;
};

static PamBusData *pam_bus_data_free(PamBusData *d) {
        /* The actual destructor */
        if (!d)
                return NULL;

        /* NB: PAM sessions usually involve forking off a child process, and thus the PAM context might be
         * duplicated in the child. This destructor might be called twice: both in the parent and in the
         * child. sd_bus_flush_close_unref() however is smart enough to be a NOP when invoked in any other
         * process than the one it was invoked from, hence we don't need to add any extra protection here to
         * ensure that destruction of the bus connection in the child affects the parent's connection
         * somehow. */
        sd_bus_flush_close_unref(d->bus);
        free(d->cache_id);

        /* Note: we don't destroy pam_handle here, because this object is pinned by the handle, and not vice versa! */

        return mfree(d);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(PamBusData*, pam_bus_data_free);

static void pam_bus_data_destroy(pam_handle_t *handle, void *data, int error_status) {
        /* Destructor when called from PAM. Note that error_status is supposed to tell us via PAM_DATA_SILENT
         * whether we are called in a forked off child of the PAM session or in the original parent. We don't
         * bother with that however, and instead rely on the PID checks that sd_bus_flush_close_unref() does
         * internally anyway. That said, we still generate a warning message, since this really shouldn't
         * happen. */

        if (error_status & PAM_DATA_SILENT)
                pam_syslog(handle, LOG_DEBUG, "Attempted to close sd-bus after fork, this should not happen.");

        pam_bus_data_free(data);
}

static char* pam_make_bus_cache_id(const char *module_name) {
        char *id;

        /* We want to cache bus connections between hooks. But we don't want to allow them to be reused in
         * child processes (because sd-bus doesn't support that). We also don't want them to be reused
         * between our own PAM modules, because they might be linked against different versions of our
         * utility functions and share different state. Hence include both a module ID and a PID in the data
         * field ID. */

        if (asprintf(&id, "system-bus-%s-" PID_FMT, ASSERT_PTR(module_name), getpid_cached()) < 0)
                return NULL;

        return id;
}

void pam_bus_data_disconnectp(PamBusData **_d) {
        PamBusData *d = *ASSERT_PTR(_d);
        pam_handle_t *handle;
        int r;

        /* Disconnects the connection explicitly (for use via _cleanup_()) when called */

        if (!d)
                return;

        handle = ASSERT_PTR(d->pam_handle); /* Keep a reference to the session even after 'd' might be invalidated */

        r = pam_set_data(handle, ASSERT_PTR(d->cache_id), NULL, NULL);
        if (r != PAM_SUCCESS)
                pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to release PAM user record data, ignoring: @PAMERR@");

        /* Note, the pam_set_data() call will invalidate 'd', don't access here anymore */
}

int pam_acquire_bus_connection(
                pam_handle_t *handle,
                const char *module_name,
                sd_bus **ret_bus,
                PamBusData **ret_pam_bus_data) {

        _cleanup_(pam_bus_data_freep) PamBusData *d = NULL;
        _cleanup_free_ char *cache_id = NULL;
        int r;

        assert(handle);
        assert(module_name);
        assert(ret_bus);

        cache_id = pam_make_bus_cache_id(module_name);
        if (!cache_id)
                return pam_log_oom(handle);

        /* We cache the bus connection so that we can share it between the session and the authentication hooks */
        r = pam_get_data(handle, cache_id, (const void**) &d);
        if (r == PAM_SUCCESS && d)
                goto success;
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get bus connection: @PAMERR@");

        d = new(PamBusData, 1);
        if (!d)
                return pam_log_oom(handle);

        *d = (PamBusData) {
                .cache_id = TAKE_PTR(cache_id),
                .pam_handle = handle,
        };

        r = sd_bus_open_system(&d->bus);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to connect to system bus: %m");

        r = pam_set_data(handle, d->cache_id, d, pam_bus_data_destroy);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to set PAM bus data: @PAMERR@");

success:
        *ret_bus = sd_bus_ref(d->bus);

        if (ret_pam_bus_data)
                *ret_pam_bus_data = d;

        TAKE_PTR(d); /* don't auto-destroy anymore, it's installed now */

        return PAM_SUCCESS;
}

int pam_release_bus_connection(pam_handle_t *handle, const char *module_name) {
        _cleanup_free_ char *cache_id = NULL;
        int r;

        assert(module_name);

        cache_id = pam_make_bus_cache_id(module_name);
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

int pam_get_item_many_internal(pam_handle_t *handle, ...) {
        va_list ap;
        int r;

        va_start(ap, handle);
        for (;;) {
                int item_type = va_arg(ap, int);

                if (item_type <= 0) {
                        r = PAM_SUCCESS;
                        break;
                }

                const void **value = ASSERT_PTR(va_arg(ap, const void **));

                r = pam_get_item(handle, item_type, value);
                if (!IN_SET(r, PAM_BAD_ITEM, PAM_SUCCESS))
                        break;
        }
        va_end(ap);

        return r;
}

int pam_prompt_graceful(pam_handle_t *handle, int style, char **ret_response, const char *fmt, ...) {
        va_list args;
        int r;

        assert(handle);
        assert(fmt);

        /* This is just like pam_prompt(), but does not noisily (i.e. beyond LOG_DEBUG) log on its own, but leaves that to the caller */

        _cleanup_free_ char *msg = NULL;
        va_start(args, fmt);
        r = vasprintf(&msg, fmt, args);
        va_end(args);
        if (r < 0)
                return PAM_BUF_ERR;

        const struct pam_conv *conv = NULL;
        r = pam_get_item(handle, PAM_CONV, (const void**) &conv);
        if (!IN_SET(r, PAM_SUCCESS, PAM_BAD_ITEM))
                return pam_syslog_pam_error(handle, LOG_DEBUG, r, "Failed to get conversation function structure: @PAMERR@");
        if (!conv || !conv->conv) {
                pam_syslog(handle, LOG_DEBUG, "No conversation function.");
                return PAM_SYSTEM_ERR;
        }

        struct pam_message message = {
                .msg_style = style,
                .msg = msg,
        };
        const struct pam_message *pmessage = &message;
        _cleanup_free_ struct pam_response *response = NULL;
        r = conv->conv(1, &pmessage, &response, conv->appdata_ptr);
        _cleanup_free_ char *rr = response ? response->resp : NULL; /* make sure string is freed */
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_DEBUG, r, "Conversation function failed: @PAMERR@");

        if (ret_response)
                *ret_response = TAKE_PTR(rr);

        return PAM_SUCCESS;
}
