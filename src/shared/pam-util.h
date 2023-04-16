/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <security/pam_modules.h>

#include "sd-bus.h"

int pam_syslog_errno(pam_handle_t *handle, int level, int error, const char *format, ...) _printf_(4,5);

int pam_syslog_pam_error(pam_handle_t *handle, int level, int error, const char *format, ...) _printf_(4,5);

static inline int pam_log_oom(pam_handle_t *handle) {
        /* This is like log_oom(), but uses PAM logging */
        return pam_syslog_errno(handle, LOG_ERR, ENOMEM, "Out of memory.");
}

static inline int pam_bus_log_create_error(pam_handle_t *handle, int r) {
        /* This is like bus_log_create_error(), but uses PAM logging */
        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to create bus message: %m");
}

static inline int pam_bus_log_parse_error(pam_handle_t *handle, int r) {
        /* This is like bus_log_parse_error(), but uses PAM logging */
        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to parse bus message: %m");
}

/* Use a different module name per different PAM module. They are all loaded in the same namespace, and this
 * helps avoid a clash in the internal data structures of sd-bus. It will be used as key for cache items. */
int pam_acquire_bus_connection(pam_handle_t *handle, const char *module_name, sd_bus **ret);
int pam_release_bus_connection(pam_handle_t *handle, const char *module_name);

void pam_cleanup_free(pam_handle_t *handle, void *data, int error_status);
