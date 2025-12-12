/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_PAM
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h> /* IWYU pragma: export */
#include <syslog.h>

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(pam_acct_mgmt);
extern DLSYM_PROTOTYPE(pam_close_session);
extern DLSYM_PROTOTYPE(pam_end);
extern DLSYM_PROTOTYPE(pam_get_data);
extern DLSYM_PROTOTYPE(pam_get_item);
extern DLSYM_PROTOTYPE(pam_getenvlist);
extern DLSYM_PROTOTYPE(pam_open_session);
extern DLSYM_PROTOTYPE(pam_putenv);
extern DLSYM_PROTOTYPE(pam_set_data);
extern DLSYM_PROTOTYPE(pam_set_item);
extern DLSYM_PROTOTYPE(pam_setcred);
extern DLSYM_PROTOTYPE(pam_start);
extern DLSYM_PROTOTYPE(pam_strerror);
extern DLSYM_PROTOTYPE(pam_syslog);
extern DLSYM_PROTOTYPE(pam_vsyslog);

int dlopen_libpam(void);

void pam_log_setup(void);

int errno_to_pam_error(int error) _const_;

int pam_syslog_errno(pam_handle_t *handle, int level, int error, const char *format, ...) _printf_(4,5);

int pam_syslog_pam_error(pam_handle_t *handle, int level, int error, const char *format, ...) _printf_(4,5);

/* Call sym_pam_syslog if debug is enabled */
#define pam_debug_syslog(handle, debug, fmt, ...)                       \
        ({                                                              \
                if (debug)                                              \
                        sym_pam_syslog(handle, LOG_DEBUG, fmt, ## __VA_ARGS__); \
        })

/* Call pam_syslog_errno if debug is enabled */
#define pam_debug_syslog_errno(handle, debug, error, fmt, ...)          \
        ({                                                              \
                int _error = (error);                                   \
                debug ?                                                 \
                        pam_syslog_errno(handle, LOG_DEBUG, _error, fmt, ## __VA_ARGS__) : \
                        errno_to_pam_error(_error);                     \
        })

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

typedef struct PamBusData PamBusData;
void pam_bus_data_disconnectp(PamBusData **d);

/* Use a different module name per different PAM module. They are all loaded in the same namespace, and this
 * helps avoid a clash in the internal data structures of sd-bus. It will be used as key for cache items. */
int pam_acquire_bus_connection(
                pam_handle_t *handle,
                const char *module_name,
                bool debug,
                sd_bus **ret_bus,
                PamBusData **ret_pam_bus_data);
int pam_get_bus_data(pam_handle_t *handle, const char *module_name, PamBusData **ret);

void pam_cleanup_free(pam_handle_t *handle, void *data, int error_status);
void pam_cleanup_close(pam_handle_t *handle, void *data, int error_status);

int pam_get_item_many_internal(pam_handle_t *handle, ...);
#define pam_get_item_many(handle, ...) pam_get_item_many_internal(handle, __VA_ARGS__, -1)

int pam_get_data_many_internal(pam_handle_t *handle, ...) _sentinel_;
#define pam_get_data_many(handle, ...) pam_get_data_many_internal(handle, __VA_ARGS__, NULL)

int pam_prompt_graceful(pam_handle_t *handle, int style, char **ret_response, const char *fmt, ...) _printf_(4,5);

#else

static inline int dlopen_libpam(void) {
        return -EOPNOTSUPP;
}

#endif
