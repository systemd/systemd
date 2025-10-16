/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "shared-forward.h"

#if HAVE_SELINUX
#include <selinux/avc.h>
#include <selinux/label.h>
#include <selinux/context.h>
#include <selinux/selinux.h> /* IWYU pragma: export */

#include "dlfcn-util.h"

int dlopen_libselinux(void);

extern DLSYM_PROTOTYPE(avc_open);
extern DLSYM_PROTOTYPE(context_free);
extern DLSYM_PROTOTYPE(context_new);
extern DLSYM_PROTOTYPE(context_range_get);
extern DLSYM_PROTOTYPE(context_range_set);
extern DLSYM_PROTOTYPE(context_str);
extern DLSYM_PROTOTYPE(fgetfilecon_raw);
extern DLSYM_PROTOTYPE(fini_selinuxmnt);
extern DLSYM_PROTOTYPE(freecon);
extern DLSYM_PROTOTYPE(getcon_raw);
extern DLSYM_PROTOTYPE(getfilecon_raw);
extern DLSYM_PROTOTYPE(getpeercon_raw);
extern DLSYM_PROTOTYPE(getpidcon_raw);
extern DLSYM_PROTOTYPE(is_selinux_enabled);
extern DLSYM_PROTOTYPE(security_compute_create_raw);
extern DLSYM_PROTOTYPE(security_getenforce);
extern DLSYM_PROTOTYPE(selabel_close);
extern DLSYM_PROTOTYPE(selabel_lookup_raw);
extern DLSYM_PROTOTYPE(selabel_open);
extern DLSYM_PROTOTYPE(selinux_check_access);
extern DLSYM_PROTOTYPE(selinux_getenforcemode);
extern DLSYM_PROTOTYPE(selinux_init_load_policy);
extern DLSYM_PROTOTYPE(selinux_path);
extern DLSYM_PROTOTYPE(selinux_set_callback);
extern DLSYM_PROTOTYPE(selinux_status_close);
extern DLSYM_PROTOTYPE(selinux_status_getenforce);
extern DLSYM_PROTOTYPE(selinux_status_open);
extern DLSYM_PROTOTYPE(selinux_status_policyload);
extern DLSYM_PROTOTYPE(setcon_raw);
extern DLSYM_PROTOTYPE(setexeccon_raw);
extern DLSYM_PROTOTYPE(setfilecon_raw);
extern DLSYM_PROTOTYPE(setfscreatecon_raw);
extern DLSYM_PROTOTYPE(setsockcreatecon_raw);
extern DLSYM_PROTOTYPE(string_to_security_class);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(char*, sym_freecon, freeconp, NULL);

#else

static inline int dlopen_libselinux(void) {
        return -EOPNOTSUPP;
}

static inline void freeconp(char **p) {
        assert(*p == NULL);
}
#endif

#define _cleanup_freecon_ _cleanup_(freeconp)

/* This accepts 0 error, like _zerook(). */
#define log_selinux_enforcing_errno(error, ...)                         \
        ({                                                              \
                int _e = (error);                                       \
                bool _enforcing = mac_selinux_enforcing();              \
                int _level =                                            \
                        ERRNO_VALUE(_e) == 0 ? LOG_DEBUG :              \
                                  _enforcing ? LOG_ERR : LOG_WARNING;   \
                                                                        \
                int _r = (log_get_max_level() >= LOG_PRI(_level))       \
                        ? log_internal(_level, _e, PROJECT_FILE, __LINE__, __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
                _enforcing ? _r : 0;                                    \
        })

bool mac_selinux_use(void);
void mac_selinux_retest(void);
bool mac_selinux_enforcing(void);

int mac_selinux_init(void);
int mac_selinux_init_lazy(void);
void mac_selinux_maybe_reload(void);
void mac_selinux_finish(void);

void mac_selinux_disable_logging(void);

int mac_selinux_fix_full(int atfd, const char *inode_path, const char *label_path, LabelFixFlags flags);

int mac_selinux_apply(const char *path, const char *label);
int mac_selinux_apply_fd(int fd, const char *path, const char *label);

int mac_selinux_get_create_label_from_exe(const char *exe, char **ret_label);
int mac_selinux_get_our_label(char **ret_label);
int mac_selinux_get_peer_label(int socket_fd, char **ret_label);
int mac_selinux_get_child_mls_label(int socket_fd, const char *exe, const char *exec_label, char **ret_label);

int mac_selinux_create_file_prepare_at(int dirfd, const char *path, mode_t mode);
static inline int mac_selinux_create_file_prepare(const char *path, mode_t mode) {
        return mac_selinux_create_file_prepare_at(AT_FDCWD, path, mode);
}
int mac_selinux_create_file_prepare_label(const char *path, const char *label);
void mac_selinux_create_file_clear(void);

int mac_selinux_create_socket_prepare(const char *label);
void mac_selinux_create_socket_clear(void);

int mac_selinux_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);
