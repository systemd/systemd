/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "macro.h"
#include "label.h"

#if HAVE_SELINUX
#include <selinux/selinux.h>

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(char*, freecon, NULL);
#define _cleanup_freecon_ _cleanup_(freeconp)
#endif

bool mac_selinux_use(void);
void mac_selinux_retest(void);
bool mac_selinux_enforcing(void);

int mac_selinux_init(void);
void mac_selinux_maybe_reload(void);
void mac_selinux_finish(void);

int mac_selinux_fix_full(int atfd, const char *inode_path, const char *label_path, LabelFixFlags flags);

int mac_selinux_apply(const char *path, const char *label);
int mac_selinux_apply_fd(int fd, const char *path, const char *label);

int mac_selinux_get_create_label_from_exe(const char *exe, char **label);
int mac_selinux_get_our_label(char **label);
int mac_selinux_get_child_mls_label(int socket_fd, const char *exe, const char *exec_label, char **label);
char* mac_selinux_free(char *label);

int mac_selinux_create_file_prepare_at(int dirfd, const char *path, mode_t mode);
static inline int mac_selinux_create_file_prepare(const char *path, mode_t mode) {
        return mac_selinux_create_file_prepare_at(AT_FDCWD, path, mode);
}
int mac_selinux_create_file_prepare_label(const char *path, const char *label);
void mac_selinux_create_file_clear(void);

int mac_selinux_create_socket_prepare(const char *label);
void mac_selinux_create_socket_clear(void);

int mac_selinux_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);

DEFINE_TRIVIAL_CLEANUP_FUNC(char*, mac_selinux_free);
