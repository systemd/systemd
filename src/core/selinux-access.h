/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

typedef struct MacSelinuxAccessCheckContext {
        bool initialized;
        int result;
        sd_bus_creds *creds;
        const char *selinux_context;
        char *owned_selinux_context;
        char *cmdline;
} MacSelinuxAccessCheckContext;

void mac_selinux_access_check_context_done(MacSelinuxAccessCheckContext *context);
int mac_selinux_access_check_context_init(
                sd_bus_message *message,
                MacSelinuxAccessCheckContext *context,
                sd_bus_error *reterr_error);

int mac_selinux_access_check_bus_internal(
                sd_bus_message *message,
                const Unit *unit,
                const char *permission,
                const char *function,
                sd_bus_error *reterr_error);
int mac_selinux_access_check_bus_internal_full(
                sd_bus_message *message,
                const Unit *unit,
                MacSelinuxAccessCheckContext *context,
                const char *permission,
                const char *function,
                sd_bus_error *reterr_error);
int mac_selinux_access_check_varlink_internal(
                sd_varlink *link,
                const Unit *unit,
                const char *permission,
                const char *function);
int mac_selinux_access_check_varlink_context_init(
                sd_varlink *link,
                MacSelinuxAccessCheckContext *context);
int mac_selinux_access_check_varlink_internal_full(
                sd_varlink *link,
                const Unit *unit,
                MacSelinuxAccessCheckContext *context,
                const char *permission,
                const char *function);

#define mac_selinux_access_check(message, permission, error) \
        mac_selinux_access_check_bus_internal((message), NULL, (permission), __func__, (error))

#define mac_selinux_access_check_full(message, context, permission, error) \
        mac_selinux_access_check_bus_internal_full((message), NULL, (context), (permission), __func__, (error))

#define mac_selinux_unit_access_check(unit, message, permission, error) \
        mac_selinux_access_check_bus_internal((message), (unit), (permission), __func__, (error))

#define mac_selinux_unit_access_check_full(unit, message, context, permission, error) \
        mac_selinux_access_check_bus_internal_full((message), (unit), (context), (permission), __func__, (error))

#define mac_selinux_access_check_varlink(link, permission) \
        mac_selinux_access_check_varlink_internal((link), NULL, (permission), __func__)

#define mac_selinux_access_check_varlink_full(link, context, permission) \
        mac_selinux_access_check_varlink_internal_full((link), NULL, (context), (permission), __func__)

#define mac_selinux_unit_access_check_varlink(unit, link, permission) \
        mac_selinux_access_check_varlink_internal((link), (unit), (permission), __func__)

#define mac_selinux_unit_access_check_varlink_full(unit, link, context, permission) \
        mac_selinux_access_check_varlink_internal_full((link), (unit), (context), (permission), __func__)
