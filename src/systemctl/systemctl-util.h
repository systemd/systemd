/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "systemctl.h"

/* The init script exit codes for the LSB 'status' verb. (This is different from the 'start' verb, whose exit
   codes are defined in exit-status.h.)

   0       program is running or service is OK
   1       program is dead and /var/run pid file exists
   2       program is dead and /var/lock lock file exists
   3       program is not running
   4       program or service status is unknown
   5-99    reserved for future LSB use
   100-149 reserved for distribution use
   150-199 reserved for application use
   200-254 reserved

   https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html
*/
enum {
        EXIT_PROGRAM_RUNNING_OR_SERVICE_OK        = 0,
        EXIT_PROGRAM_DEAD_AND_PID_EXISTS          = 1,
        EXIT_PROGRAM_DEAD_AND_LOCK_FILE_EXISTS    = 2,
        EXIT_PROGRAM_NOT_RUNNING                  = 3,
        EXIT_PROGRAM_OR_SERVICES_STATUS_UNKNOWN   = 4,
};

typedef enum BusFocus {
        BUS_FULL,      /* The full bus indicated via --system or --user */
        BUS_MANAGER,   /* The manager itself, possibly directly, possibly via the bus */
        _BUS_FOCUS_MAX
} BusFocus;

int acquire_bus_full(BusFocus focus, bool graceful, sd_bus **ret);
static inline int acquire_bus(BusFocus focus, sd_bus **ret) {
        return acquire_bus_full(focus, false, ret);
}
void release_busses(void);

void ask_password_agent_open_maybe(void);
void polkit_agent_open_maybe(void);

int translate_bus_error_to_exit_status(int r, const sd_bus_error *error);

int get_state_one_unit(sd_bus *bus, const char *unit, UnitActiveState *ret_active_state);
int get_sub_state_one_unit(sd_bus *bus, const char *unit, char **ret_sub_state);
int get_unit_list(sd_bus *bus, const char *machine, char **patterns, UnitInfo **unit_infos, int c, sd_bus_message **ret_reply);
int expand_unit_names(sd_bus *bus, char * const *names, const char* suffix, char ***ret, bool *ret_expanded);

int get_active_triggering_units(sd_bus *bus, const char *unit, bool ignore_masked, char ***ret);
void warn_triggering_units(sd_bus *bus, const char *unit, const char *operation, bool ignore_masked);

int need_daemon_reload(sd_bus *bus, const char *unit);

void warn_unit_file_changed(const char *unit);

int append_unit_dependencies(sd_bus *bus, char **names, char ***ret);
int maybe_extend_with_unit_dependencies(sd_bus *bus, char ***list);

int unit_file_find_path(LookupPaths *lp, const char *unit_name, char **ret_unit_path);
int unit_find_paths(sd_bus *bus, const char *unit_name, LookupPaths *lp, bool force_client_side, Hashmap **cached_id_map, Hashmap **cached_name_map, char **ret_fragment_path, char ***ret_dropin_paths);

int unit_is_masked(sd_bus *bus, const char *unit);
int unit_exists(LookupPaths *lp, const char *unit);

int unit_get_dependencies(sd_bus *bus, const char *name, char ***ret);

const char* unit_type_suffix(const char *unit);
bool output_show_unit(const UnitInfo *u, char **patterns);

typedef enum InstallClientSide {
        INSTALL_CLIENT_SIDE_NO = 0,
        INSTALL_CLIENT_SIDE_OVERRIDE,
        INSTALL_CLIENT_SIDE_ARG_ROOT,
        INSTALL_CLIENT_SIDE_OFFLINE,
        INSTALL_CLIENT_SIDE_NOT_BOOTED,
        INSTALL_CLIENT_SIDE_GLOBAL_SCOPE,
} InstallClientSide;

InstallClientSide install_client_side(void);

int output_table(Table *table);

bool show_preset_for_state(UnitFileState state);

int mangle_names(const char *operation, char * const *original_names, char ***ret);

UnitFileFlags unit_file_flags_from_args(void);

int halt_now(enum action a);

int get_unit_by_pid(sd_bus *bus, pid_t pid, char **ret_unit, char **ret_path);
int lookup_unit_by_pidref(sd_bus *bus, pid_t pid, char **ret_unit, char **ret_path);
