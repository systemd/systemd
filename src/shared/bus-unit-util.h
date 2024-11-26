/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "install.h"
#include "pidref.h"
#include "unit-def.h"

typedef enum ExecDirectoryFlags {
        EXEC_DIRECTORY_READ_ONLY      = 1 << 0, /* Public API via DBUS, do not change */
        EXEC_DIRECTORY_ONLY_CREATE    = 1 << 1, /* Only the private directory will be created, not the symlink to it */
        _EXEC_DIRECTORY_FLAGS_MAX,
        _EXEC_DIRECTORY_FLAGS_PUBLIC  = EXEC_DIRECTORY_READ_ONLY,
        _EXEC_DIRECTORY_FLAGS_INVALID = -EINVAL,
} ExecDirectoryFlags;

ExecDirectoryFlags exec_directory_flags_from_string(const char *s) _pure_;

typedef struct UnitInfo {
        const char *machine;
        const char *id;
        const char *description;
        const char *load_state;
        const char *active_state;
        const char *sub_state;
        const char *following;
        const char *unit_path;
        uint32_t job_id;
        const char *job_type;
        const char *job_path;
} UnitInfo;

int bus_parse_unit_info(sd_bus_message *message, UnitInfo *u);

int bus_append_unit_property_assignment(sd_bus_message *m, UnitType t, const char *assignment);
int bus_append_unit_property_assignment_many(sd_bus_message *m, UnitType t, char **l);

int bus_append_scope_pidref(sd_bus_message *m, const PidRef *pidref, bool allow_pidfd);

int bus_deserialize_and_dump_unit_file_changes(sd_bus_message *m, bool quiet);

int unit_load_state(sd_bus *bus, const char *name, char **load_state);

int unit_info_compare(const UnitInfo *a, const UnitInfo *b);

int bus_service_manager_reload(sd_bus *bus);

typedef struct UnitFreezer UnitFreezer;

UnitFreezer* unit_freezer_free(UnitFreezer *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(UnitFreezer*, unit_freezer_free);

int unit_freezer_new(const char *name, UnitFreezer **ret);

int unit_freezer_freeze(UnitFreezer *f);
int unit_freezer_thaw(UnitFreezer *f);
