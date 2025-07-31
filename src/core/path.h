/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"
#include "unit.h"

typedef enum PathType {
        PATH_EXISTS,
        PATH_EXISTS_GLOB,
        PATH_DIRECTORY_NOT_EMPTY,
        PATH_CHANGED,
        PATH_MODIFIED,
        _PATH_TYPE_MAX,
        _PATH_TYPE_INVALID = -EINVAL,
} PathType;

typedef struct PathSpec {
        Unit *unit;

        char *path;

        sd_event_source *event_source;

        LIST_FIELDS(struct PathSpec, spec);

        PathType type;
        int inotify_fd;
        int primary_wd;

        bool previous_exists;
} PathSpec;

int path_spec_watch(PathSpec *s, sd_event_io_handler_t handler);
void path_spec_unwatch(PathSpec *s);
int path_spec_fd_event(PathSpec *s, uint32_t events);
void path_spec_done(PathSpec *s);

static inline bool path_spec_owns_inotify_fd(PathSpec *s, int fd) {
        return s->inotify_fd == fd;
}

typedef enum PathResult {
        PATH_SUCCESS,
        PATH_FAILURE_RESOURCES,
        PATH_FAILURE_START_LIMIT_HIT,
        PATH_FAILURE_UNIT_START_LIMIT_HIT,
        PATH_FAILURE_TRIGGER_LIMIT_HIT,
        _PATH_RESULT_MAX,
        _PATH_RESULT_INVALID = -EINVAL,
} PathResult;

typedef struct Path {
        Unit meta;

        LIST_HEAD(PathSpec, specs);

        PathState state, deserialized_state;

        bool make_directory;
        mode_t directory_mode;

        PathResult result;

        RateLimit trigger_limit;

        sd_event_source *trigger_notify_event_source;
} Path;

typedef struct ActivationDetailsPath {
        ActivationDetails meta;
        char *trigger_path_filename;
} ActivationDetailsPath;

void path_free_specs(Path *p);

extern const UnitVTable path_vtable;
extern const ActivationDetailsVTable activation_details_path_vtable;

const char* path_type_to_string(PathType i) _const_;
PathType path_type_from_string(const char *s) _pure_;

const char* path_result_to_string(PathResult i) _const_;
PathResult path_result_from_string(const char *s) _pure_;

DEFINE_CAST(PATH, Path);
DEFINE_ACTIVATION_DETAILS_CAST(ACTIVATION_DETAILS_PATH, ActivationDetailsPath, PATH);
