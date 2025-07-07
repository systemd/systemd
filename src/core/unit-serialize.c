/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bitfield.h"
#include "cgroup.h"
#include "condition.h"
#include "dbus.h"
#include "extract-word.h"
#include "fileio.h"
#include "format-util.h"
#include "glyph-util.h"
#include "parse-util.h"
#include "serialize.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "unit.h"
#include "unit-serialize.h"
#include "user-util.h"

/* Make sure out values fit in the bitfield. */
assert_cc(_UNIT_MARKER_MAX <= sizeof(((Unit){}).markers) * 8);

static int serialize_markers(FILE *f, unsigned markers) {
        assert(f);

        if (markers == 0)
                return 0;

        bool space = false;

        fputs("markers=", f);
        BIT_FOREACH(m, markers)
                fputs_with_separator(f, unit_marker_to_string(m), /* separator = */ NULL, &space);
        fputc('\n', f);
        return 0;
}

static int deserialize_markers(Unit *u, const char *value) {
        assert(u);
        assert(value);
        int r;

        for (const char *p = value;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r <= 0)
                        return r;

                UnitMarker m = unit_marker_from_string(word);
                if (m < 0) {
                        log_unit_debug_errno(u, m, "Unknown unit marker \"%s\", ignoring.", word);
                        continue;
                }

                u->markers |= 1u << m;
        }
}

int unit_serialize_state(Unit *u, FILE *f, FDSet *fds, bool switching_root) {
        int r;

        assert(u);
        assert(f);
        assert(fds);

        if (switching_root && UNIT_VTABLE(u)->exclude_from_switch_root_serialization) {
                /* In the new root, paths for mounts and automounts will be different, so it doesn't make
                 * much sense to serialize things. API file systems will be moved to the new root, but we
                 * don't have mount units for those. */
                log_unit_debug(u, "not serializing before switch-root");
                return 0;
        }

        /* Start marker */
        fputs(u->id, f);
        fputc('\n', f);

        assert(!!UNIT_VTABLE(u)->serialize == !!UNIT_VTABLE(u)->deserialize_item);

        if (UNIT_VTABLE(u)->serialize) {
                r = UNIT_VTABLE(u)->serialize(u, f, fds);
                if (r < 0)
                        return r;
        }

        (void) serialize_dual_timestamp(f, "state-change-timestamp", &u->state_change_timestamp);

        (void) serialize_dual_timestamp(f, "inactive-exit-timestamp", &u->inactive_exit_timestamp);
        (void) serialize_dual_timestamp(f, "active-enter-timestamp", &u->active_enter_timestamp);
        (void) serialize_dual_timestamp(f, "active-exit-timestamp", &u->active_exit_timestamp);
        (void) serialize_dual_timestamp(f, "inactive-enter-timestamp", &u->inactive_enter_timestamp);

        (void) serialize_dual_timestamp(f, "condition-timestamp", &u->condition_timestamp);
        (void) serialize_dual_timestamp(f, "assert-timestamp", &u->assert_timestamp);

        (void) serialize_ratelimit(f, "start-ratelimit", &u->start_ratelimit);
        (void) serialize_ratelimit(f, "auto-start-stop-ratelimit", &u->auto_start_stop_ratelimit);

        if (dual_timestamp_is_set(&u->condition_timestamp))
                (void) serialize_bool(f, "condition-result", u->condition_result);

        if (dual_timestamp_is_set(&u->assert_timestamp))
                (void) serialize_bool(f, "assert-result", u->assert_result);

        (void) serialize_bool(f, "transient", u->transient);
        (void) serialize_bool(f, "in-audit", u->in_audit);

        (void) serialize_bool(f, "debug-invocation", u->debug_invocation);

        (void) serialize_bool(f, "exported-invocation-id", u->exported_invocation_id);
        (void) serialize_bool(f, "exported-log-level-max", u->exported_log_level_max);
        (void) serialize_bool(f, "exported-log-extra-fields", u->exported_log_extra_fields);
        (void) serialize_bool(f, "exported-log-rate-limit-interval", u->exported_log_ratelimit_interval);
        (void) serialize_bool(f, "exported-log-rate-limit-burst", u->exported_log_ratelimit_burst);

        (void) cgroup_runtime_serialize(u, f, fds);

        if (uid_is_valid(u->ref_uid))
                (void) serialize_item_format(f, "ref-uid", UID_FMT, u->ref_uid);
        if (gid_is_valid(u->ref_gid))
                (void) serialize_item_format(f, "ref-gid", GID_FMT, u->ref_gid);

        (void) serialize_id128(f, "invocation-id", u->invocation_id);

        (void) serialize_item(f, "freezer-state", freezer_state_to_string(u->freezer_state));

        (void) serialize_markers(f, u->markers);

        bus_track_serialize(u->bus_track, f, "ref");

        if (!switching_root) {
                if (u->job) {
                        fputs("job\n", f);
                        job_serialize(u->job, f);
                }

                if (u->nop_job) {
                        fputs("job\n", f);
                        job_serialize(u->nop_job, f);
                }
        }

        /* End marker */
        fputc('\n', f);
        return 0;
}

static int unit_deserialize_job(Unit *u, FILE *f) {
        _cleanup_(job_freep) Job *j = NULL;
        int r;

        assert(u);
        assert(f);

        j = job_new_raw(u);
        if (!j)
                return log_oom();

        r = job_deserialize(j, f);
        if (r < 0)
                return r;

        r = job_install_deserialized(j);
        if (r < 0)
                return r;

        TAKE_PTR(j);
        return 0;
}

#define MATCH_DESERIALIZE(key, l, v, parse_func, target)                \
        ({                                                              \
                bool _deserialize_matched = streq(l, key);              \
                if (_deserialize_matched) {                             \
                        int _deserialize_r = parse_func(v);             \
                        if (_deserialize_r < 0)                         \
                                log_unit_debug_errno(u, _deserialize_r, \
                                                     "Failed to parse \"%s=%s\", ignoring.", l, v); \
                        else                                            \
                                target = _deserialize_r;                \
                };                                                      \
                _deserialize_matched;                                   \
        })

#define MATCH_DESERIALIZE_IMMEDIATE(key, l, v, parse_func, target)      \
        ({                                                              \
                bool _deserialize_matched = streq(l, key);              \
                if (_deserialize_matched) {                             \
                        int _deserialize_r = parse_func(v, &target);    \
                        if (_deserialize_r < 0)                         \
                                log_unit_debug_errno(u, _deserialize_r, \
                                                     "Failed to parse \"%s=%s\", ignoring", l, v); \
                };                                                      \
                _deserialize_matched;                                   \
        })

int unit_deserialize_state(Unit *u, FILE *f, FDSet *fds) {
        int r;

        assert(u);
        assert(f);
        assert(fds);

        for (;;) {
                _cleanup_free_ char *l  = NULL;
                size_t k;
                char *v;

                r = deserialize_read_line(f, &l);
                if (r < 0)
                        return r;
                if (r == 0) /* eof or end marker */
                        break;

                k = strcspn(l, "=");

                if (l[k] == '=') {
                        l[k] = 0;
                        v = l+k+1;
                } else
                        v = l+k;

                if (streq(l, "job")) {
                        if (v[0] == '\0') {
                                /* New-style serialized job */
                                r = unit_deserialize_job(u, f);
                                if (r < 0)
                                        return r;
                        } else  /* Legacy for pre-44 */
                                log_unit_warning(u, "Update from too old systemd versions are unsupported, cannot deserialize job: %s", v);
                        continue;
                } else if (streq(l, "state-change-timestamp")) {
                        (void) deserialize_dual_timestamp(v, &u->state_change_timestamp);
                        continue;
                } else if (streq(l, "inactive-exit-timestamp")) {
                        (void) deserialize_dual_timestamp(v, &u->inactive_exit_timestamp);
                        continue;
                } else if (streq(l, "active-enter-timestamp")) {
                        (void) deserialize_dual_timestamp(v, &u->active_enter_timestamp);
                        continue;
                } else if (streq(l, "active-exit-timestamp")) {
                        (void) deserialize_dual_timestamp(v, &u->active_exit_timestamp);
                        continue;
                } else if (streq(l, "inactive-enter-timestamp")) {
                        (void) deserialize_dual_timestamp(v, &u->inactive_enter_timestamp);
                        continue;
                } else if (streq(l, "condition-timestamp")) {
                        (void) deserialize_dual_timestamp(v, &u->condition_timestamp);
                        continue;
                } else if (streq(l, "assert-timestamp")) {
                        (void) deserialize_dual_timestamp(v, &u->assert_timestamp);
                        continue;

                } else if (streq(l, "start-ratelimit")) {
                        deserialize_ratelimit(&u->start_ratelimit, l, v);
                        continue;
                } else if (streq(l, "auto-start-stop-ratelimit")) {
                        deserialize_ratelimit(&u->auto_start_stop_ratelimit, l, v);
                        continue;

                } else if (MATCH_DESERIALIZE("condition-result", l, v, parse_boolean, u->condition_result))
                        continue;

                else if (MATCH_DESERIALIZE("assert-result", l, v, parse_boolean, u->assert_result))
                        continue;

                else if (MATCH_DESERIALIZE("transient", l, v, parse_boolean, u->transient))
                        continue;

                else if (MATCH_DESERIALIZE("in-audit", l, v, parse_boolean, u->in_audit))
                        continue;

                else if (MATCH_DESERIALIZE("debug-invocation", l, v, parse_boolean, u->debug_invocation))
                        continue;

                else if (MATCH_DESERIALIZE("exported-invocation-id", l, v, parse_boolean, u->exported_invocation_id))
                        continue;

                else if (MATCH_DESERIALIZE("exported-log-level-max", l, v, parse_boolean, u->exported_log_level_max))
                        continue;

                else if (MATCH_DESERIALIZE("exported-log-extra-fields", l, v, parse_boolean, u->exported_log_extra_fields))
                        continue;

                else if (MATCH_DESERIALIZE("exported-log-rate-limit-interval", l, v, parse_boolean, u->exported_log_ratelimit_interval))
                        continue;

                else if (MATCH_DESERIALIZE("exported-log-rate-limit-burst", l, v, parse_boolean, u->exported_log_ratelimit_burst))
                        continue;

                else if (streq(l, "ref-uid")) {
                        uid_t uid;

                        r = parse_uid(v, &uid);
                        if (r < 0)
                                log_unit_debug(u, "Failed to parse \"%s=%s\", ignoring.", l, v);
                        else
                                unit_ref_uid_gid(u, uid, GID_INVALID);
                        continue;

                } else if (streq(l, "ref-gid")) {
                        gid_t gid;

                        r = parse_gid(v, &gid);
                        if (r < 0)
                                log_unit_debug(u, "Failed to parse \"%s=%s\", ignoring.", l, v);
                        else
                                unit_ref_uid_gid(u, UID_INVALID, gid);
                        continue;

                } else if (streq(l, "ref")) {
                        r = strv_extend(&u->deserialized_refs, v);
                        if (r < 0)
                                return log_oom();
                        continue;

                } else if (streq(l, "invocation-id")) {
                        sd_id128_t id;

                        r = sd_id128_from_string(v, &id);
                        if (r < 0)
                                log_unit_debug(u, "Failed to parse \"%s=%s\", ignoring.", l, v);
                        else {
                                r = unit_set_invocation_id(u, id);
                                if (r < 0)
                                        log_unit_warning_errno(u, r, "Failed to set invocation ID for unit: %m");
                        }

                        continue;

                } else if (MATCH_DESERIALIZE("freezer-state", l, v, freezer_state_from_string, u->freezer_state))
                        continue;

                else if (streq(l, "markers")) {
                        r = deserialize_markers(u, v);
                        if (r < 0)
                                log_unit_debug_errno(u, r, "Failed to deserialize \"%s=%s\", ignoring: %m", l, v);
                        continue;
                }

                r = exec_shared_runtime_deserialize_compat(u, l, v, fds);
                if (r < 0) {
                        log_unit_warning(u, "Failed to deserialize runtime parameter '%s', ignoring.", l);
                        continue;
                } else if (r > 0)
                        /* Returns positive if key was handled by the call */
                        continue;

                r = cgroup_runtime_deserialize_one(u, l, v, fds);
                if (r < 0) {
                        log_unit_warning(u, "Failed to deserialize cgroup runtime parameter '%s, ignoring.", l);
                        continue;
                } else if (r > 0)
                        continue; /* was handled */

                if (UNIT_VTABLE(u)->deserialize_item) {
                        r = UNIT_VTABLE(u)->deserialize_item(u, l, v, fds);
                        if (r < 0)
                                log_unit_warning(u, "Failed to deserialize unit parameter '%s', ignoring.", l);
                }
        }

        /* Let's make sure that everything that is deserialized also gets any potential new cgroup settings
         * applied after we are done. For that we invalidate anything already realized, so that we can
         * realize it again. */
        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (crt && crt->cgroup_path) {
                /* Since v258, CGroupRuntime.cgroup_path is coupled with cgroup realized state, which however
                 * wasn't the case in prior versions with the realized state tracked in a discrete field.
                 * Patch cgroup_realized == 0 back to no cgroup_path here hence. */
                if (crt->deserialized_cgroup_realized == 0)
                        unit_release_cgroup(u, /* drop_cgroup_runtime = */ false);
                else {
                        unit_invalidate_cgroup(u, _CGROUP_MASK_ALL);
                        unit_invalidate_cgroup_bpf(u);
                }
        }

        return 0;
}

int unit_deserialize_state_skip(FILE *f) {
        int r;

        assert(f);

        /* Skip serialized data for this unit. We don't know what it is. */

        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        return 0;

                /* End marker */
                if (isempty(line))
                        return 1;
        }
}

static void print_unit_dependency_mask(FILE *f, const char *kind, UnitDependencyMask mask, bool *space) {
        const struct {
                UnitDependencyMask mask;
                const char *name;
        } table[] = {
                { UNIT_DEPENDENCY_FILE,               "file"               },
                { UNIT_DEPENDENCY_IMPLICIT,           "implicit"           },
                { UNIT_DEPENDENCY_DEFAULT,            "default"            },
                { UNIT_DEPENDENCY_UDEV,               "udev"               },
                { UNIT_DEPENDENCY_PATH,               "path"               },
                { UNIT_DEPENDENCY_MOUNT_FILE,         "mount-file"         },
                { UNIT_DEPENDENCY_MOUNTINFO,          "mountinfo"          },
                { UNIT_DEPENDENCY_PROC_SWAP,          "proc-swap"          },
                { UNIT_DEPENDENCY_SLICE_PROPERTY,     "slice-property"     },
        };

        assert(f);
        assert(kind);
        assert(space);

        FOREACH_ELEMENT(i, table) {
                if (mask == 0)
                        break;

                if (FLAGS_SET(mask, i->mask)) {
                        if (*space)
                                fputc(' ', f);
                        else
                                *space = true;

                        fputs(kind, f);
                        fputs("-", f);
                        fputs(i->name, f);

                        mask &= ~i->mask;
                }
        }

        assert(mask == 0);
}

void unit_dump(Unit *u, FILE *f, const char *prefix) {
        char *t;
        const char *prefix2;
        Unit *following;
        _cleanup_set_free_ Set *following_set = NULL;
        CGroupMask m;
        int r;

        assert(u);
        assert(u->type >= 0);

        prefix = strempty(prefix);
        prefix2 = strjoina(prefix, "\t");

        fprintf(f,
                "%s%s Unit %s:\n",
                prefix, glyph(GLYPH_ARROW_RIGHT), u->id);

        SET_FOREACH(t, u->aliases)
                fprintf(f, "%s\tAlias: %s\n", prefix, t);

        fprintf(f,
                "%s\tDescription: %s\n"
                "%s\tInstance: %s\n"
                "%s\tUnit Load State: %s\n"
                "%s\tUnit Active State: %s\n"
                "%s\tState Change Timestamp: %s\n"
                "%s\tInactive Exit Timestamp: %s\n"
                "%s\tActive Enter Timestamp: %s\n"
                "%s\tActive Exit Timestamp: %s\n"
                "%s\tInactive Enter Timestamp: %s\n"
                "%s\tMay GC: %s\n"
                "%s\tNeed Daemon Reload: %s\n"
                "%s\tTransient: %s\n"
                "%s\tPerpetual: %s\n"
                "%s\tGarbage Collection Mode: %s\n",
                prefix, unit_description(u),
                prefix, strna(u->instance),
                prefix, unit_load_state_to_string(u->load_state),
                prefix, unit_active_state_to_string(unit_active_state(u)),
                prefix, strna(FORMAT_TIMESTAMP(u->state_change_timestamp.realtime)),
                prefix, strna(FORMAT_TIMESTAMP(u->inactive_exit_timestamp.realtime)),
                prefix, strna(FORMAT_TIMESTAMP(u->active_enter_timestamp.realtime)),
                prefix, strna(FORMAT_TIMESTAMP(u->active_exit_timestamp.realtime)),
                prefix, strna(FORMAT_TIMESTAMP(u->inactive_enter_timestamp.realtime)),
                prefix, yes_no(unit_may_gc(u)),
                prefix, yes_no(unit_need_daemon_reload(u)),
                prefix, yes_no(u->transient),
                prefix, yes_no(u->perpetual),
                prefix, collect_mode_to_string(u->collect_mode));

        if (u->markers != 0) {
                fprintf(f, "%s\tMarkers:", prefix);

                BIT_FOREACH(marker, u->markers)
                        fprintf(f, " %s", unit_marker_to_string(marker));
                fputs("\n", f);
        }

        if (UNIT_HAS_CGROUP_CONTEXT(u)) {
                CGroupRuntime *crt = unit_get_cgroup_runtime(u);

                fprintf(f,
                        "%s\tSlice: %s\n"
                        "%s\tCGroup: %s\n",
                        prefix, strna(unit_slice_name(u)),
                        prefix, strna(crt ? crt->cgroup_path : NULL));

                if (crt && crt->cgroup_realized_mask != 0) {
                        _cleanup_free_ char *s = NULL;
                        (void) cg_mask_to_string(crt->cgroup_realized_mask, &s);
                        fprintf(f, "%s\tCGroup realized mask: %s\n", prefix, strnull(s));
                }

                if (crt && crt->cgroup_enabled_mask != 0) {
                        _cleanup_free_ char *s = NULL;
                        (void) cg_mask_to_string(crt->cgroup_enabled_mask, &s);
                        fprintf(f, "%s\tCGroup enabled mask: %s\n", prefix, strnull(s));
                }

                m = unit_get_own_mask(u);
                if (m != 0) {
                        _cleanup_free_ char *s = NULL;
                        (void) cg_mask_to_string(m, &s);
                        fprintf(f, "%s\tCGroup own mask: %s\n", prefix, strnull(s));
                }

                m = unit_get_members_mask(u);
                if (m != 0) {
                        _cleanup_free_ char *s = NULL;
                        (void) cg_mask_to_string(m, &s);
                        fprintf(f, "%s\tCGroup members mask: %s\n", prefix, strnull(s));
                }

                m = unit_get_delegate_mask(u);
                if (m != 0) {
                        _cleanup_free_ char *s = NULL;
                        (void) cg_mask_to_string(m, &s);
                        fprintf(f, "%s\tCGroup delegate mask: %s\n", prefix, strnull(s));
                }
        }

        if (!sd_id128_is_null(u->invocation_id))
                fprintf(f, "%s\tInvocation ID: " SD_ID128_FORMAT_STR "\n",
                        prefix, SD_ID128_FORMAT_VAL(u->invocation_id));

        STRV_FOREACH(j, u->documentation)
                fprintf(f, "%s\tDocumentation: %s\n", prefix, *j);

        if (u->access_selinux_context)
                fprintf(f, "%s\tAccess SELinux Context: %s\n", prefix, u->access_selinux_context);

        following = unit_following(u);
        if (following)
                fprintf(f, "%s\tFollowing: %s\n", prefix, following->id);

        r = unit_following_set(u, &following_set);
        if (r >= 0) {
                Unit *other;

                SET_FOREACH(other, following_set)
                        fprintf(f, "%s\tFollowing Set Member: %s\n", prefix, other->id);
        }

        if (u->fragment_path)
                fprintf(f, "%s\tFragment Path: %s\n", prefix, u->fragment_path);

        if (u->source_path)
                fprintf(f, "%s\tSource Path: %s\n", prefix, u->source_path);

        STRV_FOREACH(j, u->dropin_paths)
                fprintf(f, "%s\tDropIn Path: %s\n", prefix, *j);

        if (u->failure_action != EMERGENCY_ACTION_NONE)
                fprintf(f, "%s\tFailure Action: %s\n", prefix, emergency_action_to_string(u->failure_action));
        if (u->failure_action_exit_status >= 0)
                fprintf(f, "%s\tFailure Action Exit Status: %i\n", prefix, u->failure_action_exit_status);
        if (u->success_action != EMERGENCY_ACTION_NONE)
                fprintf(f, "%s\tSuccess Action: %s\n", prefix, emergency_action_to_string(u->success_action));
        if (u->success_action_exit_status >= 0)
                fprintf(f, "%s\tSuccess Action Exit Status: %i\n", prefix, u->success_action_exit_status);

        if (u->job_timeout != USEC_INFINITY)
                fprintf(f, "%s\tJob Timeout: %s\n", prefix, FORMAT_TIMESPAN(u->job_timeout, 0));

        if (u->job_timeout_action != EMERGENCY_ACTION_NONE)
                fprintf(f, "%s\tJob Timeout Action: %s\n", prefix, emergency_action_to_string(u->job_timeout_action));

        if (u->job_timeout_reboot_arg)
                fprintf(f, "%s\tJob Timeout Reboot Argument: %s\n", prefix, u->job_timeout_reboot_arg);

        condition_dump_list(u->conditions, f, prefix, condition_type_to_string);
        condition_dump_list(u->asserts, f, prefix, assert_type_to_string);

        if (dual_timestamp_is_set(&u->condition_timestamp))
                fprintf(f,
                        "%s\tCondition Timestamp: %s\n"
                        "%s\tCondition Result: %s\n",
                        prefix, strna(FORMAT_TIMESTAMP(u->condition_timestamp.realtime)),
                        prefix, yes_no(u->condition_result));

        if (dual_timestamp_is_set(&u->assert_timestamp))
                fprintf(f,
                        "%s\tAssert Timestamp: %s\n"
                        "%s\tAssert Result: %s\n",
                        prefix, strna(FORMAT_TIMESTAMP(u->assert_timestamp.realtime)),
                        prefix, yes_no(u->assert_result));

        for (UnitDependency d = 0; d < _UNIT_DEPENDENCY_MAX; d++) {
                UnitDependencyInfo di;
                Unit *other;

                HASHMAP_FOREACH_KEY(di.data, other, unit_get_dependencies(u, d)) {
                        bool space = false;

                        fprintf(f, "%s\t%s: %s (", prefix, unit_dependency_to_string(d), other->id);

                        print_unit_dependency_mask(f, "origin", di.origin_mask, &space);
                        print_unit_dependency_mask(f, "destination", di.destination_mask, &space);

                        fputs(")\n", f);
                }
        }

        for (UnitMountDependencyType type = 0; type < _UNIT_MOUNT_DEPENDENCY_TYPE_MAX; type++)
                if (!hashmap_isempty(u->mounts_for[type])) {
                        UnitDependencyInfo di;
                        const char *path;

                        HASHMAP_FOREACH_KEY(di.data, path, u->mounts_for[type]) {
                                bool space = false;

                                fprintf(f,
                                        "%s\t%s: %s (",
                                        prefix,
                                        unit_mount_dependency_type_to_string(type),
                                        path);

                                print_unit_dependency_mask(f, "origin", di.origin_mask, &space);
                                print_unit_dependency_mask(f, "destination", di.destination_mask, &space);

                                fputs(")\n", f);
                        }
                }

        if (u->load_state == UNIT_LOADED) {

                fprintf(f,
                        "%s\tStopWhenUnneeded: %s\n"
                        "%s\tRefuseManualStart: %s\n"
                        "%s\tRefuseManualStop: %s\n"
                        "%s\tDefaultDependencies: %s\n"
                        "%s\tSurviveFinalKillSignal: %s\n"
                        "%s\tOnSuccessJobMode: %s\n"
                        "%s\tOnFailureJobMode: %s\n"
                        "%s\tIgnoreOnIsolate: %s\n",
                        prefix, yes_no(u->stop_when_unneeded),
                        prefix, yes_no(u->refuse_manual_start),
                        prefix, yes_no(u->refuse_manual_stop),
                        prefix, yes_no(u->default_dependencies),
                        prefix, yes_no(u->survive_final_kill_signal),
                        prefix, job_mode_to_string(u->on_success_job_mode),
                        prefix, job_mode_to_string(u->on_failure_job_mode),
                        prefix, yes_no(u->ignore_on_isolate));

                if (UNIT_VTABLE(u)->dump)
                        UNIT_VTABLE(u)->dump(u, f, prefix2);

        } else if (u->load_state == UNIT_MERGED)
                fprintf(f,
                        "%s\tMerged into: %s\n",
                        prefix, u->merged_into->id);
        else if (u->load_state == UNIT_ERROR) {
                errno = ABS(u->load_error);
                fprintf(f, "%s\tLoad Error Code: %m\n", prefix);
        }

        for (const char *n = sd_bus_track_first(u->bus_track); n; n = sd_bus_track_next(u->bus_track))
                fprintf(f, "%s\tBus Ref: %s\n", prefix, n);

        if (u->job)
                job_dump(u->job, f, prefix2);

        if (u->nop_job)
                job_dump(u->nop_job, f, prefix2);
}
