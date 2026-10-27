/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "capability-list.h"
#include "dissect-image.h"
#include "errno-list.h"
#include "exec-credential.h"
#include "execute.h"
#include "image-policy.h"
#include "ioprio-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "manager.h"
#include "mountpoint-util.h"
#include "namespace.h"
#include "nsflags.h"
#include "ordered-set.h"
#include "path-util.h"
#include "process-util.h"
#include "securebits-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "unit.h"
#include "user-util.h"
#include "varlink-common.h"
#include "varlink-execute.h"

/* Read side of the Exec context for List. */

#define JSON_BUILD_PAIR_MOUNT_PROPAGATION_FLAG(name, s) \
        SD_JSON_BUILD_PAIR_CONDITION(!isempty(s), name, JSON_BUILD_STRING_UNDERSCORIFY(s))

static int working_directory_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        const char *wd = c->working_directory_home ? "~" : c->working_directory;
        if (!wd) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("path", wd),
                        SD_JSON_BUILD_PAIR_BOOLEAN("missingOK", c->working_directory_missing_ok));
}

static int json_append_mount_options(sd_json_variant **v, MountOptions *options) {
        int r;

        assert(v);

        if (!options)
                return 0;

        for (PartitionDesignator j = 0; j < _PARTITION_DESIGNATOR_MAX; j++) {
                if (isempty(options->options[j]))
                        continue;

                r = sd_json_variant_append_arraybo(
                                v,
                                SD_JSON_BUILD_PAIR_STRING("partitionDesignator", partition_designator_to_string(j)),
                                SD_JSON_BUILD_PAIR_STRING("options", options->options[j]));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int root_image_options_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        MountOptions *root_image_options = userdata;

        assert(ret);
        assert(name);

        if (!root_image_options) {
                *ret = NULL;
                return 0;
        }

        return json_append_mount_options(ret, root_image_options);
}

static int image_policy_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_free_ char *s = NULL;
        ImagePolicy *policy = userdata;
        int r;

        assert(ret);
        assert(name);

        r = image_policy_to_string(policy ?: &image_policy_service, /* simplify= */ true, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert image policy to string: %m");

        return sd_json_variant_new_string(ret, s);
}

static int bind_paths_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);
        assert(name);

        bool ro = strstr(name, "ReadOnly");
        FOREACH_ARRAY(i, c->bind_mounts, c->n_bind_mounts) {
                if (ro != i->read_only)
                        continue;

                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("source", i->source),
                                SD_JSON_BUILD_PAIR_STRING("destination", i->destination),
                                SD_JSON_BUILD_PAIR_BOOLEAN("ignoreEnoent", i->ignore_enoent),
                                SD_JSON_BUILD_PAIR_STRV("options", STRV_MAKE(i->recursive ? "rbind" : "norbind")));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int mount_images_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);
        assert(name);

        FOREACH_ARRAY(i, c->mount_images, c->n_mount_images) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mo = NULL;

                r = json_append_mount_options(&mo, i->mount_options);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("source", i->source),
                                SD_JSON_BUILD_PAIR_STRING("destination", i->destination),
                                SD_JSON_BUILD_PAIR_BOOLEAN("ignoreEnoent", i->ignore_enoent),
                                SD_JSON_BUILD_PAIR_VARIANT("mountOptions", mo));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int extension_images_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);
        assert(name);

        FOREACH_ARRAY(i, c->extension_images, c->n_extension_images) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mo = NULL;

                r = json_append_mount_options(&mo, i->mount_options);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("source", i->source),
                                SD_JSON_BUILD_PAIR_BOOLEAN("ignoreEnoent", i->ignore_enoent),
                                SD_JSON_BUILD_PAIR_VARIANT("mountOptions", mo));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int capability_set_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        uint64_t capability_set = PTR_TO_INT64(userdata);
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(ret);
        assert(name);

        r = capability_set_to_strv(capability_set, &l);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert capability set to strv: %m");

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_array_strv(ret, l);
}

static int secure_bits_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        int secure_bits = PTR_TO_INT(userdata);
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(ret);
        assert(name);

        r = secure_bits_to_strv(secure_bits, &l);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert secure bits to strv: %m");

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_array_strv(ret, l);
}

static int rlimit_table_with_defaults_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        /* This function is similar rlimit_table_build_json() but it falls back
         * to Manager's default if ExecContext doesn't have one. */

        /* Note, this is deviation from DBus implementation. DBus falls
         * back directly to getrlimit() without considering Manager's defaults */

        Unit *u = ASSERT_PTR(userdata);
        Manager *m = ASSERT_PTR(u->manager);
        ExecContext *c = ASSERT_PTR(unit_get_exec_context(u));
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(ret);
        assert(name);

        for (int i = 0; i < _RLIMIT_MAX; i++) {
                r = sd_json_variant_merge_objectbo(
                        &v,
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL(rlimit_to_string(i), rlimit_build_json, c->rlimit[i] ?: m->defaults.rlimit[i]));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int cpu_sched_class_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);
        assert(name);

        int p = exec_context_get_cpu_sched_policy(c);
        r = sched_policy_to_string_alloc(p, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert sched policy to string: %m");

        return sd_json_variant_new_string(ret, json_underscorify(s));
}

static int cpu_affinity_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(cpu_set_done) CPUSet numa_cpuset = {};
        ExecContext *c = ASSERT_PTR(userdata);
        CPUSet *s = NULL;
        int r;

        assert(ret);
        assert(name);

        bool cpu_affinity_from_numa = exec_context_get_cpu_affinity_from_numa(c);
        if (cpu_affinity_from_numa) {
                r = numa_to_cpu_set(&c->numa_policy, &numa_cpuset);
                if (r < 0)
                        return log_debug_errno(r, "Failed to convert numa policy to cpu set: %m");

                s = &numa_cpuset;
        } else
                s = &c->cpu_set;

        r = cpuset_build_json(&v, /* name= */ NULL, s);
        if (r < 0)
                return r;

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_VARIANT("affinity", v),
                        SD_JSON_BUILD_PAIR_BOOLEAN("fromNUMA", cpu_affinity_from_numa));
}

static int numa_policy_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        int t = numa_policy_get_type(&c->numa_policy);
        if (!mpol_is_valid(t)) {
                *ret = NULL;
                return 0;
        }

        _cleanup_free_ char *s = strdup(mpol_to_string(t));
        if (!s)
                return -ENOMEM;

        return sd_json_variant_new_string(ret, json_underscorify(s));
}

static int numa_mask_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        int t = numa_policy_get_type(&c->numa_policy);
        if (!mpol_is_valid(t)) {
                *ret = NULL;
                return 0;
        }

        return cpuset_build_json(ret, /* name= */ NULL, &c->numa_policy.nodes);
}

static int ioprio_class_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);
        assert(name);

        int ioprio = exec_context_get_effective_ioprio(c);
        r = ioprio_class_to_string_alloc(ioprio_prio_class(ioprio), &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert IO priority class to string: %m");

        return sd_json_variant_new_string(ret, json_underscorify(s));
}

static int exec_dir_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecDirectory *exec_dir = ASSERT_PTR(userdata);
        const ExecQuotaLimit *quota = &exec_dir->exec_quota;
        int r;

        assert(ret);
        assert(name);

        if (exec_dir->n_items == 0) {
                *ret = NULL;
                return 0;
        }

        FOREACH_ARRAY(dir, exec_dir->items, exec_dir->n_items) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("path", dir->path),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("symlinks", dir->symlinks));
                if (r < 0)
                        return r;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_VARIANT("paths", v),
                        SD_JSON_BUILD_PAIR_UNSIGNED("mode", exec_dir->mode),
                        SD_JSON_BUILD_PAIR("quota",
                                SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_BOOLEAN("accounting", quota->quota_accounting),
                                        SD_JSON_BUILD_PAIR_BOOLEAN("enforce", quota->quota_enforce),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("quotaAbsolute", quota->quota_absolute),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("quotaScale", quota->quota_scale))));
}

static int temporary_filesystems_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);
        assert(name);

        FOREACH_ARRAY(t, c->temporary_filesystems, c->n_temporary_filesystems) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("path", t->path),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("options", t->options));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int address_families_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        l = exec_context_get_address_families(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->address_families_allow_list),
                        SD_JSON_BUILD_PAIR_STRV("addressFamilies", l));
}

static int restrict_filesystems_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;

        assert(ret);
        assert(name);

        l = exec_context_get_restrict_filesystems(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->restrict_filesystems_allow_list),
                        SD_JSON_BUILD_PAIR_STRV("filesystems", l));
}

static int namespace_flags_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        unsigned long namespaces = PTR_TO_ULONG(userdata);
        int r;

        assert(ret);
        assert(name);

        r = namespace_flags_to_strv(namespaces, &l);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert namespace flags to strv: %m");

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_array_strv(ret, l);
}

static int private_bpf_delegate_commands_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *v = bpf_delegate_commands_to_string(c->bpf_delegate_commands);

        assert(ret);

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ret, v);
}

static int private_bpf_delegate_maps_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *v = bpf_delegate_maps_to_string(c->bpf_delegate_maps);

        assert(ret);

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ret, v);
}

static int private_bpf_delegate_programs_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *v = bpf_delegate_programs_to_string(c->bpf_delegate_programs);

        assert(ret);

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ret, v);
}

static int private_bpf_delegate_attachments_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *v = bpf_delegate_attachments_to_string(c->bpf_delegate_attachments);

        assert(ret);

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ret, v);
}

static int syscall_filter_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;

        assert(ret);
        assert(name);

        l = exec_context_get_syscall_filter(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->syscall_allow_list),
                        SD_JSON_BUILD_PAIR_STRV("systemCalls", l));
}

static int syscall_error_number_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);

        assert(ret);
        assert(name);

        if (c->syscall_errno == 0) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ret, ERRNO_NAME(c->syscall_errno));
}

static int syscall_archs_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;

        assert(ret);
        assert(name);

        l = exec_context_get_syscall_archs(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_array_strv(ret, l);
}

static int syscall_log_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;

        assert(ret);
        assert(name);

        l = exec_context_get_syscall_log(c);
        if (!l)
                return -ENOMEM;

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", c->syscall_allow_list),
                        SD_JSON_BUILD_PAIR_STRV("systemCalls", l));
}

static int environment_files_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        char **environment_files = userdata;
        int r;

        assert(ret);
        assert(name);

        STRV_FOREACH(j, environment_files) {
                const char *fn = *j;
                if (isempty(fn))
                        continue;

                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("path", fn[0] == '-' ? fn + 1 : fn),
                                SD_JSON_BUILD_PAIR_BOOLEAN("graceful", fn[0] == '-'));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int log_level_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        int log_level = PTR_TO_INT(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);
        assert(name);

        if (log_level < 0) {
                *ret = NULL;
                return 0;
        }

        r = log_level_to_string_alloc(log_level, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert log level to string: %m");

        return sd_json_variant_new_string(ret, s);
}

static int log_extra_fields_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        int r;

        assert(ret);
        assert(name);

        FOREACH_ARRAY(i, c->log_extra_fields, c->n_log_extra_fields) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *s = NULL;
                r = sd_json_variant_new_stringn(&s, i->iov_base, i->iov_len);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&v, s);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int log_filter_patterns_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecContext *c = ASSERT_PTR(userdata);
        const char *pattern;
        int r;

        assert(ret);
        assert(name);

        SET_FOREACH(pattern, c->log_filter_allowed_patterns) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", true),
                                SD_JSON_BUILD_PAIR_STRING("pattern", pattern));
                if (r < 0)
                        return r;
        }

        SET_FOREACH(pattern, c->log_filter_denied_patterns) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_BOOLEAN("isAllowList", false),
                                SD_JSON_BUILD_PAIR_STRING("pattern", pattern));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int syslog_facility_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        int log_facility = PTR_TO_INT(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);
        assert(name);

        r = log_facility_unshifted_to_string_alloc(log_facility, &s);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert log facility to string: %m");

        return sd_json_variant_new_string(ret, s);
}

static int load_credential_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Hashmap *load_credentials = userdata;
        ExecLoadCredential *lc;
        int r;

        assert(ret);
        assert(name);

        bool encrypted = streq(name, "LoadCredentialEncrypted");
        HASHMAP_FOREACH(lc, load_credentials) {
                if (lc->encrypted != encrypted)
                        continue;

                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("id", lc->id),
                                SD_JSON_BUILD_PAIR_STRING("path", lc->path));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int import_credential_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        OrderedSet *import_credentials = userdata;
        ExecImportCredential *ic;
        int r;

        assert(ret);

        ORDERED_SET_FOREACH(ic, import_credentials) {
                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("glob", ic->glob),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("rename", ic->rename));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int set_credential_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Hashmap *set_credentials = userdata;
        ExecSetCredential *sc;
        int r;

        assert(ret);
        assert(name);

        bool encrypted = streq(name, "SetCredentialEncrypted");
        HASHMAP_FOREACH(sc, set_credentials) {
                if (sc->encrypted != encrypted)
                        continue;

                r = sd_json_variant_append_arraybo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("id", sc->id),
                                SD_JSON_BUILD_PAIR_BASE64("value", sc->data, sc->size));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int unit_exec_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        ExecContext *c = unit_get_exec_context(u);

        assert(ret);

        if (!c) {
                *ret = NULL;
                return 0;
        }

        return sd_json_buildo(
                        ASSERT_PTR(ret),

                        /* Paths */
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ExecSearchPath", c->exec_search_path),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("WorkingDirectory", working_directory_build_json, c),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootDirectory", c->root_directory),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootImage", c->root_image),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootMStack", c->root_mstack),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RootImageOptions", root_image_options_build_json, c->root_image_options),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RootEphemeral", c->root_ephemeral),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("RootHash", c->root_hash.iov_base, c->root_hash.iov_len),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootHashPath", c->root_hash_path),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("RootHashSignature", c->root_hash_sig.iov_base, c->root_hash_sig.iov_len),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootHashSignaturePath", c->root_hash_sig_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RootVerity", c->root_verity),
                        SD_JSON_BUILD_PAIR_CALLBACK("RootImagePolicy", image_policy_build_json, c->root_image_policy),
                        SD_JSON_BUILD_PAIR_CALLBACK("MountImagePolicy", image_policy_build_json, c->mount_image_policy),
                        SD_JSON_BUILD_PAIR_CALLBACK("ExtensionImagePolicy", image_policy_build_json, c->extension_image_policy),
                        JSON_BUILD_PAIR_YES_NO("MountAPIVFS", exec_context_get_effective_mount_apivfs(c)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("BindLogSockets", exec_context_get_effective_bind_log_sockets(c)),
                        JSON_BUILD_PAIR_ENUM("ProtectProc", protect_proc_to_string(c->protect_proc)),
                        JSON_BUILD_PAIR_ENUM("ProcSubset", proc_subset_to_string(c->proc_subset)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BindPaths", bind_paths_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BindReadOnlyPaths", bind_paths_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("MountImages", mount_images_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExtensionImages", extension_images_build_json, c),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ExtensionDirectories", c->extension_directories),

                        /* User/Group Identity */
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("User", c->user),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Group", c->group),
                        SD_JSON_BUILD_PAIR_BOOLEAN("DynamicUser", c->dynamic_user),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("SupplementaryGroups", c->supplementary_groups),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("SetLoginEnvironment", c->set_login_environment),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("PAMName", c->pam_name),

                        /* Capabilities */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CapabilityBoundingSet", capability_set_build_json, INT64_TO_PTR(c->capability_bounding_set)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("AmbientCapabilities", capability_set_build_json, INT64_TO_PTR(c->capability_ambient_set)),

                        /* Security */
                        SD_JSON_BUILD_PAIR_BOOLEAN("NoNewPrivileges", c->no_new_privileges),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SecureBits", secure_bits_build_json, INT_TO_PTR(c->secure_bits)),

                        /* Mandatory Access Control */
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->selinux_context, "SELinuxContext",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("ignore", c->selinux_context_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("context", c->selinux_context))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->apparmor_profile, "AppArmorProfile",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("ignore", c->apparmor_profile_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("profile", c->apparmor_profile))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->smack_process_label, "SmackProcessLabel",
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("ignore", c->smack_process_label_ignore),
                                                SD_JSON_BUILD_PAIR_STRING("label", c->smack_process_label))),

                        /* Process Properties */
                        SD_JSON_BUILD_PAIR_CALLBACK("Limits", rlimit_table_with_defaults_build_json, u),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("UMask", c->umask),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("CoredumpFilter", exec_context_get_coredump_filter(c)),
                        JSON_BUILD_PAIR_ENUM("KeyringMode", exec_keyring_mode_to_string(c->keyring_mode)),
                        JSON_BUILD_PAIR_INTEGER_NON_ZERO("OOMScoreAdjust", exec_context_get_oom_score_adjust(c)),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("TimerSlackNSec", exec_context_get_timer_slack_nsec(c), NSEC_INFINITY),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Personality", personality_to_string(c->personality)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("IgnoreSIGPIPE", c->ignore_sigpipe),

                        /* Scheduling */
                        SD_JSON_BUILD_PAIR_INTEGER("Nice", exec_context_get_nice(c)),
                        SD_JSON_BUILD_PAIR_CALLBACK("CPUSchedulingPolicy", cpu_sched_class_build_json, c),
                        SD_JSON_BUILD_PAIR_INTEGER("CPUSchedulingPriority", exec_context_get_cpu_sched_priority(c)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CPUSchedulingResetOnFork", c->cpu_sched_reset_on_fork),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CPUAffinity", cpu_affinity_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("NUMAPolicy", numa_policy_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("NUMAMask", numa_mask_build_json, c),
                        SD_JSON_BUILD_PAIR_CALLBACK("IOSchedulingClass", ioprio_class_build_json, c),
                        SD_JSON_BUILD_PAIR_INTEGER("IOSchedulingPriority", ioprio_prio_data(exec_context_get_effective_ioprio(c))),

                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("MemoryKSM", c->memory_ksm),
                        JSON_BUILD_PAIR_ENUM("MemoryTHP", exec_memory_thp_to_string(c->memory_thp)),

                        /* Sandboxing */
                        JSON_BUILD_PAIR_ENUM("ProtectSystem", protect_system_to_string(c->protect_system)),
                        JSON_BUILD_PAIR_ENUM("ProtectHome", protect_home_to_string(c->protect_home)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RuntimeDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_RUNTIME]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StateDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_STATE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CacheDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CACHE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogsDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_LOGS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConfigurationDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CONFIGURATION]),
                        JSON_BUILD_PAIR_ENUM("RuntimeDirectoryPreserve", exec_preserve_mode_to_string(c->runtime_directory_preserve_mode)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutCleanUSec", c->timeout_clean_usec),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ReadWritePaths", c->read_write_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ReadOnlyPaths", c->read_only_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("InaccessiblePaths", c->inaccessible_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ExecPaths", c->exec_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("NoExecPaths", c->no_exec_paths),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TemporaryFileSystem", temporary_filesystems_build_json, c),
                        /* XXX should we make all these Private/Protect strings??? */
                        JSON_BUILD_PAIR_ENUM("PrivateTmp", private_tmp_to_string(c->private_tmp)),
                        JSON_BUILD_PAIR_YES_NO("PrivateDevices", c->private_devices),
                        JSON_BUILD_PAIR_YES_NO("PrivateNetwork", c->private_network),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("NetworkNamespacePath", c->network_namespace_path),
                        JSON_BUILD_PAIR_YES_NO("PrivateIPC", c->private_ipc),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("IPCNamespacePath", c->ipc_namespace_path),
                        JSON_BUILD_PAIR_ENUM("PrivatePIDs", private_pids_to_string(c->private_pids)),
                        JSON_BUILD_PAIR_ENUM("PrivateUsers", private_users_to_string(c->private_users)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UserNamespacePath", c->user_namespace_path),
                        JSON_BUILD_PAIR_ENUM("ProtectHostname", protect_hostname_to_string(c->protect_hostname)),
                        JSON_BUILD_PAIR_YES_NO("ProtectClock", c->protect_clock),
                        JSON_BUILD_PAIR_YES_NO("ProtectKernelTunables", c->protect_kernel_tunables),
                        JSON_BUILD_PAIR_YES_NO("ProtectKernelModules", c->protect_kernel_modules),
                        JSON_BUILD_PAIR_YES_NO("ProtectKernelLogs", c->protect_kernel_logs),
                        JSON_BUILD_PAIR_ENUM("ProtectControlGroups", protect_control_groups_to_string(c->protect_control_groups)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictAddressFamilies", address_families_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictFileSystems", restrict_filesystems_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictNamespaces", namespace_flags_build_json, ULONG_TO_PTR(c->restrict_namespaces)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DelegateNamespaces", namespace_flags_build_json, ULONG_TO_PTR(c->delegate_namespaces)),
                        JSON_BUILD_PAIR_ENUM("PrivatePBF", private_bpf_to_string(c->private_bpf)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BPFDelegateCommands", private_bpf_delegate_commands_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BPFDelegateMaps", private_bpf_delegate_maps_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BPFDelegatePrograms", private_bpf_delegate_programs_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("BPFDelegateAttachments", private_bpf_delegate_attachments_build_json, c),
                        SD_JSON_BUILD_PAIR_BOOLEAN("LockPersonality", c->lock_personality),
                        SD_JSON_BUILD_PAIR_BOOLEAN("MemoryDenyWriteExecute", c->memory_deny_write_execute),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RestrictRealtime", c->restrict_realtime),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RestrictSUIDSGID", c->restrict_suid_sgid),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RemoveIPC", c->remove_ipc),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("PrivateMounts", c->private_mounts),
                        JSON_BUILD_PAIR_MOUNT_PROPAGATION_FLAG("MountFlags", mount_propagation_flag_to_string(c->mount_propagation_flag)),

                        /* System Call Filtering */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SystemCallFilter", syscall_filter_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SystemCallErrorNumber", syscall_error_number_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SystemCallArchitectures", syscall_archs_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SystemCallLog", syscall_log_build_json, c),

                        /* Environment */
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Environment", c->environment),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("EnvironmentFiles", environment_files_build_json, c->environment_files),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("PassEnvironment", c->pass_environment),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("UnsetEnvironment", c->unset_environment),

                        /* Logging and Standard Input/Output */
                        JSON_BUILD_PAIR_ENUM("StandardInput", exec_input_to_string(c->std_input)),
                        JSON_BUILD_PAIR_ENUM("StandardOutput", exec_output_to_string(c->std_output)),
                        JSON_BUILD_PAIR_ENUM("StandardError", exec_output_to_string(c->std_error)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StandardInputFileDescriptorName", exec_context_fdname(c, STDIN_FILENO)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StandardOutputFileDescriptorName", exec_context_fdname(c, STDOUT_FILENO)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("StandardErrorFileDescriptorName", exec_context_fdname(c, STDERR_FILENO)),
                        JSON_BUILD_PAIR_BASE64_NON_EMPTY("StandardInputData", c->stdin_data, c->stdin_data_size),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogLevelMax", log_level_build_json, INT_TO_PTR(exec_log_level_max(c))),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogExtraFields", log_extra_fields_build_json, c),
                        JSON_BUILD_PAIR_RATELIMIT_ENABLED("LogRateLimit", &c->log_ratelimit),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogFilterPatterns", log_filter_patterns_build_json, c),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("LogNamespace", c->log_namespace),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SyslogIdentifier", c->syslog_identifier),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SyslogFacility", syslog_facility_build_json, INT_TO_PTR(LOG_FAC(c->syslog_priority))),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SyslogLevel", log_level_build_json, INT_TO_PTR(LOG_PRI(c->syslog_priority))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("SyslogLevelPrefix", c->syslog_level_prefix),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("TTYPath", c->tty_path),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(!!c->tty_path, "TTYReset", c->tty_reset),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(!!c->tty_path, "TTYVHangup", c->tty_vhangup),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(!!c->tty_path, "TTYRows", c->tty_rows),
                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(!!c->tty_path, "TTYColumns", c->tty_cols),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(!!c->tty_path, "TTYVTDisallocate", c->tty_vt_disallocate),

                        /* Credentials */
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LoadCredential", load_credential_build_json, c->load_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LoadCredentialEncrypted", load_credential_build_json, c->load_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ImportCredential", import_credential_build_json, c->import_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SetCredential", set_credential_build_json, c->set_credentials),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("SetCredentialEncrypted", set_credential_build_json, c->set_credentials),

                        /* System V Compatibility */
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UtmpIdentifier", c->utmp_id),
                        JSON_BUILD_PAIR_ENUM("UtmpMode", exec_utmp_mode_to_string(c->utmp_mode)));
}

/* Write side of the Exec context for StartTransient. */

typedef struct TransientWorkingDirectory {
        char *path;
        bool home;
        bool missing_ok;
} TransientWorkingDirectory;

typedef struct TransientSetCredential {
        const char *id;
        struct iovec value;
} TransientSetCredential;

struct TransientExecContextParameters {
        bool working_directory_set;
        TransientWorkingDirectory working_directory;
        bool environment_set;
        char **environment;

        bool set_credentials_set;
        TransientSetCredential *set_credentials;
        size_t n_set_credentials;

        bool set_credentials_encrypted_set;
        TransientSetCredential *set_credentials_encrypted;
        size_t n_set_credentials_encrypted;

        const char *user;
        const char *group;
        char **supplementary_groups;
        const char *pam_name;
        /* Absolute-path strings: must validate via path_is_absolute(). */
        const char *ipc_namespace_path;
        const char *network_namespace_path;
        const char *root_directory;
        const char *root_hash_path;
        const char *root_hash_sig_path;
        const char *root_image;
        const char *root_mstack;
        const char *root_verity;
        const char *tty_path;
        const char *user_namespace_path;
        bool nice_set;
        int nice;
        bool oom_score_adjust_set;
        int oom_score_adjust;
        bool umask_set;
        uint32_t umask;
        /* Tristate bools: -1 = absent, 0/1 = no/yes. */
        int dynamic_user;
        int ignore_sigpipe;
        int lock_personality;
        int memory_deny_write_execute;
        int no_new_privileges;
        int remove_ipc;
        int restrict_realtime;
        int restrict_suid_sgid;
        int root_ephemeral;
        /* Enums: parsed via JSON_DISPATCH_ENUM_DEFINE dispatchers, negative = absent. */
        ExecInput std_input;
        ExecOutput std_output;
        ExecOutput std_error;
        /* PrivateNetwork is a tristate bool too, but arrives as a yes/no string: the runtime
         * context emits it via JSON_BUILD_PAIR_YES_NO and the IDL types it as string. */
        int private_network;
        /* Int-backed enums: -1 = absent (seeded like the tristates), parsed values >= 0. */
        ProtectSystem protect_system;
        ProtectHome protect_home;
        PrivateTmp private_tmp;
        PrivateUsers private_users;

        char *bad_field; /* Field path for error propagation. */
};

static ExecOutput exec_output_from_string_harder(const char *s) {
        ExecOutput o;

        /* Like exec_output_from_string(), but also accepts the spelling of the combined types used in the
         * Varlink IDL (and hence in our own JSON output), i.e. with "_" instead of "+", so that what we emit
         * can be fed back to us. */

        o = exec_output_from_string(s);
        if (o >= 0)
                return o;

        if (streq_ptr(s, "kmsg_console"))
                return EXEC_OUTPUT_KMSG_AND_CONSOLE;
        if (streq_ptr(s, "journal_console"))
                return EXEC_OUTPUT_JOURNAL_AND_CONSOLE;

        return _EXEC_OUTPUT_INVALID;
}


static void transient_set_credential_array_free(TransientSetCredential *items, size_t n) {
        FOREACH_ARRAY(item, items, n)
                iovec_done_erase(&item->value);
        free(items);
}

TransientExecContextParameters* transient_exec_context_parameters_free(TransientExecContextParameters *p) {
        if (!p)
                return NULL;

        strv_free(p->environment);
        strv_free(p->supplementary_groups);
        transient_set_credential_array_free(p->set_credentials, p->n_set_credentials);
        transient_set_credential_array_free(p->set_credentials_encrypted, p->n_set_credentials_encrypted);
        free(p->bad_field);
        free(p->working_directory.path);

        return mfree(p);
}

static int dispatch_transient_working_directory(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch[] = {
                { "path",      SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(TransientWorkingDirectory, path),       0 },
                { "home",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(TransientWorkingDirectory, home),       0 },
                { "missingOK", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(TransientWorkingDirectory, missing_ok), 0 },
                {}
        };

        TransientExecContextParameters *p = ASSERT_PTR(userdata);
        TransientWorkingDirectory *wd = &p->working_directory;
        const char *bad_field = NULL;
        int r;

        r = sd_json_dispatch_full(variant, dispatch, /* bad= */ NULL, flags, wd, &bad_field);
        if (r < 0) {
                if (bad_field)
                        varlink_propagate_bad_field(bad_field, /* child_bad_field= */ NULL, &p->bad_field);
                return r;
        }

        if (wd->home && wd->path)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "WorkingDirectory: 'home' and 'path' are mutually exclusive");
        if (!wd->home && !wd->path)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "WorkingDirectory: must specify either 'home' or 'path'");

        /* D-Bus keeps its parsed path NULL for empty input. Use the same reset value, since mount
         * dependency setup treats a non-NULL empty string as a configured path. An empty path with
         * missingOK corresponds to D-Bus "-", which must fail the absolute path check below. */
        if (isempty(wd->path) && !wd->home && !wd->missing_ok) {
                wd->path = mfree(wd->path);
        } else if (!wd->home) {
                if (!path_is_absolute(wd->path)) {
                        varlink_propagate_bad_field("path", /* child_bad_field= */ NULL, &p->bad_field);
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "WorkingDirectory: expects an absolute path");
                }

                path_simplify(wd->path);
                if (!path_is_normalized(wd->path)) {
                        varlink_propagate_bad_field("path", /* child_bad_field= */ NULL, &p->bad_field);
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "WorkingDirectory: expects a normalized path");
                }
        }

        p->working_directory_set = true;
        return 0;
}

static int dispatch_transient_set_credential_array(
                const char *name,
                sd_json_variant *variant,
                sd_json_dispatch_flags_t flags,
                TransientSetCredential **ret_items,
                size_t *ret_n,
                char **reterr_bad_field) {

        static const sd_json_dispatch_field item_dispatch[] = {
                { "id",    SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(TransientSetCredential, id),    SD_JSON_MANDATORY },
                { "value", SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec,  offsetof(TransientSetCredential, value), SD_JSON_MANDATORY },
                {}
        };

        TransientSetCredential *items;
        size_t n_items;
        int r;

        assert(ret_items);
        assert(ret_n);

        n_items = sd_json_variant_elements(variant);
        if (n_items == 0) {
                *ret_items = NULL;
                *ret_n = 0;
                return 0;
        }

        items = new0(TransientSetCredential, n_items);
        if (!items)
                return -ENOMEM;

        CLEANUP_ARRAY(items, n_items, transient_set_credential_array_free);

        for (size_t i = 0; i < n_items; i++) {
                const char *bad_field = NULL;

                r = sd_json_dispatch_full(sd_json_variant_by_index(variant, i), item_dispatch,
                                          /* bad= */ NULL, /* flags= */ 0, &items[i], &bad_field);
                if (r < 0) {
                        if (bad_field)
                                varlink_propagate_bad_field(bad_field, /* child_bad_field= */ NULL, reterr_bad_field);
                        return r;
                }
        }

        *ret_n = n_items;
        *ret_items = TAKE_PTR(items);
        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_exec_output,    ExecOutput,    exec_output_from_string_harder);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_exec_input,     ExecInput,     exec_input_from_string);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_protect_system, ProtectSystem, protect_system_from_string);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_protect_home,   ProtectHome,   protect_home_from_string);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_private_tmp,    PrivateTmp,    private_tmp_from_string);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_private_users,  PrivateUsers,  private_users_from_string);

#define DEFINE_DISPATCH_EXEC_SETTABLE(field, dispatch, ...) \
        DEFINE_VARLINK_DISPATCH_SETTABLE(field, TransientExecContextParameters, dispatch __VA_OPT__(,) __VA_ARGS__)

static DEFINE_DISPATCH_EXEC_SETTABLE(environment,               json_dispatch_strv_environment);
static DEFINE_DISPATCH_EXEC_SETTABLE(nice,                      sd_json_dispatch_int32);
static DEFINE_DISPATCH_EXEC_SETTABLE(oom_score_adjust,          sd_json_dispatch_int32);
static DEFINE_DISPATCH_EXEC_SETTABLE(umask,                     sd_json_dispatch_uint32);
static DEFINE_DISPATCH_EXEC_SETTABLE(set_credentials,           dispatch_transient_set_credential_array, &p->n_set_credentials, &p->bad_field);
static DEFINE_DISPATCH_EXEC_SETTABLE(set_credentials_encrypted, dispatch_transient_set_credential_array, &p->n_set_credentials_encrypted, &p->bad_field);

static int transient_apply_set_credentials(
                Unit *u,
                ExecContext *c,
                const TransientSetCredential *items,
                size_t n_items,
                bool encrypted,
                char **reterr_bad_field) {

        int r;

        assert(u);
        assert(c);

        FOREACH_ARRAY(item, items, n_items) {
                const char *err = NULL;

                r = exec_context_apply_set_credential(u, c, item->id, item->value.iov_base, item->value.iov_len,
                                                     encrypted, UNIT_RUNTIME|UNIT_PRIVATE, &err);
                if (r == -EINVAL) {
                        varlink_propagate_bad_field("id", /* child_bad_field= */ NULL, reterr_bad_field);
                        return log_debug_errno(r, "%s: %s", err, item->id);
                }
                if (r < 0)
                        return r;
        }

        return 0;
}

static int apply_exec_environment(Unit *u, ExecContext *c, TransientExecContextParameters *p) {
        int r;

        assert(p);

        if (!p->environment_set)
                return 0;

        r = exec_context_apply_environment(u, c, p->environment, UNIT_RUNTIME|UNIT_PRIVATE);
        if (IN_SET(r, -E2BIG, -EINVAL))
                /* Convert E2BIG into EINVAL so the caller reports an invalid parameter. */
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       r == -E2BIG ? "Too many environment assignments." : "Invalid Environment list.");
        return r;
}

static int apply_exec_nice(Unit *u, ExecContext *c, TransientExecContextParameters *p) {
        assert(p);

        if (!p->nice_set)
                return 0;

        if (!nice_is_valid(p->nice))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid Nice= value: %i", p->nice);

        c->nice = p->nice;
        c->nice_set = true;

        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "Nice", "Nice=%i", p->nice);
        return 0;
}

static int apply_exec_oom_score_adjust(Unit *u, ExecContext *c, TransientExecContextParameters *p) {
        if (!p->oom_score_adjust_set)
                return 0;

        if (!oom_score_adjust_is_valid(p->oom_score_adjust))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid OOMScoreAdjust= value: %i", p->oom_score_adjust);

        c->oom_score_adjust = p->oom_score_adjust;
        c->oom_score_adjust_set = true;

        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "OOMScoreAdjust",
                            "OOMScoreAdjust=%i", p->oom_score_adjust);
        return 0;
}

#define DEFINE_APPLY_EXEC_SETTABLE(field, apply, ...) \
        DEFINE_VARLINK_APPLY_SETTABLE(field, ExecContext, TransientExecContextParameters, apply __VA_OPT__(,) __VA_ARGS__)

static DEFINE_APPLY_EXEC_SETTABLE(set_credentials, transient_apply_set_credentials,
                                 p->n_set_credentials, /* encrypted= */ false, &p->bad_field);
static DEFINE_APPLY_EXEC_SETTABLE(set_credentials_encrypted, transient_apply_set_credentials,
                                 p->n_set_credentials_encrypted, /* encrypted= */ true, &p->bad_field);

static int apply_exec_supplementary_groups(Unit *u, ExecContext *c, TransientExecContextParameters *p) {
        assert(c);
        assert(p);

        STRV_FOREACH(g, p->supplementary_groups)
                if (!valid_user_group_name(*g, VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid supplementary group name: %s", *g);

        return varlink_apply_strv_escaped(u, "SupplementaryGroups", &c->supplementary_groups,
                                         p->supplementary_groups, UNIT_RUNTIME|UNIT_PRIVATE);
}

static int apply_exec_umask(Unit *u, ExecContext *c, TransientExecContextParameters *p) {
        if (!p->umask_set)
                return 0;

        /* mode_t bits beyond 07777 are reserved/meaningless; reject so a caller passing a stray
         * negative or out-of-range int fails clearly instead of having the kernel silently mask it. */
        if (p->umask > 07777)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid UMask= value: %#" PRIo32, p->umask);

        c->umask = (mode_t) p->umask;

        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE, "UMask", "UMask=%04" PRIo32, p->umask);
        return 0;
}

static int apply_exec_working_directory(Unit *u, ExecContext *c, TransientExecContextParameters *p) {
        assert(p);

        if (!p->working_directory_set)
                return 0;

        /* StartTransient may reuse a unit with a working directory already set by defaults or drop-ins. */
        TransientWorkingDirectory *wd = &p->working_directory;
        free_and_replace(c->working_directory, wd->path);
        c->working_directory_home = wd->home;
        c->working_directory_missing_ok = wd->missing_ok;

        unit_write_settingf(u, UNIT_RUNTIME|UNIT_PRIVATE|UNIT_ESCAPE_SPECIFIERS, "WorkingDirectory",
                            "WorkingDirectory=%s%s",
                            c->working_directory_missing_ok ? "-" : "",
                            c->working_directory_home ? "~" : strempty(c->working_directory));
        return 0;
}

#define DEFINE_APPLY_EXEC(field, JsonName, apply_fn, ...)                                    \
        int apply_exec_##field(Unit *u, ExecContext *c, TransientExecContextParameters *p) { \
                assert(c);                                                                   \
                assert(p);                                                                   \
                                                                                             \
                return (apply_fn)(u, (JsonName), &c->field, p->field,                        \
                                  __VA_ARGS__ __VA_OPT__(,) UNIT_RUNTIME|UNIT_PRIVATE);      \
        }

static DEFINE_APPLY_EXEC(user,                   "User",                 varlink_apply_string_escaped);
static DEFINE_APPLY_EXEC(group,                  "Group",                varlink_apply_string_escaped);
static DEFINE_APPLY_EXEC(pam_name,               "PAMName",              varlink_apply_string_escaped);
static DEFINE_APPLY_EXEC(ipc_namespace_path,     "IPCNamespacePath",     varlink_apply_absolute_path);
static DEFINE_APPLY_EXEC(network_namespace_path, "NetworkNamespacePath", varlink_apply_absolute_path);
static DEFINE_APPLY_EXEC(root_directory,         "RootDirectory",        varlink_apply_absolute_path);
static DEFINE_APPLY_EXEC(root_image,             "RootImage",            varlink_apply_absolute_path);
static DEFINE_APPLY_EXEC(root_mstack,            "RootMStack",           varlink_apply_absolute_path);
static DEFINE_APPLY_EXEC(root_verity,            "RootVerity",           varlink_apply_absolute_path);
static DEFINE_APPLY_EXEC(tty_path,               "TTYPath",              varlink_apply_absolute_path);
static DEFINE_APPLY_EXEC(user_namespace_path,    "UserNamespacePath",    varlink_apply_absolute_path);

static DEFINE_APPLY_EXEC(dynamic_user,              "DynamicUser",            varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(ignore_sigpipe,            "IgnoreSIGPIPE",          varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(lock_personality,          "LockPersonality",        varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(memory_deny_write_execute, "MemoryDenyWriteExecute", varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(no_new_privileges,         "NoNewPrivileges",        varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(private_network,           "PrivateNetwork",         varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(remove_ipc,                "RemoveIPC",              varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(restrict_realtime,         "RestrictRealtime",       varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(restrict_suid_sgid,        "RestrictSUIDSGID",       varlink_apply_tristate_bool);
static DEFINE_APPLY_EXEC(root_ephemeral,            "RootEphemeral",          varlink_apply_tristate_bool);

/* The stdio types that require a companion setting: the file based ones need a path (StandardInputFile=,
 * StandardOutputFile=, …) and StandardInput=data needs the payload (StandardInputData=). The Varlink
 * interface has no way to pass either yet, and without them the executor cannot set them up (it would assert
 * on the missing path, and silently fall back to /dev/null on the missing payload), hence refuse them for
 * now. For the output types exec_output_is_file() expresses the same. */
static bool exec_input_needs_companion(ExecInput i) {
        return IN_SET(i, EXEC_INPUT_FILE, EXEC_INPUT_DATA);
}

static DEFINE_VARLINK_APPLY_ENUM(exec_input,     ExecInput,     exec_input_to_string);
static DEFINE_VARLINK_APPLY_ENUM(exec_output,    ExecOutput,    exec_output_to_string);
static DEFINE_VARLINK_APPLY_ENUM(protect_system, ProtectSystem, protect_system_to_string);
static DEFINE_VARLINK_APPLY_ENUM(protect_home,   ProtectHome,   protect_home_to_string);
static DEFINE_VARLINK_APPLY_ENUM(private_tmp,    PrivateTmp,    private_tmp_to_string);
static DEFINE_VARLINK_APPLY_ENUM(private_users,  PrivateUsers,  private_users_to_string);

/* Refusal callbacks reject otherwise valid enum values that Varlink cannot configure yet. */
static DEFINE_APPLY_EXEC(std_error,      "StandardError",  varlink_apply_enum_exec_output,    exec_output_is_file);
static DEFINE_APPLY_EXEC(std_input,      "StandardInput",  varlink_apply_enum_exec_input,     exec_input_needs_companion);
static DEFINE_APPLY_EXEC(std_output,     "StandardOutput", varlink_apply_enum_exec_output,    exec_output_is_file);
static DEFINE_APPLY_EXEC(protect_system, "ProtectSystem",  varlink_apply_enum_protect_system, /* refuse= */ NULL);
static DEFINE_APPLY_EXEC(protect_home,   "ProtectHome",    varlink_apply_enum_protect_home,   /* refuse= */ NULL);
static DEFINE_APPLY_EXEC(private_tmp,    "PrivateTmp",     varlink_apply_enum_private_tmp,    /* refuse= */ NULL);
static DEFINE_APPLY_EXEC(private_users,  "PrivateUsers",   varlink_apply_enum_private_users,  /* refuse= */ NULL);

/* RootHashPath and RootHashSignaturePath need custom apply fns: the corresponding unit-file
 * directive is "RootHash="/"RootHashSignature=" (not the JSON name), and setting the path form
 * must clear the byte-buffer (iovec) form to match the D-Bus semantics. */
static int apply_exec_root_hash_path(Unit *u, ExecContext *c, TransientExecContextParameters *p) {
        int r;

        assert(c);
        assert(p);

        r = varlink_apply_absolute_path(u, "RootHash", &c->root_hash_path, p->root_hash_path,
                                       UNIT_RUNTIME|UNIT_PRIVATE);
        if (r > 0)
                iovec_done(&c->root_hash);
        return r;
}

static int apply_exec_root_hash_sig_path(Unit *u, ExecContext *c, TransientExecContextParameters *p) {
        int r;

        assert(c);
        assert(p);

        r = varlink_apply_absolute_path(u, "RootHashSignature", &c->root_hash_sig_path, p->root_hash_sig_path,
                                       UNIT_RUNTIME|UNIT_PRIVATE);
        if (r > 0)
                iovec_done(&c->root_hash_sig);
        return r;
}

/* Per-property descriptor for fields of the Exec context.
 *
 *   json_name     - JSON key inside the Exec object (e.g. "Nice").
 *   json_type     - Expected JSON type for sd_json_dispatch_full().
 *   dispatch      - Parses the JSON value into TransientExecContextParameters.
 *   parse_offset  - offsetof() into TransientExecContextParameters; 0 if dispatch writes via &p directly.
 *   json_flags    - Per-field flags forwarded to sd_json_dispatch_full().
 *   apply         - Writes the parsed value to ExecContext. Returns 0 on success (whether or not
 *                   the property was set), <0 on error. EINVAL error field paths are prefixed with json_name.
 *   tristate      - If true, the int at parse_offset is initialized to -1 (absent sentinel) by
 *                   transient_exec_context_parameters_init(). Used for tristate bools and enum
 *                   fields (both treat negative as absent). Defaults to false.
 */
typedef struct TransientExecProperty {
        const char *json_name;
        sd_json_variant_type_t json_type;
        sd_json_dispatch_callback_t dispatch;
        size_t parse_offset;
        sd_json_dispatch_flags_t json_flags;
        int (*apply)(Unit *u, ExecContext *c, TransientExecContextParameters *p);
        bool tristate;
} TransientExecProperty;

/* Property descriptors for the Exec object. Ordered to match src/shared/varlink-io.systemd.Unit.c so related
 * fields (e.g. User/Group) stay close. JSON keys match the D-Bus property names. */
#define EXEC_PROPERTY_FULL(json, type, dispatch_fn, parse_offset, json_flags, apply_fn) \
        { json, type, dispatch_fn, parse_offset, json_flags, apply_fn }

#define EXEC_PROPERTY(json, field, type) \
        EXEC_PROPERTY_FULL(json, type, dispatch_transient_##field, 0, 0, apply_exec_##field)

/* Tristate-bool property: parsed via sd_json_dispatch_tristate into an int (-1 = absent).
 * Sets .tristate=true so transient_exec_context_parameters_init() seeds the int to -1 before
 * dispatch. */
#define EXEC_PROPERTY_TRISTATE_BOOL(json, field)                                          \
        { json, SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,                       \
          offsetof(TransientExecContextParameters, field), 0, apply_exec_##field, true }

/* String property: dispatched into a const char* field and applied via the matching
 * DEFINE_APPLY_EXEC() function. */
#define EXEC_PROPERTY_STRING(json, field)                                                  \
        { json, SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,                     \
          offsetof(TransientExecContextParameters, field), 0, apply_exec_##field }

#define EXEC_PROPERTY_FILENAME(json, field)                                                \
        { json, SD_JSON_VARIANT_STRING, json_dispatch_const_filename,                     \
          offsetof(TransientExecContextParameters, field), 0, apply_exec_##field }

#define EXEC_PROPERTY_USER_GROUP(json, field)                                              \
        { json, SD_JSON_VARIANT_STRING, json_dispatch_const_user_group_name,               \
          offsetof(TransientExecContextParameters, field), SD_JSON_RELAX, apply_exec_##field }

/* Preserve [] so apply can distinguish an explicit reset from an absent setting. */
#define EXEC_PROPERTY_STRV(json, field)                                                 \
        { json, SD_JSON_VARIANT_ARRAY, varlink_dispatch_strv_preserve_empty,            \
          offsetof(TransientExecContextParameters, field), SD_JSON_NULLABLE, apply_exec_##field }

/* Settable dispatchers update both the value and its _set flag in the parameter structure. */
#define EXEC_PROPERTY_SETTABLE_FULL(json, type, dispatch_fn, apply_fn)                  \
        { json, type, dispatch_fn, 0, SD_JSON_NULLABLE, apply_fn }

#define EXEC_PROPERTY_SETTABLE(json, field, type) \
        EXEC_PROPERTY_SETTABLE_FULL(json, type, varlink_dispatch_settable_##field, apply_exec_##field)

#define EXEC_PROPERTY_SETTABLE_APPLY(json, field, type) \
        EXEC_PROPERTY_SETTABLE_FULL(json, type, varlink_dispatch_settable_##field, varlink_apply_settable_##field)

/* Enum property: parsed via a JSON_DISPATCH_ENUM_DEFINE dispatcher directly into the enum field at
 * parse_offset. Sets .tristate=true so the field is seeded to -1 (= absent) before dispatch; the
 * matching apply function treats any negative value as unset. */
#define EXEC_PROPERTY_ENUM(json, field, dispatch_fn)                                       \
        { json, SD_JSON_VARIANT_STRING, dispatch_fn,                                       \
          offsetof(TransientExecContextParameters, field), 0, apply_exec_##field, true }

/* Yes/no-string property: a tristate bool whose IDL type is string, see json_dispatch_yes_no_string(). */
#define EXEC_PROPERTY_YES_NO_STRING(json, field)                                          \
        { json, SD_JSON_VARIANT_STRING, json_dispatch_yes_no_string,                      \
          offsetof(TransientExecContextParameters, field), 0, apply_exec_##field, true }

static const TransientExecProperty exec_properties[] = {
        EXEC_PROPERTY              ("WorkingDirectory",       working_directory,         SD_JSON_VARIANT_OBJECT),
        EXEC_PROPERTY_STRING       ("RootDirectory",          root_directory),
        EXEC_PROPERTY_STRING       ("RootImage",              root_image),
        EXEC_PROPERTY_STRING       ("RootMStack",             root_mstack),
        EXEC_PROPERTY_TRISTATE_BOOL("RootEphemeral",          root_ephemeral),
        EXEC_PROPERTY_STRING       ("RootHashPath",           root_hash_path),
        EXEC_PROPERTY_STRING       ("RootHashSignaturePath",  root_hash_sig_path),
        EXEC_PROPERTY_STRING       ("RootVerity",             root_verity),
        EXEC_PROPERTY_USER_GROUP   ("User",                   user),
        EXEC_PROPERTY_USER_GROUP   ("Group",                  group),
        EXEC_PROPERTY_TRISTATE_BOOL("DynamicUser",            dynamic_user),
        EXEC_PROPERTY_STRV         ("SupplementaryGroups",    supplementary_groups),
        EXEC_PROPERTY_FILENAME     ("PAMName",                pam_name),
        EXEC_PROPERTY_TRISTATE_BOOL("NoNewPrivileges",        no_new_privileges),
        EXEC_PROPERTY_SETTABLE     ("UMask",                  umask,                     SD_JSON_VARIANT_INTEGER),
        EXEC_PROPERTY_SETTABLE     ("OOMScoreAdjust",         oom_score_adjust,          SD_JSON_VARIANT_INTEGER),
        EXEC_PROPERTY_TRISTATE_BOOL("IgnoreSIGPIPE",          ignore_sigpipe),
        EXEC_PROPERTY_SETTABLE     ("Nice",                   nice,                      SD_JSON_VARIANT_INTEGER),
        EXEC_PROPERTY_ENUM         ("ProtectSystem",          protect_system, dispatch_protect_system),
        EXEC_PROPERTY_ENUM         ("ProtectHome",            protect_home,   dispatch_protect_home),
        EXEC_PROPERTY_ENUM         ("PrivateTmp",             private_tmp,    dispatch_private_tmp),
        EXEC_PROPERTY_YES_NO_STRING("PrivateNetwork",         private_network),
        EXEC_PROPERTY_STRING       ("NetworkNamespacePath",   network_namespace_path),
        EXEC_PROPERTY_STRING       ("IPCNamespacePath",       ipc_namespace_path),
        EXEC_PROPERTY_ENUM         ("PrivateUsers",           private_users,  dispatch_private_users),
        EXEC_PROPERTY_STRING       ("UserNamespacePath",      user_namespace_path),
        EXEC_PROPERTY_TRISTATE_BOOL("LockPersonality",        lock_personality),
        EXEC_PROPERTY_TRISTATE_BOOL("MemoryDenyWriteExecute", memory_deny_write_execute),
        EXEC_PROPERTY_TRISTATE_BOOL("RestrictRealtime",       restrict_realtime),
        EXEC_PROPERTY_TRISTATE_BOOL("RestrictSUIDSGID",       restrict_suid_sgid),
        EXEC_PROPERTY_TRISTATE_BOOL("RemoveIPC",              remove_ipc),
        EXEC_PROPERTY_SETTABLE     ("Environment",            environment,               SD_JSON_VARIANT_ARRAY),
        EXEC_PROPERTY_ENUM         ("StandardInput",          std_input,  dispatch_exec_input),
        EXEC_PROPERTY_ENUM         ("StandardOutput",         std_output, dispatch_exec_output),
        EXEC_PROPERTY_ENUM         ("StandardError",          std_error,  dispatch_exec_output),
        EXEC_PROPERTY_STRING       ("TTYPath",                tty_path),
        EXEC_PROPERTY_SETTABLE_APPLY("SetCredential",          set_credentials,           SD_JSON_VARIANT_ARRAY),
        EXEC_PROPERTY_SETTABLE_APPLY("SetCredentialEncrypted", set_credentials_encrypted, SD_JSON_VARIANT_ARRAY),
};
#undef EXEC_PROPERTY_FULL
#undef EXEC_PROPERTY
#undef EXEC_PROPERTY_TRISTATE_BOOL
#undef EXEC_PROPERTY_STRING
#undef EXEC_PROPERTY_FILENAME
#undef EXEC_PROPERTY_USER_GROUP
#undef EXEC_PROPERTY_STRV
#undef EXEC_PROPERTY_SETTABLE_FULL
#undef EXEC_PROPERTY_SETTABLE
#undef EXEC_PROPERTY_SETTABLE_APPLY
#undef EXEC_PROPERTY_ENUM
#undef EXEC_PROPERTY_YES_NO_STRING

/* Tristate-bool and enum fields default to -1 (= absent). Default-zeroed slots would look
 * "explicitly set" to the apply path. Initialize all tristate fields here so adding a new such property only
 * requires a new exec_properties[] row, never a fresh designated initializer at the call site.
 * The .tristate descriptor flag drives the loop -- mirrors the .cleanup hook used on the Service
 * side, and avoids fragile dispatch-function-pointer equality checks. */
static void transient_exec_context_parameters_init(TransientExecContextParameters *p) {
        assert(p);

        /* The enum fields are seeded through an int pointer below, hence make sure they really are that
         * wide (their dispatchers write them through their own type) */
        assert_cc(sizeof(ExecInput) == sizeof(int));
        assert_cc(sizeof(ExecOutput) == sizeof(int));
        assert_cc(sizeof(ProtectSystem) == sizeof(int));
        assert_cc(sizeof(ProtectHome) == sizeof(int));
        assert_cc(sizeof(PrivateTmp) == sizeof(int));
        assert_cc(sizeof(PrivateUsers) == sizeof(int));

        FOREACH_ELEMENT(prop, exec_properties)
                if (prop->tristate)
                        *(int*) ((uint8_t*) p + prop->parse_offset) = -1;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(TransientExecContextParameters*, transient_exec_context_parameters_free);

int transient_exec_context_dispatch(
                sd_json_variant *variant,
                TransientExecContextParameters **ret,
                char **reterr_bad_field) {

        /* Build dispatch table only once, its constant. */
        static sd_json_dispatch_field exec_dispatch[ELEMENTSOF(exec_properties) + 1] = {};
        static bool exec_dispatch_set = false;

        const char *bad_field = NULL;
        int r;

        assert(ret);

        if (!exec_dispatch_set) {
                FOREACH_ELEMENT(prop, exec_properties)
                        exec_dispatch[prop - exec_properties] = (sd_json_dispatch_field) {
                                .name = prop->json_name,
                                .type = prop->json_type,
                                .callback = prop->dispatch,
                                .offset = prop->parse_offset,
                                .flags = prop->json_flags,
                        };
                exec_dispatch_set = true;
        }

        _cleanup_(transient_exec_context_parameters_freep) TransientExecContextParameters *p = NULL;
        p = new0(TransientExecContextParameters, 1);
        if (!p)
                return -ENOMEM;

        transient_exec_context_parameters_init(p);

        r = sd_json_dispatch_full(variant, exec_dispatch, /* bad= */ NULL, /* flags= */ 0, p, &bad_field);
        if (r < 0) {
                if (bad_field)
                        varlink_propagate_bad_field(bad_field, p->bad_field, reterr_bad_field);
                return r;
        }

        *ret = TAKE_PTR(p);
        return r;
}

int transient_exec_context_apply_properties(Unit *u, ExecContext *c, TransientExecContextParameters *p, char **reterr_bad_field) {
        int r;

        assert(u);
        assert(c);
        assert(p);

        FOREACH_ELEMENT(prop, exec_properties) {
                r = prop->apply(u, c, p);
                if (r == -EINVAL)
                        return varlink_propagate_bad_field_errno(r, prop->json_name, p->bad_field, reterr_bad_field);
                if (r < 0)
                        return r;
        }

        return 0;
}
