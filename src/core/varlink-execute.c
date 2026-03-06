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
#include "json-util.h"
#include "manager.h"
#include "mountpoint-util.h"
#include "namespace.h"
#include "nsflags.h"
#include "ordered-set.h"
#include "process-util.h"
#include "securebits-util.h"
#include "set.h"
#include "strv.h"
#include "syslog-util.h"
#include "unit.h"
#include "varlink-common.h"
#include "varlink-execute.h"

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

        return sd_json_variant_new_string(ret, s);
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

        return sd_json_variant_new_string(ret, mpol_to_string(t));
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

        return sd_json_variant_new_string(ret, s);
}

static int exec_dir_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ExecDirectory *exec_dir = ASSERT_PTR(userdata);
        const QuotaLimit *quota = &exec_dir->exec_quota;
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

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ASSERT_PTR(ret), v);
}

static int private_bpf_delegate_maps_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *v = bpf_delegate_maps_to_string(c->bpf_delegate_maps);

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ASSERT_PTR(ret), v);
}

static int private_bpf_delegate_programs_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *v = bpf_delegate_programs_to_string(c->bpf_delegate_programs);

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ASSERT_PTR(ret), v);
}

static int private_bpf_delegate_attachments_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        ExecContext *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *v = bpf_delegate_attachments_to_string(c->bpf_delegate_attachments);

        if (!v) {
                *ret = NULL;
                return 0;
        }

        return sd_json_variant_new_string(ASSERT_PTR(ret), v);
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
                        SD_JSON_BUILD_PAIR_STRING("ProtectProc", protect_proc_to_string(c->protect_proc)),
                        SD_JSON_BUILD_PAIR_STRING("ProcSubset", proc_subset_to_string(c->proc_subset)),
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
                        SD_JSON_BUILD_PAIR_STRING("KeyringMode", exec_keyring_mode_to_string(c->keyring_mode)),
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
                        SD_JSON_BUILD_PAIR_STRING("MemoryTHP", memory_thp_to_string(c->memory_thp)),

                        /* Sandboxing */
                        SD_JSON_BUILD_PAIR_STRING("ProtectSystem", protect_system_to_string(c->protect_system)),
                        SD_JSON_BUILD_PAIR_STRING("ProtectHome", protect_home_to_string(c->protect_home)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RuntimeDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_RUNTIME]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("StateDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_STATE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("CacheDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CACHE]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("LogsDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_LOGS]),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ConfigurationDirectory", exec_dir_build_json, &c->directories[EXEC_DIRECTORY_CONFIGURATION]),
                        SD_JSON_BUILD_PAIR_STRING("RuntimeDirectoryPreserve", exec_preserve_mode_to_string(c->runtime_directory_preserve_mode)),
                        JSON_BUILD_PAIR_FINITE_USEC("TimeoutCleanUSec", c->timeout_clean_usec),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ReadWritePaths", c->read_write_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ReadOnlyPaths", c->read_only_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("InaccessiblePaths", c->inaccessible_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("ExecPaths", c->exec_paths),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("NoExecPaths", c->no_exec_paths),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("TemporaryFileSystem", temporary_filesystems_build_json, c),
                        /* XXX should we make all these Private/Protect strings??? */
                        SD_JSON_BUILD_PAIR_STRING("PrivateTmp", private_tmp_to_string(c->private_tmp)),
                        JSON_BUILD_PAIR_YES_NO("PrivateDevices", c->private_devices),
                        JSON_BUILD_PAIR_YES_NO("PrivateNetwork", c->private_network),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("NetworkNamespacePath", c->network_namespace_path),
                        JSON_BUILD_PAIR_YES_NO("PrivateIPC", c->private_ipc),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("IPCNamespacePath", c->ipc_namespace_path),
                        SD_JSON_BUILD_PAIR_STRING("PrivatePIDs", private_pids_to_string(c->private_pids)),
                        SD_JSON_BUILD_PAIR_STRING("PrivateUsers", private_users_to_string(c->private_users)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("UserNamespacePath", c->user_namespace_path),
                        SD_JSON_BUILD_PAIR_STRING("ProtectHostname", protect_hostname_to_string(c->protect_hostname)),
                        JSON_BUILD_PAIR_YES_NO("ProtectClock", c->protect_clock),
                        JSON_BUILD_PAIR_YES_NO("ProtectKernelTunables", c->protect_kernel_tunables),
                        JSON_BUILD_PAIR_YES_NO("ProtectKernelModules", c->protect_kernel_modules),
                        JSON_BUILD_PAIR_YES_NO("ProtectKernelLogs", c->protect_kernel_logs),
                        SD_JSON_BUILD_PAIR_STRING("ProtectControlGroups", protect_control_groups_to_string(c->protect_control_groups)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictAddressFamilies", address_families_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictFileSystems", restrict_filesystems_build_json, c),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("RestrictNamespaces", namespace_flags_build_json, ULONG_TO_PTR(c->restrict_namespaces)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("DelegateNamespaces", namespace_flags_build_json, ULONG_TO_PTR(c->delegate_namespaces)),
                        SD_JSON_BUILD_PAIR_STRING("PrivatePBF", private_bpf_to_string(c->private_bpf)),
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
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("MountFlags", mount_propagation_flag_to_string(c->mount_propagation_flag)),

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
                        SD_JSON_BUILD_PAIR_STRING("StandardInput", exec_input_to_string(c->std_input)),
                        SD_JSON_BUILD_PAIR_STRING("StandardOutput", exec_output_to_string(c->std_output)),
                        SD_JSON_BUILD_PAIR_STRING("StandardError", exec_output_to_string(c->std_error)),
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
                        SD_JSON_BUILD_PAIR_STRING("UtmpMode", exec_utmp_mode_to_string(c->utmp_mode)));
}
