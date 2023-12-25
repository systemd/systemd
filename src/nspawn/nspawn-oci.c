/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/oom.h>

#include "bus-util.h"
#include "cap-list.h"
#include "cpu-set-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "env-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "json.h"
#include "missing_sched.h"
#include "nspawn-oci.h"
#include "path-util.h"
#include "rlimit-util.h"
#include "seccomp-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

/* TODO:
 * OCI runtime tool implementation
 * hooks
 *
 * Spec issues:
 *
 * How is RLIM_INFINITY supposed to be encoded?
 * configured effective caps is bullshit, as execv() corrupts it anyway
 * pipes bind mounted is *very* different from pipes newly created, comments regarding bind mount or not are bogus
 * annotation values structured? or string?
 * configurable file system namespace path, but then also root path? wtf?
 * apply sysctl inside of the container? or outside?
 * how is unlimited pids tasks limit to be encoded?
 * what are the defaults for caps if not specified?
 * what are the default uid/gid mappings if one is missing but the other set, or when user ns is on but no namespace configured
 * the source field of "mounts" is really weird, as it cannot realistically be relative to the bundle, since we never know if that's what the fs wants
 * spec contradicts itself on the mount "type" field, as the example uses "bind" as type, but it's not listed in /proc/filesystem, and is something made up by /bin/mount
 * if type of mount is left out, what shall be assumed? "bind"?
 * readonly mounts is entirely redundant?
 * should escaping be applied when joining mount options with ","?
 * devices cgroup support is bogus, "allow" and "deny" on the kernel level is about adding/removing entries, not about access
 * spec needs to say that "rwm" devices cgroup combination can't be the empty string
 * cgrouspv1 crap: kernel, kernelTCP, swappiness, disableOOMKiller, swap, devices, leafWeight
 * general: it shouldn't leak lower level abstractions this obviously
 * unmanagable cgroups stuff: realtimeRuntime/realtimePeriod
 * needs to say what happense when some option is not specified, i.e. which defaults apply
 * no architecture? no personality?
 * seccomp example and logic is simply broken: there's no constant "SCMP_ACT_ERRNO".
 * spec should say what to do with unknown props
 * /bin/mount regarding NFS and FUSE required?
 * what does terminal=false mean?
 * sysctl inside or outside? allow-listing?
 * swapiness typo -> swappiness
 *
 * Unsupported:
 *
 * apparmorProfile
 * selinuxLabel + mountLabel
 * hugepageLimits
 * network
 * rdma
 * intelRdt
 * swappiness, disableOOMKiller, kernel, kernelTCP, leafWeight (because it's dead, cgroupsv2 can't do it and hence systemd neither)
 *
 * Non-slice cgroup paths
 * Propagation that is not slave + shared
 * more than one uid/gid mapping, mappings with a container base != 0, or non-matching uid/gid mappings
 * device cgroups access = false items that are not catchall
 * device cgroups matches where minor is specified, but major isn't. similar where major is specified but char/block is not. also, any match that only has a type set that has less than "rwm" set. also, any entry that has none of rwm set.
 *
 */

static int oci_unexpected(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                        "Unexpected OCI element '%s' of type '%s'.", name, json_variant_type_to_string(json_variant_type(v)));
}

static int oci_dispatch(JsonVariant *v, const JsonDispatch table[], JsonDispatchFlags flags, void *userdata) {
        return json_dispatch_full(v, table, oci_unexpected, flags, userdata, /* reterr_bad_field= */ NULL);
}

static int oci_unsupported(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                        "Unsupported OCI element '%s' of type '%s'.", name, json_variant_type_to_string(json_variant_type(v)));
}

static int oci_terminal(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);

        /* If not specified, or set to true, we'll default to either an interactive or a read-only
         * console. If specified as false, we'll forcibly move to "pipe" mode though. */
        s->console_mode = json_variant_boolean(v) ? _CONSOLE_MODE_INVALID : CONSOLE_PIPE;
        return 0;
}

static int oci_console_dimension(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        unsigned *u = ASSERT_PTR(userdata);
        uint64_t k;

        k = json_variant_unsigned(variant);
        if (k == 0)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE),
                                "Console size field '%s' is too small.", strna(name));
        if (k > USHRT_MAX) /* TIOCSWINSZ's struct winsize uses "unsigned short" for width and height */
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE),
                                "Console size field '%s' is too large.", strna(name));

        *u = (unsigned) k;
        return 0;
}

static int oci_console_size(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);

        static const JsonDispatch table[] = {
                { "height", JSON_VARIANT_UNSIGNED, oci_console_dimension, offsetof(Settings, console_height), JSON_MANDATORY },
                { "width",  JSON_VARIANT_UNSIGNED, oci_console_dimension, offsetof(Settings, console_width),  JSON_MANDATORY },
                {}
        };

        return oci_dispatch(v, table, flags, s);
}

static int oci_absolute_path(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        char **p = ASSERT_PTR(userdata);
        const char *n;

        n = json_variant_string(v);

        if (!path_is_absolute(n))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Path in JSON field '%s' is not absolute: %s", strna(name), n);

        return free_and_strdup_warn(p, n);
}

static int oci_env(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        char ***l = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                const char *n;

                if (!json_variant_is_string(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Environment array contains non-string.");

                assert_se(n = json_variant_string(e));

                if (!env_assignment_is_valid(n))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Environment assignment not valid: %s", n);

                r = strv_extend(l, n);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int oci_args(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        char ***value = ASSERT_PTR(userdata);
        int r;

        r = json_variant_strv(v, &l);
        if (r < 0)
                return json_log(v, flags, r, "Cannot parse arguments as list of strings: %m");

        if (strv_isempty(l))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Argument list empty, refusing.");

        if (isempty(l[0]))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Executable name is empty, refusing.");

        return strv_free_and_replace(*value, l);
}

static int oci_rlimit_type(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        const char *z;
        int *type = ASSERT_PTR(userdata);
        int t;

        z = startswith(json_variant_string(v), "RLIMIT_");
        if (!z)
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "rlimit entry's name does not begin with 'RLIMIT_', refusing: %s",
                                json_variant_string(v));

        t = rlimit_from_string(z);
        if (t < 0)
                return json_log(v, flags, t,
                                "rlimit name unknown: %s", json_variant_string(v));

        *type = t;
        return 0;
}

static int oci_rlimit_value(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        rlim_t *value = ASSERT_PTR(userdata);
        rlim_t z;

        if (json_variant_is_negative(v))
                z = RLIM_INFINITY;
        else {
                if (!json_variant_is_unsigned(v))
                        return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                        "rlimits limit not unsigned, refusing.");

                z = (rlim_t) json_variant_unsigned(v);

                if ((uint64_t) z != json_variant_unsigned(v))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "rlimits limit out of range, refusing.");
        }

        *value = z;
        return 0;
}

static int oci_rlimits(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {

                struct rlimit_data {
                        int type;
                        rlim_t soft;
                        rlim_t hard;
                } data = {
                        .type = -1,
                        .soft = RLIM_INFINITY,
                        .hard = RLIM_INFINITY,
                };

                static const JsonDispatch table[] = {
                        { "soft", JSON_VARIANT_NUMBER, oci_rlimit_value, offsetof(struct rlimit_data, soft), JSON_MANDATORY },
                        { "hard", JSON_VARIANT_NUMBER, oci_rlimit_value, offsetof(struct rlimit_data, hard), JSON_MANDATORY },
                        { "type", JSON_VARIANT_STRING, oci_rlimit_type,  offsetof(struct rlimit_data, type), JSON_MANDATORY },
                        {}
                };

                r = oci_dispatch(e, table, flags, &data);
                if (r < 0)
                        return r;

                assert(data.type >= 0);
                assert(data.type < _RLIMIT_MAX);

                if (s->rlimit[data.type])
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "rlimits array contains duplicate entry, refusing.");

                s->rlimit[data.type] = new(struct rlimit, 1);
                if (!s->rlimit[data.type])
                        return log_oom();

                *s->rlimit[data.type] = (struct rlimit) {
                        .rlim_cur = data.soft,
                        .rlim_max = data.hard,
                };

        }
        return 0;
}

static int oci_capability_array(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        uint64_t *mask = ASSERT_PTR(userdata);
        uint64_t m = 0;
        JsonVariant *e;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                const char *n;
                int cap;

                if (!json_variant_is_string(e))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Entry in capabilities array is not a string.");

                assert_se(n = json_variant_string(e));

                cap = capability_from_name(n);
                if (cap < 0)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Unknown capability: %s", n);

                m |= UINT64_C(1) << cap;
        }

        if (*mask == UINT64_MAX)
                *mask = m;
        else
                *mask |= m;

        return 0;
}

static int oci_capabilities(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "effective",   JSON_VARIANT_ARRAY, oci_capability_array, offsetof(CapabilityQuintet, effective)   },
                { "bounding",    JSON_VARIANT_ARRAY, oci_capability_array, offsetof(CapabilityQuintet, bounding)    },
                { "inheritable", JSON_VARIANT_ARRAY, oci_capability_array, offsetof(CapabilityQuintet, inheritable) },
                { "permitted",   JSON_VARIANT_ARRAY, oci_capability_array, offsetof(CapabilityQuintet, permitted)   },
                { "ambient",     JSON_VARIANT_ARRAY, oci_capability_array, offsetof(CapabilityQuintet, ambient)     },
                {}
        };

        Settings *s = ASSERT_PTR(userdata);
        int r;

        r = oci_dispatch(v, table, flags, &s->full_capabilities);
        if (r < 0)
                return r;

        if (s->full_capabilities.bounding != UINT64_MAX) {
                s->capability = s->full_capabilities.bounding;
                s->drop_capability = ~s->full_capabilities.bounding;
        }

        return 0;
}

static int oci_oom_score_adj(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        int64_t k;

        k = json_variant_integer(v);
        if (k < OOM_SCORE_ADJ_MIN || k > OOM_SCORE_ADJ_MAX)
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "oomScoreAdj value out of range: %" PRIi64, k);

        s->oom_score_adjust = (int) k;
        s->oom_score_adjust_set = true;

        return 0;
}

static int oci_uid_gid(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        uid_t *uid = ASSERT_PTR(userdata);
        uid_t u;
        uint64_t k;

        assert_cc(sizeof(uid_t) == sizeof(gid_t));

        k = json_variant_unsigned(v);
        u = (uid_t) k;
        if ((uint64_t) u != k)
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "UID/GID out of range: %" PRIu64, k);

        if (!uid_is_valid(u))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "UID/GID is not valid: " UID_FMT, u);

        *uid = u;
        return 0;
}

static int oci_supplementary_gids(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                gid_t gid, *a;

                if (!json_variant_is_unsigned(e))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Supplementary GID entry is not a UID.");

                r = oci_uid_gid(name, e, flags, &gid);
                if (r < 0)
                        return r;

                a = reallocarray(s->supplementary_gids, s->n_supplementary_gids + 1, sizeof(gid_t));
                if (!a)
                        return log_oom();

                s->supplementary_gids = a;
                s->supplementary_gids[s->n_supplementary_gids++] = gid;
        }

        return 0;
}

static int oci_user(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "uid",            JSON_VARIANT_UNSIGNED, oci_uid_gid,            offsetof(Settings, uid), JSON_MANDATORY },
                { "gid",            JSON_VARIANT_UNSIGNED, oci_uid_gid,            offsetof(Settings, gid), JSON_MANDATORY },
                { "additionalGids", JSON_VARIANT_ARRAY,    oci_supplementary_gids, 0,                       0              },
                {}
        };

        return oci_dispatch(v, table, flags, userdata);
}

static int oci_process(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "terminal",        JSON_VARIANT_BOOLEAN, oci_terminal,          0,                                     0               },
                { "consoleSize",     JSON_VARIANT_OBJECT,  oci_console_size,      0,                                     0               },
                { "cwd",             JSON_VARIANT_STRING,  oci_absolute_path,     offsetof(Settings, working_directory), 0               },
                { "env",             JSON_VARIANT_ARRAY,   oci_env,               offsetof(Settings, environment),       0               },
                { "args",            JSON_VARIANT_ARRAY,   oci_args,              offsetof(Settings, parameters),        0               },
                { "rlimits",         JSON_VARIANT_ARRAY,   oci_rlimits,           0,                                     0               },
                { "apparmorProfile", JSON_VARIANT_STRING,  oci_unsupported,       0,                                     JSON_PERMISSIVE },
                { "capabilities",    JSON_VARIANT_OBJECT,  oci_capabilities,      0,                                     0               },
                { "noNewPrivileges", JSON_VARIANT_BOOLEAN, json_dispatch_boolean, offsetof(Settings, no_new_privileges), 0               },
                { "oomScoreAdj",     JSON_VARIANT_INTEGER, oci_oom_score_adj,     0,                                     0               },
                { "selinuxLabel",    JSON_VARIANT_STRING,  oci_unsupported,       0,                                     JSON_PERMISSIVE },
                { "user",            JSON_VARIANT_OBJECT,  oci_user,              0,                                     0               },
                {}
        };

        return oci_dispatch(v, table, flags, userdata);
}

static int oci_root(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        int r;

        static const JsonDispatch table[] = {
                { "path",     JSON_VARIANT_STRING,  json_dispatch_string,  offsetof(Settings, root)      },
                { "readonly", JSON_VARIANT_BOOLEAN, json_dispatch_boolean, offsetof(Settings, read_only) },
                {}
        };

        r = oci_dispatch(v, table, flags, s);
        if (r < 0)
                return r;

        if (s->root && !path_is_absolute(s->root)) {
                char *joined;

                joined = path_join(s->bundle, s->root);
                if (!joined)
                        return log_oom();

                free_and_replace(s->root, joined);
        }

        return 0;
}

static int oci_hostname(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        const char *n;

        assert_se(n = json_variant_string(v));

        if (!hostname_is_valid(n, 0))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Hostname string is not a valid hostname: %s", n);

        return free_and_strdup_warn(&s->hostname, n);
}

static bool oci_exclude_mount(const char *path) {

        /* Returns "true" for all mounts we insist to mount on our own, and hence ignore the OCI data. */

        if (PATH_IN_SET(path,
                        "/dev",
                        "/dev/mqueue",
                        "/dev/pts",
                        "/dev/shm",
                        "/proc",
                        "/proc/acpi",
                        "/proc/apm",
                        "/proc/asound",
                        "/proc/bus",
                        "/proc/fs",
                        "/proc/irq",
                        "/proc/kallsyms",
                        "/proc/kcore",
                        "/proc/keys",
                        "/proc/scsi",
                        "/proc/sys",
                        "/proc/sys/net",
                        "/proc/sysrq-trigger",
                        "/proc/timer_list",
                        "/run",
                        "/sys",
                        "/sys",
                        "/sys/fs/selinux",
                        "/tmp"))
                return true;

        /* Similar, skip the whole /sys/fs/cgroups subtree */
        if (path_startswith(path, "/sys/fs/cgroup"))
                return true;

        return false;
}

typedef struct oci_mount_data {
        char *destination;
        char *source;
        char *type;
        char **options;
} oci_mount_data;

static void oci_mount_data_done(oci_mount_data *data) {
        assert(data);

        free(data->destination);
        free(data->source);
        free(data->type);
        strv_free(data->options);
}

static int oci_mounts(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                static const JsonDispatch table[] = {
                        { "destination", JSON_VARIANT_STRING, oci_absolute_path,    offsetof(oci_mount_data, destination), JSON_MANDATORY },
                        { "source",      JSON_VARIANT_STRING, json_dispatch_string, offsetof(oci_mount_data, source),      0              },
                        { "options",     JSON_VARIANT_ARRAY,  json_dispatch_strv,   offsetof(oci_mount_data, options),     0,             },
                        { "type",        JSON_VARIANT_STRING, json_dispatch_string, offsetof(oci_mount_data, type),        0              },
                        {}
                };

                _cleanup_free_ char *joined_options = NULL;
                _cleanup_(oci_mount_data_done) oci_mount_data data = {};
                CustomMount *m;

                r = oci_dispatch(e, table, flags, &data);
                if (r < 0)
                        return r;

                if (!path_is_absolute(data.destination))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Mount destination not an absolute path: %s", data.destination);

                if (oci_exclude_mount(data.destination))
                        continue;

                if (data.options) {
                        joined_options = strv_join(data.options, ",");
                        if (!joined_options)
                                return log_oom();
                }

                if (!data.type || streq(data.type, "bind")) {
                        if (data.source && !path_is_absolute(data.source)) {
                                char *joined;

                                joined = path_join(s->bundle, data.source);
                                if (!joined)
                                        return log_oom();

                                free_and_replace(data.source, joined);
                        }

                        data.type = mfree(data.type);

                        m = custom_mount_add(&s->custom_mounts, &s->n_custom_mounts, CUSTOM_MOUNT_BIND);
                } else
                        m = custom_mount_add(&s->custom_mounts, &s->n_custom_mounts, CUSTOM_MOUNT_ARBITRARY);
                if (!m)
                        return log_oom();

                m->destination = TAKE_PTR(data.destination);
                m->source = TAKE_PTR(data.source);
                m->options = TAKE_PTR(joined_options);
                m->type_argument = TAKE_PTR(data.type);
        }

        return 0;
}

static int oci_namespace_type(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        unsigned long *nsflags = ASSERT_PTR(userdata);
        const char *n;

        assert_se(n = json_variant_string(v));

        /* We don't use namespace_flags_from_string() here, as the OCI spec uses slightly different names than the
         * kernel here. */
        if (streq(n, "pid"))
                *nsflags = CLONE_NEWPID;
        else if (streq(n, "network"))
                *nsflags = CLONE_NEWNET;
        else if (streq(n, "mount"))
                *nsflags = CLONE_NEWNS;
        else if (streq(n, "ipc"))
                *nsflags = CLONE_NEWIPC;
        else if (streq(n, "uts"))
                *nsflags = CLONE_NEWUTS;
        else if (streq(n, "user"))
                *nsflags = CLONE_NEWUSER;
        else if (streq(n, "cgroup"))
                *nsflags = CLONE_NEWCGROUP;
        else
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Unknown namespace type, refusing: %s", n);

        return 0;
}

struct namespace_data {
        unsigned long type;
        char *path;
};

static void namespace_data_done(struct namespace_data *data) {
        assert(data);

        free(data->path);
}

static int oci_namespaces(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        unsigned long n = 0;
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                _cleanup_(namespace_data_done) struct namespace_data data = {};

                static const JsonDispatch table[] = {
                        { "type", JSON_VARIANT_STRING, oci_namespace_type, offsetof(struct namespace_data, type), JSON_MANDATORY },
                        { "path", JSON_VARIANT_STRING, oci_absolute_path,  offsetof(struct namespace_data, path), 0              },
                        {}
                };

                r = oci_dispatch(e, table, flags, &data);
                if (r < 0)
                        return r;

                if (data.path) {
                        if (data.type != CLONE_NEWNET)
                                return json_log(e, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                "Specifying namespace path for non-network namespace is not supported.");

                        if (s->network_namespace_path)
                                return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL),
                                                "Network namespace path specified more than once, refusing.");

                        free_and_replace(s->network_namespace_path, data.path);
                }

                if (FLAGS_SET(n, data.type))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Duplicate namespace specification, refusing.");

                n |= data.type;
        }

        if (!FLAGS_SET(n, CLONE_NEWNS))
                return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "Containers without a mount namespace aren't supported.");

        s->private_network = FLAGS_SET(n, CLONE_NEWNET);
        s->userns_mode = FLAGS_SET(n, CLONE_NEWUSER) ? USER_NAMESPACE_FIXED : USER_NAMESPACE_NO;
        s->use_cgns = FLAGS_SET(n, CLONE_NEWCGROUP);

        s->clone_ns_flags = n & (CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS);

        return 0;
}

static int oci_uid_gid_range(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        uid_t *uid = ASSERT_PTR(userdata);
        uid_t u;
        uint64_t k;

        assert_cc(sizeof(uid_t) == sizeof(gid_t));

        /* This is very much like oci_uid_gid(), except the checks are a bit different, as this is a UID range rather
         * than a specific UID, and hence UID_INVALID has no special significance. OTOH a range of zero makes no
         * sense. */

        k = json_variant_unsigned(v);
        u = (uid_t) k;
        if ((uint64_t) u != k)
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "UID/GID out of range: %" PRIu64, k);
        if (u == 0)
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "UID/GID range can't be zero.");

        *uid = u;
        return 0;
}

static int oci_uid_gid_mappings(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        struct mapping_data {
                uid_t host_id;
                uid_t container_id;
                uid_t range;
        } data = {
                .host_id = UID_INVALID,
                .container_id = UID_INVALID,
                .range = 0,
        };

        static const JsonDispatch table[] = {
                { "containerID", JSON_VARIANT_UNSIGNED, oci_uid_gid,       offsetof(struct mapping_data, container_id), JSON_MANDATORY },
                { "hostID",      JSON_VARIANT_UNSIGNED, oci_uid_gid,       offsetof(struct mapping_data, host_id),      JSON_MANDATORY },
                { "size",        JSON_VARIANT_UNSIGNED, oci_uid_gid_range, offsetof(struct mapping_data, range),        JSON_MANDATORY },
                {}
        };

        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        if (json_variant_elements(v) == 0)
                return 0;

        if (json_variant_elements(v) > 1)
                return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "UID/GID mappings with more than one entry are not supported.");

        assert_se(e = json_variant_by_index(v, 0));

        r = oci_dispatch(e, table, flags, &data);
        if (r < 0)
                return r;

        if (data.host_id + data.range < data.host_id ||
            data.container_id + data.range < data.container_id)
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "UID/GID range goes beyond UID/GID validity range, refusing.");

        if (data.container_id != 0)
                return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "UID/GID mappings with a non-zero container base are not supported.");

        if (data.range < 0x10000)
                json_log(v, flags|JSON_WARNING, 0,
                         "UID/GID mapping with less than 65536 UID/GIDS set up, you are looking for trouble.");

        if (s->uid_range != UID_INVALID &&
            (s->uid_shift != data.host_id || s->uid_range != data.range))
                return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "Non-matching UID and GID mappings are not supported.");

        s->uid_shift = data.host_id;
        s->uid_range = data.range;

        return 0;
}

static int oci_device_type(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        mode_t *mode = ASSERT_PTR(userdata);
        const char *t;

        assert_se(t = json_variant_string(v));

        if (STR_IN_SET(t, "c", "u"))
                *mode = (*mode & ~S_IFMT) | S_IFCHR;
        else if (streq(t, "b"))
                *mode = (*mode & ~S_IFMT) | S_IFBLK;
        else if (streq(t, "p"))
                *mode = (*mode & ~S_IFMT) | S_IFIFO;
        else
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Unknown device type: %s", t);

        return 0;
}

static int oci_device_major(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        unsigned *u = ASSERT_PTR(userdata);
        uint64_t k;

        k = json_variant_unsigned(v);
        if (!DEVICE_MAJOR_VALID(k))
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "Device major %" PRIu64 " out of range.", k);

        *u = (unsigned) k;
        return 0;
}

static int oci_device_minor(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        unsigned *u = ASSERT_PTR(userdata);
        uint64_t k;

        k = json_variant_unsigned(v);
        if (!DEVICE_MINOR_VALID(k))
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "Device minor %" PRIu64 " out of range.", k);

        *u = (unsigned) k;
        return 0;
}

static int oci_device_file_mode(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        mode_t *mode = ASSERT_PTR(userdata);
        mode_t m;
        uint64_t k;

        k = json_variant_unsigned(v);
        m = (mode_t) k;

        if ((m & ~07777) != 0 || (uint64_t) m != k)
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "fileMode out of range, refusing.");

        *mode = (*mode & ~07777) | m;
        return 0;
}

static int oci_devices(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {

                static const JsonDispatch table[] = {
                        { "type",     JSON_VARIANT_STRING,   oci_device_type,      offsetof(DeviceNode, mode),  JSON_MANDATORY },
                        { "path",     JSON_VARIANT_STRING,   oci_absolute_path,    offsetof(DeviceNode, path),  JSON_MANDATORY },
                        { "major",    JSON_VARIANT_UNSIGNED, oci_device_major,     offsetof(DeviceNode, major), 0              },
                        { "minor",    JSON_VARIANT_UNSIGNED, oci_device_minor,     offsetof(DeviceNode, minor), 0              },
                        { "fileMode", JSON_VARIANT_UNSIGNED, oci_device_file_mode, offsetof(DeviceNode, mode),  0              },
                        { "uid",      JSON_VARIANT_UNSIGNED, oci_uid_gid,          offsetof(DeviceNode, uid),   0              },
                        { "gid",      JSON_VARIANT_UNSIGNED, oci_uid_gid,          offsetof(DeviceNode, gid),   0              },
                        {}
                };

                DeviceNode *node, *nodes;

                nodes = reallocarray(s->extra_nodes, s->n_extra_nodes + 1, sizeof(DeviceNode));
                if (!nodes)
                        return log_oom();

                s->extra_nodes = nodes;

                node = nodes + s->n_extra_nodes;
                *node = (DeviceNode) {
                        .uid = UID_INVALID,
                        .gid = GID_INVALID,
                        .major = UINT_MAX,
                        .minor = UINT_MAX,
                        .mode = 0644,
                };

                r = oci_dispatch(e, table, flags, node);
                if (r < 0)
                        goto fail_element;

                if (S_ISCHR(node->mode) || S_ISBLK(node->mode)) {
                        _cleanup_free_ char *path = NULL;

                        if (node->major == UINT_MAX || node->minor == UINT_MAX) {
                                r = json_log(e, flags, SYNTHETIC_ERRNO(EINVAL),
                                             "Major/minor required when device node is device node");
                                goto fail_element;
                        }

                        /* Suppress a couple of implicit device nodes */
                        r = devname_from_devnum(node->mode, makedev(node->major, node->minor), &path);
                        if (r < 0)
                                json_log(e, flags|JSON_DEBUG, r, "Failed to resolve device node %u:%u, ignoring: %m", node->major, node->minor);
                        else {
                                if (PATH_IN_SET(path,
                                                "/dev/null",
                                                "/dev/zero",
                                                "/dev/full",
                                                "/dev/random",
                                                "/dev/urandom",
                                                "/dev/tty",
                                                "/dev/net/tun",
                                                "/dev/ptmx",
                                                "/dev/pts/ptmx",
                                                "/dev/console")) {

                                        json_log(e, flags|JSON_DEBUG, 0, "Ignoring devices item for device '%s', as it is implicitly created anyway.", path);
                                        free(node->path);
                                        continue;
                                }
                        }
                }

                s->n_extra_nodes++;
                continue;

        fail_element:
                free(node->path);
                return r;
        }

        return 0;
}

static int oci_cgroups_path(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        _cleanup_free_ char *slice = NULL, *backwards = NULL;
        Settings *s = ASSERT_PTR(userdata);
        const char *p;
        int r;

        assert_se(p = json_variant_string(v));

        r = cg_path_get_slice(p, &slice);
        if (r < 0)
                return json_log(v, flags, r, "Couldn't derive slice unit name from path '%s': %m", p);

        r = cg_slice_to_path(slice, &backwards);
        if (r < 0)
                return json_log(v, flags, r, "Couldn't convert slice unit name '%s' back to path: %m", slice);

        if (!path_equal(backwards, p))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Control group path '%s' does not refer to slice unit, refusing.", p);

        free_and_replace(s->slice, slice);
        return 0;
}

static int oci_cgroup_device_type(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        mode_t *mode = ASSERT_PTR(userdata);
        const char *n;

        assert_se(n = json_variant_string(v));

        if (streq(n, "c"))
                *mode = S_IFCHR;
        else if (streq(n, "b"))
                *mode = S_IFBLK;
        else
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Control group device type unknown: %s", n);

        return 0;
}

struct device_data {
        bool allow;
        bool r;
        bool w;
        bool m;
        mode_t type;
        unsigned major;
        unsigned minor;
};

static int oci_cgroup_device_access(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        struct device_data *d = ASSERT_PTR(userdata);
        bool r = false, w = false, m = false;
        const char *s;
        size_t i;

        assert_se(s = json_variant_string(v));

        for (i = 0; s[i]; i++)
                if (s[i] == 'r')
                        r = true;
                else if (s[i] == 'w')
                        w = true;
                else if (s[i] == 'm')
                        m = true;
                else
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Unknown device access character '%c'.", s[i]);

        d->r = r;
        d->w = w;
        d->m = m;

        return 0;
}

static int oci_cgroup_devices(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        _cleanup_free_ struct device_data *list = NULL;
        Settings *s = ASSERT_PTR(userdata);
        size_t n_list = 0, i;
        bool noop = false;
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {

                struct device_data data = {
                        .major = UINT_MAX,
                        .minor = UINT_MAX,
                }, *a;

                static const JsonDispatch table[] = {
                        { "allow",  JSON_VARIANT_BOOLEAN,  json_dispatch_boolean,    offsetof(struct device_data, allow), JSON_MANDATORY },
                        { "type",   JSON_VARIANT_STRING,   oci_cgroup_device_type,   offsetof(struct device_data, type),  0              },
                        { "major",  JSON_VARIANT_UNSIGNED, oci_device_major,         offsetof(struct device_data, major), 0              },
                        { "minor",  JSON_VARIANT_UNSIGNED, oci_device_minor,         offsetof(struct device_data, minor), 0              },
                        { "access", JSON_VARIANT_STRING,   oci_cgroup_device_access, 0,                                   0              },
                        {}
                };

                r = oci_dispatch(e, table, flags, &data);
                if (r < 0)
                        return r;

                if (!data.allow) {
                        /* The fact that OCI allows 'deny' entries makes really no sense, as 'allow'
                         * vs. 'deny' for the devices cgroup controller is really not about allow-listing and
                         * deny-listing but about adding and removing entries from the allow list. Since we
                         * always start out with an empty allow list we hence ignore the whole thing, as
                         * removing entries which don't exist make no sense. We'll log about this, since this
                         * is really borked in the spec, with one exception: the entry that's supposed to
                         * drop the kernel's default we ignore silently */

                        if (!data.r || !data.w || !data.m || data.type != 0 || data.major != UINT_MAX || data.minor != UINT_MAX)
                                json_log(v, flags|JSON_WARNING, 0, "Devices cgroup allow list with arbitrary 'allow' entries not supported, ignoring.");

                        /* We ignore the 'deny' entry as for us that's implied */
                        continue;
                }

                if (!data.r && !data.w && !data.m) {
                        json_log(v, flags|LOG_WARNING, 0, "Device cgroup allow list entry with no effect found, ignoring.");
                        continue;
                }

                if (data.minor != UINT_MAX && data.major == UINT_MAX)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                        "Device cgroup allow list entries with minors but no majors not supported.");

                if (data.major != UINT_MAX && data.type == 0)
                        return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                        "Device cgroup allow list entries with majors but no device node type not supported.");

                if (data.type == 0) {
                        if (data.r && data.w && data.m) /* a catchall allow list entry means we are looking at a noop */
                                noop = true;
                        else
                                return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                "Device cgroup allow list entries with no type not supported.");
                }

                a = reallocarray(list, n_list + 1, sizeof(struct device_data));
                if (!a)
                        return log_oom();

                list = a;
                list[n_list++] = data;
        }

        if (noop)
                return 0;

        r = settings_allocate_properties(s);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(s->properties, 'r', "sv");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(s->properties, "s", "DeviceAllow");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(s->properties, 'v', "a(ss)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(s->properties, 'a', "(ss)");
        if (r < 0)
                return bus_log_create_error(r);

        for (i = 0; i < n_list; i++) {
                _cleanup_free_ char *pattern = NULL;
                char access[4];
                size_t n = 0;

                if (list[i].minor == UINT_MAX) {
                        const char *t;

                        if (list[i].type == S_IFBLK)
                                t = "block";
                        else {
                                assert(list[i].type == S_IFCHR);
                                t = "char";
                        }

                        if (list[i].major == UINT_MAX) {
                                pattern = strjoin(t, "-*");
                                if (!pattern)
                                        return log_oom();
                        } else {
                                if (asprintf(&pattern, "%s-%u", t, list[i].major) < 0)
                                        return log_oom();
                        }

                } else {
                        assert(list[i].major != UINT_MAX); /* If a minor is specified, then a major also needs to be specified */

                        r = device_path_make_major_minor(list[i].type, makedev(list[i].major, list[i].minor), &pattern);
                        if (r < 0)
                                return log_oom();
                }

                if (list[i].r)
                        access[n++] = 'r';
                if (list[i].w)
                        access[n++] = 'w';
                if (list[i].m)
                        access[n++] = 'm';
                access[n] = 0;

                assert(n > 0);

                r = sd_bus_message_append(s->properties, "(ss)", pattern, access);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(s->properties);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(s->properties);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(s->properties);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

static int oci_cgroup_memory_limit(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        uint64_t *m = ASSERT_PTR(userdata);
        uint64_t k;

        if (json_variant_is_negative(v)) {
                *m = UINT64_MAX;
                return 0;
        }

        if (!json_variant_is_unsigned(v))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Memory limit is not an unsigned integer");

        k = json_variant_unsigned(v);
        if (k >= UINT64_MAX)
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "Memory limit too large: %" PRIu64, k);

        *m = (uint64_t) k;
        return 0;
}

static int oci_cgroup_memory(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        struct memory_data {
                uint64_t limit;
                uint64_t reservation;
                uint64_t swap;
        } data = {
                .limit = UINT64_MAX,
                .reservation = UINT64_MAX,
                .swap = UINT64_MAX,
        };

        static const JsonDispatch table[] = {
                { "limit",            JSON_VARIANT_NUMBER,  oci_cgroup_memory_limit, offsetof(struct memory_data, limit),       0               },
                { "reservation",      JSON_VARIANT_NUMBER,  oci_cgroup_memory_limit, offsetof(struct memory_data, reservation), 0               },
                { "swap",             JSON_VARIANT_NUMBER,  oci_cgroup_memory_limit, offsetof(struct memory_data, swap),        0               },
                { "kernel",           JSON_VARIANT_NUMBER,  oci_unsupported,         0,                                         JSON_PERMISSIVE },
                { "kernelTCP",        JSON_VARIANT_NUMBER,  oci_unsupported,         0,                                         JSON_PERMISSIVE },
                { "swapiness",        JSON_VARIANT_NUMBER,  oci_unsupported,         0,                                         JSON_PERMISSIVE },
                { "disableOOMKiller", JSON_VARIANT_BOOLEAN, oci_unsupported,         0,                                         JSON_PERMISSIVE },
                {}
        };

        Settings *s = ASSERT_PTR(userdata);
        int r;

        r = oci_dispatch(v, table, flags, &data);
        if (r < 0)
                return r;

        if (data.swap != UINT64_MAX) {
                if (data.limit == UINT64_MAX)
                        json_log(v, flags|LOG_WARNING, 0, "swap limit without memory limit is not supported, ignoring.");
                else if (data.swap < data.limit)
                        json_log(v, flags|LOG_WARNING, 0, "swap limit is below memory limit, ignoring.");
                else {
                        r = settings_allocate_properties(s);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_append(s->properties, "(sv)", "MemorySwapMax", "t", data.swap - data.limit);
                        if (r < 0)
                                return bus_log_create_error(r);
                }
        }

        if (data.limit != UINT64_MAX) {
                r = settings_allocate_properties(s);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(s->properties, "(sv)", "MemoryMax", "t", data.limit);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (data.reservation != UINT64_MAX) {
                r = settings_allocate_properties(s);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(s->properties, "(sv)", "MemoryLow", "t", data.reservation);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        return 0;
}

struct cpu_data {
        uint64_t shares;
        uint64_t quota;
        uint64_t period;
        CPUSet cpu_set;
};

static int oci_cgroup_cpu_shares(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        uint64_t *u = ASSERT_PTR(userdata);
        uint64_t k;

        k = json_variant_unsigned(v);
        if (k < CGROUP_CPU_SHARES_MIN || k > CGROUP_CPU_SHARES_MAX)
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "shares value out of range.");

        *u = (uint64_t) k;
        return 0;
}

static int oci_cgroup_cpu_quota(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        uint64_t *u = ASSERT_PTR(userdata);
        uint64_t k;

        k = json_variant_unsigned(v);
        if (k <= 0 || k >= UINT64_MAX)
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "period/quota value out of range.");

        *u = (uint64_t) k;
        return 0;
}

static int oci_cgroup_cpu_cpus(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        struct cpu_data *data = ASSERT_PTR(userdata);
        CPUSet set;
        const char *n;
        int r;

        assert_se(n = json_variant_string(v));

        r = parse_cpu_set(n, &set);
        if (r < 0)
                return json_log(v, flags, r, "Failed to parse CPU set specification: %s", n);

        cpu_set_reset(&data->cpu_set);
        data->cpu_set = set;

        return 0;
}

static int oci_cgroup_cpu(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "shares",          JSON_VARIANT_UNSIGNED, oci_cgroup_cpu_shares, offsetof(struct cpu_data, shares), 0 },
                { "quota",           JSON_VARIANT_UNSIGNED, oci_cgroup_cpu_quota,  offsetof(struct cpu_data, quota),  0 },
                { "period",          JSON_VARIANT_UNSIGNED, oci_cgroup_cpu_quota,  offsetof(struct cpu_data, period), 0 },
                { "realtimeRuntime", JSON_VARIANT_UNSIGNED, oci_unsupported,       0,                                 0 },
                { "realtimePeriod",  JSON_VARIANT_UNSIGNED, oci_unsupported,       0,                                 0 },
                { "cpus",            JSON_VARIANT_STRING,   oci_cgroup_cpu_cpus,   0,                                 0 },
                { "mems",            JSON_VARIANT_STRING,   oci_unsupported,       0,                                 0 },
                {}
        };

        struct cpu_data data = {
                .shares = UINT64_MAX,
                .quota = UINT64_MAX,
                .period = UINT64_MAX,
        };

        Settings *s = ASSERT_PTR(userdata);
        int r;

        r = oci_dispatch(v, table, flags, &data);
        if (r < 0) {
                cpu_set_reset(&data.cpu_set);
                return r;
        }

        cpu_set_reset(&s->cpu_set);
        s->cpu_set = data.cpu_set;

        if (data.shares != UINT64_MAX) {
                r = settings_allocate_properties(s);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(s->properties, "(sv)", "CPUShares", "t", data.shares);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (data.quota != UINT64_MAX && data.period != UINT64_MAX) {
                r = settings_allocate_properties(s);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(s->properties, "(sv)", "CPUQuotaPerSecUSec", "t", (uint64_t) (data.quota * USEC_PER_SEC / data.period));
                if (r < 0)
                        return bus_log_create_error(r);

        } else if ((data.quota != UINT64_MAX) != (data.period != UINT64_MAX))
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                "CPU quota and period not used together.");

        return 0;
}

static int oci_cgroup_block_io_weight(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        uint64_t k;
        int r;

        k = json_variant_unsigned(v);
        if (k < CGROUP_BLKIO_WEIGHT_MIN || k > CGROUP_BLKIO_WEIGHT_MAX)
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "Block I/O weight out of range.");

        r = settings_allocate_properties(s);
        if (r < 0)
                return r;

        r = sd_bus_message_append(s->properties, "(sv)", "BlockIOWeight", "t", (uint64_t) k);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

static int oci_cgroup_block_io_weight_device(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                struct device_data {
                        unsigned major;
                        unsigned minor;
                        uint64_t weight;
                } data = {
                        .major = UINT_MAX,
                        .minor = UINT_MAX,
                        .weight = UINT64_MAX,
                };

                static const JsonDispatch table[] =  {
                        { "major",      JSON_VARIANT_UNSIGNED, oci_device_major,     offsetof(struct device_data, major),  JSON_MANDATORY  },
                        { "minor",      JSON_VARIANT_UNSIGNED, oci_device_minor,     offsetof(struct device_data, minor),  JSON_MANDATORY  },
                        { "weight",     JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct device_data, weight), 0               },
                        { "leafWeight", JSON_VARIANT_INTEGER,  oci_unsupported,      0,                                    JSON_PERMISSIVE },
                        {}
                };

                _cleanup_free_ char *path = NULL;

                r = oci_dispatch(e, table, flags, &data);
                if (r < 0)
                        return r;

                if (data.weight == UINT64_MAX)
                        continue;

                if (data.weight < CGROUP_BLKIO_WEIGHT_MIN || data.weight > CGROUP_BLKIO_WEIGHT_MAX)
                        return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                        "Block I/O device weight out of range.");

                r = device_path_make_major_minor(S_IFBLK, makedev(data.major, data.minor), &path);
                if (r < 0)
                        return json_log(v, flags, r, "Failed to build device path: %m");

                r = settings_allocate_properties(s);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(s->properties, "(sv)", "BlockIODeviceWeight", "a(st)", 1, path, (uint64_t) data.weight);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        return 0;
}

static int oci_cgroup_block_io_throttle(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        const char *pname;
        JsonVariant *e;
        int r;

        pname = streq(name, "throttleReadBpsDevice")  ? "IOReadBandwidthMax" :
                streq(name, "throttleWriteBpsDevice") ? "IOWriteBandwidthMax" :
                streq(name, "throttleReadIOPSDevice") ? "IOReadIOPSMax" :
                                                        "IOWriteIOPSMax";

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                struct device_data {
                        unsigned major;
                        unsigned minor;
                        uint64_t rate;
                } data = {
                        .major = UINT_MAX,
                        .minor = UINT_MAX,
                };

                static const JsonDispatch table[] = {
                        { "major", JSON_VARIANT_UNSIGNED, oci_device_major,     offsetof(struct device_data, major), JSON_MANDATORY },
                        { "minor", JSON_VARIANT_UNSIGNED, oci_device_minor,     offsetof(struct device_data, minor), JSON_MANDATORY },
                        { "rate",  JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct device_data, rate),  JSON_MANDATORY },
                        {}
                };

                _cleanup_free_ char *path = NULL;

                r = oci_dispatch(e, table, flags, &data);
                if (r < 0)
                        return r;

                if (data.rate >= UINT64_MAX)
                        return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                        "Block I/O device rate out of range.");

                r = device_path_make_major_minor(S_IFBLK, makedev(data.major, data.minor), &path);
                if (r < 0)
                        return json_log(v, flags, r, "Failed to build device path: %m");

                r = settings_allocate_properties(s);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(s->properties, "(sv)", pname, "a(st)", 1, path, (uint64_t) data.rate);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        return 0;
}

static int oci_cgroup_block_io(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "weight",                  JSON_VARIANT_UNSIGNED, oci_cgroup_block_io_weight,        0, 0               },
                { "leafWeight",              JSON_VARIANT_UNSIGNED, oci_unsupported,                   0, JSON_PERMISSIVE },
                { "weightDevice",            JSON_VARIANT_ARRAY,    oci_cgroup_block_io_weight_device, 0, 0               },
                { "throttleReadBpsDevice",   JSON_VARIANT_ARRAY,    oci_cgroup_block_io_throttle,      0, 0               },
                { "throttleWriteBpsDevice",  JSON_VARIANT_ARRAY,    oci_cgroup_block_io_throttle,      0, 0               },
                { "throttleReadIOPSDevice",  JSON_VARIANT_ARRAY,    oci_cgroup_block_io_throttle,      0, 0               },
                { "throttleWriteIOPSDevice", JSON_VARIANT_ARRAY,    oci_cgroup_block_io_throttle,      0, 0               },
                {}
        };

        return oci_dispatch(v, table, flags, userdata);
}

static int oci_cgroup_pids(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "limit", JSON_VARIANT_NUMBER, json_dispatch_variant, 0, JSON_MANDATORY },
                {}
        };

        _cleanup_(json_variant_unrefp) JsonVariant *k = NULL;
        Settings *s = ASSERT_PTR(userdata);
        uint64_t m;
        int r;

        r = oci_dispatch(v, table, flags, &k);
        if (r < 0)
                return r;

        if (json_variant_is_negative(k))
                m = UINT64_MAX;
        else {
                if (!json_variant_is_unsigned(k))
                        return json_log(k, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "pids limit not unsigned integer, refusing.");

                m = (uint64_t) json_variant_unsigned(k);

                if ((uint64_t) m != json_variant_unsigned(k))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "pids limit out of range, refusing.");
        }

        r = settings_allocate_properties(s);
        if (r < 0)
                return r;

        r = sd_bus_message_append(s->properties, "(sv)", "TasksMax", "t", m);
        if (r < 0)
                return bus_log_create_error(r);

        return 0;
}

static int oci_resources(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "devices",        JSON_VARIANT_ARRAY,  oci_cgroup_devices,  0, 0 },
                { "memory",         JSON_VARIANT_OBJECT, oci_cgroup_memory,   0, 0 },
                { "cpu",            JSON_VARIANT_OBJECT, oci_cgroup_cpu,      0, 0 },
                { "blockIO",        JSON_VARIANT_OBJECT, oci_cgroup_block_io, 0, 0 },
                { "hugepageLimits", JSON_VARIANT_ARRAY,  oci_unsupported,     0, 0 },
                { "network",        JSON_VARIANT_OBJECT, oci_unsupported,     0, 0 },
                { "pids",           JSON_VARIANT_OBJECT, oci_cgroup_pids,     0, 0 },
                { "rdma",           JSON_VARIANT_OBJECT, oci_unsupported,     0, 0 },
                {}
        };

        return oci_dispatch(v, table, flags, userdata);
}

static bool sysctl_key_valid(const char *s) {
        bool dot = true;

        /* Note that we are a bit stricter here than in systemd-sysctl, as that inherited semantics from the old sysctl
         * tool, which were really weird (as it swaps / and . in both ways) */

        if (isempty(s))
                return false;

        for (; *s; s++) {

                if (*s <= ' ' || *s >= 127)
                        return false;
                if (*s == '/')
                        return false;
                if (*s == '.') {

                        if (dot) /* Don't allow two dots next to each other (or at the beginning) */
                                return false;

                        dot = true;
                } else
                        dot = false;
        }

        if (dot) /* don't allow a dot at the end */
                return false;

        return true;
}

static int oci_sysctl(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *w;
        const char *k;
        int r;

        JSON_VARIANT_OBJECT_FOREACH(k, w, v) {
                const char *m;

                if (!json_variant_is_string(w))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "sysctl parameter is not a string, refusing.");

                assert_se(m = json_variant_string(w));

                if (!sysctl_key_valid(k))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "sysctl key invalid, refusing: %s", k);

                r = strv_extend_strv(&s->sysctl, STRV_MAKE(k, m), false);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

#if HAVE_SECCOMP
static int oci_seccomp_action_from_string(const char *name, uint32_t *ret) {

        static const struct {
                const char *name;
                uint32_t action;
        } table[] = {
                { "SCMP_ACT_ALLOW",         SCMP_ACT_ALLOW        },
                { "SCMP_ACT_ERRNO",         SCMP_ACT_ERRNO(EPERM) }, /* the OCI spec doesn't document the error, but it appears EPERM is supposed to be used */
                { "SCMP_ACT_KILL",          SCMP_ACT_KILL         },
#ifdef SCMP_ACT_KILL_PROCESS
                { "SCMP_ACT_KILL_PROCESS",  SCMP_ACT_KILL_PROCESS },
#endif
#ifdef SCMP_ACT_KILL_THREAD
                { "SCMP_ACT_KILL_THREAD",   SCMP_ACT_KILL_THREAD  },
#endif
#ifdef SCMP_ACT_LOG
                { "SCMP_ACT_LOG",           SCMP_ACT_LOG          },
#endif
                { "SCMP_ACT_TRAP",          SCMP_ACT_TRAP         },

                /* We don't support SCMP_ACT_TRACE because that requires a tracer, and that doesn't really make sense
                 * here */
        };

        size_t i;

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (streq_ptr(name, table[i].name)) {
                        *ret = table[i].action;
                        return 0;
                }

        return -EINVAL;
}

static int oci_seccomp_arch_from_string(const char *name, uint32_t *ret) {

        static const struct {
                const char *name;
                uint32_t arch;
        } table[] = {
                { "SCMP_ARCH_AARCH64",     SCMP_ARCH_AARCH64     },
                { "SCMP_ARCH_ARM",         SCMP_ARCH_ARM         },
#ifdef SCMP_ARCH_LOONGARCH64
                { "SCMP_ARCH_LOONGARCH64", SCMP_ARCH_LOONGARCH64 },
#endif
                { "SCMP_ARCH_MIPS",        SCMP_ARCH_MIPS        },
                { "SCMP_ARCH_MIPS64",      SCMP_ARCH_MIPS64      },
                { "SCMP_ARCH_MIPS64N32",   SCMP_ARCH_MIPS64N32   },
                { "SCMP_ARCH_MIPSEL",      SCMP_ARCH_MIPSEL      },
                { "SCMP_ARCH_MIPSEL64",    SCMP_ARCH_MIPSEL64    },
                { "SCMP_ARCH_MIPSEL64N32", SCMP_ARCH_MIPSEL64N32 },
                { "SCMP_ARCH_NATIVE",      SCMP_ARCH_NATIVE      },
#ifdef SCMP_ARCH_PARISC
                { "SCMP_ARCH_PARISC",      SCMP_ARCH_PARISC      },
#endif
#ifdef SCMP_ARCH_PARISC64
                { "SCMP_ARCH_PARISC64",    SCMP_ARCH_PARISC64    },
#endif
                { "SCMP_ARCH_PPC",         SCMP_ARCH_PPC         },
                { "SCMP_ARCH_PPC64",       SCMP_ARCH_PPC64       },
                { "SCMP_ARCH_PPC64LE",     SCMP_ARCH_PPC64LE     },
#ifdef SCMP_ARCH_RISCV64
                { "SCMP_ARCH_RISCV64",     SCMP_ARCH_RISCV64     },
#endif
                { "SCMP_ARCH_S390",        SCMP_ARCH_S390        },
                { "SCMP_ARCH_S390X",       SCMP_ARCH_S390X       },
                { "SCMP_ARCH_X32",         SCMP_ARCH_X32         },
                { "SCMP_ARCH_X86",         SCMP_ARCH_X86         },
                { "SCMP_ARCH_X86_64",      SCMP_ARCH_X86_64      },
        };

        size_t i;

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (streq_ptr(table[i].name, name)) {
                        *ret = table[i].arch;
                        return 0;
                }

        return -EINVAL;
}

static int oci_seccomp_compare_from_string(const char *name, enum scmp_compare *ret) {

        static const struct {
                const char *name;
                enum scmp_compare op;
        } table[] = {
                { "SCMP_CMP_NE",        SCMP_CMP_NE        },
                { "SCMP_CMP_LT",        SCMP_CMP_LT        },
                { "SCMP_CMP_LE",        SCMP_CMP_LE        },
                { "SCMP_CMP_EQ",        SCMP_CMP_EQ        },
                { "SCMP_CMP_GE",        SCMP_CMP_GE        },
                { "SCMP_CMP_GT",        SCMP_CMP_GT        },
                { "SCMP_CMP_MASKED_EQ", SCMP_CMP_MASKED_EQ },
        };

        size_t i;

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (streq_ptr(table[i].name, name)) {
                        *ret = table[i].op;
                        return 0;
                }

        return -EINVAL;
}

static int oci_seccomp_archs(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        scmp_filter_ctx *sc = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                uint32_t a;

                if (!json_variant_is_string(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Architecture entry is not a string");

                r = oci_seccomp_arch_from_string(json_variant_string(e), &a);
                if (r < 0)
                        return json_log(e, flags, r, "Unknown architecture: %s", json_variant_string(e));

                r = seccomp_arch_add(sc, a);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return json_log(e, flags, r, "Failed to add architecture to seccomp filter: %m");
        }

        return 0;
}

struct syscall_rule {
        char **names;
        uint32_t action;
        struct scmp_arg_cmp *arguments;
        size_t n_arguments;
};

static void syscall_rule_done(struct syscall_rule *rule) {
        assert(rule);

        strv_free(rule->names);
        free(rule->arguments);
};

static int oci_seccomp_action(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        uint32_t *action = ASSERT_PTR(userdata);
        int r;

        r = oci_seccomp_action_from_string(json_variant_string(v), action);
        if (r < 0)
                return json_log(v, flags, r, "Unknown system call action '%s': %m", json_variant_string(v));

        return 0;
}

static int oci_seccomp_op(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        enum scmp_compare *op = ASSERT_PTR(userdata);
        int r;

        r = oci_seccomp_compare_from_string(json_variant_string(v), op);
        if (r < 0)
                return json_log(v, flags, r, "Unknown seccomp operator '%s': %m", json_variant_string(v));

        return 0;
}

static int oci_seccomp_args(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        struct syscall_rule *rule = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                static const struct JsonDispatch table[] = {
                        { "index",    JSON_VARIANT_UNSIGNED, json_dispatch_uint32, offsetof(struct scmp_arg_cmp, arg),     JSON_MANDATORY },
                        { "value",    JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct scmp_arg_cmp, datum_a), JSON_MANDATORY },
                        { "valueTwo", JSON_VARIANT_UNSIGNED, json_dispatch_uint64, offsetof(struct scmp_arg_cmp, datum_b), 0              },
                        { "op",       JSON_VARIANT_STRING,   oci_seccomp_op,       offsetof(struct scmp_arg_cmp, op),      JSON_MANDATORY },
                        {},
                };

                struct scmp_arg_cmp *a, *p;
                int expected;

                a = reallocarray(rule->arguments, rule->n_arguments + 1, sizeof(struct syscall_rule));
                if (!a)
                        return log_oom();

                rule->arguments = a;
                p = rule->arguments + rule->n_arguments;

                *p = (struct scmp_arg_cmp) {
                        .arg = 0,
                        .datum_a = 0,
                        .datum_b = 0,
                        .op = 0,
                };

                r = oci_dispatch(e, table, flags, p);
                if (r < 0)
                        return r;

                expected = p->op == SCMP_CMP_MASKED_EQ ? 4 : 3;
                if (r != expected)
                        json_log(e, flags|JSON_WARNING, 0, "Wrong number of system call arguments for JSON data, ignoring.");

                /* Note that we are a bit sloppy here and do not insist that SCMP_CMP_MASKED_EQ gets two datum values,
                 * and the other only one. That's because buildah for example by default calls things with
                 * SCMP_CMP_MASKED_EQ but only one argument. We use 0 when the value is not specified. */

                rule->n_arguments++;
        }

        return 0;
}

static int oci_seccomp_syscalls(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        scmp_filter_ctx *sc = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                static const JsonDispatch table[] = {
                        { "names",  JSON_VARIANT_ARRAY,  json_dispatch_strv, offsetof(struct syscall_rule, names),  JSON_MANDATORY },
                        { "action", JSON_VARIANT_STRING, oci_seccomp_action, offsetof(struct syscall_rule, action), JSON_MANDATORY },
                        { "args",   JSON_VARIANT_ARRAY,  oci_seccomp_args,   0,                                     0              },
                        {}
                };
                _cleanup_(syscall_rule_done) struct syscall_rule rule = {
                        .action = UINT32_MAX,
                };

                r = oci_dispatch(e, table, flags, &rule);
                if (r < 0)
                        return r;

                if (strv_isempty(rule.names))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "System call name list is empty.");

                STRV_FOREACH(i, rule.names) {
                        int nr;

                        nr = seccomp_syscall_resolve_name(*i);
                        if (nr == __NR_SCMP_ERROR) {
                                log_debug("Unknown syscall %s, skipping.", *i);
                                continue;
                        }

                        r = seccomp_rule_add_array(sc, rule.action, nr, rule.n_arguments, rule.arguments);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
#endif

static int oci_seccomp(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

#if HAVE_SECCOMP
        static const JsonDispatch table[] = {
                { "defaultAction", JSON_VARIANT_STRING, NULL,                 0, JSON_MANDATORY },
                { "architectures", JSON_VARIANT_ARRAY,  oci_seccomp_archs,    0, 0              },
                { "syscalls",      JSON_VARIANT_ARRAY,  oci_seccomp_syscalls, 0, 0              },
                {}
        };

        _cleanup_(seccomp_releasep) scmp_filter_ctx sc = NULL;
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *def;
        uint32_t d;
        int r;

        def = json_variant_by_key(v, "defaultAction");
        if (!def)
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL), "defaultAction element missing.");

        if (!json_variant_is_string(def))
                return json_log(def, flags, SYNTHETIC_ERRNO(EINVAL), "defaultAction is not a string.");

        r = oci_seccomp_action_from_string(json_variant_string(def), &d);
        if (r < 0)
                return json_log(def, flags, r, "Unknown default action: %s", json_variant_string(def));

        sc = seccomp_init(d);
        if (!sc)
                return json_log(v, flags, SYNTHETIC_ERRNO(ENOMEM), "Couldn't allocate seccomp object.");

        r = oci_dispatch(v, table, flags, sc);
        if (r < 0)
                return r;

        seccomp_release(s->seccomp);
        s->seccomp = TAKE_PTR(sc);
        return 0;
#else
        return json_log(v, flags, SYNTHETIC_ERRNO(EOPNOTSUPP), "libseccomp support not enabled, can't parse seccomp object.");
#endif
}

static int oci_rootfs_propagation(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        const char *s;

        s = json_variant_string(v);

        if (streq(s, "shared"))
                return 0;

        json_log(v, flags|JSON_DEBUG, 0, "Ignoring rootfsPropagation setting '%s'.", s);
        return 0;
}

static int oci_masked_paths(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                _cleanup_free_ char *destination = NULL;
                CustomMount *m;
                const char *p;

                if (!json_variant_is_string(e))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Path is not a string, refusing.");

                assert_se(p = json_variant_string(e));

                if (!path_is_absolute(p))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Path is not absolute, refusing: %s", p);

                if (oci_exclude_mount(p))
                        continue;

                destination = strdup(p);
                if (!destination)
                        return log_oom();

                m = custom_mount_add(&s->custom_mounts, &s->n_custom_mounts, CUSTOM_MOUNT_INACCESSIBLE);
                if (!m)
                        return log_oom();

                m->destination = TAKE_PTR(destination);

                /* The spec doesn't say this, but apparently pre-existing implementations are lenient towards
                 * non-existing paths to mask. Let's hence be too. */
                m->graceful = true;
        }

        return 0;
}

static int oci_readonly_paths(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                _cleanup_free_ char *source = NULL, *destination = NULL;
                CustomMount *m;
                const char *p;

                if (!json_variant_is_string(e))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Path is not a string, refusing.");

                assert_se(p = json_variant_string(e));

                if (!path_is_absolute(p))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Path is not absolute, refusing: %s", p);

                if (oci_exclude_mount(p))
                        continue;

                source = strjoin("+", p);
                if (!source)
                        return log_oom();

                destination = strdup(p);
                if (!destination)
                        return log_oom();

                m = custom_mount_add(&s->custom_mounts, &s->n_custom_mounts, CUSTOM_MOUNT_BIND);
                if (!m)
                        return log_oom();

                m->source = TAKE_PTR(source);
                m->destination = TAKE_PTR(destination);
                m->read_only = true;
        }

        return 0;
}

static int oci_linux(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "namespaces",        JSON_VARIANT_ARRAY,  oci_namespaces,         0, 0               },
                { "uidMappings",       JSON_VARIANT_ARRAY,  oci_uid_gid_mappings,   0, 0               },
                { "gidMappings",       JSON_VARIANT_ARRAY,  oci_uid_gid_mappings,   0, 0               },
                { "devices",           JSON_VARIANT_ARRAY,  oci_devices,            0, 0               },
                { "cgroupsPath",       JSON_VARIANT_STRING, oci_cgroups_path,       0, 0               },
                { "resources",         JSON_VARIANT_OBJECT, oci_resources,          0, 0               },
                { "intelRdt",          JSON_VARIANT_OBJECT, oci_unsupported,        0, JSON_PERMISSIVE },
                { "sysctl",            JSON_VARIANT_OBJECT, oci_sysctl,             0, 0               },
                { "seccomp",           JSON_VARIANT_OBJECT, oci_seccomp,            0, 0               },
                { "rootfsPropagation", JSON_VARIANT_STRING, oci_rootfs_propagation, 0, 0               },
                { "maskedPaths",       JSON_VARIANT_ARRAY,  oci_masked_paths,       0, 0               },
                { "readonlyPaths",     JSON_VARIANT_ARRAY,  oci_readonly_paths,     0, 0               },
                { "mountLabel",        JSON_VARIANT_STRING, oci_unsupported,        0, JSON_PERMISSIVE },
                {}
        };

        return oci_dispatch(v, table, flags, userdata);
}

static int oci_hook_timeout(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        usec_t *u = ASSERT_PTR(userdata);
        uint64_t k;

        k = json_variant_unsigned(v);
        if (k == 0 || k > (UINT64_MAX-1)/USEC_PER_SEC)
                return json_log(v, flags, SYNTHETIC_ERRNO(ERANGE),
                                "Hook timeout value out of range.");

        *u = k * USEC_PER_SEC;
        return 0;
}

static int oci_hooks_array(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        Settings *s = ASSERT_PTR(userdata);
        JsonVariant *e;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {

                static const JsonDispatch table[] = {
                        { "path",    JSON_VARIANT_STRING,   oci_absolute_path, offsetof(OciHook, path),    JSON_MANDATORY },
                        { "args",    JSON_VARIANT_ARRAY,    oci_args,          offsetof(OciHook, args),    0              },
                        { "env",     JSON_VARIANT_ARRAY,    oci_env,           offsetof(OciHook, env),     0              },
                        { "timeout", JSON_VARIANT_UNSIGNED, oci_hook_timeout,  offsetof(OciHook, timeout), 0              },
                        {}
                };

                OciHook *a, **array, *new_item;
                size_t *n_array;

                if (streq(name, "prestart")) {
                        array = &s->oci_hooks_prestart;
                        n_array = &s->n_oci_hooks_prestart;
                } else if (streq(name, "poststart")) {
                        array = &s->oci_hooks_poststart;
                        n_array = &s->n_oci_hooks_poststart;
                } else {
                        assert(streq(name, "poststop"));
                        array = &s->oci_hooks_poststop;
                        n_array = &s->n_oci_hooks_poststop;
                }

                a = reallocarray(*array, *n_array + 1, sizeof(OciHook));
                if (!a)
                        return log_oom();

                *array = a;
                new_item = a + *n_array;

                *new_item = (OciHook) {
                        .timeout = USEC_INFINITY,
                };

                r = oci_dispatch(e, table, flags, new_item);
                if (r < 0) {
                        free(new_item->path);
                        strv_free(new_item->args);
                        strv_free(new_item->env);
                        return r;
                }

                (*n_array)++;
        }

        return 0;
}

static int oci_hooks(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {

        static const JsonDispatch table[] = {
                { "prestart",  JSON_VARIANT_ARRAY, oci_hooks_array, 0, 0 },
                { "poststart", JSON_VARIANT_ARRAY, oci_hooks_array, 0, 0 },
                { "poststop",  JSON_VARIANT_ARRAY, oci_hooks_array, 0, 0 },
                {}
        };

        return oci_dispatch(v, table, flags, userdata);
}

static int oci_annotations(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        JsonVariant *w;
        const char *k;

        JSON_VARIANT_OBJECT_FOREACH(k, w, v) {

                if (isempty(k))
                        return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Annotation with empty key, refusing.");

                if (!json_variant_is_string(w))
                        return json_log(w, flags, SYNTHETIC_ERRNO(EINVAL),
                                        "Annotation has non-string value, refusing.");

                json_log(w, flags|JSON_DEBUG, 0, "Ignoring annotation '%s' with value '%s'.", k, json_variant_string(w));
        }

        return 0;
}

int oci_load(FILE *f, const char *bundle, Settings **ret) {

        static const JsonDispatch table[] = {
                { "ociVersion",  JSON_VARIANT_STRING, NULL,            0, JSON_MANDATORY },
                { "process",     JSON_VARIANT_OBJECT, oci_process,     0, 0 },
                { "root",        JSON_VARIANT_OBJECT, oci_root,        0, 0 },
                { "hostname",    JSON_VARIANT_STRING, oci_hostname,    0, 0 },
                { "mounts",      JSON_VARIANT_ARRAY,  oci_mounts,      0, 0 },
                { "linux",       JSON_VARIANT_OBJECT, oci_linux,       0, 0 },
                { "hooks",       JSON_VARIANT_OBJECT, oci_hooks,       0, 0 },
                { "annotations", JSON_VARIANT_OBJECT, oci_annotations, 0, 0 },
                {}
        };

        _cleanup_(json_variant_unrefp) JsonVariant *oci = NULL;
        _cleanup_(settings_freep) Settings *s = NULL;
        unsigned line = 0, column = 0;
        JsonVariant *v;
        const char *path;
        int r;

        assert_se(bundle);

        path = strjoina(bundle, "/config.json");

        r = json_parse_file(f, path, 0, &oci, &line, &column);
        if (r < 0) {
                if (line != 0 && column != 0)
                        return log_error_errno(r, "Failed to parse '%s' at %u:%u: %m", path, line, column);
                else
                        return log_error_errno(r, "Failed to parse '%s': %m", path);
        }

        v = json_variant_by_key(oci, "ociVersion");
        if (!v)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "JSON file '%s' is not an OCI bundle configuration file. Refusing.",
                                       path);
        if (!streq_ptr(json_variant_string(v), "1.0.0"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "OCI bundle version not supported: %s",
                                       strna(json_variant_string(v)));

        // {
        //         _cleanup_free_ char *formatted = NULL;
        //         assert_se(json_variant_format(oci, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR, &formatted) >= 0);
        //         fputs(formatted, stdout);
        // }

        s = settings_new();
        if (!s)
                return log_oom();

        s->start_mode = START_PID1;
        s->resolv_conf = RESOLV_CONF_OFF;
        s->link_journal = LINK_NO;
        s->timezone = TIMEZONE_OFF;

        s->bundle = strdup(bundle);
        if (!s->bundle)
                return log_oom();

        r = oci_dispatch(oci, table, 0, s);
        if (r < 0)
                return r;

        if (s->properties) {
                r = sd_bus_message_seal(s->properties, 0, 0);
                if (r < 0)
                        return log_error_errno(r, "Cannot seal properties bus message: %m");
        }

        *ret = TAKE_PTR(s);
        return 0;
}
