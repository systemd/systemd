/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "copy.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "json-util.h"
#include "machine-varlink.h"
#include "machine.h"
#include "mount-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "user-util.h"
#include "varlink-util.h"

static JSON_DISPATCH_ENUM_DEFINE(dispatch_machine_class, MachineClass, machine_class_from_string);

static int machine_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **m = ASSERT_PTR(userdata);
        const char *hostname;
        int r;

        assert(variant);

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        hostname = sd_json_variant_string(variant);
        if (!hostname_is_valid(hostname, /* flags= */ 0))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid machine name");

        r = free_and_strdup(m, hostname);
        if (r < 0)
                return json_log_oom(variant, flags);

        return 0;
}

static int machine_leader(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        PidRef *leader = ASSERT_PTR(userdata);
        _cleanup_(pidref_done) PidRef temp = PIDREF_NULL;
        int r;

        r = json_dispatch_pidref(name, variant, flags, &temp);
        if (r < 0)
                return r;

        if (temp.pid == 1) /* refuse PID 1 */
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid leader PID.", strna(name));

        /* When both leader and leaderProcessId are specified, they must be consistent with each other. */
        if (pidref_is_set(leader) && !pidref_equal(leader, &temp))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' conflicts with already dispatched leader PID.", strna(name));

        pidref_done(leader);
        *leader = TAKE_PIDREF(temp);

        return 0;
}

static int machine_ifindices(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Machine *m = ASSERT_PTR(userdata);
        _cleanup_free_ int *netif = NULL;
        size_t n_netif, k = 0;

        assert(variant);

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        n_netif = sd_json_variant_elements(variant);

        netif = new(int, n_netif);
        if (!netif)
                return json_log_oom(variant, flags);

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                uint64_t b;

                if (!sd_json_variant_is_unsigned(i))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Element %zu of JSON field '%s' is not an unsigned integer.", k, strna(name));

                b = sd_json_variant_unsigned(i);
                if (b > INT_MAX || b <= 0)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid network interface index %"PRIu64, b);

                netif[k++] = (int) b;
        }
        assert(k == n_netif);

        free_and_replace(m->netif, netif);
        m->n_netif = n_netif;

        return 0;
}

static int machine_cid(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        unsigned cid, *c = ASSERT_PTR(userdata);
        int r;

        assert(variant);

        r = sd_json_dispatch_uint(name, variant, flags, &cid);
        if (r < 0)
                return r;

        if (!VSOCK_CID_IS_REGULAR(cid))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a regular VSOCK CID.", strna(name));

        *c = cid;
        return 0;
}

int vl_method_register(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(machine_freep) Machine *machine = NULL;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",              SD_JSON_VARIANT_STRING,        machine_name,             offsetof(Machine, name),                 SD_JSON_MANDATORY },
                { "id",                SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,   offsetof(Machine, id),                   0                 },
                { "service",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,  offsetof(Machine, service),              0                 },
                { "class",             SD_JSON_VARIANT_STRING,        dispatch_machine_class,   offsetof(Machine, class),                SD_JSON_MANDATORY },
                { "leader",            _SD_JSON_VARIANT_TYPE_INVALID, machine_leader,           offsetof(Machine, leader),               SD_JSON_STRICT    },
                { "leaderProcessId",   SD_JSON_VARIANT_OBJECT,        machine_leader,           offsetof(Machine, leader),               SD_JSON_STRICT    },
                { "rootDirectory",     SD_JSON_VARIANT_STRING,        json_dispatch_path,       offsetof(Machine, root_directory),       0                 },
                { "ifIndices",         SD_JSON_VARIANT_ARRAY,         machine_ifindices,        0,                                       0                 },
                { "vSockCid",          _SD_JSON_VARIANT_TYPE_INVALID, machine_cid,              offsetof(Machine, vsock_cid),            0                 },
                { "sshAddress",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,  offsetof(Machine, ssh_address),          SD_JSON_STRICT    },
                { "sshPrivateKeyPath", SD_JSON_VARIANT_STRING,        json_dispatch_path,       offsetof(Machine, ssh_private_key_path), 0                 },
                { "allocateUnit",      SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, offsetof(Machine, allocate_unit),        0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = machine_new(_MACHINE_CLASS_INVALID, NULL, &machine);
        if (r < 0)
                return r;

        r = sd_varlink_dispatch(link, parameters, dispatch_table, machine);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.create-machine",
                        (const char**) STRV_MAKE("name", machine->name,
                                                 "class", machine_class_to_string(machine->class)),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (!pidref_is_set(&machine->leader)) {
                r = varlink_get_peer_pidref(link, &machine->leader);
                if (r < 0)
                        return r;
        }

        r = machine_link(manager, machine);
        if (r == -EEXIST)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_EXISTS, NULL);
        if (r < 0)
                return r;

        if (!machine->allocate_unit) {
                r = cg_pidref_get_unit(&machine->leader, &machine->unit);
                if (r < 0)
                        return r;
        }

        r = machine_start(machine, /* properties= */ NULL, /* error= */ NULL);
        if (r < 0)
                return r;

        /* the manager will free this machine */
        TAKE_PTR(machine);

        return sd_varlink_reply(link, NULL);
}

static int lookup_machine_by_name(sd_varlink *link, Manager *manager, const char *machine_name, Machine **ret_machine) {
        assert(link);
        assert(manager);
        assert(ret_machine);

        if (!machine_name)
                return -EINVAL;

        if (!hostname_is_valid(machine_name, /* flags= */ VALID_HOSTNAME_DOT_HOST))
                return -EINVAL;

        Machine *machine = hashmap_get(manager->machines, machine_name);
        if (!machine)
                return -ESRCH;

        *ret_machine = machine;
        return 0;
}

static int lookup_machine_by_pidref(sd_varlink *link, Manager *manager, const PidRef *pidref, Machine **ret_machine) {
        _cleanup_(pidref_done) PidRef peer = PIDREF_NULL;
        Machine *machine;
        int r;

        assert(link);
        assert(manager);
        assert(ret_machine);

        if (pidref_is_automatic(pidref)) {
                r = varlink_get_peer_pidref(link, &peer);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get peer pidref: %m");

                pidref = &peer;
        } else if (!pidref_is_set(pidref))
                return -EINVAL;

        r = manager_get_machine_by_pidref(manager, pidref, &machine);
        if (r < 0)
                return r;
        if (!machine)
                return -ESRCH;

        *ret_machine = machine;
        return 0;
}

int lookup_machine_by_name_or_pidref(sd_varlink *link, Manager *manager, const char *machine_name, const PidRef *pidref, Machine **ret_machine) {
        Machine *machine = NULL, *pid_machine = NULL;
        int r;

        assert(link);
        assert(manager);
        assert(ret_machine);

        if (machine_name) {
                r = lookup_machine_by_name(link, manager, machine_name, &machine);
                if (r == -EINVAL)
                        return sd_varlink_error_invalid_parameter_name(link, "name");
                if (r < 0)
                        return r;
        }

        if (pidref_is_set(pidref) || pidref_is_automatic(pidref)) {
                r = lookup_machine_by_pidref(link, manager, pidref, &pid_machine);
                if (r == -EINVAL)
                        return sd_varlink_error_invalid_parameter_name(link, "pid");
                if (r < 0)
                        return r;
        }

        if (machine && pid_machine && machine != pid_machine)
                return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "Search by machine name '%s' and pid " PID_FMT " resulted in two different machines", machine_name, pidref->pid);
        if (machine)
                *ret_machine = machine;
        else if (pid_machine)
                *ret_machine = pid_machine;
        else
                return -ESRCH;

        return 0;
}

int vl_method_unregister_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Machine *machine = ASSERT_PTR(userdata);
        Manager *manager = ASSERT_PTR(machine->manager);
        int r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-machines",
                        (const char**) STRV_MAKE("name", machine->name,
                                                 "verb", "unregister"),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        r = machine_finalize(machine);
        if (r < 0)
                return log_debug_errno(r, "Failed to finalize machine: %m");

        return sd_varlink_reply(link, NULL);
}

int vl_method_terminate_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Machine *machine = ASSERT_PTR(userdata);
        Manager *manager = ASSERT_PTR(machine->manager);
        int r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-machines",
                        (const char**) STRV_MAKE("name", machine->name,
                                                 "verb", "terminate"),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        r = machine_stop(machine);
        if (r < 0)
                return log_debug_errno(r, "Failed to stop machine: %m");

        return sd_varlink_reply(link, NULL);
}

typedef struct MachineKillParameters {
        const char *name;
        PidRef pidref;
        const char *swhom;
        int32_t signo;
} MachineKillParameters;

static void machine_kill_paramaters_done(MachineKillParameters *p) {
        assert(p);

        pidref_done(&p->pidref);
}

int vl_method_kill(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(MachineKillParameters),
                { "whom",   SD_JSON_VARIANT_STRING,         sd_json_dispatch_const_string, offsetof(MachineKillParameters, swhom), 0                 },
                { "signal", _SD_JSON_VARIANT_TYPE_INVALID , sd_json_dispatch_signal,       offsetof(MachineKillParameters, signo), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(machine_kill_paramaters_done) MachineKillParameters p = {
                .pidref = PIDREF_NULL,
        };
        KillWhom whom;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Machine *machine;
        r = lookup_machine_by_name_or_pidref(link, manager, p.name, &p.pidref, &machine);
        if (r == -ESRCH)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
        if (r < 0)
                return r;

        if (isempty(p.swhom))
                whom = KILL_ALL;
        else {
                whom = kill_whom_from_string(p.swhom);
                if (whom < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "whom");
        }

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-machines",
                        (const char**) STRV_MAKE("name", machine->name,
                                                 "verb", "kill"),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        r = machine_kill(machine, whom, p.signo);
        if (r < 0)
                return log_debug_errno(r, "Failed to send signal to machine: %m");

        return sd_varlink_reply(link, NULL);
}

typedef enum MachineOpenMode {
        MACHINE_OPEN_MODE_TTY,
        MACHINE_OPEN_MODE_LOGIN,
        MACHINE_OPEN_MODE_SHELL,
        _MACHINE_OPEN_MODE_MAX,
        _MACHINE_OPEN_MODE_INVALID = -EINVAL,
} MachineOpenMode;

static const char* const machine_open_mode_table[_MACHINE_OPEN_MODE_MAX] = {
        [MACHINE_OPEN_MODE_TTY]   = "tty",
        [MACHINE_OPEN_MODE_LOGIN] = "login",
        [MACHINE_OPEN_MODE_SHELL] = "shell",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(machine_open_mode, MachineOpenMode);
static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_machine_open_mode, MachineOpenMode, machine_open_mode_from_string);

typedef struct MachineOpenParameters {
        const char *name;
        const char *user;
        PidRef pidref;
        MachineOpenMode mode;
        const char *path;
        char **args;
        char **env;
} MachineOpenParameters;

static void machine_open_paramaters_done(MachineOpenParameters *p) {
        assert(p);
        pidref_done(&p->pidref);
        strv_free(p->args);
        strv_free(p->env);
}

inline static const char* machine_open_polkit_action(MachineOpenMode mode, MachineClass class) {
        switch (mode) {
                case MACHINE_OPEN_MODE_TTY:
                        return class == MACHINE_HOST ? "org.freedesktop.machine1.host-open-pty" : "org.freedesktop.machine1.open-pty";
                case MACHINE_OPEN_MODE_LOGIN:
                        return class == MACHINE_HOST ? "org.freedesktop.machine1.host-login"    : "org.freedesktop.machine1.login";
                case MACHINE_OPEN_MODE_SHELL:
                        return class == MACHINE_HOST ? "org.freedesktop.machine1.host-shell"    : "org.freedesktop.machine1.shell";
                default:
                        assert_not_reached();
        }
}

inline static char** machine_open_polkit_details(MachineOpenMode mode, const char *machine_name, const char *user, const char *path, const char *command_line) {
        assert(machine_name);

        switch (mode) {
                case MACHINE_OPEN_MODE_TTY:
                        return strv_new("machine", machine_name);
                case MACHINE_OPEN_MODE_LOGIN:
                        return strv_new("machine", machine_name, "verb", "login");
                case MACHINE_OPEN_MODE_SHELL:
                        assert(user);
                        assert(path);
                        assert(command_line);
                        return strv_new(
                                        "machine", machine_name,
                                        "verb", "shell",
                                        "user", user,
                                        "program", path,
                                        "command_line", command_line);
                default:
                        assert_not_reached();
        }
}

int vl_method_open(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(MachineOpenParameters),
                { "mode",        SD_JSON_VARIANT_STRING, json_dispatch_machine_open_mode,     offsetof(MachineOpenParameters, mode), SD_JSON_MANDATORY },
                { "user",        SD_JSON_VARIANT_STRING, json_dispatch_const_user_group_name, offsetof(MachineOpenParameters, user), SD_JSON_RELAX     },
                { "path",        SD_JSON_VARIANT_STRING, json_dispatch_const_path,            offsetof(MachineOpenParameters, path), 0                 },
                { "args",        SD_JSON_VARIANT_ARRAY,  sd_json_dispatch_strv,               offsetof(MachineOpenParameters, args), 0                 },
                { "environment", SD_JSON_VARIANT_ARRAY,  json_dispatch_strv_environment,      offsetof(MachineOpenParameters, env),  0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_close_ int ptmx_fd = -EBADF;
        _cleanup_(machine_open_paramaters_done) MachineOpenParameters p = {
                .pidref = PIDREF_NULL,
                .mode = _MACHINE_OPEN_MODE_INVALID,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *ptmx_name = NULL, *command_line = NULL;
        _cleanup_strv_free_ char **polkit_details = NULL, **args = NULL;
        const char *user = NULL, *path = NULL; /* gcc complains about uninitialized variables */
        Machine *machine;
        int r, ptmx_fd_idx;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.mode == MACHINE_OPEN_MODE_SHELL) {
                /* json_dispatch_const_user_group_name() does valid_user_group_name(p.user) */
                /* json_dispatch_const_path() does path_is_absolute(p.path) */
                /* json_dispatch_strv_environment() does validation of p.env */

                user = p.user ?: "root";
                path = p.path ?: machine_default_shell_path();
                args = !p.path ? machine_default_shell_args(user) : strv_isempty(p.args) ? strv_new(path) : TAKE_PTR(p.args);
                if (!args)
                        return -ENOMEM;

                command_line = strv_join(args, " ");
                if (!command_line)
                        return -ENOMEM;
        }

        r = lookup_machine_by_name_or_pidref(link, manager, p.name, &p.pidref, &machine);
        if (r == -ESRCH)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
        if (r < 0)
                return r;

        polkit_details = machine_open_polkit_details(p.mode, machine->name, user, path, command_line);
        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        machine_open_polkit_action(p.mode, machine->class),
                        (const char**) polkit_details,
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        ptmx_fd = machine_openpt(machine, O_RDWR|O_NOCTTY|O_CLOEXEC, &ptmx_name);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(ptmx_fd))
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);
        if (ptmx_fd < 0)
                return log_debug_errno(ptmx_fd, "Failed to open pseudo terminal: %m");

        switch (p.mode) {
                case MACHINE_OPEN_MODE_TTY:
                        /* noop */
                        break;

                case MACHINE_OPEN_MODE_LOGIN:
                        r = machine_start_getty(machine, ptmx_name, /* error = */ NULL);
                        if (r == -ENOENT)
                                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_IPC, NULL);
                        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to start getty for machine '%s': %m", machine->name);

                        break;

                case MACHINE_OPEN_MODE_SHELL: {
                        assert(user && path && args); /* to avoid gcc complaining about possible uninitialized variables */
                        r = machine_start_shell(machine, ptmx_fd, ptmx_name, user, path, args, p.env, /* error = */ NULL);
                        if (r == -ENOENT)
                                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_IPC, NULL);
                        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to start shell for machine '%s': %m", machine->name);

                        break;
                }

                default:
                        assert_not_reached();
        }

        ptmx_fd_idx = sd_varlink_push_fd(link, ptmx_fd);
        if (ERRNO_IS_PRIVILEGE(ptmx_fd_idx))
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);
        if (ptmx_fd_idx < 0)
                return log_debug_errno(ptmx_fd_idx, "Failed to push file descriptor over varlink: %m");

        TAKE_FD(ptmx_fd);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_INTEGER("ptyFileDescriptor", ptmx_fd_idx),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ptyPath", ptmx_name));
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

typedef struct MachineMapParameters {
        const char *name;
        PidRef pidref;
        uid_t uid;
        gid_t gid;
} MachineMapParameters;

static void machine_map_paramaters_done(MachineMapParameters *p) {
        assert(p);
        pidref_done(&p->pidref);
}

int vl_method_map_from(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(MachineOpenParameters),
                { "uid", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid, offsetof(MachineMapParameters, uid), 0 },
                { "gid", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid, offsetof(MachineMapParameters, gid), 0 },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(machine_map_paramaters_done) MachineMapParameters p = {
                .pidref = PIDREF_NULL,
                .uid = UID_INVALID,
                .gid = GID_INVALID,
        };
        uid_t converted_uid = UID_INVALID;
        gid_t converted_gid = GID_INVALID;
        Machine *machine;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.uid != UID_INVALID && !uid_is_valid(p.uid))
                return sd_varlink_error_invalid_parameter_name(link, "uid");

        if (p.gid != GID_INVALID && !gid_is_valid(p.gid))
                return sd_varlink_error_invalid_parameter_name(link, "gid");

        r = lookup_machine_by_name_or_pidref(link, manager, p.name, &p.pidref, &machine);
        if (r == -ESRCH)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
        if (r < 0)
                return r;

        if (machine->class != MACHINE_CONTAINER)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);

        if (p.uid != UID_INVALID) {
                r = machine_translate_uid(machine, p.uid, &converted_uid);
                if (r == -ESRCH)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_USER, NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to map uid=%u for machine '%s': %m", p.uid, machine->name);
        }

        if (p.gid != UID_INVALID) {
                r = machine_translate_gid(machine, p.gid, &converted_gid);
                if (r == -ESRCH)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_GROUP, NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to map gid=%u for machine '%s': %m", p.gid, machine->name);
        }

        r = sd_json_buildo(&v,
                           JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("uid", converted_uid, UID_INVALID),
                           JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("gid", converted_gid, GID_INVALID));
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

int vl_method_map_to(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "uid", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid, offsetof(MachineMapParameters, uid), 0 },
                { "gid", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid, offsetof(MachineMapParameters, gid), 0 },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(machine_map_paramaters_done) MachineMapParameters p = {
                .pidref = PIDREF_NULL,
                .uid = UID_INVALID,
                .gid = GID_INVALID,
        };
        Machine *machine_by_uid = NULL, *machine_by_gid = NULL;
        uid_t converted_uid = UID_INVALID;
        gid_t converted_gid = GID_INVALID;
        const char *machine_name = NULL;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.uid != UID_INVALID) {
                if (!uid_is_valid(p.uid))
                        return sd_varlink_error_invalid_parameter_name(link, "uid");
                if (p.uid < 0x10000)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_USER_IN_HOST_RANGE, NULL);
        }

        if (p.gid != GID_INVALID) {
                if (!gid_is_valid(p.gid))
                        return sd_varlink_error_invalid_parameter_name(link, "gid");
                if (p.gid < 0x10000)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_GROUP_IN_HOST_RANGE, NULL);
        }

        if (p.uid != UID_INVALID) {
                r = manager_find_machine_for_uid(manager, p.uid, &machine_by_uid, &converted_uid);
                if (r < 0)
                        return log_debug_errno(r, "Failed to find machine for uid=%u: %m", p.uid);
                if (!r)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_USER, NULL);
        }

        if (p.gid != GID_INVALID) {
                r = manager_find_machine_for_gid(manager, p.gid, &machine_by_gid, &converted_gid);
                if (r < 0)
                        return log_debug_errno(r, "Failed to find machine for gid=%u: %m", p.gid);
                if (!r)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_GROUP, NULL);
        }

        if (machine_by_uid && machine_by_gid && machine_by_uid != machine_by_gid) {
                log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "Mapping of UID %u and GID %u resulted in two different machines", p.uid, p.gid);
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
        }

        if (machine_by_uid)
                machine_name = machine_by_uid->name;
        else if (machine_by_gid)
                machine_name = machine_by_gid->name;
        else
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);

        r = sd_json_buildo(&v,
                           JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("uid", converted_uid, UID_INVALID),
                           JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("gid", converted_gid, GID_INVALID),
                           JSON_BUILD_PAIR_STRING_NON_EMPTY("machineName", machine_name));
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

typedef struct MachineMountParameters {
        const char *name;
        PidRef pidref;
        const char *src;
        const char *dest;
        bool read_only;
        bool mkdir;
} MachineMountParameters;

static void machine_mount_paramaters_done(MachineMountParameters *p) {
        assert(p);

        pidref_done(&p->pidref);
}

int vl_method_bind_mount(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(MachineOpenParameters),
                { "source",      SD_JSON_VARIANT_STRING,  json_dispatch_const_path, offsetof(MachineMountParameters, src),       SD_JSON_MANDATORY },
                { "destination", SD_JSON_VARIANT_STRING,  json_dispatch_const_path, offsetof(MachineMountParameters, dest),      0                 },
                { "readOnly",    SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(MachineMountParameters, read_only), 0                 },
                { "mkdir",       SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(MachineMountParameters, mkdir),     0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(machine_mount_paramaters_done) MachineMountParameters p = {
                .pidref = PIDREF_NULL,
        };
        MountInNamespaceFlags mount_flags = 0;
        uid_t uid_shift;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* There is no need for extra validation since json_dispatch_const_path() does path_is_valid() and path_is_absolute(). */
        const char *dest = p.dest ?: p.src;

        Machine *machine;
        r = lookup_machine_by_name_or_pidref(link, manager, p.name, &p.pidref, &machine);
        if (r == -ESRCH)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
        if (r != 0)
                return r;

        if (machine->class != MACHINE_CONTAINER)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-machines",
                        (const char**) STRV_MAKE("name", machine->name,
                                                 "verb", "bind",
                                                 "src", p.src,
                                                 "dest", dest),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        r = machine_get_uid_shift(machine, &uid_shift);
        if (r < 0)
                return log_debug_errno(r, "Failed to get machine UID shift: %m");
        if (uid_shift != 0) {
                log_debug("Can't bind mount on container '%s' with user namespacing applied", machine->name);
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);
        }

        if (p.read_only)
                mount_flags |= MOUNT_IN_NAMESPACE_READ_ONLY;
        if (p.mkdir)
                mount_flags |= MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY;

        const char *propagate_directory = strjoina("/run/systemd/nspawn/propagate/", machine->name);

        r = bind_mount_in_namespace(
                        &machine->leader,
                        propagate_directory,
                        "/run/host/incoming/",
                        p.src,
                        dest,
                        mount_flags);
        if (r < 0)
                return log_debug_errno(r, "Failed to mount %s on %s in the namespace of machine '%s': %m", p.src, dest, machine->name);

        return sd_varlink_reply(link, NULL);
}

typedef struct MachineCopyParameters {
        const char *name;
        PidRef pidref;
        const char *src;
        const char *dest;
        bool replace;
} MachineCopyParameters;

static void machine_copy_paramaters_done(MachineCopyParameters *p) {
        assert(p);

        pidref_done(&p->pidref);
}

static int copy_done(Operation *operation, int ret, sd_bus_error *error) {
        assert(operation);
        assert(operation->link);

        if (ERRNO_IS_PRIVILEGE(ret))
                return sd_varlink_error(operation->link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(ret))
                return sd_varlink_error(operation->link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);
        if (ret < 0)
                return sd_varlink_error_errno(operation->link, ret);

        return sd_varlink_reply(operation->link, NULL);
}

int vl_method_copy_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata, bool copy_from) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(MachineCopyParameters),
                { "source",      SD_JSON_VARIANT_STRING,  json_dispatch_const_path, offsetof(MachineCopyParameters, src),     SD_JSON_MANDATORY },
                { "destination", SD_JSON_VARIANT_STRING,  json_dispatch_const_path, offsetof(MachineCopyParameters, dest),    0                 },
                { "replace",     SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(MachineCopyParameters, replace), 0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        int r;
        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(machine_copy_paramaters_done) MachineCopyParameters p = {
                .pidref = PIDREF_NULL
        };

        assert(link);
        assert(parameters);

        if (manager->n_operations >= OPERATIONS_MAX)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_TOO_MANY_OPERATIONS, NULL);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* There is no need for extra validation since json_dispatch_const_path() does path_is_valid() and path_is_absolute(). */
        const char *dest = p.dest ?: p.src;
        const char *container_path = copy_from ? p.src : dest;
        const char *host_path = copy_from ? dest : p.src;
        CopyFlags copy_flags = COPY_REFLINK|COPY_MERGE|COPY_HARDLINKS;
        copy_flags |= p.replace ? COPY_REPLACE : 0;

        Machine *machine;
        r = lookup_machine_by_name_or_pidref(link, manager, p.name, &p.pidref, &machine);
        if (r == -ESRCH)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
        if (r != 0)
                return r;

        if (machine->class != MACHINE_CONTAINER)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-machines",
                        (const char**) STRV_MAKE("name", machine->name,
                                                 "verb", "copy",
                                                 "src", p.src,
                                                 "dest", dest),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        Operation *op;
        r = machine_copy_from_to(manager, machine, host_path, container_path, copy_from, copy_flags, &op);
        if (r < 0)
                return r;

        operation_attach_varlink_reply(op, link);
        op->done = copy_done;
        return 1;
}

int vl_method_open_root_directory_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_close_ int fd = -EBADF;
        Machine *machine = ASSERT_PTR(userdata);
        Manager *manager = ASSERT_PTR(machine->manager);
        int r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-machines",
                        (const char**) STRV_MAKE("name", machine->name,
                                                 "verb", "open_root_directory"),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        fd = machine_open_root_directory(machine);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(fd))
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_SUPPORTED, NULL);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open root directory of machine '%s': %m", machine->name);

        int fd_idx = sd_varlink_push_fd(link, fd);
        if (ERRNO_IS_PRIVILEGE(fd_idx))
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);
        if (fd_idx < 0)
                return log_debug_errno(fd_idx, "Failed to push file descriptor over varlink: %m");

        TAKE_FD(fd);

        r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR_INTEGER("fileDescriptor", fd_idx));
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}
