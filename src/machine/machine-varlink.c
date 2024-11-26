/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "json-util.h"
#include "machine-varlink.h"
#include "machine.h"
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
                return sd_varlink_error(link, "io.systemd.Machine.MachineExists", NULL);
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
                return sd_varlink_error(link, "io.systemd.Machine.NoSuchMachine", NULL);
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
        const char *name, *user;
        PidRef pidref;
        MachineOpenMode mode;
        char *path, **args, **env;
} MachineOpenParameters;

static void machine_open_paramaters_done(MachineOpenParameters *p) {
        assert(p);
        pidref_done(&p->pidref);
        free(p->path);
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
                { "path",        SD_JSON_VARIANT_STRING, json_dispatch_path,                  offsetof(MachineOpenParameters, path), 0                 },
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

        r = sd_varlink_set_allow_fd_passing_output(link, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable varlink fd passing for write: %m");

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.mode == MACHINE_OPEN_MODE_SHELL) {
                /* json_dispatch_const_user_group_name() does valid_user_group_name(p.user) */
                /* json_dispatch_path() does path_is_absolute(p.path) */
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
                return sd_varlink_error(link, "io.systemd.Machine.NoSuchMachine", NULL);
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
                return sd_varlink_error(link, "io.systemd.Machine.NotSupported", NULL);
        if (ptmx_fd < 0)
                return log_debug_errno(ptmx_fd, "Failed to open pseudo terminal: %m");

        switch (p.mode) {
                case MACHINE_OPEN_MODE_TTY:
                        /* noop */
                        break;

                case MACHINE_OPEN_MODE_LOGIN:
                        r = machine_start_getty(machine, ptmx_name, /* error = */ NULL);
                        if (r == -ENOENT)
                                return sd_varlink_error(link, "io.systemd.Machine.NoIPC", NULL);
                        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                                return sd_varlink_error(link, "io.systemd.Machine.NotSupported", NULL);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to start getty for machine '%s': %m", machine->name);

                        break;

                case MACHINE_OPEN_MODE_SHELL: {
                        assert(user && path && args); /* to avoid gcc complaining about possible uninitialized variables */
                        r = machine_start_shell(machine, ptmx_fd, ptmx_name, user, path, args, p.env, /* error = */ NULL);
                        if (r == -ENOENT)
                                return sd_varlink_error(link, "io.systemd.Machine.NoIPC", NULL);
                        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                                return sd_varlink_error(link, "io.systemd.Machine.NotSupported", NULL);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to start shell for machine '%s': %m", machine->name);

                        break;
                }

                default:
                        assert_not_reached();
        }

        ptmx_fd_idx = sd_varlink_push_fd(link, ptmx_fd);
        /* no need to handle -EPERM because we do sd_varlink_set_allow_fd_passing_output() above */
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
