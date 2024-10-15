/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "hostname-util.h"
#include "json-util.h"
#include "machine-varlink.h"
#include "machine.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
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

        /* This returns 0 on success, 1 on error and it is replied, and a negative errno otherwise. */

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
        if (r != 0)
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
