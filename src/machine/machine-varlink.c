/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hostname-util.h"
#include "json.h"
#include "machine-varlink.h"
#include "machine.h"
#include "path-util.h"
#include "process-util.h"
#include "sd-id128.h"
#include "string-util.h"
#include "varlink.h"

static int machine_name(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **m = ASSERT_PTR(userdata);
        int r;

        assert(variant);

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        if (!hostname_is_valid(json_variant_string(variant), 0))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid machine name");

        r = free_and_strdup(m, json_variant_string(variant));
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

static int machine_class(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        MachineClass *class = ASSERT_PTR(userdata);

        assert(variant);

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        *class = machine_class_from_string(json_variant_string(variant));

        return 0;
}

static int machine_leader(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        PidRef *leader = ASSERT_PTR(userdata);
        uint64_t k;
        int r;

        if (!json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        k = json_variant_unsigned(variant);
        if (k > PID_T_MAX || !pid_is_valid(k))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid PID.", strna(name));

        if (k == 1)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid leader PID.", strna(name));

        r = pidref_set_pid(leader, k);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to pin process " PID_FMT ": %m", leader->pid);

        return 0;
}

static int json_dispatch_path(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        const char *path;
        char **p = ASSERT_PTR(userdata);
        int r;

        assert(variant);

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        path = strempty(json_variant_string(variant));
        if (!isempty(path) && !path_is_absolute(path))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' must be empty or an absolute path.", strna(name));

        r = free_and_strdup(p, path);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

static int machine_ifindices(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        Machine *m = ASSERT_PTR(userdata);
        _cleanup_free_ int *netif = NULL;
        size_t n_netif, k = 0;

        assert(variant);

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));


        n_netif = json_variant_elements(variant);

        netif = new(int, n_netif);
        if (!netif)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ENOMEM), "Out of memory.");

        JsonVariant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                uint64_t b;

                if (!json_variant_is_unsigned(i))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Element %zu of JSON field '%s' is not an unsigned integer.", k, strna(name));

                b = json_variant_unsigned(i);
                if (b > INT_MAX || b <= 0)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid network interface index %"PRIu64, b);

                netif[k++] = (int) b;
        }
        assert(k == n_netif);

        m->netif = TAKE_PTR(netif);
        m->n_netif = n_netif;

        return 0;
}

int vl_method_register(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(machine_freep) Machine *user_machine = NULL;
        Machine *managed_machine;
        int r;

        static const JsonDispatch dispatch_table[] = {
                { "name",              JSON_VARIANT_STRING,   machine_name,         offsetof(Machine, name),                 JSON_MANDATORY },
                { "id",                JSON_VARIANT_STRING,   json_dispatch_id128,  offsetof(Machine, id),                   0 },
                { "service",           JSON_VARIANT_STRING,   json_dispatch_string, offsetof(Machine, service),              0 },
                { "class",             JSON_VARIANT_STRING,   machine_class,        offsetof(Machine, class),                JSON_MANDATORY },
                { "leader",            JSON_VARIANT_UNSIGNED, machine_leader,       offsetof(Machine, leader),               0 },
                { "rootDirectory",     JSON_VARIANT_STRING,   json_dispatch_path,   offsetof(Machine, root_directory),       0 },
                { "ifIndices",         JSON_VARIANT_ARRAY,    machine_ifindices,    0,                                       0 },
                { "sshAddress",        JSON_VARIANT_STRING,   json_dispatch_string, offsetof(Machine, ssh_address),          JSON_SAFE },
                { "sshPrivateKeyPath", JSON_VARIANT_STRING,   json_dispatch_path,   offsetof(Machine, ssh_private_key_path), JSON_SAFE },
                {}
        };

        user_machine = new0(Machine, 1);
        if (!user_machine)
                return log_oom();

        r = varlink_dispatch(link, parameters, dispatch_table, user_machine);
        if (r != 0)
                return r;

        r = manager_add_machine(manager, user_machine->name, &managed_machine);
        if (r < 0)
                return r;

        managed_machine->name = user_machine->name;
        managed_machine->id = user_machine->id;
        managed_machine->service = user_machine->service;
        managed_machine->class = user_machine->class;
        managed_machine->leader = user_machine->leader;
        managed_machine->root_directory = user_machine->root_directory;
        managed_machine->netif = user_machine->netif;
        managed_machine->n_netif = user_machine->n_netif;
        managed_machine->ssh_address = user_machine->ssh_address;
        managed_machine->ssh_private_key_path = user_machine->ssh_private_key_path;

        user_machine = mfree(user_machine);

        return varlink_reply(link, NULL);
}
