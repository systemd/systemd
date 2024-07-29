/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "format-util.h"
#include "hostname-util.h"
#include "json-util.h"
#include "machine-varlink.h"
#include "machined-varlink.h"
#include "mkdir.h"
#include "socket-util.h"
#include "user-util.h"
#include "varlink-io.systemd.Machine.h"
#include "varlink-io.systemd.UserDatabase.h"

typedef struct LookupParameters {
        const char *user_name;
        const char *group_name;
        union {
                uid_t uid;
                gid_t gid;
        };
        const char *service;
} LookupParameters;

static int build_user_json(const char *user_name, uid_t uid, const char *real_name, sd_json_variant **ret) {
        assert(user_name);
        assert(uid_is_valid(uid));
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_OBJECT(
                                                           SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(user_name)),
                                                           SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)),
                                                           SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(GID_NOBODY)),
                                                           SD_JSON_BUILD_PAIR_CONDITION(!isempty(real_name), "realName", SD_JSON_BUILD_STRING(real_name)),
                                                           SD_JSON_BUILD_PAIR("homeDirectory", JSON_BUILD_CONST_STRING("/")),
                                                           SD_JSON_BUILD_PAIR("shell", JSON_BUILD_CONST_STRING(NOLOGIN)),
                                                           SD_JSON_BUILD_PAIR("locked", SD_JSON_BUILD_BOOLEAN(true)),
                                                           SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.Machine")),
                                                           SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("container")))));
}

static bool user_match_lookup_parameters(LookupParameters *p, const char *name, uid_t uid) {
        assert(p);

        if (p->user_name && !streq(name, p->user_name))
                return false;

        if (uid_is_valid(p->uid) && uid != p->uid)
                return false;

        return true;
}

static int user_lookup_uid(Manager *m, uid_t uid, char **ret_name, char **ret_real_name) {
        _cleanup_free_ char *n = NULL, *rn = NULL;
        uid_t converted_uid;
        Machine *machine;
        int r;

        assert(m);
        assert(uid_is_valid(uid));
        assert(ret_name);
        assert(ret_real_name);

        if (uid < 0x10000) /* Host UID range */
                return -ESRCH;

        r = manager_find_machine_for_uid(m, uid, &machine, &converted_uid);
        if (r < 0)
                return r;
        if (!r)
                return -ESRCH;

        if (asprintf(&n, "vu-%s-" UID_FMT, machine->name, converted_uid) < 0)
                return -ENOMEM;

        /* Don't synthesize invalid user/group names (too long...) */
        if (!valid_user_group_name(n, 0))
                return -ESRCH;

        if (asprintf(&rn, "UID " UID_FMT " of Container %s", converted_uid, machine->name) < 0)
                return -ENOMEM;

        /* Don't synthesize invalid real names either, but since this field doesn't matter much, simply invalidate things */
        if (!valid_gecos(rn))
                rn = mfree(rn);

        *ret_name = TAKE_PTR(n);
        *ret_real_name = TAKE_PTR(rn);
        return 0;
}

static int user_lookup_name(Manager *m, const char *name, uid_t *ret_uid, char **ret_real_name) {
        _cleanup_free_ char *mn = NULL, *rn = NULL;
        uid_t uid, converted_uid;
        Machine *machine;
        const char *e, *d;
        int r;

        assert(m);
        assert(ret_uid);
        assert(ret_real_name);

        if (!valid_user_group_name(name, 0))
                return -ESRCH;

        e = startswith(name, "vu-");
        if (!e)
                return -ESRCH;

        d = strrchr(e, '-');
        if (!d)
                return -ESRCH;

        if (parse_uid(d + 1, &uid) < 0)
                return -ESRCH;

        mn = strndup(e, d - e);
        if (!mn)
                return -ENOMEM;

        machine = hashmap_get(m->machines, mn);
        if (!machine)
                return -ESRCH;

        if (machine->class != MACHINE_CONTAINER)
                return -ESRCH;

        r = machine_translate_uid(machine, uid, &converted_uid);
        if (r < 0)
                return r;

        if (asprintf(&rn, "UID " UID_FMT " of Container %s", uid, machine->name) < 0)
                return -ENOMEM;
        if (!valid_gecos(rn))
                rn = mfree(rn);

        *ret_uid = converted_uid;
        *ret_real_name = TAKE_PTR(rn);
        return 0;
}

static int vl_method_get_user_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "uid",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid,      offsetof(LookupParameters, uid),       0              },
                { "userName", SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, offsetof(LookupParameters, user_name), SD_JSON_STRICT },
                { "service",  SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, offsetof(LookupParameters, service),   0              },
                {}
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        LookupParameters p = {
                .uid = UID_INVALID,
        };
        _cleanup_free_ char *found_name = NULL, *found_real_name = NULL;
        uid_t found_uid = UID_INVALID, uid;
        Manager *m = ASSERT_PTR(userdata);
        const char *un;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.Machine"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (uid_is_valid(p.uid))
                r = user_lookup_uid(m, p.uid, &found_name, &found_real_name);
        else if (p.user_name)
                r = user_lookup_name(m, p.user_name, &found_uid, &found_real_name);
        else
                return sd_varlink_error(link, "io.systemd.UserDatabase.EnumerationNotSupported", NULL);
        if (r == -ESRCH)
                return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
        if (r < 0)
                return r;

        uid = uid_is_valid(found_uid) ? found_uid : p.uid;
        un = found_name ?: p.user_name;

        if (!user_match_lookup_parameters(&p, un, uid))
                return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        r = build_user_json(un, uid, found_real_name, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

static int build_group_json(const char *group_name, gid_t gid, const char *description, sd_json_variant **ret) {
        assert(group_name);
        assert(gid_is_valid(gid));
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_OBJECT(
                                                           SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(group_name)),
                                                           SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(gid)),
                                                           SD_JSON_BUILD_PAIR_CONDITION(!isempty(description), "description", SD_JSON_BUILD_STRING(description)),
                                                           SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.Machine")),
                                                           SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("container")))));
}

static bool group_match_lookup_parameters(LookupParameters *p, const char *name, gid_t gid) {
        assert(p);

        if (p->group_name && !streq(name, p->group_name))
                return false;

        if (gid_is_valid(p->gid) && gid != p->gid)
                return false;

        return true;
}

static int group_lookup_gid(Manager *m, gid_t gid, char **ret_name, char **ret_description) {
        _cleanup_free_ char *n = NULL, *d = NULL;
        gid_t converted_gid;
        Machine *machine;
        int r;

        assert(m);
        assert(gid_is_valid(gid));
        assert(ret_name);
        assert(ret_description);

        if (gid < 0x10000) /* Host GID range */
                return -ESRCH;

        r = manager_find_machine_for_gid(m, gid, &machine, &converted_gid);
        if (r < 0)
                return r;
        if (!r)
                return -ESRCH;

        if (asprintf(&n, "vg-%s-" GID_FMT, machine->name, converted_gid) < 0)
                return -ENOMEM;

        if (!valid_user_group_name(n, 0))
                return -ESRCH;

        if (asprintf(&d, "GID " GID_FMT " of Container %s", converted_gid, machine->name) < 0)
                return -ENOMEM;
        if (!valid_gecos(d))
                d = mfree(d);

        *ret_name = TAKE_PTR(n);
        *ret_description = TAKE_PTR(d);

        return 0;
}

static int group_lookup_name(Manager *m, const char *name, gid_t *ret_gid, char **ret_description) {
        _cleanup_free_ char *mn = NULL, *desc = NULL;
        gid_t gid, converted_gid;
        Machine *machine;
        const char *e, *d;
        int r;

        assert(m);
        assert(ret_gid);
        assert(ret_description);

        if (!valid_user_group_name(name, 0))
                return -ESRCH;

        e = startswith(name, "vg-");
        if (!e)
                return -ESRCH;

        d = strrchr(e, '-');
        if (!d)
                return -ESRCH;

        if (parse_gid(d + 1, &gid) < 0)
                return -ESRCH;

        mn = strndup(e, d - e);
        if (!mn)
                return -ENOMEM;

        machine = hashmap_get(m->machines, mn);
        if (!machine)
                return -ESRCH;

        if (machine->class != MACHINE_CONTAINER)
                return -ESRCH;

        r = machine_translate_gid(machine, gid, &converted_gid);
        if (r < 0)
                return r;

        if (asprintf(&desc, "GID " GID_FMT " of Container %s", gid, machine->name) < 0)
                return -ENOMEM;
        if (!valid_gecos(desc))
                desc = mfree(desc);

        *ret_gid = converted_gid;
        *ret_description = TAKE_PTR(desc);
        return 0;
}

static int vl_method_get_group_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "gid",       SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid,      offsetof(LookupParameters, gid),        0              },
                { "groupName", SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, offsetof(LookupParameters, group_name), SD_JSON_STRICT },
                { "service",   SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, offsetof(LookupParameters, service),    0              },
                {}
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        LookupParameters p = {
                .gid = GID_INVALID,
        };
        _cleanup_free_ char *found_name = NULL, *found_description = NULL;
        uid_t found_gid = GID_INVALID, gid;
        Manager *m = ASSERT_PTR(userdata);
        const char *gn;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.Machine"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (gid_is_valid(p.gid))
                r = group_lookup_gid(m, p.gid, &found_name, &found_description);
        else if (p.group_name)
                r = group_lookup_name(m, p.group_name, (uid_t*) &found_gid, &found_description);
        else
                return sd_varlink_error(link, "io.systemd.UserDatabase.EnumerationNotSupported", NULL);
        if (r == -ESRCH)
                return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
        if (r < 0)
                return r;

        gid = gid_is_valid(found_gid) ? found_gid : p.gid;
        gn = found_name ?: p.group_name;

        if (!group_match_lookup_parameters(&p, gn, gid))
                return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        r = build_group_json(gn, gid, found_description, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

static int vl_method_get_memberships(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "userName",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(LookupParameters, user_name),  SD_JSON_STRICT },
                { "groupName", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(LookupParameters, group_name), SD_JSON_STRICT },
                { "service",   SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(LookupParameters, service),    0              },
                {}
        };

        LookupParameters p = {};
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.Machine"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        /* We don't support auxiliary groups for machines. */
        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}

static int list_machine_one(sd_varlink *link, Machine *m, bool more) {
        int r;

        assert(link);
        assert(m);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR("name", SD_JSON_BUILD_STRING(m->name)),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(m->id), "id", SD_JSON_BUILD_ID128(m->id)),
                        SD_JSON_BUILD_PAIR("class", SD_JSON_BUILD_STRING(machine_class_to_string(m->class))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->service, "service", SD_JSON_BUILD_STRING(m->service)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->root_directory, "rootDirectory", SD_JSON_BUILD_STRING(m->root_directory)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->unit, "unit", SD_JSON_BUILD_STRING(m->unit)),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(&m->leader), "leader", SD_JSON_BUILD_UNSIGNED(m->leader.pid)),
                        SD_JSON_BUILD_PAIR_CONDITION(dual_timestamp_is_set(&m->timestamp), "timestamp", JSON_BUILD_DUAL_TIMESTAMP(&m->timestamp)),
                        SD_JSON_BUILD_PAIR_CONDITION(m->vsock_cid != VMADDR_CID_ANY, "vSockCid", SD_JSON_BUILD_UNSIGNED(m->vsock_cid)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!m->ssh_address, "sshAddress", SD_JSON_BUILD_STRING(m->ssh_address)));
        if (r < 0)
                return r;

        if (more)
                return sd_varlink_notify(link, v);

        return sd_varlink_reply(link, v);
}

static int vl_method_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        const char *mn = NULL;

        const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, PTR_TO_SIZE(&mn), 0 },
                {}
        };

        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, 0);
        if (r != 0)
                return r;

        if (mn) {
                if (!hostname_is_valid(mn, /* flags= */ VALID_HOSTNAME_DOT_HOST))
                        return sd_varlink_error_invalid_parameter_name(link, "name");

                Machine *machine = hashmap_get(m->machines, mn);
                if (!machine)
                        return sd_varlink_error(link, "io.systemd.Machine.NoSuchMachine", NULL);

                return list_machine_one(link, machine, /* more= */ false);
        }

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        Machine *previous = NULL, *i;
        HASHMAP_FOREACH(i, m->machines) {
                if (previous) {
                        r = list_machine_one(link, previous, /* more= */ true);
                        if (r < 0)
                                return r;
                }

                previous = i;
        }

        if (previous)
                return list_machine_one(link, previous, /* more= */ false);

        return sd_varlink_error(link, "io.systemd.Machine.NoSuchMachine", NULL);
}

static int manager_varlink_init_userdb(Manager *m) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(m);

        if (m->varlink_userdb_server)
                return 0;

        r = sd_varlink_server_new(&s, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        sd_varlink_server_set_userdata(s, m);

        r = sd_varlink_server_add_interface(s, &vl_interface_io_systemd_UserDatabase);
        if (r < 0)
                return log_error_errno(r, "Failed to add UserDatabase interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.UserDatabase.GetUserRecord",  vl_method_get_user_record,
                        "io.systemd.UserDatabase.GetGroupRecord", vl_method_get_group_record,
                        "io.systemd.UserDatabase.GetMemberships", vl_method_get_memberships);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        (void) mkdir_p("/run/systemd/userdb", 0755);

        r = sd_varlink_server_listen_address(s, "/run/systemd/userdb/io.systemd.Machine", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = sd_varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_userdb_server = TAKE_PTR(s);
        return 0;
}

static int manager_varlink_init_machine(Manager *m) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(m);

        if (m->varlink_machine_server)
                return 0;

        r = sd_varlink_server_new(&s, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        sd_varlink_server_set_userdata(s, m);

        r = sd_varlink_server_add_interface(s, &vl_interface_io_systemd_Machine);
        if (r < 0)
                return log_error_errno(r, "Failed to add UserDatabase interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Machine.Register", vl_method_register,
                        "io.systemd.Machine.List",     vl_method_list);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        (void) mkdir_p("/run/systemd/machine", 0755);

        r = sd_varlink_server_listen_address(s, "/run/systemd/machine/io.systemd.Machine", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = sd_varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_machine_server = TAKE_PTR(s);
        return 0;
}

int manager_varlink_init(Manager *m) {
        int r;

        r = manager_varlink_init_userdb(m);
        if (r < 0)
                return r;

        r = manager_varlink_init_machine(m);
        if (r < 0)
                return r;

        return 0;
}

void manager_varlink_done(Manager *m) {
        assert(m);

        m->varlink_userdb_server = sd_varlink_server_unref(m->varlink_userdb_server);
        m->varlink_machine_server = sd_varlink_server_unref(m->varlink_machine_server);
}
