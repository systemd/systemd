/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "bus-polkit.h"
#include "discover-image.h"
#include "format-util.h"
#include "hostname-util.h"
#include "image-varlink.h"
#include "json-util.h"
#include "machine-varlink.h"
#include "machined-varlink.h"
#include "mkdir.h"
#include "process-util.h"
#include "socket-util.h"
#include "user-util.h"
#include "varlink-io.systemd.Machine.h"
#include "varlink-io.systemd.MachineImage.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

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
                { "uid",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, uid),       0             },
                { "userName", SD_JSON_VARIANT_STRING,   json_dispatch_const_user_group_name, offsetof(LookupParameters, user_name), SD_JSON_RELAX },
                { "service",  SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string,       offsetof(LookupParameters, service),   0             },
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
                { "gid",       SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, gid),        0             },
                { "groupName", SD_JSON_VARIANT_STRING,   json_dispatch_const_user_group_name, offsetof(LookupParameters, group_name), SD_JSON_RELAX },
                { "service",   SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string,       offsetof(LookupParameters, service),    0             },
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
                { "userName",  SD_JSON_VARIANT_STRING, json_dispatch_const_user_group_name, offsetof(LookupParameters, user_name),  SD_JSON_RELAX },
                { "groupName", SD_JSON_VARIANT_STRING, json_dispatch_const_user_group_name, offsetof(LookupParameters, group_name), SD_JSON_RELAX },
                { "service",   SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,       offsetof(LookupParameters, service),    0             },
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

static int json_build_local_addresses(const struct local_address *addresses, size_t n_addresses, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(addresses || n_addresses == 0);
        assert(ret);

        FOREACH_ARRAY(a, addresses, n_addresses) {
                r = sd_json_variant_append_arraybo(
                                &array,
                                JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("ifindex", a->ifindex),
                                SD_JSON_BUILD_PAIR_INTEGER("family", a->family),
                                SD_JSON_BUILD_PAIR_BYTE_ARRAY("address", &a->address.bytes, FAMILY_ADDRESS_SIZE(a->family)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(array);
        return 0;
}

static int list_machine_one_and_maybe_read_metadata(sd_varlink *link, Machine *m, bool more, AcquireMetadata am) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *addr_array = NULL;
        _cleanup_strv_free_ char **os_release = NULL;
        uid_t shift = UID_INVALID;
        int r;

        assert(link);
        assert(m);

        if (should_acquire_metadata(am)) {
                _cleanup_free_ struct local_address *addresses = NULL;

                r = machine_get_addresses(m, &addresses);
                if (r < 0 && am == ACQUIRE_METADATA_GRACEFUL)
                        log_debug_errno(r, "Failed to get address (graceful mode), ignoring: %m");
                else if (r == -ENONET)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_PRIVATE_NETWORKING, NULL);
                else if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_AVAILABLE, NULL);
                else if (r < 0)
                        return log_debug_errno(r, "Failed to get addresses: %m");
                else {
                        r = json_build_local_addresses(addresses, r, &addr_array);
                        if (r < 0)
                                return r;
                }

                r = machine_get_os_release(m, &os_release);
                if (r < 0 && am == ACQUIRE_METADATA_GRACEFUL)
                        log_debug_errno(r, "Failed to get OS release (graceful mode), ignoring: %m");
                else if (r == -ENONET)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_OS_RELEASE_INFORMATION, NULL);
                else if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_AVAILABLE, NULL);
                else if (r < 0)
                        return log_debug_errno(r, "Failed to get OS release: %m");

                r = machine_get_uid_shift(m, &shift);
                if (r < 0 && am == ACQUIRE_METADATA_GRACEFUL)
                        log_debug_errno(r, "Failed to get UID shift (graceful mode), ignoring: %m");
                else if (r == -ENXIO)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_UID_SHIFT, NULL);
                else if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NOT_AVAILABLE, NULL);
                else if (r < 0)
                        return log_debug_errno(r, "Failed to get UID shift: %m");
        }

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR("name", SD_JSON_BUILD_STRING(m->name)),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(m->id), "id", SD_JSON_BUILD_ID128(m->id)),
                        SD_JSON_BUILD_PAIR("class", SD_JSON_BUILD_STRING(machine_class_to_string(m->class))),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("service", m->service),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("rootDirectory", m->root_directory),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("unit", m->unit),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(&m->leader), "leader", JSON_BUILD_PIDREF(&m->leader)),
                        SD_JSON_BUILD_PAIR_CONDITION(dual_timestamp_is_set(&m->timestamp), "timestamp", JSON_BUILD_DUAL_TIMESTAMP(&m->timestamp)),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("vSockCid", m->vsock_cid, VMADDR_CID_ANY),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("sshAddress", m->ssh_address),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("sshPrivateKeyPath", m->ssh_private_key_path),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("addresses", addr_array),
                        JSON_BUILD_PAIR_STRV_ENV_PAIR_NON_EMPTY("OSRelease", os_release),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("UIDShift", shift, UID_INVALID));
        if (r < 0)
                return r;

        if (more)
                return sd_varlink_notify(link, v);

        return sd_varlink_reply(link, v);
}

typedef struct MachineLookupParameters {
        const char *name;
        PidRef pidref;
        AcquireMetadata acquire_metadata;
} MachineLookupParameters;

static void machine_lookup_parameters_done(MachineLookupParameters *p) {
        assert(p);

        pidref_done(&p->pidref);
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_acquire_metadata, AcquireMetadata, acquire_metadata_from_string);

static int vl_method_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(MachineLookupParameters),
                { "acquireMetadata", SD_JSON_VARIANT_STRING, json_dispatch_acquire_metadata, offsetof(MachineLookupParameters, acquire_metadata), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(machine_lookup_parameters_done) MachineLookupParameters p = {
                .pidref = PIDREF_NULL,
        };

        Machine *machine;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.name || pidref_is_set(&p.pidref) || pidref_is_automatic(&p.pidref)) {
                r = lookup_machine_by_name_or_pidref(link, m, p.name, &p.pidref, &machine);
                if (r == -ESRCH)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
                if (r < 0)
                        return r;

                return list_machine_one_and_maybe_read_metadata(link, machine, /* more = */ false, p.acquire_metadata);
        }

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        Machine *previous = NULL, *i;
        HASHMAP_FOREACH(i, m->machines) {
                if (previous) {
                        r = list_machine_one_and_maybe_read_metadata(link, previous, /* more = */ true, p.acquire_metadata);
                        if (r < 0)
                                return r;
                }

                previous = i;
        }

        if (previous)
                return list_machine_one_and_maybe_read_metadata(link, previous, /* more = */ false, p.acquire_metadata);

        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
}

static int lookup_machine_and_call_method(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata, sd_varlink_method_t method) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(MachineLookupParameters),
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(machine_lookup_parameters_done) MachineLookupParameters p = {
                .pidref = PIDREF_NULL,
        };
        Machine *machine;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = lookup_machine_by_name_or_pidref(link, manager, p.name, &p.pidref, &machine);
        if (r == -ESRCH)
                return sd_varlink_error(link, VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE, NULL);
        if (r < 0)
                return r;

        return method(link, parameters, flags, machine);
}

static int vl_method_unregister(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return lookup_machine_and_call_method(link, parameters, flags, userdata, vl_method_unregister_internal);
}

static int vl_method_terminate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return lookup_machine_and_call_method(link, parameters, flags, userdata, vl_method_terminate_internal);
}

static int vl_method_copy_from(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_copy_internal(link, parameters, flags, userdata, /* copy_from = */ true);
}

static int vl_method_copy_to(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_copy_internal(link, parameters, flags, userdata, /* copy_from = */ false);
}

static int vl_method_open_root_directory(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return lookup_machine_and_call_method(link, parameters, flags, userdata, vl_method_open_root_directory_internal);
}

static int list_image_one_and_maybe_read_metadata(sd_varlink *link, Image *image, bool more, AcquireMetadata am) {
        int r;

        assert(link);
        assert(image);

        if (should_acquire_metadata(am) && !image->metadata_valid) {
                r = image_read_metadata(image, &image_policy_container);
                if (r < 0 && am != ACQUIRE_METADATA_GRACEFUL)
                        return log_debug_errno(r, "Failed to read image metadata: %m");
                if (r < 0)
                        log_debug_errno(r, "Failed to read image metadata (graceful mode), ignoring: %m");
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("name", image->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("path", image->path),
                        SD_JSON_BUILD_PAIR_STRING("type", image_type_to_string(image->type)),
                        SD_JSON_BUILD_PAIR_STRING("class", image_class_to_string(image->class)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("readOnly", image->read_only),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("creationTimestamp", image->crtime),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("modificationTimestamp", image->mtime),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("usage", image->usage, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("usageExclusive", image->usage_exclusive, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("limit", image->limit, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("limitExclusive", image->limit_exclusive, UINT64_MAX));
        if (r < 0)
                return r;

        if (should_acquire_metadata(am) && image->metadata_valid) {
                r = sd_json_variant_merge_objectbo(
                                &v,
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("hostname", image->hostname),
                                SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(image->machine_id), "machineId", SD_JSON_BUILD_ID128(image->machine_id)),
                                JSON_BUILD_PAIR_STRV_ENV_PAIR_NON_EMPTY("machineInfo", image->machine_info),
                                JSON_BUILD_PAIR_STRV_ENV_PAIR_NON_EMPTY("OSRelease", image->os_release));
                if (r < 0)
                        return r;
        }

        if (more)
                return sd_varlink_notify(link, v);

        return sd_varlink_reply(link, v);
}

static int vl_method_list_images(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        struct params {
                const char *image_name;
                AcquireMetadata acquire_metadata;
        } p = {};
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",            SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  offsetof(struct params, image_name),       0 },
                { "acquireMetadata", SD_JSON_VARIANT_STRING, json_dispatch_acquire_metadata, offsetof(struct params, acquire_metadata), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.image_name) {
                _cleanup_(image_unrefp) Image *found = NULL;

                if (!image_name_is_valid(p.image_name))
                        return sd_varlink_error_invalid_parameter_name(link, "name");

                r = image_find(m->runtime_scope, IMAGE_MACHINE, p.image_name, /* root = */ NULL, &found);
                if (r == -ENOENT)
                        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_IMAGE_NO_SUCH_IMAGE, NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to find image: %m");

                return list_image_one_and_maybe_read_metadata(link, found, /* more = */ false, p.acquire_metadata);
        }

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        _cleanup_hashmap_free_ Hashmap *images = hashmap_new(&image_hash_ops);
        if (!images)
                return -ENOMEM;

        r = image_discover(m->runtime_scope, IMAGE_MACHINE, /* root = */ NULL, images);
        if (r < 0)
                return log_debug_errno(r, "Failed to discover images: %m");

        Image *image, *previous = NULL;
        HASHMAP_FOREACH(image, images) {
                if (previous) {
                        r = list_image_one_and_maybe_read_metadata(link, previous, /* more = */ true, p.acquire_metadata);
                        if (r < 0)
                                return r;
                }

                previous = image;
        }

        if (previous)
                return list_image_one_and_maybe_read_metadata(link, previous, /* more = */ false, p.acquire_metadata);

        return sd_varlink_error(link, VARLINK_ERROR_MACHINE_IMAGE_NO_SUCH_IMAGE, NULL);
}

static int manager_varlink_init_userdb(Manager *m) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(m);

        if (m->varlink_userdb_server)
                return 0;

        r = varlink_server_new(&s, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

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

        r = varlink_server_new(
                        &s,
                        SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface_many(
                        s,
                        &vl_interface_io_systemd_Machine,
                        &vl_interface_io_systemd_MachineImage,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Machine and MachineImage interfaces to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Machine.Register",          vl_method_register,
                        "io.systemd.Machine.List",              vl_method_list,
                        "io.systemd.Machine.Unregister",        vl_method_unregister,
                        "io.systemd.Machine.Terminate",         vl_method_terminate,
                        "io.systemd.Machine.Kill",              vl_method_kill,
                        "io.systemd.Machine.Open",              vl_method_open,
                        "io.systemd.Machine.OpenRootDirectory", vl_method_open_root_directory,
                        "io.systemd.Machine.MapFrom",           vl_method_map_from,
                        "io.systemd.Machine.MapTo",             vl_method_map_to,
                        "io.systemd.Machine.BindMount",         vl_method_bind_mount,
                        "io.systemd.Machine.CopyFrom",          vl_method_copy_from,
                        "io.systemd.Machine.CopyTo",            vl_method_copy_to,
                        "io.systemd.MachineImage.List",         vl_method_list_images,
                        "io.systemd.MachineImage.Update",       vl_method_update_image,
                        "io.systemd.MachineImage.Clone",        vl_method_clone_image,
                        "io.systemd.MachineImage.Remove",       vl_method_remove_image,
                        "io.systemd.MachineImage.SetPoolLimit", vl_method_set_pool_limit,
                        "io.systemd.service.Ping",              varlink_method_ping,
                        "io.systemd.service.SetLogLevel",       varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment",    varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        (void) mkdir_p("/run/systemd/machine", 0755);

        r = sd_varlink_server_listen_address(s, "/run/systemd/machine/io.systemd.Machine", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to io.systemd.Machine varlink socket: %m");

        r = sd_varlink_server_listen_address(s, "/run/systemd/machine/io.systemd.MachineImage", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to io.systemd.MachineImage varlink socket: %m");

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
