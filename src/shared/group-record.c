/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bitfield.h"
#include "group-record.h"
#include "json-util.h"
#include "strv.h"
#include "uid-classification.h"
#include "user-util.h"

GroupRecord* group_record_new(void) {
        GroupRecord *h;

        h = new(GroupRecord, 1);
        if (!h)
                return NULL;

        *h = (GroupRecord) {
                .n_ref = 1,
                .disposition = _USER_DISPOSITION_INVALID,
                .last_change_usec = UINT64_MAX,
                .gid = GID_INVALID,
        };

        return h;
}

static GroupRecord *group_record_free(GroupRecord *g) {
        if (!g)
                return NULL;

        free(g->group_name);
        free(g->realm);
        free(g->group_name_and_realm_auto);
        free(g->description);

        strv_free(g->members);
        free(g->service);
        strv_free(g->administrators);
        strv_free_erase(g->hashed_password);

        sd_json_variant_unref(g->json);

        return mfree(g);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(GroupRecord, group_record, group_record_free);

static int dispatch_privileged(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field privileged_dispatch_table[] = {
                { "hashedPassword", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_strv, offsetof(GroupRecord, hashed_password), SD_JSON_STRICT },
                {},
        };

        return sd_json_dispatch(variant, privileged_dispatch_table, flags, userdata);
}

static int dispatch_binding(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field binding_dispatch_table[] = {
                { "gid", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid, offsetof(GroupRecord, gid), 0 },
                {},
        };

        sd_json_variant *m;
        sd_id128_t mid;
        int r;

        if (!variant)
                return 0;

        if (!sd_json_variant_is_object(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an object.", strna(name));

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to determine machine ID: %m");

        m = sd_json_variant_by_key(variant, SD_ID128_TO_STRING(mid));
        if (!m)
                return 0;

        return sd_json_dispatch(m, binding_dispatch_table, flags, userdata);
}

static int dispatch_per_machine(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field per_machine_dispatch_table[] = {
                { "matchMachineId", _SD_JSON_VARIANT_TYPE_INVALID, NULL,                           0,                                     0             },
                { "matchHostname",  _SD_JSON_VARIANT_TYPE_INVALID, NULL,                           0,                                     0             },
                { "gid",            SD_JSON_VARIANT_UNSIGNED,      sd_json_dispatch_uid_gid,       offsetof(GroupRecord, gid),            0             },
                { "members",        SD_JSON_VARIANT_ARRAY,         json_dispatch_user_group_list,  offsetof(GroupRecord, members),        SD_JSON_RELAX },
                { "administrators", SD_JSON_VARIANT_ARRAY,         json_dispatch_user_group_list,  offsetof(GroupRecord, administrators), SD_JSON_RELAX },
                {},
        };

        sd_json_variant *e;
        int r;

        if (!variant)
                return 0;

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                if (!sd_json_variant_is_object(e))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array of objects.", strna(name));

                r = per_machine_match(e, flags);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = sd_json_dispatch(e, per_machine_dispatch_table, flags, userdata);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dispatch_status(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field status_dispatch_table[] = {
                { "service", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(GroupRecord, service), SD_JSON_STRICT },
                {},
        };

        sd_json_variant *m;
        sd_id128_t mid;
        int r;

        if (!variant)
                return 0;

        if (!sd_json_variant_is_object(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an object.", strna(name));

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to determine machine ID: %m");

        m = sd_json_variant_by_key(variant, SD_ID128_TO_STRING(mid));
        if (!m)
                return 0;

        return sd_json_dispatch(m, status_dispatch_table, flags, userdata);
}

static int group_record_augment(GroupRecord *h, sd_json_dispatch_flags_t json_flags) {
        assert(h);

        if (!FLAGS_SET(h->mask, USER_RECORD_REGULAR))
                return 0;

        assert(h->group_name);

        if (!h->group_name_and_realm_auto && h->realm) {
                h->group_name_and_realm_auto = strjoin(h->group_name, "@", h->realm);
                if (!h->group_name_and_realm_auto)
                        return json_log_oom(h->json, json_flags);
        }

        return 0;
}

int group_record_load(
                GroupRecord *h,
                sd_json_variant *v,
                UserRecordLoadFlags load_flags) {

        static const sd_json_dispatch_field group_dispatch_table[] = {
                { "groupName",      SD_JSON_VARIANT_STRING,        json_dispatch_user_group_name,  offsetof(GroupRecord, group_name),       SD_JSON_RELAX  },
                { "realm",          SD_JSON_VARIANT_STRING,        json_dispatch_realm,            offsetof(GroupRecord, realm),            0              },
                { "description",    SD_JSON_VARIANT_STRING,        json_dispatch_gecos,            offsetof(GroupRecord, description),      0              },
                { "disposition",    SD_JSON_VARIANT_STRING,        json_dispatch_user_disposition, offsetof(GroupRecord, disposition),      0              },
                { "service",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        offsetof(GroupRecord, service),          SD_JSON_STRICT },
                { "lastChangeUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(GroupRecord, last_change_usec), 0              },
                { "gid",            SD_JSON_VARIANT_UNSIGNED,      sd_json_dispatch_uid_gid,       offsetof(GroupRecord, gid),              0              },
                { "members",        SD_JSON_VARIANT_ARRAY,         json_dispatch_user_group_list,  offsetof(GroupRecord, members),          SD_JSON_RELAX  },
                { "administrators", SD_JSON_VARIANT_ARRAY,         json_dispatch_user_group_list,  offsetof(GroupRecord, administrators),   SD_JSON_RELAX  },

                { "privileged",     SD_JSON_VARIANT_OBJECT,        dispatch_privileged,            0,                                       0              },

                /* Not defined for now, for groups, but let's at least generate sensible errors about it */
                { "secret",         SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_unsupported,   0,                                       0              },

                /* Ignore the perMachine, binding and status stuff here, and process it later, so that it overrides whatever is set above */
                { "perMachine",     SD_JSON_VARIANT_ARRAY,         NULL,                           0,                                       0              },
                { "binding",        SD_JSON_VARIANT_OBJECT,        NULL,                           0,                                       0              },
                { "status",         SD_JSON_VARIANT_OBJECT,        NULL,                           0,                                       0              },

                /* Ignore 'signature', we check it with explicit accessors instead */
                { "signature",      SD_JSON_VARIANT_ARRAY,         NULL,                           0,                                       0              },
                {},
        };

        sd_json_dispatch_flags_t json_flags = USER_RECORD_LOAD_FLAGS_TO_JSON_DISPATCH_FLAGS(load_flags);
        int r;

        assert(h);
        assert(!h->json);

        /* Note that this call will leave a half-initialized record around on failure! */

        if ((USER_RECORD_REQUIRE_MASK(load_flags) & (USER_RECORD_SECRET|USER_RECORD_PRIVILEGED)))
                return json_log(v, json_flags, SYNTHETIC_ERRNO(EINVAL), "Secret and privileged section currently not available for groups, refusing.");

        r = user_group_record_mangle(v, load_flags, &h->json, &h->mask);
        if (r < 0)
                return r;

        r = sd_json_dispatch(h->json, group_dispatch_table, json_flags | SD_JSON_ALLOW_EXTENSIONS, h);
        if (r < 0)
                return r;

        /* During the parsing operation above we ignored the 'perMachine', 'binding' and 'status' fields, since we want
         * them to override the global options. Let's process them now. */

        r = dispatch_per_machine("perMachine", sd_json_variant_by_key(h->json, "perMachine"), json_flags, h);
        if (r < 0)
                return r;

        r = dispatch_binding("binding", sd_json_variant_by_key(h->json, "binding"), json_flags, h);
        if (r < 0)
                return r;

        r = dispatch_status("status", sd_json_variant_by_key(h->json, "status"), json_flags, h);
        if (r < 0)
                return r;

        if (FLAGS_SET(h->mask, USER_RECORD_REGULAR) && !h->group_name)
                return json_log(h->json, json_flags, SYNTHETIC_ERRNO(EINVAL), "Group name field missing, refusing.");

        r = group_record_augment(h, json_flags);
        if (r < 0)
                return r;

        return 0;
}

int group_record_build(GroupRecord **ret, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        va_list ap;
        int r;

        assert(ret);

        va_start(ap, ret);
        r = sd_json_buildv(&v, ap);
        va_end(ap);

        if (r < 0)
                return r;

        g = group_record_new();
        if (!g)
                return -ENOMEM;

        r = group_record_load(g, v, USER_RECORD_LOAD_FULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(g);
        return 0;
}

const char* group_record_group_name_and_realm(GroupRecord *h) {
        assert(h);

        /* Return the pre-initialized joined string if it is defined */
        if (h->group_name_and_realm_auto)
                return h->group_name_and_realm_auto;

        /* If it's not defined then we cannot have a realm */
        assert(!h->realm);
        return h->group_name;
}

UserDisposition group_record_disposition(GroupRecord *h) {
        assert(h);

        if (h->disposition >= 0)
                return h->disposition;

        /* If not declared, derive from GID */

        if (!gid_is_valid(h->gid))
                return _USER_DISPOSITION_INVALID;

        if (h->gid == 0 || h->gid == GID_NOBODY)
                return USER_INTRINSIC;

        if (gid_is_system(h->gid))
                return USER_SYSTEM;

        if (gid_is_dynamic(h->gid))
                return USER_DYNAMIC;

        if (gid_is_container(h->gid))
                return USER_CONTAINER;

        if (gid_is_foreign(h->gid))
                return USER_FOREIGN;

        if (h->gid > INT32_MAX)
                return USER_RESERVED;

        return USER_REGULAR;
}

int group_record_clone(GroupRecord *h, UserRecordLoadFlags flags, GroupRecord **ret) {
        _cleanup_(group_record_unrefp) GroupRecord *c = NULL;
        int r;

        assert(h);
        assert(ret);

        c = group_record_new();
        if (!c)
                return -ENOMEM;

        r = group_record_load(c, h->json, flags);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

bool group_record_matches_group_name(const GroupRecord *g, const char *group_name) {
        assert(g);
        assert(group_name);

        if (streq_ptr(g->group_name, group_name))
                return true;

        if (streq_ptr(g->group_name_and_realm_auto, group_name))
                return true;

        return false;
}

int group_record_match(GroupRecord *h, const UserDBMatch *match) {
        assert(h);

        if (!match)
                return true;

        if (h->gid < match->gid_min || h->gid > match->gid_max)
                return false;

        if (!BIT_SET(match->disposition_mask, group_record_disposition(h)))
                return false;

        if (!strv_isempty(match->fuzzy_names)) {
                const char* names[] = {
                        h->group_name,
                        group_record_group_name_and_realm(h),
                        h->description,
                };

                if (!user_name_fuzzy_match(names, ELEMENTSOF(names), match->fuzzy_names))
                        return false;
        }

        return true;
}
