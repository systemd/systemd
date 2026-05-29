/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "cryptenroll.h"
#include "cryptenroll-list.h"
#include "cryptsetup-util.h"
#include "format-table.h"
#include "json-util.h"
#include "log.h"
#include "parse-util.h"

int collect_enrolled_slots(struct crypt_device *cd, EnrolledSlot **ret, size_t *ret_n) {
        _cleanup_free_ EnrolledSlot *slots = NULL;
        size_t n_slots = 0;
        int slot_max, r;

        assert(cd);
        assert(ret);
        assert(ret_n);

        /* First step, find out all currently used slots. A slot without an associated token is a bare
         * passphrase slot, hence default to ENROLL_PASSWORD. */
        assert_se((slot_max = sym_crypt_keyslot_max(CRYPT_LUKS2)) > 0);
        for (int slot = 0; slot < slot_max; slot++) {
                crypt_keyslot_info status;

                status = sym_crypt_keyslot_status(cd, slot);
                if (!IN_SET(status, CRYPT_SLOT_ACTIVE, CRYPT_SLOT_ACTIVE_LAST))
                        continue;

                if (!GREEDY_REALLOC(slots, n_slots + 1))
                        return log_oom();

                slots[n_slots++] = (EnrolledSlot) {
                        .slot = slot,
                        .type = ENROLL_PASSWORD,
                };
        }

        /* Second step, enumerate through all tokens, and update the slot table, indicating what kind of
         * token they are assigned to */
        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                sd_json_variant *w, *z;
                EnrollType et;

                r = cryptsetup_get_token_as_json(cd, token, NULL, &v);
                if (IN_SET(r, -ENOENT, -EINVAL))
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read JSON token data off disk, ignoring: %m");
                        continue;
                }

                w = sd_json_variant_by_key(v, "type");
                if (!w || !sd_json_variant_is_string(w)) {
                        log_warning("Token JSON data lacks type field, ignoring.");
                        continue;
                }

                et = luks2_token_type_from_string(sd_json_variant_string(w)); /* _ENROLL_TYPE_INVALID for unrecognized type */

                w = sd_json_variant_by_key(v, "keyslots");
                if (!w || !sd_json_variant_is_array(w)) {
                        log_warning("Token JSON data lacks keyslots field, ignoring.");
                        continue;
                }

                JSON_VARIANT_ARRAY_FOREACH(z, w) {
                        unsigned u;

                        if (!sd_json_variant_is_string(z)) {
                                log_warning("Token JSON data's keyslot field is not an array of strings, ignoring.");
                                continue;
                        }

                        r = safe_atou(sd_json_variant_string(z), &u);
                        if (r < 0) {
                                log_warning_errno(r, "Token JSON data's keyslot field is not an integer formatted as string, ignoring.");
                                continue;
                        }

                        FOREACH_ARRAY(s, slots, n_slots) {
                                if ((unsigned) s->slot != u)
                                        continue;

                                if (s->conflict) /* Already marked as claimed multiple times. */
                                        break;

                                if (s->type != ENROLL_PASSWORD) /* Slot already claimed by another token? */
                                        s->conflict = true;
                                else
                                        s->type = et;
                        }
                }
        }

        *ret = TAKE_PTR(slots);
        *ret_n = n_slots;
        return 0;
}

int list_enrolled(struct crypt_device *cd) {
        _cleanup_free_ EnrolledSlot *slots = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        size_t n_slots;
        int r;
        TableCell *cell;

        assert(cd);

        r = collect_enrolled_slots(cd, &slots, &n_slots);
        if (r < 0)
                return r;

        /* Create a table out of it all */
        t = table_new("slot", "type");
        if (!t)
                return log_oom();

        assert_se(cell = table_get_cell(t, 0, 0));
        (void) table_set_align_percent(t, cell, 100);

        FOREACH_ARRAY(s, slots, n_slots) {
                const char *type;

                if (s->conflict)
                        type = "conflict";
                else if (s->type < 0)
                        type = "other"; /* token of unrecognized type */
                else
                        type = enroll_type_to_string(s->type);

                r = table_add_many(
                                t,
                                TABLE_INT, s->slot,
                                TABLE_STRING, type);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (table_isempty(t)) {
                log_info("No slots found.");
                return 0;
        }

        return table_print_or_warn(t);
}
