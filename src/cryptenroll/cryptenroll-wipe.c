/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cryptenroll.h"
#include "cryptenroll-wipe.h"
#include "cryptsetup-util.h"
#include "json-util.h"
#include "log.h"
#include "parse-util.h"
#include "set.h"
#include "sort-util.h"

static int find_all_slots(struct crypt_device *cd, Set *wipe_slots, Set *keep_slots) {
        int slot_max;

        assert(cd);
        assert(wipe_slots);
        assert_se((slot_max = sym_crypt_keyslot_max(CRYPT_LUKS2)) > 0);

        /* Finds all currently assigned slots, and adds them to 'wipe_slots', except if listed already in 'keep_slots' */

        for (int slot = 0; slot < slot_max; slot++) {
                crypt_keyslot_info status;

                /* No need to check this slot if we already know we want to wipe it or definitely keep it. */
                if (set_contains(keep_slots, INT_TO_PTR(slot)) ||
                    set_contains(wipe_slots, INT_TO_PTR(slot)))
                        continue;

                status = sym_crypt_keyslot_status(cd, slot);
                if (!IN_SET(status, CRYPT_SLOT_ACTIVE, CRYPT_SLOT_ACTIVE_LAST))
                        continue;

                if (set_put(wipe_slots, INT_TO_PTR(slot)) < 0)
                        return log_oom();
        }

        return 0;
}

static int find_empty_passphrase_slots(struct crypt_device *cd, Set *wipe_slots, Set *keep_slots) {
        size_t vks;
        int r, slot_max;

        assert(cd);
        assert(wipe_slots);
        assert_se((slot_max = sym_crypt_keyslot_max(CRYPT_LUKS2)) > 0);

        /* Finds all slots with an empty passphrase assigned (i.e. "") and adds them to 'wipe_slots', except
         * if listed already in 'keep_slots' */

        r = sym_crypt_get_volume_key_size(cd);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine LUKS volume key size");
        vks = (size_t) r;

        for (int slot = 0; slot < slot_max; slot++) {
                _cleanup_(erase_and_freep) char *vk = NULL;
                crypt_keyslot_info status;

                /* No need to check this slot if we already know we want to wipe it or definitely keep it. */
                if (set_contains(keep_slots, INT_TO_PTR(slot)) ||
                    set_contains(wipe_slots, INT_TO_PTR(slot)))
                        continue;

                status = sym_crypt_keyslot_status(cd, slot);
                if (!IN_SET(status, CRYPT_SLOT_ACTIVE, CRYPT_SLOT_ACTIVE_LAST))
                        continue;

                vk = malloc(vks);
                if (!vk)
                        return log_oom();

                r = sym_crypt_volume_key_get(cd, slot, vk, &vks, "", 0);
                if (r < 0) {
                        log_debug_errno(r, "Failed to acquire volume key from slot %i with empty password, ignoring: %m", slot);
                        continue;
                }

                if (set_put(wipe_slots, INT_TO_PTR(r)) < 0)
                        return log_oom();
        }

        return 0;
}

static int find_slots_by_mask(
                struct crypt_device *cd,
                Set *wipe_slots,
                Set *keep_slots,
                unsigned by_mask) {

        _cleanup_set_free_ Set *listed_slots = NULL;
        int r;

        assert(cd);
        assert(wipe_slots);

        if (by_mask == 0)
                return 0;

        /* Find all slots that are associated with a token of a type in the specified token type mask */

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                sd_json_variant *w, *z;
                EnrollType t;

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

                t = luks2_token_type_from_string(sd_json_variant_string(w));

                w = sd_json_variant_by_key(v, "keyslots");
                if (!w || !sd_json_variant_is_array(w)) {
                        log_warning("Token JSON data lacks keyslots field, ignoring.");
                        continue;
                }

                JSON_VARIANT_ARRAY_FOREACH(z, w) {
                        int slot;

                        if (!sd_json_variant_is_string(z)) {
                                log_warning("Token JSON data's keyslot field is not an array of strings, ignoring.");
                                continue;
                        }

                        r = safe_atoi(sd_json_variant_string(z), &slot);
                        if (r < 0) {
                                log_warning_errno(r, "Token JSON data's keyslot filed is not an integer formatted as string, ignoring.");
                                continue;
                        }

                        if (t >= 0 && (by_mask & (1U << t)) != 0) {
                                /* Selected by token type */
                                if (set_put(wipe_slots, INT_TO_PTR(slot)) < 0)
                                        return log_oom();
                        } else if ((by_mask & (1U << ENROLL_PASSWORD)) != 0) {
                                /* If we shall remove all plain password slots, let's maintain a list of
                                 * slots that are listed in any tokens, since those are *NOT* plain
                                 * passwords */
                                if (set_ensure_allocated(&listed_slots, NULL) < 0)
                                        return log_oom();

                                if (set_put(listed_slots, INT_TO_PTR(slot)) < 0)
                                        return log_oom();
                        }
                }
        }

        /* "password" slots are those which have no token assigned. If we shall remove those, iterate through
         * all slots and mark those for wiping that weren't listed in any token */
        if ((by_mask & (1U << ENROLL_PASSWORD)) != 0) {
                int slot_max;

                assert_se((slot_max = sym_crypt_keyslot_max(CRYPT_LUKS2)) > 0);

                for (int slot = 0; slot < slot_max; slot++) {
                        crypt_keyslot_info status;

                        /* No need to check this slot if we already know we want to wipe it or definitely keep it. */
                        if (set_contains(keep_slots, INT_TO_PTR(slot)) ||
                            set_contains(wipe_slots, INT_TO_PTR(slot)))
                                continue;

                        if (set_contains(listed_slots, INT_TO_PTR(slot))) /* This has a token, hence is not a password. */
                                continue;

                        status = sym_crypt_keyslot_status(cd, slot);
                        if (!IN_SET(status, CRYPT_SLOT_ACTIVE, CRYPT_SLOT_ACTIVE_LAST)) /* Not actually assigned? */
                                continue;

                        /* Finally, we found a password, add it to the list of slots to wipe */
                        if (set_put(wipe_slots, INT_TO_PTR(slot)) < 0)
                                return log_oom();
                }
        }

        return 0;
}

static int find_slot_tokens(struct crypt_device *cd, Set *wipe_slots, Set *keep_slots, Set *wipe_tokens) {
        int r;

        assert(cd);
        assert(wipe_slots);
        assert(keep_slots);
        assert(wipe_tokens);

        /* Find all tokens matching the slots we want to wipe, so that we can wipe them too. Also, for update
         * the slots sets according to the token data: add any other slots listed in the tokens we act on. */

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                bool shall_wipe = false;
                sd_json_variant *w, *z;

                r = cryptsetup_get_token_as_json(cd, token, NULL, &v);
                if (IN_SET(r, -ENOENT, -EINVAL))
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read JSON token data off disk, ignoring: %m");
                        continue;
                }

                w = sd_json_variant_by_key(v, "keyslots");
                if (!w || !sd_json_variant_is_array(w)) {
                        log_warning("Token JSON data lacks keyslots field, ignoring.");
                        continue;
                }

                /* Go through the slots associated with this token: if we shall keep any slot of them, the token shall stay too. */
                JSON_VARIANT_ARRAY_FOREACH(z, w) {
                        int slot;

                        if (!sd_json_variant_is_string(z)) {
                                log_warning("Token JSON data's keyslot field is not an array of strings, ignoring.");
                                continue;
                        }

                        r = safe_atoi(sd_json_variant_string(z), &slot);
                        if (r < 0) {
                                log_warning_errno(r, "Token JSON data's keyslot filed is not an integer formatted as string, ignoring.");
                                continue;
                        }

                        if (set_contains(keep_slots, INT_TO_PTR(slot))) {
                                shall_wipe = false;
                                break; /* If we shall keep this slot, then this is definite: we will keep its token too */
                        }

                        /* If there's a slot associated with this token that we shall wipe, then remove the
                         * token too. But we are careful here: let's continue iterating, maybe there's a slot
                         * that we need to keep, in which case we can reverse the decision again. */
                        if (set_contains(wipe_slots, INT_TO_PTR(slot)))
                                shall_wipe = true;
                }

                /* Go through the slots again, and this time add them to the list of slots to keep/remove */
                JSON_VARIANT_ARRAY_FOREACH(z, w) {
                        int slot;

                        if (!sd_json_variant_is_string(z))
                                continue;
                        if (safe_atoi(sd_json_variant_string(z), &slot) < 0)
                                continue;

                        if (set_put(shall_wipe ? wipe_slots : keep_slots, INT_TO_PTR(slot)) < 0)
                                return log_oom();
                }

                /* And of course, also remember the tokens to remove. */
                if (shall_wipe)
                        if (set_put(wipe_tokens, INT_TO_PTR(token)) < 0)
                                return log_oom();
        }

        return 0;
}

static bool slots_remain(struct crypt_device *cd, Set *wipe_slots, Set *keep_slots) {
        int slot_max;

        assert(cd);
        assert_se((slot_max = sym_crypt_keyslot_max(CRYPT_LUKS2)) > 0);

        /* Checks if any slots remaining in the LUKS2 header if we remove all slots listed in 'wipe_slots'
         * (keeping those listed in 'keep_slots') */

        for (int slot = 0; slot < slot_max; slot++) {
                crypt_keyslot_info status;

                status = sym_crypt_keyslot_status(cd, slot);
                if (!IN_SET(status, CRYPT_SLOT_ACTIVE, CRYPT_SLOT_ACTIVE_LAST))
                        continue;

                /* The "keep" set wins if a slot is listed in both sets. This is important so that we can
                 * safely add a new slot and remove all others of the same type, which in a naive
                 * implementation might mean we remove what we just added — which we of course don't want. */
                if (set_contains(keep_slots, INT_TO_PTR(slot)) ||
                    !set_contains(wipe_slots, INT_TO_PTR(slot)))
                        return true;
        }

        return false;
}

int wipe_slots(struct crypt_device *cd,
               const int explicit_slots[],
               size_t n_explicit_slots,
               WipeScope by_scope,
               unsigned by_mask,
               int except_slot) {

        _cleanup_set_free_ Set *wipe_slots = NULL, *wipe_tokens = NULL, *keep_slots = NULL;
        _cleanup_free_ int *ordered_slots = NULL, *ordered_tokens = NULL;
        size_t n_ordered_slots = 0, n_ordered_tokens = 0;
        int r, slot_max, ret;
        void *e;

        assert_se(cd);

        /* Shortcut if nothing to wipe. */
        if (n_explicit_slots == 0 && by_mask == 0 && by_scope == WIPE_EXPLICIT)
                return 0;

        /* So this is a bit more complicated than I'd wish, but we want support three different axis for wiping slots:
         *
         *    1. Wiping by slot indexes
         *    2. Wiping slots of specified token types
         *    3. Wiping "all" entries, or entries with an empty password (i.e. "")
         *
         * (or any combination of the above)
         *
         * Plus: We always want to remove tokens matching the slots.
         * Plus: We always want to exclude the slots/tokens we just added.
         */

        wipe_slots = set_new(NULL);
        keep_slots = set_new(NULL);
        wipe_tokens = set_new(NULL);
        if (!wipe_slots || !keep_slots || !wipe_tokens)
                return log_oom();

        /* Let's maintain one set of slots for the slots we definitely want to keep */
        if (except_slot >= 0)
                if (set_put(keep_slots, INT_TO_PTR(except_slot)) < 0)
                        return log_oom();

        assert_se((slot_max = sym_crypt_keyslot_max(CRYPT_LUKS2)) > 0);

        /* Maintain another set of the slots we intend to wipe */
        for (size_t i = 0; i < n_explicit_slots; i++) {
                if (explicit_slots[i] >= slot_max)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Slot index %i out of range.", explicit_slots[i]);

                if (set_put(wipe_slots, INT_TO_PTR(explicit_slots[i])) < 0)
                        return log_oom();
        }

        /* Now, handle the "all" and "empty passphrase" cases. */
        switch (by_scope) {

        case WIPE_EXPLICIT:
                break; /* Nothing to do here */

        case WIPE_ALL:
                r = find_all_slots(cd, wipe_slots, keep_slots);
                if (r < 0)
                        return r;

                break;

        case WIPE_EMPTY_PASSPHRASE:
                r = find_empty_passphrase_slots(cd, wipe_slots, keep_slots);
                if (r < 0)
                        return r;

                break;
        default:
                assert_not_reached();
        }

        /* Then add all slots that match a token type */
        r = find_slots_by_mask(cd, wipe_slots, keep_slots, by_mask);
        if (r < 0)
                return r;

        /* And determine tokens that we shall remove */
        r = find_slot_tokens(cd, wipe_slots, keep_slots, wipe_tokens);
        if (r < 0)
                return r;

        /* Safety check: let's make sure that after we are done there's at least one slot remaining */
        if (!slots_remain(cd, wipe_slots, keep_slots))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Wipe operation would leave no valid slots around, can't allow that, sorry.");

        /* Generated ordered lists of the slots and the tokens to remove */
        ordered_slots = new(int, set_size(wipe_slots));
        if (!ordered_slots)
                return log_oom();
        SET_FOREACH(e, wipe_slots) {
                int slot = PTR_TO_INT(e);

                if (set_contains(keep_slots, INT_TO_PTR(slot)))
                        continue;

                ordered_slots[n_ordered_slots++] = slot;
        }
        typesafe_qsort(ordered_slots, n_ordered_slots, cmp_int);

        ordered_tokens = new(int, set_size(wipe_tokens));
        if (!ordered_tokens)
                return log_oom();
        SET_FOREACH(e, wipe_tokens)
                ordered_tokens[n_ordered_tokens++] = PTR_TO_INT(e);
        typesafe_qsort(ordered_tokens, n_ordered_tokens, cmp_int);

        if (n_ordered_slots == 0 && n_ordered_tokens == 0) {
                log_full(except_slot < 0 ? LOG_NOTICE : LOG_DEBUG,
                         "No slots to remove selected.");
                return 0;
        }

        if (DEBUG_LOGGING) {
                for (size_t i = 0; i < n_ordered_slots; i++)
                        log_debug("Going to wipe slot %i.", ordered_slots[i]);
                for (size_t i = 0; i < n_ordered_tokens; i++)
                        log_debug("Going to wipe token %i.", ordered_tokens[i]);
        }

        /* Now, let's actually start wiping things. (We go from back to front, to make space at the end
         * first.) */
        ret = 0;
        for (size_t i = n_ordered_slots; i > 0; i--) {
                r = sym_crypt_keyslot_destroy(cd, ordered_slots[i - 1]);
                if (r < 0) {
                        if (r == -ENOENT)
                                log_warning_errno(r, "Failed to wipe non-existent slot %i, continuing.", ordered_slots[i - 1]);
                        else
                                log_warning_errno(r, "Failed to wipe slot %i, continuing: %m", ordered_slots[i - 1]);
                        if (ret == 0)
                                ret = r;
                } else
                        log_info("Wiped slot %i.", ordered_slots[i - 1]);
        }

        for (size_t i = n_ordered_tokens; i > 0; i--) {
                r = sym_crypt_token_json_set(cd, ordered_tokens[i - 1], NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to wipe token %i, continuing: %m", ordered_tokens[i - 1]);
                        if (ret == 0)
                                ret = r;
                }
        }

        return ret;
}
