/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "cryptenroll.h"
#include "cryptenroll-interactive.h"
#include "cryptenroll-list.h"
#include "cryptsetup-util.h"
#include "glyph-util.h"
#include "libfido2-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "prompt-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

static int collect_existing_types(struct crypt_device *cd, unsigned *ret_mask) {
        _cleanup_free_ EnrolledSlot *slots = NULL;
        size_t n_slots;
        unsigned mask = 0;
        int r;

        assert(cd);
        assert(ret_mask);

        r = collect_enrolled_slots(cd, &slots, &n_slots);
        if (r < 0)
                return r;

        FOREACH_ARRAY(s, slots, n_slots)
                if (!s->conflict && s->type >= 0)
                        mask |= 1U << s->type;

        *ret_mask = mask;
        return 0;
}

static int choose_mechanism(EnrollContext *c) {
        int r;

        assert(c);

        /* Top-level menu. Each iteration re-enumerates the FIDO2 tokens, so a token plugged in after the
         * menu was first shown appears once the user picks "Rescan". An empty answer leaves the volume
         * untouched. */

        for (;;) {
                Fido2DeviceInfo *devices = NULL;
                size_t n_devices = 0;
                CLEANUP_ARRAY(devices, n_devices, fido2_device_info_free_many);

                /* Best effort: if FIDO2 isn't available we simply offer no token rows. */
                (void) fido2_enumerate_devices(&devices, &n_devices);

                _cleanup_strv_free_ char **menu = strv_new("Enroll a recovery key", "Enroll a passphrase");
                if (!menu)
                        return log_oom();

                FOREACH_ARRAY(d, devices, n_devices) {
                        _cleanup_free_ char *label = NULL;

                        label = strjoin("Enroll FIDO2 security token: ",
                                        d->manufacturer ?: "Security Token",
                                        d->product ? " " : "", strempty(d->product),
                                        " (", d->path, ")");
                        if (!label)
                                return log_oom();

                        if (strv_consume(&menu, TAKE_PTR(label)) < 0)
                                return log_oom();
                }

                if (strv_extend(&menu, "Rescan for FIDO2 security tokens") < 0)
                        return log_oom();

                _cleanup_free_ char *choice = NULL;
                r = prompt_loop(
                                "Select enrollment option",
                                GLYPH_LOCK_AND_KEY,
                                /* prefill= */ NULL,
                                menu,
                                /* accepted= */ menu, /* only accept exact menu entries (or their numbers) */
                                /* ellipsize_percentage= */ 60,
                                /* n_columns= */ 1,
                                /* column_width= */ SIZE_MAX, /* auto-size to the widest entry */
                                /* is_valid= */ NULL,
                                /* refresh= */ NULL,
                                /* userdata= */ NULL,
                                PROMPT_MAY_SKIP|PROMPT_SHOW_MENU|PROMPT_SHOW_MENU_NOW|PROMPT_HIDE_MENU_HINT,
                                &choice);
                if (r < 0)
                        return r;
                if (!choice) {
                        /* Empty answer: do nothing. */
                        log_info("No selection made, leaving volume unchanged.");
                        return 0;
                }

                /* Map the chosen label back to its index. */
                size_t idx = SIZE_MAX;
                STRV_FOREACH(m, menu)
                        if (streq(*m, choice)) {
                                idx = m - menu;
                                break;
                        }

                assert(idx != SIZE_MAX);

                if (idx == 0)
                        c->enroll_type = ENROLL_RECOVERY;
                else if (idx == 1)
                        c->enroll_type = ENROLL_PASSWORD;
                else if (idx + 1 == strv_length(menu)) /* "Rescan" */
                        continue;
                else {
                        c->enroll_type = ENROLL_FIDO2;
                        assert(idx > 1);
                        assert(idx + 1 < strv_length(menu));

                        if (strdup_to(&c->fido2_device, devices[idx - 2].path) < 0)
                                return log_oom();
                }

                return 1;
        }
}

static int ask_wipe(EnrollContext *c, unsigned existing_mask) {
        static const EnrollType candidates[] = {
                ENROLL_PASSWORD,
                ENROLL_RECOVERY,
                ENROLL_FIDO2,
        };
        int r;

        assert(c);

        /* For each already-enrolled type the wizard understands, offer to wipe it alongside the new
         * enrollment. */

        FOREACH_ELEMENT(t, candidates) {
                if (!FLAGS_SET(existing_mask, 1U << *t))
                        continue;

                _cleanup_free_ char *question = NULL;
                question = strjoin("A ", enroll_type_to_string(*t), " slot is already enrolled. Wipe it as part of this enrollment?");
                if (!question)
                        return log_oom();

                bool wipe;
                r = prompt_loop_yes_no(question, /* def= */ false, &wipe);
                if (r < 0)
                        return r;

                if (wipe)
                        c->wipe_slots_mask |= 1U << *t;
        }

        return 0;
}

int cryptenroll_run_interactive(EnrollContext *c, unsigned prompt_suppress_mask) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        unsigned existing_mask = 0;
        int r;

        assert(c);
        assert(c->node);

        /* Honour the systemd.firstboot= kernel command line option, just like systemd-firstboot. */
        bool enabled;
        r = proc_cmdline_get_bool("systemd.firstboot", PROC_CMDLINE_TRUE_WHEN_MISSING, &enabled);
        if (r < 0)
                log_warning_errno(r, "Failed to parse systemd.firstboot= kernel command line option, ignoring: %m");
        else if (!enabled) {
                log_debug("systemd.firstboot=no set, skipping interactive enrollment.");
                return 0;
        }

        /* Open the volume just to inspect its header (no unlocking needed yet). */
        r = prepare_luks(c, &cd, /* ret_volume_key= */ NULL);
        if (r < 0)
                return r;

        r = collect_existing_types(cd, &existing_mask);
        if (r < 0)
                return r;

        /* If a credential of a suppressed type is already enrolled, do nothing. This lets the wizard be
         * wired into first boot but stay quiet once the system has been set up. */
        if ((existing_mask & prompt_suppress_mask) != 0) {
                log_debug("A credential of a suppressed type is already enrolled, skipping interactive setup.");
                return 0;
        }

        if (existing_mask == 0) {
                log_debug("No recognized LUKS slots, we're unlikely able to unlock, skipping interactive setup.");
                return 0;
        }

        /* Draw the installer-style chrome (blue bars at the top and bottom) around the wizard, matching
         * systemd-sysinstall. The caller hides it again via a deferred chrome_hide() once enrollment is
         * complete. */
        (void) terminal_reset_defensive_locked(STDOUT_FILENO, /* flags= */ 0);
        (void) chrome_show("Additional Disk Encryption Key Enrollment", /* bottom= */ NULL);

        printf("%s%s%sLet's enroll additional disk encryption mechanisms for recovering access to the system.%s\n\n",
               emoji_enabled() ? glyph(GLYPH_COMPUTER_DISK) : "", emoji_enabled() ? " " : "",
               ansi_highlight(), ansi_normal());

        _cleanup_free_ char *s = NULL;
        for (EnrollType t = 0; t < _ENROLL_TYPE_MAX; t++) {
                if (!FLAGS_SET(existing_mask, 1 << t))
                        continue;

                if (!strextend_with_separator(&s, ", ", enroll_type_to_string(t)))
                        return log_oom();
        }

        printf("Currently enrolled mechanisms: %s\n\n", s);

        r = choose_mechanism(c);
        if (r <= 0)
                return r;

        r = ask_wipe(c, existing_mask);
        if (r < 0)
                return r;

        return 1;
}
