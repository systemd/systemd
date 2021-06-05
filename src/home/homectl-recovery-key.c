/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "homectl-recovery-key.h"
#include "libcrypt-util.h"
#include "locale-util.h"
#include "memory-util.h"
#include "qrcode-util.h"
#include "random-util.h"
#include "recovery-key.h"
#include "strv.h"
#include "terminal-util.h"

static int add_privileged(JsonVariant **v, const char *hashed) {
        _cleanup_(json_variant_unrefp) JsonVariant *e = NULL, *w = NULL, *l = NULL;
        int r;

        assert(v);
        assert(hashed);

        r = json_build(&e, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("type", JSON_BUILD_STRING("modhex64")),
                                       JSON_BUILD_PAIR("hashedPassword", JSON_BUILD_STRING(hashed))));
        if (r < 0)
                return log_error_errno(r, "Failed to build recover key JSON object: %m");

        json_variant_sensitive(e);

        w = json_variant_ref(json_variant_by_key(*v, "privileged"));
        l = json_variant_ref(json_variant_by_key(w, "recoveryKey"));

        r = json_variant_append_array(&l, e);
        if (r < 0)
                return log_error_errno(r, "Failed append recovery key: %m");

        r = json_variant_set_field(&w, "recoveryKey", l);
        if (r < 0)
                return log_error_errno(r, "Failed to set recovery key array: %m");

        r = json_variant_set_field(v, "privileged", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update privileged field: %m");

        return 0;
}

static int add_public(JsonVariant **v) {
        _cleanup_strv_free_ char **types = NULL;
        int r;

        assert(v);

        r = json_variant_strv(json_variant_by_key(*v, "recoveryKeyType"), &types);
        if (r < 0)
                return log_error_errno(r, "Failed to parse recovery key type list: %m");

        r = strv_extend(&types, "modhex64");
        if (r < 0)
                return log_oom();

        r = json_variant_set_field_strv(v, "recoveryKeyType", types);
        if (r < 0)
                return log_error_errno(r, "Failed to update recovery key types: %m");

        return 0;
}

static int add_secret(JsonVariant **v, const char *password) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL, *l = NULL;
        _cleanup_(strv_free_erasep) char **passwords = NULL;
        int r;

        assert(v);
        assert(password);

        w = json_variant_ref(json_variant_by_key(*v, "secret"));
        l = json_variant_ref(json_variant_by_key(w, "password"));

        r = json_variant_strv(l, &passwords);
        if (r < 0)
                return log_error_errno(r, "Failed to convert password array: %m");

        r = strv_extend(&passwords, password);
        if (r < 0)
                return log_oom();

        r = json_variant_new_array_strv(&l, passwords);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate new password array JSON: %m");

        json_variant_sensitive(l);

        r = json_variant_set_field(&w, "password", l);
        if (r < 0)
                return log_error_errno(r, "Failed to update password field: %m");

        r = json_variant_set_field(v, "secret", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update secret object: %m");

        return 0;
}

int identity_add_recovery_key(JsonVariant **v) {
        _cleanup_(erase_and_freep) char *password = NULL, *hashed = NULL;
        int r;

        assert(v);

        /* First, let's generate a secret key  */
        r = make_recovery_key(&password);
        if (r < 0)
                return log_error_errno(r, "Failed to generate recovery key: %m");

        /* Let's UNIX hash it */
        r = hash_password(password, &hashed);
        if (r < 0)
                return log_error_errno(errno_or_else(EINVAL), "Failed to UNIX hash secret key: %m");

        /* Let's now add the "privileged" version of the recovery key */
        r = add_privileged(v, hashed);
        if (r < 0)
                return r;

        /* Let's then add the public information about the recovery key */
        r = add_public(v);
        if (r < 0)
                return r;

        /* Finally, let's add the new key to the secret part, too */
        r = add_secret(v, password);
        if (r < 0)
                return r;

        /* We output the key itself with a trailing newline to stdout and the decoration around it to stderr
         * instead. */

        fflush(stdout);
        fprintf(stderr,
                "A secret recovery key has been generated for this account:\n\n"
                "    %s%s%s",
                emoji_enabled() ? special_glyph(SPECIAL_GLYPH_LOCK_AND_KEY) : "",
                emoji_enabled() ? " " : "",
                ansi_highlight());
        fflush(stderr);

        fputs(password, stdout);
        fflush(stdout);

        fputs(ansi_normal(), stderr);
        fflush(stderr);

        fputc('\n', stdout);
        fflush(stdout);

        fputs("\nPlease save this secret recovery key at a secure location. It may be used to\n"
              "regain access to the account if the other configured access credentials have\n"
              "been lost or forgotten. The recovery key may be entered in place of a password\n"
              "whenever authentication is requested.\n", stderr);
        fflush(stderr);

        (void) print_qrcode(stderr, "You may optionally scan the recovery key off screen", password);

        return 0;
}
