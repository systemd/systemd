/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-entry.h"
#include "fileio.h"
#include "id128-util.h"
#include "os-util.h"
#include "path-util.h"
#include "string-util.h"
#include "utf8.h"

bool boot_entry_token_valid(const char *p) {
        return utf8_is_valid(p) && string_is_safe(p) && filename_is_valid(p);
}

static int entry_token_load(const char *root, const char *etc_kernel, BootEntryTokenType *type, char **token) {
        _cleanup_free_ char *buf = NULL, *p = NULL;
        int r;

        assert(type);
        assert(*type == BOOT_ENTRY_TOKEN_AUTO);
        assert(token);

        if (!etc_kernel)
                return 0;

        p = path_join(root, etc_kernel, "entry-token");
        if (!p)
                return log_oom();

        r = read_one_line_file(p, &buf);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", p);

        if (isempty(buf))
                return 0;

        if (!boot_entry_token_valid(buf)) {
                log_debug("Invalid entry token specified in %s, ignoring.", p);
                return 0;
        }

        *token = TAKE_PTR(buf);
        *type = BOOT_ENTRY_TOKEN_LITERAL;
        return 1;
}

static int entry_token_from_machine_id(sd_id128_t machine_id, BootEntryTokenType *type, char **token) {
        char *p;

        assert(type);
        assert(IN_SET(*type, BOOT_ENTRY_TOKEN_AUTO, BOOT_ENTRY_TOKEN_MACHINE_ID));
        assert(token);

        if (sd_id128_is_null(machine_id))
                return 0;

        p = strdup(SD_ID128_TO_STRING(machine_id));
        if (!p)
                return log_oom();

        *token = p;
        *type = BOOT_ENTRY_TOKEN_MACHINE_ID;
        return 1;
}

static int entry_token_from_os_release(const char *root, BootEntryTokenType *type, char **token) {
        _cleanup_free_ char *id = NULL, *image_id = NULL;
        int r;

        assert(type);
        assert(IN_SET(*type, BOOT_ENTRY_TOKEN_AUTO, BOOT_ENTRY_TOKEN_OS_IMAGE_ID, BOOT_ENTRY_TOKEN_OS_ID));
        assert(token);

        switch (*type) {
        case BOOT_ENTRY_TOKEN_AUTO:
                r = parse_os_release(root,
                                     "IMAGE_ID", &image_id,
                                     "ID",       &id);
                break;

        case BOOT_ENTRY_TOKEN_OS_IMAGE_ID:
                r = parse_os_release(root, "IMAGE_ID", &image_id);
                break;

        case BOOT_ENTRY_TOKEN_OS_ID:
                r = parse_os_release(root, "ID", &id);
                break;

        default:
                assert_not_reached();
        }
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to load %s/etc/os-release: %m", strempty(root));

        if (!isempty(image_id) && boot_entry_token_valid(image_id)) {
                *token = TAKE_PTR(image_id);
                *type = BOOT_ENTRY_TOKEN_OS_IMAGE_ID;
                return 1;
        }

        if (!isempty(id) && boot_entry_token_valid(id)) {
                *token = TAKE_PTR(id);
                *type = BOOT_ENTRY_TOKEN_OS_ID;
                return 1;
        }

        return 0;
}

int boot_entry_token_ensure(
                const char *root,
                const char *etc_kernel,
                sd_id128_t machine_id,
                BootEntryTokenType *type,
                char **token) {

        int r;

        assert(type);
        assert(token);

        if (*token)
                return 0; /* Already set. */

        switch (*type) {

        case BOOT_ENTRY_TOKEN_AUTO:
                r = entry_token_load(root, etc_kernel, type, token);
                if (r != 0)
                        return r;

                r = entry_token_from_machine_id(machine_id, type, token);
                if (r != 0)
                        return r;

                r = entry_token_from_os_release(root, type, token);
                if (r != 0)
                        return r;

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No machine ID set, and %s/etc/os-release carries no ID=/IMAGE_ID= fields.",
                                       strempty(root));

        case BOOT_ENTRY_TOKEN_MACHINE_ID:
                r = entry_token_from_machine_id(machine_id, type, token);
                if (r != 0)
                        return r;

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No machine ID set.");

        case BOOT_ENTRY_TOKEN_OS_IMAGE_ID:
                r = entry_token_from_os_release(root, type, token);
                if (r != 0)
                        return r;

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "IMAGE_ID= field not set in %s/etc/os-release.",
                                       strempty(root));

        case BOOT_ENTRY_TOKEN_OS_ID:
                r = entry_token_from_os_release(root, type, token);
                if (r != 0)
                        return r;

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ID= field not set in %s/etc/os-release.",
                                       strempty(root));

        case BOOT_ENTRY_TOKEN_LITERAL:
                /* In this case, the token should be already set by the user input. */
                return -EINVAL;

        default:
                assert_not_reached();
        }
}

int parse_boot_entry_token_type(const char *s, BootEntryTokenType *type, char **token) {
        assert(s);
        assert(type);
        assert(token);

        /*
         * This function is intended to be used in command line parsers, to handle token that are passed in.
         *
         * NOTE THAT THIS WILL FREE THE PREVIOUS ARGUMENT POINTER ON SUCCESS!
         * Hence, do not pass in uninitialized pointers.
         */

        if (streq(s, "machine-id")) {
                *type = BOOT_ENTRY_TOKEN_MACHINE_ID;
                *token = mfree(*token);
                return 0;
        }

        if (streq(s, "os-image-id")) {
                *type = BOOT_ENTRY_TOKEN_OS_IMAGE_ID;
                *token = mfree(*token);
                return 0;
        }

        if (streq(s, "os-id")) {
                *type = BOOT_ENTRY_TOKEN_OS_ID;
                *token = mfree(*token);
                return 0;
        }

        const char *e = startswith(s, "literal:");
        if (e) {
                if (!boot_entry_token_valid(e))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid entry token literal is specified for --entry-token=.");

                *type = BOOT_ENTRY_TOKEN_LITERAL;
                return free_and_strdup_warn(token, e);
        }

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Unexpected parameter for --entry-token=: %s", s);
}
