/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdarg.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"
#include "string-util.h"
#include "vmspawn-qemu-config.h"

/* Enforce QEMU's identifier grammar, so runtime data can never inject config structure. */
static bool qemu_config_identifier_valid(const char *s) {
        return !isempty(s) && in_charset(s, ALPHANUMERICAL ".-_");
}

/* Values are written quoted ('key = "%s"') and QEMU reads them literally between the quotes (no escapes),
 * only '"' and newline can break out. Nevertheless run the value through string_is_safe(), which is
 * stricter than QEMU's own parser. Relax if a valid use case occurs. */
static bool qemu_config_value_valid(const char *value) {
        return string_is_safe(value, STRING_ALLOW_EMPTY | STRING_ALLOW_BACKSLASHES | STRING_ALLOW_GLOBS);
}

int qemu_config_key(FILE *f, const char *key, const char *value) {
        assert(f);
        assert(key);
        assert(value);

        if (!qemu_config_identifier_valid(key))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "QEMU config key '%s' is not a valid identifier.", key);
        if (!qemu_config_value_valid(value))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "QEMU config value '%s' contains unsafe characters.", value);

        if (fprintf(f, "  %s = \"%s\"\n", key, value) < 0)
                return -errno_or_else(EIO);

        return 0;
}

int qemu_config_keyf(FILE *f, const char *key, const char *format, ...) {
        _cleanup_free_ char *value = NULL;
        va_list ap;
        int r;

        assert(f);
        assert(key);
        assert(format);

        va_start(ap, format);
        r = vasprintf(&value, format, ap);
        va_end(ap);
        if (r < 0)
                return -ENOMEM;

        return qemu_config_key(f, key, value);
}

int qemu_config_section_impl(FILE *f, const char *type, const char *id, ...) {
        va_list ap;
        int r;

        assert(f);
        assert(type);

        if (!qemu_config_identifier_valid(type))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "QEMU config section type '%s' is not a valid identifier.", type);

        if (id) {
                if (!qemu_config_identifier_valid(id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "QEMU config section id '%s' is not a valid identifier.", id);
                fprintf(f, "\n[%s \"%s\"]\n", type, id);
        } else
                fprintf(f, "\n[%s]\n", type);

        va_start(ap, id);
        for (;;) {
                const char *key = va_arg(ap, const char *);
                if (!key)
                        break;

                const char *value = ASSERT_PTR(va_arg(ap, const char *));

                r = qemu_config_key(f, key, value);
                if (r < 0) {
                        va_end(ap);
                        return r;
                }
        }
        va_end(ap);

        if (ferror(f))
                return -errno_or_else(EIO);

        return 0;
}
