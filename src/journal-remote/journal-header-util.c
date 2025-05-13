/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "escape.h"
#include "hashmap.h"
#include "journal-header-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"

/* According to https://developers.cloudflare.com/rules/transform/request-header-modification/reference/header-format/
 * HTTP header name can contain:
 * - Alphanumeric characters: a-z, A-Z, and 0-9
 * - The following special characters: - and _
 */
#define VALID_HEADER_NAME_CHARS \
        ALPHANUMERICAL "_-"

#define HEADER_NAME_LENGTH_MAX 40

/* No RFC defines this limit, added for safety */
#define HEADER_VALUE_LENGTH_MAX 8000

/* According to https://developers.cloudflare.com/rules/transform/request-header-modification/reference/header-format/
 * HTTP header value can contain:
 * - Alphanumeric characters: a-z, A-Z, and 0-9
 * - The following special characters: _ :;.,\/"'?!(){}[]@<>=-+*#$&`|~^%
 */
#define VALID_HEADER_VALUE_CHARS \
        ALPHANUMERICAL "_ :;.,\\/'\"?!(){}[]@<>=-+*#$&`|~^%"

bool header_name_is_valid(const char *e) {
        if (isempty(e))
                return false;

        if (strlen(e) > HEADER_NAME_LENGTH_MAX)
                return false;

        return in_charset(e, VALID_HEADER_NAME_CHARS);
}

bool header_value_is_valid(const char *e) {
        if (!e)
                return false;

        if (strlen(e) > HEADER_VALUE_LENGTH_MAX)
                return false;

        return in_charset(e, VALID_HEADER_VALUE_CHARS);
}

int header_put(OrderedHashmap **headers, const char *name, const char *value) {
        assert(headers);

        if (!header_value_is_valid(value))
                return -EINVAL;

        if (!header_name_is_valid(name))
                return -EINVAL;

        return string_strv_ordered_hashmap_put(headers, name, value);
}

int config_parse_header(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        OrderedHashmap **headers = ASSERT_PTR(data);
        _cleanup_free_ char *unescaped = NULL;
        char *t;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* an empty string clears the previous assignments. */
                *headers = ordered_hashmap_free(*headers);
                return 1;
        }

        r = cunescape(rvalue, 0, &unescaped);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to unescape headers, ignoring: %s", rvalue);
                return 0;
        }

        t = strchr(unescaped, ':');
        if (!t) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Failed to parse header, name: value separator was not found, ignoring: %s", unescaped);
                return 0;
        }

        *t++ = '\0';

        r = header_put(headers, strstrip(unescaped), skip_leading_chars(t, WHITESPACE));
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to update headers, ignoring: %s", rvalue);
                return 0;
        }

        return 1;
}
