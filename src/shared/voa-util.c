/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "constants.h"
#include "forward.h"
#include "log.h"
#include "macro.h"
#include "os-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "string-table.h"
#include "voa-util.h"

static const char* const voa_purpose_table[_VOA_PURPOSE_MAX] = {
        [VOA_PURPOSE_IMAGE]   = "image",
        [VOA_PURPOSE_PACKAGE] = "package",
};

DEFINE_STRING_TABLE_LOOKUP(voa_purpose, VOAPurpose);

static const char* const voa_context_table[_VOA_CONTEXT_MAX] = {
        [VOA_CONTEXT_MACHINE]   = "machine",
        [VOA_CONTEXT_PORTABLE]  = "portable",
        [VOA_CONTEXT_SYSEXT]    = "sysext",
        [VOA_CONTEXT_CONFEXT]   = "confext",
        [VOA_CONTEXT_HOST]      = "host",
        [VOA_CONTEXT_COMPONENT] = "component",
};

DEFINE_STRING_TABLE_LOOKUP(voa_context, VOAContext);

static const char* const voa_technology_table[_VOA_TECHNOLOGY_MAX] = {
        [VOA_TECHNOLOGY_X509] = "x509",
        [VOA_TECHNOLOGY_GPG]  = "gpg",
        [VOA_TECHNOLOGY_SSH]  = "ssh",
};

DEFINE_STRING_TABLE_LOOKUP(voa_technology, VOATechnology);

int acquire_voa_paths_full(char ***ret, VOAPurpose purpose, VOAContext context, VOATechnology technology, bool trust_anchor) {
        _cleanup_strv_free_ char **dirs = NULL;
        _cleanup_free_ char *os_str = NULL;
        _cleanup_free_ char *purpose_str = NULL;
        int r;

        assert(purpose >= 0);
        assert(purpose < _VOA_PURPOSE_MAX);
        assert(context >= 0);
        assert(context < _VOA_CONTEXT_MAX);
        assert(technology >= 0);
        assert(technology < _VOA_TECHNOLOGY_MAX);

        r = parse_os_release(/* root= */ NULL, "ID", &os_str);
        if (r < 0)
                return log_error_errno(r, "Failed to read os-release file: %m");
        if (isempty(os_str))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to get ID field from os-release file");

        if (trust_anchor) {
                purpose_str = strjoin("trust-anchor-", voa_purpose_to_string(purpose));
        } else {
                purpose_str = strdup(voa_purpose_to_string(purpose));
        }
        if (!purpose_str)
                return log_oom();

        const char *context_str = voa_context_to_string(context);
        const char *technology_str = voa_technology_to_string(technology);

        FOREACH_STRING(dir, CONF_PATHS("voa")) {
                _cleanup_free_ char *full = path_join(dir,
                                                os_str,
                                                purpose_str,
                                                context_str,
                                                technology_str);
                if (!full)
                        return log_oom();

                r = strv_consume(&dirs, TAKE_PTR(full));
                if (r < 0)
                        return r;
        }
        if (!dirs)
                return log_oom();

        *ret = TAKE_PTR(dirs);

        return 0;
}
