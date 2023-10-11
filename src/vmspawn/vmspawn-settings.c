/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "vmspawn-settings.h"
#include "macro.h"
#include "string-util-fundamental.h"

int parse_config_feature(const char *s, ConfigFeature *ret) {
        assert(s);
        assert(ret);

        if (strcaseeq(s, "auto"))
                *ret = CONFIG_FEATURE_AUTO;
        else if (strcaseeq(s, "enabled"))
                *ret = CONFIG_FEATURE_ENABLED;
        else if (strcaseeq(s, "disabled"))
                *ret = CONFIG_FEATURE_DISABLED;
        else
                return -EINVAL;

        return 0;
}
