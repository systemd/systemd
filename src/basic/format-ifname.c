/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-ifname.h"
#include "string-util.h"

assert_cc(STRLEN("%") + DECIMAL_STR_MAX(int) <= IF_NAMESIZE);

int format_ifname_full(int ifindex, FormatIfnameFlag flag, char buf[static IF_NAMESIZE]) {
        if (ifindex <= 0)
                return -EINVAL;

        if (if_indextoname(ifindex, buf))
                return 0;

        if (!FLAGS_SET(flag, FORMAT_IFNAME_IFINDEX))
                return -errno;

        if (FLAGS_SET(flag, FORMAT_IFNAME_IFINDEX_WITH_PERCENT))
                assert_se(snprintf_ok(buf, IF_NAMESIZE, "%%%d", ifindex));
        else
                assert_se(snprintf_ok(buf, IF_NAMESIZE, "%d", ifindex));

        return 0;
}

int format_ifname_full_alloc(int ifindex, FormatIfnameFlag flag, char **ret) {
        char buf[IF_NAMESIZE];
        int r;

        assert(ret);

        r = format_ifname_full(ifindex, flag, buf);
        if (r < 0)
                return r;

        return strdup_to(ret, buf);
}
