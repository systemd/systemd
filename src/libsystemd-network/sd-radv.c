/***
  This file is part of systemd.

  Copyright (C) 2017 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "sd-radv.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "radv-internal.h"
#include "socket-util.h"
#include "string-util.h"
#include "util.h"

_public_ int sd_radv_prefix_new(sd_radv_prefix **ret) {
        _cleanup_(sd_radv_prefix_unrefp) sd_radv_prefix *p = NULL;

        assert_return(ret, -EINVAL);

        p = new0(sd_radv_prefix, 1);
        if (!p)
                return -ENOMEM;

        p->n_ref = 1;

        p->opt.type = ND_OPT_PREFIX_INFORMATION;
        p->opt.length = (sizeof(p->opt) - 1) /8 + 1;

        p->opt.prefixlen = 64;

        /* RFC 4861, Section 6.2.1 */
        SET_FLAG(p->opt.flags, ND_OPT_PI_FLAG_ONLINK, true);
        SET_FLAG(p->opt.flags, ND_OPT_PI_FLAG_AUTO, true);
        p->opt.preferred_lifetime = htobe32(604800);
        p->opt.valid_lifetime = htobe32(2592000);

        *ret = p;
        p = NULL;

        return 0;
}

_public_ sd_radv_prefix *sd_radv_prefix_ref(sd_radv_prefix *p) {
        if (!p)
                return NULL;

        assert(p->n_ref > 0);
        p->n_ref++;

        return p;
}

_public_ sd_radv_prefix *sd_radv_prefix_unref(sd_radv_prefix *p) {
        if (!p)
                return NULL;

        assert(p->n_ref > 0);
        p->n_ref--;

        if (p->n_ref > 0)
                return NULL;

        return mfree(p);
}

_public_ int sd_radv_prefix_set_prefix(sd_radv_prefix *p, struct in6_addr *in6_addr,
                                       unsigned char prefixlen) {
        assert_return(p, -EINVAL);
        assert_return(in6_addr, -EINVAL);

        if (prefixlen < 3 || prefixlen > 128)
                return -EINVAL;

        if (prefixlen > 64)
                /* unusual but allowed, log it */
                log_radv("Unusual prefix length %d greater than 64", prefixlen);

        p->opt.in6_addr = *in6_addr;
        p->opt.prefixlen = prefixlen;

        return 0;
}

_public_ int sd_radv_prefix_set_onlink(sd_radv_prefix *p, int onlink) {
        assert_return(p, -EINVAL);

        SET_FLAG(p->opt.flags, ND_OPT_PI_FLAG_ONLINK, onlink);

        return 0;
}

_public_ int sd_radv_prefix_set_address_autoconfiguration(sd_radv_prefix *p,
                                                          int address_autoconfiguration) {
        assert_return(p, -EINVAL);

        SET_FLAG(p->opt.flags, ND_OPT_PI_FLAG_AUTO, address_autoconfiguration);

        return 0;
}

_public_ int sd_radv_prefix_set_valid_lifetime(sd_radv_prefix *p,
                                               uint32_t valid_lifetime) {
        assert_return(p, -EINVAL);

        p->opt.valid_lifetime = htobe32(valid_lifetime);

        return 0;
}

_public_ int sd_radv_prefix_set_preferred_lifetime(sd_radv_prefix *p,
                                                   uint32_t preferred_lifetime) {
        assert_return(p, -EINVAL);

        p->opt.preferred_lifetime = htobe32(preferred_lifetime);

        return 0;
}
