/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-network.h"

#include "alloc-util.h"
#include "cloud-provider-link.h"
#include "cloud-provider-manager.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "log-link.h"
#include "mkdir.h"
#include "network-cloud-azure.h"
#include "network-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "virt.h"

int link_new(Manager *m, Link **ret, int ifindex, const char *ifname) {
        _cleanup_(link_freep) Link *l = NULL;
        _cleanup_free_ char *n = NULL;
        int r;

        assert(m);
        assert(ifindex > 0);
        assert(ifname);

        n = strdup(ifname);
        if (!n)
                return -ENOMEM;

        l = new(Link, 1);
        if (!l)
                return -ENOMEM;

        *l = (Link) {
                .manager = m,
                .ifname = TAKE_PTR(n),
                .ifindex = ifindex,
        };

        r = hashmap_ensure_put(&m->links, NULL, INT_TO_PTR(ifindex), l);
        if (r < 0)
                return r;

        if (asprintf(&l->state_file, "/run/systemd/cloud-provider/netif/links/%i", ifindex) < 0)
                return -ENOMEM;

        if (ret)
                *ret = l;

        TAKE_PTR(l);
        return 0;
}

Link *link_free(Link *l) {
        if (!l)
                return NULL;

        if (l->manager)
                hashmap_remove(l->manager->links, INT_TO_PTR(l->ifindex));

        free(l->state_file);
        free(l->ifname);
        return mfree(l);
 }

int link_update_rtnl(Link *l, sd_netlink_message *m) {
        const char *ifname;
        int r;

        assert(l);
        assert(l->manager);
        assert(m);

        r = sd_netlink_message_read_string(m, IFLA_IFNAME, &ifname);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_ether_addr(m, IFLA_ADDRESS, &l->mac_address);
        if (r < 0)
                return r;

        if (!streq(l->ifname, ifname)) {
                char *new_ifname;

                new_ifname = strdup(ifname);
                if (!new_ifname)
                        return -ENOMEM;

                free_and_replace(l->ifname, new_ifname);
        }

        return 0;
}

int link_save(Link *l) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(l);
        assert(l->state_file);

        r = mkdir_parents(l->state_file, 0700);
        if (r < 0)
                goto fail;

        r = fopen_temporary(l->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        (void) fchmod(fileno(f), 0644);

        fputs("# This is private data. Do not parse.\n", f);

        if (detect_virtualization() == VIRTUALIZATION_MICROSOFT) {
                r = azure_link_save(l, f);
                if (r < 0)
                        return r;
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, l->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

 fail:
        (void) unlink(l->state_file);

        if (temp_path)
                (void) unlink(temp_path);

        return log_error_errno(r, "Failed to save link data %s: %m", l->state_file);
}
