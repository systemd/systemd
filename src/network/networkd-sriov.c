/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include "sd-netlink.h"

#include "device-util.h"
#include "errno-util.h"
#include "hashmap.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-sriov.h"
#include "set.h"
#include "string-util.h"

static int sr_iov_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, SRIOV *sr_iov) {
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Failed to set up %s for SR-IOV virtual function %"PRIu32", ignoring",
                                               sr_iov_attribute_to_string(req->type - _REQUEST_TYPE_SRIOV_BASE),
                                               sr_iov->vf);

        if (link->sr_iov_messages == 0) {
                log_link_debug(link, "Applied settings for SR-IOV virtual functions.");
                link->sr_iov_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int sr_iov_configure(SRIOV *sr_iov, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(sr_iov);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(req);

        SRIOVAttribute attr = req->type - _REQUEST_TYPE_SRIOV_BASE;
        assert(attr >= 0);
        assert(attr < _SR_IOV_ATTRIBUTE_MAX);

        log_link_debug(link, "Setting up %s for SR-IOV virtual function %"PRIu32".",
                       sr_iov_attribute_to_string(attr), sr_iov->vf);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = sr_iov_set_netlink_message(sr_iov, attr, m);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int sr_iov_process_request(Request *req, Link *link, SRIOV *sr_iov) {
        int r;

        assert(req);
        assert(link);
        assert(sr_iov);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        r = sr_iov_configure(sr_iov, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to set up %s for SR-IOV virtual function %"PRIu32": %m",
                                              sr_iov_attribute_to_string(req->type - _REQUEST_TYPE_SRIOV_BASE),
                                              sr_iov->vf);

        return 1;
}

int link_request_sr_iov_vfs(Link *link) {
        SRIOV *sr_iov;
        int r;

        assert(link);
        assert(link->network);

        link->sr_iov_configured = false;

        ORDERED_HASHMAP_FOREACH(sr_iov, link->network->sr_iov_by_section) {
                for (SRIOVAttribute attr = 0; attr < _SR_IOV_ATTRIBUTE_MAX; attr++) {
                        if (!sr_iov_has_config(sr_iov, attr))
                                continue;

                        r = link_queue_request_safe(
                                        link,
                                        _REQUEST_TYPE_SRIOV_BASE + attr,
                                        sr_iov,
                                        NULL,
                                        sr_iov_hash_func,
                                        sr_iov_compare_func,
                                        sr_iov_process_request,
                                        &link->sr_iov_messages,
                                        sr_iov_handler,
                                        NULL);
                        if (r < 0)
                                return log_link_warning_errno(link, r,
                                                              "Failed to request to set up %s for SR-IOV virtual function %"PRIu32": %m",
                                                              sr_iov_attribute_to_string(attr), sr_iov->vf);
                }
        }

        if (link->sr_iov_messages == 0) {
                link->sr_iov_configured = true;
                link_check_ready(link);
        } else
                log_link_debug(link, "Applying settings for SR-IOV virtual functions.");

        return 0;
}

static int find_ifindex_from_pci_dev_port(sd_device *pci_dev, const char *dev_port) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *dev;
        int ifindex, r;

        assert(pci_dev);
        assert(dev_port);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_parent(e, pci_dev);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "net", true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysattr(e, "dev_port", dev_port, true);
        if (r < 0)
                return r;

        dev = sd_device_enumerator_get_device_first(e);
        if (!dev)
                return -ENODEV; /* no device found */

        if (sd_device_enumerator_get_device_next(e))
                return -ENXIO; /* multiple devices found */

        r = sd_device_get_ifindex(dev, &ifindex);
        if (r < 0)
                return r;

        assert(ifindex > 0);
        return ifindex;
}

static int manager_update_sr_iov_ifindices(Manager *manager, int phys_port_ifindex, int virt_port_ifindex) {
        Link *phys_link = NULL, *virt_link = NULL;
        int r;

        assert(manager);
        assert(phys_port_ifindex > 0);
        assert(virt_port_ifindex > 0);

        /* This sets ifindices only when both interfaces are already managed by us. */

        r = link_get_by_index(manager, phys_port_ifindex, &phys_link);
        if (r < 0)
                return r;

        r = link_get_by_index(manager, virt_port_ifindex, &virt_link);
        if (r < 0)
                return r;

        /* update VF ifindex in PF */
        r = set_ensure_put(&phys_link->sr_iov_virt_port_ifindices, NULL, INT_TO_PTR(virt_port_ifindex));
        if (r < 0)
                return r;

        log_link_debug(phys_link,
                       "Found SR-IOV VF port %s(%i).",
                       virt_link ? virt_link->ifname : "n/a", virt_port_ifindex);

        /* update PF ifindex in VF */
        if (virt_link->sr_iov_phys_port_ifindex > 0 && virt_link->sr_iov_phys_port_ifindex != phys_port_ifindex) {
                Link *old_phys_link;

                if (link_get_by_index(manager, virt_link->sr_iov_phys_port_ifindex, &old_phys_link) >= 0)
                        set_remove(old_phys_link->sr_iov_virt_port_ifindices, INT_TO_PTR(virt_port_ifindex));
        }

        virt_link->sr_iov_phys_port_ifindex = phys_port_ifindex;

        log_link_debug(virt_link,
                       "Found SR-IOV PF port %s(%i).",
                       phys_link ? phys_link->ifname : "n/a", phys_port_ifindex);

        return 0;
}

static int link_set_sr_iov_phys_port(Link *link, sd_device *pci_dev, const char *dev_port) {
        _cleanup_(sd_device_unrefp) sd_device *pci_physfn_dev = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(pci_dev);
        assert(dev_port);

        if (link->sr_iov_phys_port_ifindex > 0)
                return 0;

        r = sd_device_new_child(&pci_physfn_dev, pci_dev, "physfn");
        if (r < 0)
                return r;

        r = find_ifindex_from_pci_dev_port(pci_physfn_dev, dev_port);
        if (r < 0)
                return r;

        return manager_update_sr_iov_ifindices(link->manager, r, link->ifindex);
}

static int link_set_sr_iov_virt_ports(Link *link, sd_device *pci_dev, const char *dev_port) {
        const char *name;
        int r;

        assert(link);
        assert(link->manager);
        assert(pci_dev);
        assert(dev_port);

        set_clear(link->sr_iov_virt_port_ifindices);

        FOREACH_DEVICE_CHILD_WITH_SUFFIX(pci_dev, child, name) {
                const char *n;

                /* Accept name prefixed with "virtfn", but refuse "virtfn" itself. */
                n = startswith(name, "virtfn");
                if (isempty(n) || !in_charset(n, DIGITS))
                        continue;

                r = find_ifindex_from_pci_dev_port(child, dev_port);
                if (r < 0)
                        continue;

                if (manager_update_sr_iov_ifindices(link->manager, link->ifindex, r) < 0)
                        continue;
        }

        return 0;
}

int link_set_sr_iov_ifindices(Link *link) {
        const char *dev_port;
        sd_device *pci_dev;
        int r;

        assert(link);

        if (!link->dev)
                return -ENODEV;

        r = sd_device_get_parent_with_subsystem_devtype(link->dev, "pci", NULL, &pci_dev);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                return 0;
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to get parent PCI device: %m");

        /* This may return -EINVAL or -ENODEV, instead of -ENOENT, if the device has been removed or is being
         * removed. Let's ignore the error codes here. */
        r = sd_device_get_sysattr_value(link->dev, "dev_port", &dev_port);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r) || r == -EINVAL)
                return 0;
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to get 'dev_port' sysfs attribute: %m");

        r = link_set_sr_iov_phys_port(link, pci_dev, dev_port);
        if (r < 0 && !ERRNO_IS_DEVICE_ABSENT(r))
                return log_link_debug_errno(link, r, "Failed to set SR-IOV physical port: %m");

        r = link_set_sr_iov_virt_ports(link, pci_dev, dev_port);
        if (r < 0 && !ERRNO_IS_DEVICE_ABSENT(r))
                return log_link_debug_errno(link, r, "Failed to set SR-IOV virtual ports: %m");

        return 0;
}

void link_clear_sr_iov_ifindices(Link *link) {
        void *v;

        assert(link);
        assert(link->manager);

        if (link->sr_iov_phys_port_ifindex > 0) {
                Link *phys_link;

                if (link_get_by_index(link->manager, link->sr_iov_phys_port_ifindex, &phys_link) >= 0)
                        set_remove(phys_link->sr_iov_virt_port_ifindices, INT_TO_PTR(link->ifindex));

                link->sr_iov_phys_port_ifindex = 0;
        }

        while ((v = set_steal_first(link->sr_iov_virt_port_ifindices))) {
                Link *virt_link;

                if (link_get_by_index(link->manager, PTR_TO_INT(v), &virt_link) >= 0)
                        virt_link->sr_iov_phys_port_ifindex = 0;
        }
}

bool check_ready_for_all_sr_iov_ports(
                Link *link,
                bool allow_unmanaged, /* for the main target */
                bool (check_one)(Link *link, bool allow_unmanaged)) {

        Link *phys_link;
        void *v;

        assert(link);
        assert(link->manager);
        assert(check_one);

        /* Some drivers make VF ports become down when their PF port becomes down, and may fail to configure
         * VF ports. Also, when a VF port becomes up/down, its PF port and other VF ports may become down.
         * See issue #23315. */

        /* First, check the main target. */
        if (!check_one(link, allow_unmanaged))
                return false;

        /* If this is a VF port, then also check the PF port. */
        if (link->sr_iov_phys_port_ifindex > 0) {
                if (link_get_by_index(link->manager, link->sr_iov_phys_port_ifindex, &phys_link) < 0 ||
                    !check_one(phys_link, /* allow_unmanaged = */ true))
                        return false;
        } else
                phys_link = link;

        /* Also check all VF ports. */
        SET_FOREACH(v, phys_link->sr_iov_virt_port_ifindices) {
                int ifindex = PTR_TO_INT(v);
                Link *virt_link;

                if (ifindex == link->ifindex)
                        continue; /* The main target link is a VF port, and its state is already checked. */

                if (link_get_by_index(link->manager, ifindex, &virt_link) < 0)
                        return false;

                if (!check_one(virt_link, /* allow_unmanaged = */ true))
                        return false;
        }

        return true;
}
