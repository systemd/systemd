/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include "chase-symlinks.h"
#include "device-enumerator-private.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-sriov.h"

static int sr_iov_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, SRIOV *sr_iov) {
        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set up SR-IOV");
                link_enter_failed(link);
                return 1;
        }

        if (link->sr_iov_messages == 0) {
                log_link_debug(link, "SR-IOV configured");
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

        log_link_debug(link, "Setting SR-IOV virtual function %"PRIu32".", sr_iov->vf);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = sr_iov_set_netlink_message(sr_iov, m);
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
                                              "Failed to configure SR-IOV virtual function %"PRIu32": %m",
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
                r = link_queue_request_safe(link, REQUEST_TYPE_SRIOV,
                                            sr_iov, NULL,
                                            sr_iov_hash_func,
                                            sr_iov_compare_func,
                                            sr_iov_process_request,
                                            &link->sr_iov_messages,
                                            sr_iov_handler,
                                            NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "Failed to request SR-IOV virtual function %"PRIu32": %m",
                                                      sr_iov->vf);
        }

        if (link->sr_iov_messages == 0) {
                link->sr_iov_configured = true;
                link_check_ready(link);
        } else
                log_link_debug(link, "Configuring SR-IOV");

        return 0;
}

static int find_ifindex_from_pci_dev_port(sd_device *pci_dev, const char *dev_port) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device **devices;
        size_t n_devices;
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

        r = device_enumerator_scan_devices(e);
        if (r < 0)
                return r;

        devices = device_enumerator_get_devices(e, &n_devices);
        if (!devices || n_devices <= 0)
                return -ENODEV;
        if (n_devices > 1)
                return -ENXIO;

        r = sd_device_get_ifindex(devices[0], &ifindex);
        if (r < 0)
                return r;

        assert(ifindex > 0);
        return ifindex;
}

int link_get_sr_iov_phys_port(Link *link, Link **ret) {
        _cleanup_(sd_device_unrefp) sd_device *pci_dev = NULL, *pci_physfn_dev = NULL;
        const char *pci_syspath, *pci_physfn_syspath, *dev_port;
        _cleanup_closedir_ DIR *dir = NULL;
        bool found = false;
        int r;

        assert(link);
        assert(link->manager);

        if (link->phys_port_ifindex > 0) {
                r = link_get_by_index(link->manager, link->phys_port_ifindex, ret);
                if (r < 0)
                        return r;

                return link->phys_port_ifindex;
        }

        if (link->phys_port_ifindex < 0) /* Previously parsed, and not found. */
                return -ENODEV;

        link->phys_port_ifindex = -1;

        if (!link->sd_device)
                return -ENODEV;

        r = sd_device_get_sysattr_value(link->sd_device, "dev_port", &dev_port);
        if (r < 0)
                return r;

        r = sd_device_get_parent_with_subsystem_devtype(link->sd_device, "pci", NULL, &pci_dev);
        if (r < 0)
                return r;

        r = sd_device_get_syspath(pci_dev, &pci_syspath);
        if (r < 0)
                return r;

        pci_physfn_syspath = strjoina(pci_syspath, "/physfn");
        r = sd_device_new_from_syspath(&pci_physfn_dev, pci_physfn_syspath);
        if (r < 0)
                return r;

        r = sd_device_get_syspath(pci_physfn_dev, &pci_physfn_syspath);
        if (r < 0)
                return r;

        dir = opendir(pci_physfn_syspath);
        if (!dir)
                return -errno;

        FOREACH_DIRENT_ALL(de, dir, break) {
                _cleanup_free_ char *virtfn_link_file = NULL, *virtfn_pci_syspath = NULL;

                if (isempty(startswith(de->d_name, "virtfn")))
                        continue;

                virtfn_link_file = path_join(pci_physfn_syspath, de->d_name);
                if (!virtfn_link_file)
                        return -ENOMEM;

                if (chase_symlinks(virtfn_link_file, NULL, 0, &virtfn_pci_syspath, NULL) < 0)
                        continue;

                if (path_equal(pci_syspath, virtfn_pci_syspath)) {
                        found = true;
                        break;
                }
        }
        if (!found)
                return -ENODEV;


        r = find_ifindex_from_pci_dev_port(pci_physfn_dev, dev_port);
        if (r < 0)
                return r;

        /* Cache ifindex before link_get_by_index(), as the PF port may not have been detected yet. */
        link->phys_port_ifindex = r;

        log_link_debug(link,
                       "Found SR-IOV PF device '%s' and its physical network interface %i.",
                       pci_physfn_syspath, link->phys_port_ifindex);

        r = link_get_by_index(link->manager, link->phys_port_ifindex, ret);
        if (r < 0)
                return r;

        return link->phys_port_ifindex;
}

int link_get_sr_iov_virt_ports(Link *link, int **ret) {
        _cleanup_(sd_device_unrefp) sd_device *pci_physfn_dev = NULL;
        const char *dev_port, *pci_physfn_syspath;
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ int *vfs = NULL;
        size_t n_vfs = 0;
        usec_t now_usec;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->event);
        assert(ret);

        /* TODO: Find a more efficient way to detect VF port changes. */

        r = sd_event_now(link->manager->event, CLOCK_BOOTTIME, &now_usec);
        if (r < 0)
                return r;

        if (link->virt_port_ifindices_usec == now_usec) {
                /* Use cached results */
                if (link->n_virt_port_ifindices <= 0)
                        return -ENODEV;

                *ret = ASSERT_PTR(link->virt_port_ifindices);
                return link->n_virt_port_ifindices;
        }

        /* Clear cached results */
        link->virt_port_ifindices_usec = now_usec;
        link->virt_port_ifindices = mfree(link->virt_port_ifindices);
        link->n_virt_port_ifindices = 0;

        if (!link->sd_device)
                return -ENODEV;

        r = sd_device_get_sysattr_value(link->sd_device, "dev_port", &dev_port);
        if (r < 0)
                return r;

        r = sd_device_get_parent_with_subsystem_devtype(link->sd_device, "pci", NULL, &pci_physfn_dev);
        if (r < 0)
                return r;

        r = sd_device_get_syspath(pci_physfn_dev, &pci_physfn_syspath);
        if (r < 0)
                return r;

        dir = opendir(pci_physfn_syspath);
        if (!dir)
                return -errno;

        FOREACH_DIRENT_ALL(de, dir, break) {
                _cleanup_(sd_device_unrefp) sd_device *pci_virtfn_dev = NULL;
                _cleanup_free_ char *virtfn_link_file = NULL;
                int ifindex;

                if (isempty(startswith(de->d_name, "virtfn")))
                        continue;

                virtfn_link_file = path_join(pci_physfn_syspath, de->d_name);
                if (!virtfn_link_file)
                        return -ENOMEM;

                if (sd_device_new_from_syspath(&pci_virtfn_dev, virtfn_link_file) < 0)
                        continue;

                ifindex = find_ifindex_from_pci_dev_port(pci_virtfn_dev, dev_port);
                if (ifindex < 0)
                        continue;

                if (link_get_by_index(link->manager, ifindex, NULL) < 0)
                        continue;

                if (!GREEDY_REALLOC(vfs, n_vfs + 1))
                        return -ENOMEM;

                vfs[n_vfs++] = ifindex;
        }
        if (n_vfs <= 0)
                return -ENODEV;

        *ret = link->virt_port_ifindices = TAKE_PTR(vfs);
        return link->n_virt_port_ifindices = n_vfs;
}
