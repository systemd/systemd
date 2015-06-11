/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "util.h"
#include "process-util.h"
#include "virt.h"
#include "fileio.h"

static int detect_vm_cpuid(const char **_id) {

        /* Both CPUID and DMI are x86 specific interfaces... */
#if defined(__i386__) || defined(__x86_64__)

        static const char cpuid_vendor_table[] =
                "XenVMMXenVMM\0"          "xen\0"
                "KVMKVMKVM\0"             "kvm\0"
                /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
                "VMwareVMware\0"          "vmware\0"
                /* http://msdn.microsoft.com/en-us/library/ff542428.aspx */
                "Microsoft Hv\0"          "microsoft\0";

        uint32_t eax, ecx;
        union {
                uint32_t sig32[3];
                char text[13];
        } sig = {};
        const char *j, *k;
        bool hypervisor;

        /* http://lwn.net/Articles/301888/ */

#if defined (__i386__)
#define REG_a "eax"
#define REG_b "ebx"
#elif defined (__amd64__)
#define REG_a "rax"
#define REG_b "rbx"
#endif

        /* First detect whether there is a hypervisor */
        eax = 1;
        __asm__ __volatile__ (
                /* ebx/rbx is being used for PIC! */
                "  push %%"REG_b"         \n\t"
                "  cpuid                  \n\t"
                "  pop %%"REG_b"          \n\t"

                : "=a" (eax), "=c" (ecx)
                : "0" (eax)
        );

        hypervisor = !!(ecx & 0x80000000U);

        if (hypervisor) {

                /* There is a hypervisor, see what it is */
                eax = 0x40000000U;
                __asm__ __volatile__ (
                        /* ebx/rbx is being used for PIC! */
                        "  push %%"REG_b"         \n\t"
                        "  cpuid                  \n\t"
                        "  mov %%ebx, %1          \n\t"
                        "  pop %%"REG_b"          \n\t"

                        : "=a" (eax), "=r" (sig.sig32[0]), "=c" (sig.sig32[1]), "=d" (sig.sig32[2])
                        : "0" (eax)
                );

                NULSTR_FOREACH_PAIR(j, k, cpuid_vendor_table)
                        if (streq(sig.text, j)) {
                                *_id = k;
                                return 1;
                        }

                *_id = "other";
                return 0;
        }
#endif

        return 0;
}

static int detect_vm_devicetree(const char **_id) {
#if defined(__arm__) || defined(__aarch64__) || defined(__powerpc__) || defined(__powerpc64__)
        _cleanup_free_ char *hvtype = NULL;
        int r;

        r = read_one_line_file("/proc/device-tree/hypervisor/compatible", &hvtype);
        if (r >= 0) {
                if (streq(hvtype, "linux,kvm")) {
                        *_id = "kvm";
                        return 1;
                } else if (strstr(hvtype, "xen")) {
                        *_id = "xen";
                        return 1;
                }
        } else if (r == -ENOENT) {
                _cleanup_closedir_ DIR *dir = NULL;
                struct dirent *dent;

                dir = opendir("/proc/device-tree");
                if (!dir) {
                        if (errno == ENOENT)
                                return 0;
                        return -errno;
                }

                FOREACH_DIRENT(dent, dir, return -errno) {
                        if (strstr(dent->d_name, "fw-cfg")) {
                                *_id = "qemu";
                                return 1;
                        }
                }
        }
#endif
        return 0;
}

static int detect_vm_dmi(const char **_id) {

        /* Both CPUID and DMI are x86 specific interfaces... */
#if defined(__i386__) || defined(__x86_64__)

        static const char *const dmi_vendors[] = {
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor",
                "/sys/class/dmi/id/bios_vendor"
        };

        static const char dmi_vendor_table[] =
                "QEMU\0"                  "qemu\0"
                /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
                "VMware\0"                "vmware\0"
                "VMW\0"                   "vmware\0"
                "innotek GmbH\0"          "oracle\0"
                "Xen\0"                   "xen\0"
                "Bochs\0"                 "bochs\0";
        unsigned i;

        for (i = 0; i < ELEMENTSOF(dmi_vendors); i++) {
                _cleanup_free_ char *s = NULL;
                const char *j, *k;
                int r;

                r = read_one_line_file(dmi_vendors[i], &s);
                if (r < 0) {
                        if (r != -ENOENT)
                                return r;

                        continue;
                }

                NULSTR_FOREACH_PAIR(j, k, dmi_vendor_table)
                        if (startswith(s, j)) {
                                *_id = k;
                                return 1;
                        }
        }
#endif

        return 0;
}

/* Returns a short identifier for the various VM implementations */
int detect_vm(const char **id) {
        _cleanup_free_ char *domcap = NULL, *cpuinfo_contents = NULL;
        static thread_local int cached_found = -1;
        static thread_local const char *cached_id = NULL;
        const char *_id = NULL;
        int r;

        if (_likely_(cached_found >= 0)) {

                if (id)
                        *id = cached_id;

                return cached_found;
        }

        /* Try xen capabilities file first, if not found try high-level hypervisor sysfs file:
         *
         * https://bugs.freedesktop.org/show_bug.cgi?id=77271 */
        r = read_one_line_file("/proc/xen/capabilities", &domcap);
        if (r >= 0) {
                char *cap, *i = domcap;

                while ((cap = strsep(&i, ",")))
                        if (streq(cap, "control_d"))
                                break;

                if (!cap)  {
                        _id = "xen";
                        r = 1;
                }

                goto finish;

        } else if (r == -ENOENT) {
                _cleanup_free_ char *hvtype = NULL;

                r = read_one_line_file("/sys/hypervisor/type", &hvtype);
                if (r >= 0) {
                        if (streq(hvtype, "xen")) {
                                _id = "xen";
                                r = 1;
                                goto finish;
                        }
                } else if (r != -ENOENT)
                        return r;
        } else
                return r;

        /* this will set _id to "other" and return 0 for unknown hypervisors */
        r = detect_vm_cpuid(&_id);
        if (r != 0)
                goto finish;

        r = detect_vm_dmi(&_id);
        if (r != 0)
                goto finish;

        r = detect_vm_devicetree(&_id);
        if (r != 0)
                goto finish;

        if (_id) {
                /* "other" */
                r = 1;
                goto finish;
        }

        /* Detect User-Mode Linux by reading /proc/cpuinfo */
        r = read_full_file("/proc/cpuinfo", &cpuinfo_contents, NULL);
        if (r < 0)
                return r;
        if (strstr(cpuinfo_contents, "\nvendor_id\t: User Mode Linux\n")) {
                _id = "uml";
                r = 1;
                goto finish;
        }

#if defined(__s390__)
        {
                _cleanup_free_ char *t = NULL;

                r = get_status_field("/proc/sysinfo", "VM00 Control Program:", &t);
                if (r >= 0) {
                        if (streq(t, "z/VM"))
                                _id = "zvm";
                        else
                                _id = "kvm";
                        r = 1;

                        goto finish;
                }
        }
#endif

        r = 0;

finish:
        cached_found = r;

        cached_id = _id;
        if (id)
                *id = _id;

        return r;
}

int detect_container(const char **id) {

        static thread_local int cached_found = -1;
        static thread_local const char *cached_id = NULL;

        _cleanup_free_ char *m = NULL;
        const char *_id = NULL, *e = NULL;
        int r;

        if (_likely_(cached_found >= 0)) {

                if (id)
                        *id = cached_id;

                return cached_found;
        }

        /* /proc/vz exists in container and outside of the container,
         * /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) >= 0 &&
            access("/proc/bc", F_OK) < 0) {
                _id = "openvz";
                r = 1;
                goto finish;
        }

        if (getpid() == 1) {
                /* If we are PID 1 we can just check our own
                 * environment variable */

                e = getenv("container");
                if (isempty(e)) {
                        r = 0;
                        goto finish;
                }
        } else {

                /* Otherwise, PID 1 dropped this information into a
                 * file in /run. This is better than accessing
                 * /proc/1/environ, since we don't need CAP_SYS_PTRACE
                 * for that. */

                r = read_one_line_file("/run/systemd/container", &m);
                if (r == -ENOENT) {

                        /* Fallback for cases where PID 1 was not
                         * systemd (for example, cases where
                         * init=/bin/sh is used. */

                        r = getenv_for_pid(1, "container", &m);
                        if (r <= 0) {

                                /* If that didn't work, give up,
                                 * assume no container manager.
                                 *
                                 * Note: This means we still cannot
                                 * detect containers if init=/bin/sh
                                 * is passed but privileges dropped,
                                 * as /proc/1/environ is only readable
                                 * with privileges. */

                                r = 0;
                                goto finish;
                        }
                }
                if (r < 0)
                        return r;

                e = m;
        }

        /* We only recognize a selected few here, since we want to
         * enforce a redacted namespace */
        if (streq(e, "lxc"))
                _id ="lxc";
        else if (streq(e, "lxc-libvirt"))
                _id = "lxc-libvirt";
        else if (streq(e, "systemd-nspawn"))
                _id = "systemd-nspawn";
        else if (streq(e, "docker"))
                _id = "docker";
        else
                _id = "other";

        r = 1;

finish:
        cached_found = r;

        cached_id = _id;
        if (id)
                *id = _id;

        return r;
}

/* Returns a short identifier for the various VM/container implementations */
int detect_virtualization(const char **id) {
        int r;

        r = detect_container(id);
        if (r < 0)
                return r;
        if (r > 0)
                return VIRTUALIZATION_CONTAINER;

        r = detect_vm(id);
        if (r < 0)
                return r;
        if (r > 0)
                return VIRTUALIZATION_VM;

        return VIRTUALIZATION_NONE;
}
