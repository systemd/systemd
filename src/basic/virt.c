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

static int detect_vm_cpuid(void) {

        /* Both CPUID and DMI are x86 specific interfaces... */
#if defined(__i386__) || defined(__x86_64__)

        static const struct {
                const char *cpuid;
                int id;
        } cpuid_vendor_table[] = {
                { "XenVMMXenVMM", VIRTUALIZATION_XEN       },
                { "KVMKVMKVM",    VIRTUALIZATION_KVM       },
                /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
                { "VMwareVMware", VIRTUALIZATION_VMWARE    },
                /* http://msdn.microsoft.com/en-us/library/ff542428.aspx */
                { "Microsoft Hv", VIRTUALIZATION_MICROSOFT },
        };

        uint32_t eax, ecx;
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
                union {
                        uint32_t sig32[3];
                        char text[13];
                } sig = {};
                unsigned j;

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

                for (j = 0; j < ELEMENTSOF(cpuid_vendor_table); j ++)
                        if (streq(sig.text, cpuid_vendor_table[j].cpuid))
                                return cpuid_vendor_table[j].id;

                return VIRTUALIZATION_VM_OTHER;
        }
#endif

        return VIRTUALIZATION_NONE;
}

static int detect_vm_device_tree(void) {
#if defined(__arm__) || defined(__aarch64__) || defined(__powerpc__) || defined(__powerpc64__)
        _cleanup_free_ char *hvtype = NULL;
        int r;

        r = read_one_line_file("/proc/device-tree/hypervisor/compatible", &hvtype);
        if (r == -ENOENT) {
                _cleanup_closedir_ DIR *dir = NULL;
                struct dirent *dent;

                dir = opendir("/proc/device-tree");
                if (!dir) {
                        if (errno == ENOENT)
                                return VIRTUALIZATION_NONE;
                        return -errno;
                }

                FOREACH_DIRENT(dent, dir, return -errno)
                        if (strstr(dent->d_name, "fw-cfg"))
                                return VIRTUALIZATION_QEMU;

                return VIRTUALIZATION_NONE;
        } else if (r < 0)
                return r;

        if (streq(hvtype, "linux,kvm"))
                return VIRTUALIZATION_KVM;
        else if (strstr(hvtype, "xen"))
                return VIRTUALIZATION_XEN;
        else
                return VIRTUALIZATION_VM_OTHER;
#else
        return VIRTUALIZATION_NONE;
#endif
}

static int detect_vm_dmi(void) {

        /* Both CPUID and DMI are x86 specific interfaces... */
#if defined(__i386__) || defined(__x86_64__)

        static const char *const dmi_vendors[] = {
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor",
                "/sys/class/dmi/id/bios_vendor"
        };

        static const struct {
                const char *vendor;
                int id;
        } dmi_vendor_table[] = {
                { "QEMU",          VIRTUALIZATION_QEMU      },
                /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
                { "VMware",        VIRTUALIZATION_VMWARE    },
                { "VMW",           VIRTUALIZATION_VMWARE    },
                { "innotek GmbH",  VIRTUALIZATION_ORACLE    },
                { "Xen",           VIRTUALIZATION_XEN       },
                { "Bochs",         VIRTUALIZATION_BOCHS     },
                { "Parallels",     VIRTUALIZATION_PARALLELS },
        };
        unsigned i;
        int r;

        for (i = 0; i < ELEMENTSOF(dmi_vendors); i++) {
                _cleanup_free_ char *s = NULL;
                unsigned j;

                r = read_one_line_file(dmi_vendors[i], &s);
                if (r < 0) {
                        if (r == -ENOENT)
                                continue;

                        return r;
                }

                for (j = 0; j < ELEMENTSOF(dmi_vendor_table); j++)
                        if (startswith(s, dmi_vendor_table[j].vendor))
                                return dmi_vendor_table[j].id;
        }
#endif

        return VIRTUALIZATION_NONE;
}

static int detect_vm_xen(void) {
        _cleanup_free_ char *domcap = NULL;
        char *cap, *i;
        int r;

        r = read_one_line_file("/proc/xen/capabilities", &domcap);
        if (r == -ENOENT)
                return VIRTUALIZATION_NONE;

        i = domcap;
        while ((cap = strsep(&i, ",")))
                if (streq(cap, "control_d"))
                        break;

        return cap ? VIRTUALIZATION_NONE : VIRTUALIZATION_XEN;
}

static int detect_vm_hypervisor(void) {
        _cleanup_free_ char *hvtype = NULL;
        int r;

        r = read_one_line_file("/sys/hypervisor/type", &hvtype);
        if (r == -ENOENT)
                return VIRTUALIZATION_NONE;
        if (r < 0)
                return r;

        if (streq(hvtype, "xen"))
                return VIRTUALIZATION_XEN;
        else
                return VIRTUALIZATION_VM_OTHER;
}

static int detect_vm_uml(void) {
        _cleanup_free_ char *cpuinfo_contents = NULL;
        int r;

        /* Detect User-Mode Linux by reading /proc/cpuinfo */
        r = read_full_file("/proc/cpuinfo", &cpuinfo_contents, NULL);
        if (r < 0)
                return r;
        if (strstr(cpuinfo_contents, "\nvendor_id\t: User Mode Linux\n"))
                return VIRTUALIZATION_UML;

        return VIRTUALIZATION_NONE;
}

static int detect_vm_zvm(void) {

#if defined(__s390__)
        _cleanup_free_ char *t = NULL;
        int r;

        r = get_proc_field("/proc/sysinfo", "VM00 Control Program", WHITESPACE, &t);
        if (r == -ENOENT)
                return VIRTUALIZATION_NONE;
        if (r < 0)
                return r;

        if (streq(t, "z/VM"))
                return VIRTUALIZATION_ZVM;
        else
                return VIRTUALIZATION_KVM;
#else
        return VIRTUALIZATION_NONE;
#endif
}

/* Returns a short identifier for the various VM implementations */
int detect_vm(void) {
        static thread_local int cached_found = _VIRTUALIZATION_INVALID;
        int r;

        if (cached_found >= 0)
                return cached_found;

        /* Try xen capabilities file first, if not found try
         * high-level hypervisor sysfs file:
         *
         * https://bugs.freedesktop.org/show_bug.cgi?id=77271 */

        r = detect_vm_xen();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_dmi();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_cpuid();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_hypervisor();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_device_tree();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_uml();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_zvm();
        if (r < 0)
                return r;

finish:
        cached_found = r;
        return r;
}

int detect_container(void) {

        static const struct {
                const char *value;
                int id;
        } value_table[] = {
                { "lxc",            VIRTUALIZATION_LXC            },
                { "lxc-libvirt",    VIRTUALIZATION_LXC_LIBVIRT    },
                { "systemd-nspawn", VIRTUALIZATION_SYSTEMD_NSPAWN },
                { "docker",         VIRTUALIZATION_DOCKER         },
        };

        static thread_local int cached_found = _VIRTUALIZATION_INVALID;
        _cleanup_free_ char *m = NULL;
        const char *e = NULL;
        unsigned j;
        int r;

        if (cached_found >= 0)
                return cached_found;

        /* /proc/vz exists in container and outside of the container,
         * /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) >= 0 &&
            access("/proc/bc", F_OK) < 0) {
                r = VIRTUALIZATION_OPENVZ;
                goto finish;
        }

        if (getpid() == 1) {
                /* If we are PID 1 we can just check our own
                 * environment variable */

                e = getenv("container");
                if (isempty(e)) {
                        r = VIRTUALIZATION_NONE;
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

                                r = VIRTUALIZATION_NONE;
                                goto finish;
                        }
                }
                if (r < 0)
                        return r;

                e = m;
        }

        for (j = 0; j < ELEMENTSOF(value_table); j++)
                if (streq(e, value_table[j].value)) {
                        r = value_table[j].id;
                        goto finish;
                }

        r = VIRTUALIZATION_NONE;

finish:
        cached_found = r;
        return r;
}

int detect_virtualization(void) {
        int r;

        r = detect_container();
        if (r != 0)
                return r;

        return detect_vm();
}

static const char *const virtualization_table[_VIRTUALIZATION_MAX] = {
        [VIRTUALIZATION_NONE] = "none",
        [VIRTUALIZATION_KVM] = "kvm",
        [VIRTUALIZATION_QEMU] = "qemu",
        [VIRTUALIZATION_BOCHS] = "bochs",
        [VIRTUALIZATION_XEN] = "xen",
        [VIRTUALIZATION_UML] = "uml",
        [VIRTUALIZATION_VMWARE] = "vmware",
        [VIRTUALIZATION_ORACLE] = "oracle",
        [VIRTUALIZATION_MICROSOFT] = "microsoft",
        [VIRTUALIZATION_ZVM] = "zvm",
        [VIRTUALIZATION_PARALLELS] = "parallels",
        [VIRTUALIZATION_VM_OTHER] = "vm-other",

        [VIRTUALIZATION_SYSTEMD_NSPAWN] = "systemd-nspawn",
        [VIRTUALIZATION_LXC_LIBVIRT] = "lxc-libvirt",
        [VIRTUALIZATION_LXC] = "lxc",
        [VIRTUALIZATION_OPENVZ] = "openvz",
        [VIRTUALIZATION_DOCKER] = "docker",
        [VIRTUALIZATION_CONTAINER_OTHER] = "container-other",
};

DEFINE_STRING_TABLE_LOOKUP(virtualization, int);
