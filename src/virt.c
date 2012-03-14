/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "util.h"
#include "virt.h"

/* Returns a short identifier for the various VM implementations */
int detect_vm(const char **id) {

#if defined(__i386__) || defined(__x86_64__)

        /* Both CPUID and DMI are x86 specific interfaces... */

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
                "Microsoft Corporation\0" "microsoft\0"
                "innotek GmbH\0"          "oracle\0"
                "Xen\0"                   "xen\0"
                "Bochs\0"                 "bochs\0";

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
        } sig;
        unsigned i;
        const char *j, *k;
        bool hypervisor;

        /* http://lwn.net/Articles/301888/ */
        zero(sig);

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

                                if (id)
                                        *id = k;

                                return 1;
                        }
        }

        for (i = 0; i < ELEMENTSOF(dmi_vendors); i++) {
                char *s;
                int r;
                const char *found = NULL;

                if ((r = read_one_line_file(dmi_vendors[i], &s)) < 0) {
                        if (r != -ENOENT)
                                return r;

                        continue;
                }

                NULSTR_FOREACH_PAIR(j, k, dmi_vendor_table)
                        if (startswith(s, j))
                                found = k;
                free(s);

                if (found) {
                        if (id)
                                *id = found;

                        return 1;
                }
        }

        if (hypervisor) {
                if (id)
                        *id = "other";

                return 1;
        }

#endif
        return 0;
}

int detect_container(const char **id) {
        FILE *f;

        /* Unfortunately many of these operations require root access
         * in one way or another */

        if (geteuid() != 0)
                return -EPERM;

        if (running_in_chroot() > 0) {

                if (id)
                        *id = "chroot";

                return 1;
        }

        /* /proc/vz exists in container and outside of the container,
         * /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) >= 0 &&
            access("/proc/bc", F_OK) < 0) {

                if (id)
                        *id = "openvz";

                return 1;
        }

        f = fopen("/proc/1/environ", "re");
        if (f) {
                bool done = false;

                do {
                        char line[LINE_MAX];
                        unsigned i;

                        for (i = 0; i < sizeof(line)-1; i++) {
                                int c;

                                c = getc(f);
                                if (_unlikely_(c == EOF)) {
                                        done = true;
                                        break;
                                } else if (c == 0)
                                        break;

                                line[i] = c;
                        }
                        line[i] = 0;

                        if (streq(line, "container=lxc")) {
                                fclose(f);

                                if (id)
                                        *id = "lxc";
                                return 1;

                        } else if (streq(line, "container=lxc-libvirt")) {
                                fclose(f);

                                if (id)
                                        *id = "lxc-libvirt";
                                return 1;

                        } else if (streq(line, "container=systemd-nspawn")) {
                                fclose(f);

                                if (id)
                                        *id = "systemd-nspawn";
                                return 1;

                        } else if (startswith(line, "container=")) {
                                fclose(f);

                                if (id)
                                        *id = "other";
                                return 1;
                        }

                } while (!done);

                fclose(f);
        }

        return 0;
}

/* Returns a short identifier for the various VM/container implementations */
Virtualization detect_virtualization(const char **id) {

        static __thread Virtualization cached_virt = _VIRTUALIZATION_INVALID;
        static __thread const char *cached_id = NULL;

        const char *_id;
        int r;
        Virtualization v;

        if (_likely_(cached_virt >= 0)) {

                if (id && cached_virt > 0)
                        *id = cached_id;

                return cached_virt;
        }

        r = detect_container(&_id);
        if (r < 0) {
                v = r;
                goto finish;
        } else if (r > 0) {
                v = VIRTUALIZATION_CONTAINER;
                goto finish;
        }

        r = detect_vm(&_id);
        if (r < 0) {
                v = r;
                goto finish;
        } else if (r > 0) {
                v = VIRTUALIZATION_VM;
                goto finish;
        }

        v = VIRTUALIZATION_NONE;

finish:
        if (v > 0) {
                cached_id = _id;

                if (id)
                        *id = _id;
        }

        if (v >= 0)
                cached_virt = v;

        return v;
}
