/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-util.h"
#include "dirent-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "virt.h"

enum {
      SMBIOS_VM_BIT_SET,
      SMBIOS_VM_BIT_UNSET,
      SMBIOS_VM_BIT_UNKNOWN,
};

#if defined(__i386__) || defined(__x86_64__)
static const char *const vm_table[_VIRTUALIZATION_MAX] = {
        [VIRTUALIZATION_XEN]       = "XenVMMXenVMM",
        [VIRTUALIZATION_KVM]       = "KVMKVMKVM",
        [VIRTUALIZATION_QEMU]      = "TCGTCGTCGTCG",
        /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
        [VIRTUALIZATION_VMWARE]    = "VMwareVMware",
        /* https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs */
        [VIRTUALIZATION_MICROSOFT] = "Microsoft Hv",
        /* https://wiki.freebsd.org/bhyve */
        [VIRTUALIZATION_BHYVE]     = "bhyve bhyve ",
        [VIRTUALIZATION_QNX]       = "QNXQVMBSQG",
        /* https://projectacrn.org */
        [VIRTUALIZATION_ACRN]      = "ACRNACRNACRN",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(vm, int);
#endif

static int detect_vm_cpuid(void) {

        /* CPUID is an x86 specific interface. */
#if defined(__i386__) || defined(__x86_64__)

        uint32_t eax, ebx, ecx, edx;
        bool hypervisor;

        /* http://lwn.net/Articles/301888/ */

        /* First detect whether there is a hypervisor */
        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0)
                return VIRTUALIZATION_NONE;

        hypervisor = ecx & 0x80000000U;

        if (hypervisor) {
                union {
                        uint32_t sig32[3];
                        char text[13];
                } sig = {};
                int v;

                /* There is a hypervisor, see what it is */
                __cpuid(0x40000000U, eax, ebx, ecx, edx);

                sig.sig32[0] = ebx;
                sig.sig32[1] = ecx;
                sig.sig32[2] = edx;

                log_debug("Virtualization found, CPUID=%s", sig.text);

                v = vm_from_string(sig.text);
                if (v < 0)
                        return VIRTUALIZATION_VM_OTHER;

                return v;
        }
#endif
        log_debug("No virtualization found in CPUID");

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

                if (access("/proc/device-tree/ibm,partition-name", F_OK) == 0 &&
                    access("/proc/device-tree/hmc-managed?", F_OK) == 0 &&
                    access("/proc/device-tree/chosen/qemu,graphic-width", F_OK) != 0)
                        return VIRTUALIZATION_POWERVM;

                dir = opendir("/proc/device-tree");
                if (!dir) {
                        if (errno == ENOENT) {
                                log_debug_errno(errno, "/proc/device-tree: %m");
                                return VIRTUALIZATION_NONE;
                        }
                        return -errno;
                }

                FOREACH_DIRENT(dent, dir, return -errno)
                        if (strstr(dent->d_name, "fw-cfg")) {
                                log_debug("Virtualization QEMU: \"fw-cfg\" present in /proc/device-tree/%s", dent->d_name);
                                return VIRTUALIZATION_QEMU;
                        }

                log_debug("No virtualization found in /proc/device-tree/*");
                return VIRTUALIZATION_NONE;
        } else if (r < 0)
                return r;

        log_debug("Virtualization %s found in /proc/device-tree/hypervisor/compatible", hvtype);
        if (streq(hvtype, "linux,kvm"))
                return VIRTUALIZATION_KVM;
        else if (strstr(hvtype, "xen"))
                return VIRTUALIZATION_XEN;
        else if (strstr(hvtype, "vmware"))
                return VIRTUALIZATION_VMWARE;
        else
                return VIRTUALIZATION_VM_OTHER;
#else
        log_debug("This platform does not support /proc/device-tree");
        return VIRTUALIZATION_NONE;
#endif
}

#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
static int detect_vm_dmi_vendor(void) {
        static const char *const dmi_vendors[] = {
                "/sys/class/dmi/id/product_name", /* Test this before sys_vendor to detect KVM over QEMU */
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor",
                "/sys/class/dmi/id/bios_vendor"
        };

        static const struct {
                const char *vendor;
                int id;
        } dmi_vendor_table[] = {
                { "KVM",                 VIRTUALIZATION_KVM       },
                { "Amazon EC2",          VIRTUALIZATION_AMAZON    },
                { "QEMU",                VIRTUALIZATION_QEMU      },
                { "VMware",              VIRTUALIZATION_VMWARE    }, /* https://kb.vmware.com/s/article/1009458 */
                { "VMW",                 VIRTUALIZATION_VMWARE    },
                { "innotek GmbH",        VIRTUALIZATION_ORACLE    },
                { "Oracle Corporation",  VIRTUALIZATION_ORACLE    },
                { "Xen",                 VIRTUALIZATION_XEN       },
                { "Bochs",               VIRTUALIZATION_BOCHS     },
                { "Parallels",           VIRTUALIZATION_PARALLELS },
                /* https://wiki.freebsd.org/bhyve */
                { "BHYVE",               VIRTUALIZATION_BHYVE     },
        };
        int r;

        for (size_t i = 0; i < ELEMENTSOF(dmi_vendors); i++) {
                _cleanup_free_ char *s = NULL;
                unsigned j;

                r = read_one_line_file(dmi_vendors[i], &s);
                if (r < 0) {
                        if (r == -ENOENT)
                                continue;

                        return r;
                }

                for (j = 0; j < ELEMENTSOF(dmi_vendor_table); j++)
                        if (startswith(s, dmi_vendor_table[j].vendor)) {
                                log_debug("Virtualization %s found in DMI (%s)", s, dmi_vendors[i]);
                                return dmi_vendor_table[j].id;
                        }
        }
        log_debug("No virtualization found in DMI vendor table.");
        return VIRTUALIZATION_NONE;
}

static int detect_vm_smbios(void) {
        /* The SMBIOS BIOS Charateristics Extension Byte 2 (Section 2.1.2.2 of
         * https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0.pdf), specifies that
         * the 4th bit being set indicates a VM. The BIOS Characteristics table is exposed via the kernel in
         * /sys/firmware/dmi/entries/0-0. Note that in the general case, this bit being unset should not
         * imply that the system is running on bare-metal.  For example, QEMU 3.1.0 (with or without KVM)
         * with SeaBIOS does not set this bit. */
        _cleanup_free_ char *s = NULL;
        size_t readsize;
        int r;

        r = read_full_virtual_file("/sys/firmware/dmi/entries/0-0/raw", &s, &readsize);
        if (r < 0) {
                log_debug_errno(r, "Unable to read /sys/firmware/dmi/entries/0-0/raw, "
                                "using the virtualization information found in DMI vendor table, ignoring: %m");
                return SMBIOS_VM_BIT_UNKNOWN;
        }
        if (readsize < 20 || s[1] < 20) {
                /* The spec indicates that byte 1 contains the size of the table, 0x12 + the number of
                 * extension bytes. The data we're interested in is in extension byte 2, which would be at
                 * 0x13. If we didn't read that much data, or if the BIOS indicates that we don't have that
                 * much data, we don't infer anything from the SMBIOS. */
                log_debug("Only read %zu bytes from /sys/firmware/dmi/entries/0-0/raw (expected 20). "
                          "Using the virtualization information found in DMI vendor table.", readsize);
                return SMBIOS_VM_BIT_UNKNOWN;
        }

        uint8_t byte = (uint8_t) s[19];
        if (byte & (1U<<4)) {
                log_debug("DMI BIOS Extension table indicates virtualization.");
                return SMBIOS_VM_BIT_SET;
        }
        log_debug("DMI BIOS Extension table does not indicate virtualization.");
        return SMBIOS_VM_BIT_UNSET;
}
#endif /* defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__) */

static int detect_vm_dmi(void) {
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)

        int r;
        r = detect_vm_dmi_vendor();

        /* The DMI vendor tables in /sys/class/dmi/id don't help us distinguish between Amazon EC2
         * virtual machines and bare-metal instances, so we need to look at SMBIOS. */
        if (r == VIRTUALIZATION_AMAZON) {
                switch (detect_vm_smbios()) {
                case SMBIOS_VM_BIT_SET:
                        return VIRTUALIZATION_AMAZON;
                case SMBIOS_VM_BIT_UNSET:
                        return VIRTUALIZATION_NONE;
                case SMBIOS_VM_BIT_UNKNOWN: {
                        /* The DMI information we are after is only accessible to the root user,
                         * so we fallback to using the product name which is less restricted
                         * to distinguish metal systems from virtualized instances */
                        _cleanup_free_ char *s = NULL;

                        r = read_full_virtual_file("/sys/class/dmi/id/product_name", &s, NULL);
                        /* In EC2, virtualized is much more common than metal, so if for some reason
                         * we fail to read the DMI data, assume we are virtualized. */
                        if (r < 0) {
                                log_debug_errno(r, "Can't read /sys/class/dmi/id/product_name,"
                                                " assuming virtualized: %m");
                                return VIRTUALIZATION_AMAZON;
                        }
                        if (endswith(truncate_nl(s), ".metal")) {
                                log_debug("DMI product name ends with '.metal', assuming no virtualization");
                                return VIRTUALIZATION_NONE;
                        } else
                                return VIRTUALIZATION_AMAZON;
                }
                default:
                        assert_not_reached("Bad virtualization value");
              }
        }

        /* If we haven't identified a VM, but the firmware indicates that there is one, indicate as much. We
         * have no further information about what it is. */
        if (r == VIRTUALIZATION_NONE && detect_vm_smbios() == SMBIOS_VM_BIT_SET)
                return VIRTUALIZATION_VM_OTHER;
        return r;
#else
        return VIRTUALIZATION_NONE;
#endif
}

static int detect_vm_xen(void) {

        /* Check for Dom0 will be executed later in detect_vm_xen_dom0
           The presence of /proc/xen indicates some form of a Xen domain */
        if (access("/proc/xen", F_OK) < 0) {
                log_debug("Virtualization XEN not found, /proc/xen does not exist");
                return VIRTUALIZATION_NONE;
        }

        log_debug("Virtualization XEN found (/proc/xen exists)");
        return VIRTUALIZATION_XEN;
}

#define XENFEAT_dom0 11 /* xen/include/public/features.h */
#define PATH_FEATURES "/sys/hypervisor/properties/features"
/* Returns -errno, or 0 for domU, or 1 for dom0 */
static int detect_vm_xen_dom0(void) {
        _cleanup_free_ char *domcap = NULL;
        int r;

        r = read_one_line_file(PATH_FEATURES, &domcap);
        if (r < 0 && r != -ENOENT)
                return r;
        if (r >= 0) {
                unsigned long features;

                /* Here, we need to use sscanf() instead of safe_atoul()
                 * as the string lacks the leading "0x". */
                r = sscanf(domcap, "%lx", &features);
                if (r == 1) {
                        r = !!(features & (1U << XENFEAT_dom0));
                        log_debug("Virtualization XEN, found %s with value %08lx, "
                                  "XENFEAT_dom0 (indicating the 'hardware domain') is%s set.",
                                  PATH_FEATURES, features, r ? "" : " not");
                        return r;
                }
                log_debug("Virtualization XEN, found %s, unhandled content '%s'",
                          PATH_FEATURES, domcap);
        }

        r = read_one_line_file("/proc/xen/capabilities", &domcap);
        if (r == -ENOENT) {
                log_debug("Virtualization XEN because /proc/xen/capabilities does not exist");
                return 0;
        }
        if (r < 0)
                return r;

        for (const char *i = domcap;;) {
                _cleanup_free_ char *cap = NULL;

                r = extract_first_word(&i, &cap, ",", 0);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("Virtualization XEN DomU found (/proc/xen/capabilities)");
                        return 0;
                }

                if (streq(cap, "control_d")) {
                        log_debug("Virtualization XEN Dom0 ignored (/proc/xen/capabilities)");
                        return 1;
                }
        }
}

static int detect_vm_hypervisor(void) {
        _cleanup_free_ char *hvtype = NULL;
        int r;

        r = read_one_line_file("/sys/hypervisor/type", &hvtype);
        if (r == -ENOENT)
                return VIRTUALIZATION_NONE;
        if (r < 0)
                return r;

        log_debug("Virtualization %s found in /sys/hypervisor/type", hvtype);

        if (streq(hvtype, "xen"))
                return VIRTUALIZATION_XEN;
        else
                return VIRTUALIZATION_VM_OTHER;
}

static int detect_vm_uml(void) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* Detect User-Mode Linux by reading /proc/cpuinfo */
        f = fopen("/proc/cpuinfo", "re");
        if (!f) {
                if (errno == ENOENT) {
                        log_debug("/proc/cpuinfo not found, assuming no UML virtualization.");
                        return VIRTUALIZATION_NONE;
                }
                return -errno;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *t;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                t = startswith(line, "vendor_id\t: ");
                if (t) {
                        if (startswith(t, "User Mode Linux")) {
                                log_debug("UML virtualization found in /proc/cpuinfo");
                                return VIRTUALIZATION_UML;
                        }

                        break;
                }
        }

        log_debug("UML virtualization not found in /proc/cpuinfo.");
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

        log_debug("Virtualization %s found in /proc/sysinfo", t);
        if (streq(t, "z/VM"))
                return VIRTUALIZATION_ZVM;
        else
                return VIRTUALIZATION_KVM;
#else
        log_debug("This platform does not support /proc/sysinfo");
        return VIRTUALIZATION_NONE;
#endif
}

/* Returns a short identifier for the various VM implementations */
int detect_vm(void) {
        static thread_local int cached_found = _VIRTUALIZATION_INVALID;
        bool other = false;
        int r, dmi;

        if (cached_found >= 0)
                return cached_found;

        /* We have to use the correct order here:
         *
         * → First, try to detect Oracle Virtualbox and Amazon EC2 Nitro, even if they use KVM, as well as Xen even if
         *   it cloaks as Microsoft Hyper-V. Attempt to detect uml at this stage also since it runs as a user-process
         *   nested inside other VMs.
         *
         * → Second, try to detect from CPUID, this will report KVM for whatever software is used even if info in DMI is
         *   overwritten.
         *
         * → Third, try to detect from DMI. */

        dmi = detect_vm_dmi();
        if (IN_SET(dmi, VIRTUALIZATION_ORACLE, VIRTUALIZATION_XEN, VIRTUALIZATION_AMAZON)) {
                r = dmi;
                goto finish;
        }

        /* Detect UML */
        r = detect_vm_uml();
        if (r < 0)
                return r;
        if (r == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (r != VIRTUALIZATION_NONE)
                goto finish;

        /* Detect from CPUID */
        r = detect_vm_cpuid();
        if (r < 0)
                return r;
        if (r == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (r != VIRTUALIZATION_NONE)
                goto finish;

        /* Now, let's get back to DMI */
        if (dmi < 0)
                return dmi;
        if (dmi == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (dmi != VIRTUALIZATION_NONE) {
                r = dmi;
                goto finish;
        }

        /* x86 xen will most likely be detected by cpuid. If not (most likely
         * because we're not an x86 guest), then we should try the /proc/xen
         * directory next. If that's not found, then we check for the high-level
         * hypervisor sysfs file.
         */

        r = detect_vm_xen();
        if (r < 0)
                return r;
        if (r == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_hypervisor();
        if (r < 0)
                return r;
        if (r == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_device_tree();
        if (r < 0)
                return r;
        if (r == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (r != VIRTUALIZATION_NONE)
                goto finish;

        r = detect_vm_zvm();
        if (r < 0)
                return r;

finish:
        /* x86 xen Dom0 is detected as XEN in hypervisor and maybe others.
         * In order to detect the Dom0 as not virtualization we need to
         * double-check it */
        if (r == VIRTUALIZATION_XEN) {
                int dom0;

                dom0 = detect_vm_xen_dom0();
                if (dom0 < 0)
                        return dom0;
                if (dom0 > 0)
                        r = VIRTUALIZATION_NONE;
        } else if (r == VIRTUALIZATION_NONE && other)
                r = VIRTUALIZATION_VM_OTHER;

        cached_found = r;
        log_debug("Found VM virtualization %s", virtualization_to_string(r));
        return r;
}

static const char *const container_table[_VIRTUALIZATION_MAX] = {
        [VIRTUALIZATION_LXC]            = "lxc",
        [VIRTUALIZATION_LXC_LIBVIRT]    = "lxc-libvirt",
        [VIRTUALIZATION_SYSTEMD_NSPAWN] = "systemd-nspawn",
        [VIRTUALIZATION_DOCKER]         = "docker",
        [VIRTUALIZATION_PODMAN]         = "podman",
        [VIRTUALIZATION_RKT]            = "rkt",
        [VIRTUALIZATION_WSL]            = "wsl",
        [VIRTUALIZATION_PROOT]          = "proot",
        [VIRTUALIZATION_POUCH]          = "pouch",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(container, int);

static int running_in_cgroupns(void) {
        int r;

        if (!cg_ns_supported())
                return false;

        r = cg_all_unified();
        if (r < 0)
                return r;

        if (r) {
                /* cgroup v2 */

                r = access("/sys/fs/cgroup/cgroup.events", F_OK);
                if (r < 0) {
                        if (errno != ENOENT)
                                return -errno;
                        /* All kernel versions have cgroup.events in nested cgroups. */
                        return false;
                }

                /* There's no cgroup.type in the root cgroup, and future kernel versions
                 * are unlikely to add it since cgroup.type is something that makes no sense
                 * whatsoever in the root cgroup. */
                r = access("/sys/fs/cgroup/cgroup.type", F_OK);
                if (r == 0)
                        return true;
                if (r < 0 && errno != ENOENT)
                        return -errno;

                /* On older kernel versions, there's no cgroup.type */
                r = access("/sys/kernel/cgroup/features", F_OK);
                if (r < 0) {
                        if (errno != ENOENT)
                                return -errno;
                        /* This is an old kernel that we know for sure has cgroup.events
                         * only in nested cgroups. */
                        return true;
                }

                /* This is a recent kernel, and cgroup.type doesn't exist, so we must be
                 * in the root cgroup. */
                return false;
        } else {
                /* cgroup v1 */

                /* If systemd controller is not mounted, do not even bother. */
                r = access("/sys/fs/cgroup/systemd", F_OK);
                if (r < 0) {
                        if (errno != ENOENT)
                                return -errno;
                        return false;
                }

                /* release_agent only exists in the root cgroup. */
                r = access("/sys/fs/cgroup/systemd/release_agent", F_OK);
                if (r < 0) {
                        if (errno != ENOENT)
                                return -errno;
                        return true;
                }

                return false;
        }
}

static int detect_container_files(void) {
        unsigned i;

        static const struct {
                const char *file_path;
                int id;
        } container_file_table[] = {
                /* https://github.com/containers/podman/issues/6192 */
                /* https://github.com/containers/podman/issues/3586#issuecomment-661918679 */
                { "/run/.containerenv", VIRTUALIZATION_PODMAN },
                /* https://github.com/moby/moby/issues/18355 */
                /* Docker must be the last in this table, see below. */
                { "/.dockerenv",        VIRTUALIZATION_DOCKER },
        };

        for (i = 0; i < ELEMENTSOF(container_file_table); i++) {
                if (access(container_file_table[i].file_path, F_OK) >= 0)
                        return container_file_table[i].id;

                if (errno != ENOENT)
                        log_debug_errno(errno,
                                        "Checking if %s exists failed, ignoring: %m",
                                        container_file_table[i].file_path);
        }

        return VIRTUALIZATION_NONE;
}

int detect_container(void) {
        static thread_local int cached_found = _VIRTUALIZATION_INVALID;
        _cleanup_free_ char *m = NULL, *o = NULL, *p = NULL;
        const char *e = NULL;
        int r;

        if (cached_found >= 0)
                return cached_found;

        /* /proc/vz exists in container and outside of the container, /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to check if /proc/vz exists, ignoring: %m");
        } else if (access("/proc/bc", F_OK) < 0) {
                if (errno == ENOENT) {
                        r = VIRTUALIZATION_OPENVZ;
                        goto finish;
                }

                log_debug_errno(errno, "Failed to check if /proc/bc exists, ignoring: %m");
        }

        /* "Official" way of detecting WSL https://github.com/Microsoft/WSL/issues/423#issuecomment-221627364 */
        r = read_one_line_file("/proc/sys/kernel/osrelease", &o);
        if (r < 0)
                log_debug_errno(r, "Failed to read /proc/sys/kernel/osrelease, ignoring: %m");
        else if (strstr(o, "Microsoft") || strstr(o, "WSL")) {
                r = VIRTUALIZATION_WSL;
                goto finish;
        }

        /* proot doesn't use PID namespacing, so we can just check if we have a matching tracer for this
         * invocation without worrying about it being elsewhere.
         */
        r = get_proc_field("/proc/self/status", "TracerPid", WHITESPACE, &p);
        if (r < 0)
                log_debug_errno(r, "Failed to read our own trace PID, ignoring: %m");
        else if (!streq(p, "0")) {
                pid_t ptrace_pid;

                r = parse_pid(p, &ptrace_pid);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse our own tracer PID, ignoring: %m");
                else {
                        _cleanup_free_ char *ptrace_comm = NULL;
                        const char *pf;

                        pf = procfs_file_alloca(ptrace_pid, "comm");
                        r = read_one_line_file(pf, &ptrace_comm);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read %s, ignoring: %m", pf);
                        else if (startswith(ptrace_comm, "proot")) {
                                r = VIRTUALIZATION_PROOT;
                                goto finish;
                        }
                }
        }

        /* The container manager might have placed this in the /run/host/ hierarchy for us, which is best
         * because we can be consumed just like that, without special privileges. */
        r = read_one_line_file("/run/host/container-manager", &m);
        if (r > 0) {
                e = m;
                goto translate_name;
        }
        if (!IN_SET(r, -ENOENT, 0))
                return log_debug_errno(r, "Failed to read /run/host/container-manager: %m");

        if (getpid_cached() == 1) {
                /* If we are PID 1 we can just check our own environment variable, and that's authoritative.
                 * We distinguish three cases:
                 * - the variable is not defined → we jump to other checks
                 * - the variable is defined to an empty value → we are not in a container
                 * - anything else → some container, either one of the known ones or "container-other"
                 */
                e = getenv("container");
                if (!e)
                        goto check_files;
                if (isempty(e)) {
                        r = VIRTUALIZATION_NONE;
                        goto finish;
                }

                goto translate_name;
        }

        /* Otherwise, PID 1 might have dropped this information into a file in /run. This is better than accessing
         * /proc/1/environ, since we don't need CAP_SYS_PTRACE for that. */
        r = read_one_line_file("/run/systemd/container", &m);
        if (r > 0) {
                e = m;
                goto translate_name;
        }
        if (!IN_SET(r, -ENOENT, 0))
                return log_debug_errno(r, "Failed to read /run/systemd/container: %m");

        /* Fallback for cases where PID 1 was not systemd (for example, cases where init=/bin/sh is used. */
        r = getenv_for_pid(1, "container", &m);
        if (r > 0) {
                e = m;
                goto translate_name;
        }
        if (r < 0) /* This only works if we have CAP_SYS_PTRACE, hence let's better ignore failures here */
                log_debug_errno(r, "Failed to read $container of PID 1, ignoring: %m");

check_files:
        /* Check for existence of some well-known files. We only do this after checking
         * for other specific container managers, otherwise we risk mistaking another
         * container manager for Docker: the /.dockerenv file could inadvertently end up
         * in a file system image. */
        r = detect_container_files();
        if (r)
                goto finish;

        r = running_in_cgroupns();
        if (r > 0) {
                r = VIRTUALIZATION_CONTAINER_OTHER;
                goto finish;
        }
        if (r < 0)
                log_debug_errno(r, "Failed to detect cgroup namespace: %m");

        /* If none of that worked, give up, assume no container manager. */
        r = VIRTUALIZATION_NONE;
        goto finish;

translate_name:
        if (streq(e, "oci")) {
                /* Some images hardcode container=oci, but OCI is not a specific container manager.
                 * Try to detect one based on well-known files. */
                r = detect_container_files();
                if (!r)
                        r = VIRTUALIZATION_CONTAINER_OTHER;
                goto finish;
        }
        r = container_from_string(e);
        if (r < 0)
                r = VIRTUALIZATION_CONTAINER_OTHER;

finish:
        log_debug("Found container virtualization %s.", virtualization_to_string(r));
        cached_found = r;
        return r;
}

int detect_virtualization(void) {
        int r;

        r = detect_container();
        if (r == 0)
                r = detect_vm();

        return r;
}

static int userns_has_mapping(const char *name) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *buf = NULL;
        size_t n_allocated = 0;
        ssize_t n;
        uint32_t a, b, c;
        int r;

        f = fopen(name, "re");
        if (!f) {
                log_debug_errno(errno, "Failed to open %s: %m", name);
                return errno == ENOENT ? false : -errno;
        }

        n = getline(&buf, &n_allocated, f);
        if (n < 0) {
                if (feof(f)) {
                        log_debug("%s is empty, we're in an uninitialized user namespace", name);
                        return true;
                }

                return log_debug_errno(errno, "Failed to read %s: %m", name);
        }

        r = sscanf(buf, "%"PRIu32" %"PRIu32" %"PRIu32, &a, &b, &c);
        if (r < 3)
                return log_debug_errno(errno, "Failed to parse %s: %m", name);

        if (a == 0 && b == 0 && c == UINT32_MAX) {
                /* The kernel calls mappings_overlap() and does not allow overlaps */
                log_debug("%s has a full 1:1 mapping", name);
                return false;
        }

        /* Anything else implies that we are in a user namespace */
        log_debug("Mapping found in %s, we're in a user namespace", name);
        return true;
}

int running_in_userns(void) {
        _cleanup_free_ char *line = NULL;
        int r;

        r = userns_has_mapping("/proc/self/uid_map");
        if (r != 0)
                return r;

        r = userns_has_mapping("/proc/self/gid_map");
        if (r != 0)
                return r;

        /* "setgroups" file was added in kernel v3.18-rc6-15-g9cc46516dd. It is also
         * possible to compile a kernel without CONFIG_USER_NS, in which case "setgroups"
         * also does not exist. We cannot distinguish those two cases, so assume that
         * we're running on a stripped-down recent kernel, rather than on an old one,
         * and if the file is not found, return false.
         */
        r = read_one_line_file("/proc/self/setgroups", &line);
        if (r < 0) {
                log_debug_errno(r, "/proc/self/setgroups: %m");
                return r == -ENOENT ? false : r;
        }

        truncate_nl(line);
        r = streq(line, "deny");
        /* See user_namespaces(7) for a description of this "setgroups" contents. */
        log_debug("/proc/self/setgroups contains \"%s\", %s user namespace", line, r ? "in" : "not in");
        return r;
}

int running_in_chroot(void) {
        int r;

        if (getenv_bool("SYSTEMD_IGNORE_CHROOT") > 0)
                return 0;

        r = files_same("/proc/1/root", "/", 0);
        if (r < 0)
                return r;

        return r == 0;
}

#if defined(__i386__) || defined(__x86_64__)
struct cpuid_table_entry {
        uint32_t flag_bit;
        const char *name;
};

static const struct cpuid_table_entry leaf1_edx[] = {
        {  0, "fpu" },
        {  1, "vme" },
        {  2, "de" },
        {  3, "pse" },
        {  4, "tsc" },
        {  5, "msr" },
        {  6, "pae" },
        {  7, "mce" },
        {  8, "cx8" },
        {  9, "apic" },
        { 11, "sep" },
        { 12, "mtrr" },
        { 13, "pge" },
        { 14, "mca" },
        { 15, "cmov" },
        { 16, "pat" },
        { 17, "pse36" },
        { 19, "clflush" },
        { 23, "mmx" },
        { 24, "fxsr" },
        { 25, "sse" },
        { 26, "sse2" },
        { 28, "ht" },
};

static const struct cpuid_table_entry leaf1_ecx[] = {
        {  0, "pni" },
        {  1, "pclmul" },
        {  3, "monitor" },
        {  9, "ssse3" },
        { 12, "fma3" },
        { 13, "cx16" },
        { 19, "sse4_1" },
        { 20, "sse4_2" },
        { 22, "movbe" },
        { 23, "popcnt" },
        { 25, "aes" },
        { 26, "xsave" },
        { 27, "osxsave" },
        { 28, "avx" },
        { 29, "f16c" },
        { 30, "rdrand" },
};

static const struct cpuid_table_entry leaf7_ebx[] = {
        {  3, "bmi1" },
        {  5, "avx2" },
        {  8, "bmi2" },
        { 18, "rdseed" },
        { 19, "adx" },
        { 29, "sha_ni" },
};

static const struct cpuid_table_entry leaf81_edx[] = {
        { 11, "syscall" },
        { 27, "rdtscp" },
        { 29, "lm" },
};

static const struct cpuid_table_entry leaf81_ecx[] = {
        {  0, "lahf_lm" },
        {  5, "abm" },
};

static const struct cpuid_table_entry leaf87_edx[] = {
        {  8, "constant_tsc" },
};

static bool given_flag_in_set(const char *flag, const struct cpuid_table_entry *set, size_t set_size, uint32_t val) {
        for (size_t i = 0; i < set_size; i++) {
                if ((UINT32_C(1) << set[i].flag_bit) & val &&
                                streq(flag, set[i].name))
                        return true;
        }
        return false;
}

static bool real_has_cpu_with_flag(const char *flag) {
        uint32_t eax, ebx, ecx, edx;

        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
                if (given_flag_in_set(flag, leaf1_ecx, ELEMENTSOF(leaf1_ecx), ecx))
                        return true;

                if (given_flag_in_set(flag, leaf1_edx, ELEMENTSOF(leaf1_edx), edx))
                        return true;
        }

        if (__get_cpuid(7, &eax, &ebx, &ecx, &edx)) {
                if (given_flag_in_set(flag, leaf7_ebx, ELEMENTSOF(leaf7_ebx), ebx))
                        return true;
        }

        if (__get_cpuid(0x80000001U, &eax, &ebx, &ecx, &edx)) {
                if (given_flag_in_set(flag, leaf81_ecx, ELEMENTSOF(leaf81_ecx), ecx))
                        return true;

                if (given_flag_in_set(flag, leaf81_edx, ELEMENTSOF(leaf81_edx), edx))
                        return true;
        }

        if (__get_cpuid(0x80000007U, &eax, &ebx, &ecx, &edx))
                if (given_flag_in_set(flag, leaf87_edx, ELEMENTSOF(leaf87_edx), edx))
                        return true;

        return false;
}
#endif

bool has_cpu_with_flag(const char *flag) {
        /* CPUID is an x86 specific interface. Assume on all others that no CPUs have those flags. */
#if defined(__i386__) || defined(__x86_64__)
        return real_has_cpu_with_flag(flag);
#else
        return false;
#endif
}

static const char *const virtualization_table[_VIRTUALIZATION_MAX] = {
        [VIRTUALIZATION_NONE] = "none",
        [VIRTUALIZATION_KVM] = "kvm",
        [VIRTUALIZATION_AMAZON] = "amazon",
        [VIRTUALIZATION_QEMU] = "qemu",
        [VIRTUALIZATION_BOCHS] = "bochs",
        [VIRTUALIZATION_XEN] = "xen",
        [VIRTUALIZATION_UML] = "uml",
        [VIRTUALIZATION_VMWARE] = "vmware",
        [VIRTUALIZATION_ORACLE] = "oracle",
        [VIRTUALIZATION_MICROSOFT] = "microsoft",
        [VIRTUALIZATION_ZVM] = "zvm",
        [VIRTUALIZATION_PARALLELS] = "parallels",
        [VIRTUALIZATION_BHYVE] = "bhyve",
        [VIRTUALIZATION_QNX] = "qnx",
        [VIRTUALIZATION_ACRN] = "acrn",
        [VIRTUALIZATION_POWERVM] = "powervm",
        [VIRTUALIZATION_VM_OTHER] = "vm-other",

        [VIRTUALIZATION_SYSTEMD_NSPAWN] = "systemd-nspawn",
        [VIRTUALIZATION_LXC_LIBVIRT] = "lxc-libvirt",
        [VIRTUALIZATION_LXC] = "lxc",
        [VIRTUALIZATION_OPENVZ] = "openvz",
        [VIRTUALIZATION_DOCKER] = "docker",
        [VIRTUALIZATION_PODMAN] = "podman",
        [VIRTUALIZATION_RKT] = "rkt",
        [VIRTUALIZATION_WSL] = "wsl",
        [VIRTUALIZATION_PROOT] = "proot",
        [VIRTUALIZATION_POUCH] = "pouch",
        [VIRTUALIZATION_CONTAINER_OTHER] = "container-other",
};

DEFINE_STRING_TABLE_LOOKUP(virtualization, int);
