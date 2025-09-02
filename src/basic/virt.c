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
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "missing_threads.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "uid-range.h"
#include "virt.h"

enum {
      SMBIOS_VM_BIT_SET,
      SMBIOS_VM_BIT_UNSET,
      SMBIOS_VM_BIT_UNKNOWN,
};

static Virtualization detect_vm_cpuid(void) {

        /* CPUID is an x86 specific interface. */
#if defined(__i386__) || defined(__x86_64__)

        static const struct {
                const char sig[13];
                Virtualization id;
        } vm_table[] = {
                { "XenVMMXenVMM", VIRTUALIZATION_XEN       },
                { "KVMKVMKVM",    VIRTUALIZATION_KVM       }, /* qemu with KVM */
                { "Linux KVM Hv", VIRTUALIZATION_KVM       }, /* qemu with KVM + HyperV Enlightenments */
                { "TCGTCGTCGTCG", VIRTUALIZATION_QEMU      }, /* qemu without KVM */
                /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
                { "VMwareVMware", VIRTUALIZATION_VMWARE    },
                /* https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs */
                { "Microsoft Hv", VIRTUALIZATION_MICROSOFT },
                /* https://wiki.freebsd.org/bhyve */
                { "bhyve bhyve ", VIRTUALIZATION_BHYVE     },
                { "QNXQVMBSQG",   VIRTUALIZATION_QNX       },
                /* https://projectacrn.org */
                { "ACRNACRNACRN", VIRTUALIZATION_ACRN      },
                /* https://www.lockheedmartin.com/en-us/products/Hardened-Security-for-Intel-Processors.html */
                { "SRESRESRESRE", VIRTUALIZATION_SRE       },
                { "Apple VZ",     VIRTUALIZATION_APPLE     },
        };

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

                /* There is a hypervisor, see what it is */
                __cpuid(0x40000000U, eax, ebx, ecx, edx);

                sig.sig32[0] = ebx;
                sig.sig32[1] = ecx;
                sig.sig32[2] = edx;

                log_debug("Virtualization found, CPUID=%s", sig.text);

                FOREACH_ELEMENT(vm, vm_table)
                        if (memcmp_nn(sig.text, sizeof(sig.text),
                                      vm->sig, sizeof(vm->sig)) == 0)
                                return vm->id;

                log_debug("Unknown virtualization with CPUID=%s. Add to vm_table[]?", sig.text);
                return VIRTUALIZATION_VM_OTHER;
        }
#endif
        log_debug("No virtualization found in CPUID");

        return VIRTUALIZATION_NONE;
}

static Virtualization detect_vm_device_tree(void) {
#if defined(__arm__) || defined(__aarch64__) || defined(__powerpc__) || defined(__powerpc64__) || defined(__riscv)
        _cleanup_free_ char *hvtype = NULL;
        int r;

        r = read_one_line_file("/proc/device-tree/hypervisor/compatible", &hvtype);
        if (r == -ENOENT) {
                _cleanup_closedir_ DIR *dir = NULL;
                _cleanup_free_ char *compat = NULL;

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

                FOREACH_DIRENT(de, dir, return -errno)
                        if (strstr(de->d_name, "fw-cfg")) {
                                log_debug("Virtualization QEMU: \"fw-cfg\" present in /proc/device-tree/%s", de->d_name);
                                return VIRTUALIZATION_QEMU;
                        }

                r = read_one_line_file("/proc/device-tree/compatible", &compat);
                if (r < 0 && r != -ENOENT)
                        return r;
                if (r >= 0 && streq(compat, "qemu,pseries")) {
                        log_debug("Virtualization %s found in /proc/device-tree/compatible", compat);
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

#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__) || defined(__loongarch_lp64) || defined(__riscv)
static Virtualization detect_vm_dmi_vendor(void) {
        static const char* const dmi_vendors[] = {
                "/sys/class/dmi/id/product_name", /* Test this before sys_vendor to detect KVM over QEMU */
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor",
                "/sys/class/dmi/id/bios_vendor",
                "/sys/class/dmi/id/product_version", /* For Hyper-V VMs test */
                NULL
        };

        static const struct {
                const char *vendor;
                Virtualization id;
        } dmi_vendor_table[] = {
                { "KVM",                   VIRTUALIZATION_KVM       },
                { "OpenStack",             VIRTUALIZATION_KVM       }, /* Detect OpenStack instance as KVM in non x86 architecture */
                { "KubeVirt",              VIRTUALIZATION_KVM       }, /* Detect KubeVirt instance as KVM in non x86 architecture */
                { "Amazon EC2",            VIRTUALIZATION_AMAZON    },
                { "QEMU",                  VIRTUALIZATION_QEMU      },
                { "VMware",                VIRTUALIZATION_VMWARE    }, /* https://kb.vmware.com/s/article/1009458 */
                { "VMW",                   VIRTUALIZATION_VMWARE    },
                { "innotek GmbH",          VIRTUALIZATION_ORACLE    },
                { "VirtualBox",            VIRTUALIZATION_ORACLE    },
                { "Oracle Corporation",    VIRTUALIZATION_ORACLE    }, /* Detect VirtualBox on some proprietary systems via the board_vendor */
                { "Xen",                   VIRTUALIZATION_XEN       },
                { "Bochs",                 VIRTUALIZATION_BOCHS     },
                { "Parallels",             VIRTUALIZATION_PARALLELS },
                /* https://wiki.freebsd.org/bhyve */
                { "BHYVE",                 VIRTUALIZATION_BHYVE     },
                { "Hyper-V",               VIRTUALIZATION_MICROSOFT },
                { "Apple Virtualization",  VIRTUALIZATION_APPLE     },
                { "Google Compute Engine", VIRTUALIZATION_GOOGLE    }, /* https://cloud.google.com/run/docs/container-contract#sandbox */
        };
        int r;

        STRV_FOREACH(vendor, dmi_vendors) {
                _cleanup_free_ char *s = NULL;

                r = read_one_line_file(*vendor, &s);
                if (r < 0) {
                        if (r == -ENOENT)
                                continue;

                        return r;
                }

                FOREACH_ELEMENT(dmi_vendor, dmi_vendor_table)
                        if (startswith(s, dmi_vendor->vendor)) {
                                log_debug("Virtualization %s found in DMI (%s)", s, *vendor);
                                return dmi_vendor->id;
                        }
        }
        log_debug("No virtualization found in DMI vendor table.");
        return VIRTUALIZATION_NONE;
}

static int detect_vm_smbios(void) {
        /* The SMBIOS BIOS Characteristics Extension Byte 2 (Section 2.1.2.2 of
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
#endif /* defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__) || defined(__loongarch_lp64) */

static Virtualization detect_vm_dmi(void) {
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__) || defined(__loongarch_lp64) || defined(__riscv)

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
                        const char *e;

                        r = read_full_virtual_file("/sys/class/dmi/id/product_name", &s, NULL);
                        /* In EC2, virtualized is much more common than metal, so if for some reason
                         * we fail to read the DMI data, assume we are virtualized. */
                        if (r < 0) {
                                log_debug_errno(r, "Can't read /sys/class/dmi/id/product_name,"
                                                " assuming virtualized: %m");
                                return VIRTUALIZATION_AMAZON;
                        }
                        e = strstrafter(truncate_nl(s), ".metal");
                        if (e && IN_SET(*e, 0, '-')) {
                                log_debug("DMI product name has '.metal', assuming no virtualization");
                                return VIRTUALIZATION_NONE;
                        } else
                                return VIRTUALIZATION_AMAZON;
                }
                default:
                        assert_not_reached();
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

static Virtualization detect_vm_xen(void) {
        /* The presence of /proc/xen indicates some form of a Xen domain
           The check for Dom0 is handled outside this function */
        if (access("/proc/xen", F_OK) < 0) {
                log_debug("Virtualization XEN not found, /proc/xen does not exist");
                return VIRTUALIZATION_NONE;
        }
        log_debug("Virtualization XEN found (/proc/xen exists)");
        return VIRTUALIZATION_XEN;
}

static Virtualization detect_vm_hypervisor(void) {
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

static Virtualization detect_vm_uml(void) {
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

static Virtualization detect_vm_zvm(void) {

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
Virtualization detect_vm(void) {
        static thread_local Virtualization cached_found = _VIRTUALIZATION_INVALID;
        bool other = false, hyperv = false;
        int xen_dom0 = 0;
        Virtualization v, dmi;

        if (cached_found >= 0)
                return cached_found;

        /* We have to use the correct order here:
         *
         * → First, try to detect Oracle Virtualbox, Amazon EC2 Nitro, Parallels, and Google Compute Engine,
         *   even if they use KVM, as well as Xen, even if it cloaks as Microsoft Hyper-V. Attempt to detect
         *   UML at this stage too, since it runs as a user-process nested inside other VMs. Also check for
         *   Xen now, because Xen PV mode does not override CPUID when nested inside another hypervisor.
         *
         * → Second, try to detect from CPUID. This will report KVM for whatever software is used even if
         *   info in DMI is overwritten.
         *
         * → Third, try to detect from DMI. */

        dmi = detect_vm_dmi();
        if (IN_SET(dmi,
                   VIRTUALIZATION_ORACLE,
                   VIRTUALIZATION_XEN,
                   VIRTUALIZATION_AMAZON,
                   /* Unable to distinguish a GCE machine from a VM to bare-metal
                    * for non-x86 architectures due to its necessity for cpuid
                    * detection, which functions solely on x86 platforms. Report
                    * as a VM for other architectures. */
#if !defined(__i386__) && !defined(__x86_64__)
                   VIRTUALIZATION_GOOGLE,
#endif
                   VIRTUALIZATION_PARALLELS)) {
                v = dmi;
                goto finish;
        }

        /* Detect UML */
        v = detect_vm_uml();
        if (v < 0)
                return v;
        if (v != VIRTUALIZATION_NONE)
                goto finish;

        /* Detect Xen */
        v = detect_vm_xen();
        if (v < 0)
                return v;
        if (v == VIRTUALIZATION_XEN) {
                 /* If we are Dom0, then we expect to not report as a VM. However, as we might be nested
                  * inside another hypervisor which can be detected via the CPUID check, wait to report this
                  * until after the CPUID check. */
                xen_dom0 = detect_vm_xen_dom0();
                if (xen_dom0 < 0)
                        return xen_dom0;
                if (xen_dom0 == 0)
                        goto finish;
        } else if (v != VIRTUALIZATION_NONE)
                assert_not_reached();

        /* Detect from CPUID */
        v = detect_vm_cpuid();
        if (v < 0)
                return v;
        if (v == VIRTUALIZATION_MICROSOFT)
                /* QEMU sets the CPUID string to hyperv's, in case it provides hyperv enlightenments. Let's
                 * hence not return Microsoft here but just use the other mechanisms first to make a better
                 * decision. */
                hyperv = true;
        else if (v == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (v == VIRTUALIZATION_KVM && dmi == VIRTUALIZATION_GOOGLE)
                /* The DMI vendor tables in /sys/class/dmi/id don't help us distinguish between GCE
                 * virtual machines and bare-metal instances, so we need to look at hypervisor. */
                return VIRTUALIZATION_GOOGLE;
        else if (v != VIRTUALIZATION_NONE)
                goto finish;

        /* If we are in Dom0 and have not yet finished, finish with the result of detect_vm_cpuid */
        if (xen_dom0 > 0)
                goto finish;

        /* Now, let's get back to DMI */
        if (dmi < 0)
                return dmi;
        if (dmi == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (!IN_SET(dmi, VIRTUALIZATION_NONE, VIRTUALIZATION_GOOGLE)) {
                /* At this point if GCE has been detected in dmi, do not report as a VM. It should
                 * be a bare-metal machine */
                v = dmi;
                goto finish;
        }

        /* Check high-level hypervisor sysfs file */
        v = detect_vm_hypervisor();
        if (v < 0)
                return v;
        if (v == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (v != VIRTUALIZATION_NONE)
                goto finish;

        v = detect_vm_device_tree();
        if (v < 0)
                return v;
        if (v == VIRTUALIZATION_VM_OTHER)
                other = true;
        else if (v != VIRTUALIZATION_NONE)
                goto finish;

        v = detect_vm_zvm();
        if (v < 0)
                return v;

finish:
        /* None of the checks above gave us a clear answer, hence let's now use fallback logic: if hyperv
         * enlightenments are available but the VMM wasn't recognized as anything yet, it's probably
         * Microsoft. */
        if (v == VIRTUALIZATION_NONE) {
                if (hyperv)
                        v = VIRTUALIZATION_MICROSOFT;
                else if (other)
                        v = VIRTUALIZATION_VM_OTHER;
        }

        cached_found = v;
        log_debug("Found VM virtualization %s", virtualization_to_string(v));
        return v;
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

        r = namespace_is_init(NAMESPACE_CGROUP);
        if (r < 0)
                log_debug_errno(r, "Failed to test if in root cgroup namespace, ignoring: %m");
        else if (r > 0)
                return false;

        // FIXME: We really should drop the heuristics below.

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

static int running_in_pidns(void) {
        int r;

        r = namespace_is_init(NAMESPACE_PID);
        if (r < 0)
                return log_debug_errno(r, "Failed to test if in root PID namespace, ignoring: %m");

        return !r;
}

static Virtualization detect_container_files(void) {
        static const struct {
                const char *file_path;
                Virtualization id;
        } container_file_table[] = {
                /* https://github.com/containers/podman/issues/6192 */
                /* https://github.com/containers/podman/issues/3586#issuecomment-661918679 */
                { "/run/.containerenv", VIRTUALIZATION_PODMAN },
                /* https://github.com/moby/moby/issues/18355 */
                /* Docker must be the last in this table, see below. */
                { "/.dockerenv",        VIRTUALIZATION_DOCKER },
        };

        FOREACH_ELEMENT(file, container_file_table) {
                if (access(file->file_path, F_OK) >= 0)
                        return file->id;

                if (errno != ENOENT)
                        log_debug_errno(errno,
                                        "Checking if %s exists failed, ignoring: %m",
                                        file->file_path);
        }

        return VIRTUALIZATION_NONE;
}

Virtualization detect_container(void) {
        static thread_local Virtualization cached_found = _VIRTUALIZATION_INVALID;
        _cleanup_free_ char *m = NULL, *o = NULL, *p = NULL;
        const char *e = NULL;
        Virtualization v;
        int r;

        if (cached_found >= 0)
                return cached_found;

        /* /proc/vz exists in container and outside of the container, /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to check if /proc/vz exists, ignoring: %m");
        } else if (access("/proc/bc", F_OK) < 0) {
                if (errno == ENOENT) {
                        v = VIRTUALIZATION_OPENVZ;
                        goto finish;
                }

                log_debug_errno(errno, "Failed to check if /proc/bc exists, ignoring: %m");
        }

        /* "Official" way of detecting WSL https://github.com/Microsoft/WSL/issues/423#issuecomment-221627364 */
        r = read_one_line_file("/proc/sys/kernel/osrelease", &o);
        if (r < 0)
                log_debug_errno(r, "Failed to read /proc/sys/kernel/osrelease, ignoring: %m");
        else if (strstr(o, "Microsoft") || strstr(o, "WSL")) {
                v = VIRTUALIZATION_WSL;
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
                                v = VIRTUALIZATION_PROOT;
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
                        v = VIRTUALIZATION_NONE;
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
        v = detect_container_files();
        if (v < 0)
                return v;
        if (v != VIRTUALIZATION_NONE)
                goto finish;

        r = running_in_cgroupns();
        if (r > 0) {
                log_debug("Running in a cgroup namespace, assuming unknown container manager.");
                v = VIRTUALIZATION_CONTAINER_OTHER;
                goto finish;
        }
        if (r < 0)
                log_debug_errno(r, "Failed to detect cgroup namespace: %m");

        /* Finally, the root pid namespace has an hardcoded inode number of 0xEFFFFFFC since kernel 3.8, so
         * if all else fails we can check the inode number of our pid namespace and compare it. */
        if (running_in_pidns() > 0) {
                log_debug("Running in a pid namespace, assuming unknown container manager.");
                v = VIRTUALIZATION_CONTAINER_OTHER;
                goto finish;
        }

        /* If none of that worked, give up, assume no container manager. */
        v = VIRTUALIZATION_NONE;
        goto finish;

translate_name:
        if (streq(e, "oci")) {
                /* Some images hardcode container=oci, but OCI is not a specific container manager.
                 * Try to detect one based on well-known files. */
                v = detect_container_files();
                if (v == VIRTUALIZATION_NONE)
                        v = VIRTUALIZATION_CONTAINER_OTHER;
                goto finish;
        }
        v = container_from_string(e);
        if (v < 0)
                v = VIRTUALIZATION_CONTAINER_OTHER;

finish:
        log_debug("Found container virtualization %s.", virtualization_to_string(v));
        cached_found = v;
        return v;
}

Virtualization detect_virtualization(void) {
        int v;

        v = detect_container();
        if (v != VIRTUALIZATION_NONE)
                return v;

        return detect_vm();
}

static int userns_has_mapping(const char *name) {
        _cleanup_fclose_ FILE *f = NULL;
        uid_t base, shift, range;
        int r;

        f = fopen(name, "re");
        if (!f) {
                log_debug_errno(errno, "Failed to open %s: %m", name);
                return errno == ENOENT ? false : -errno;
        }

        r = uid_map_read_one(f, &base, &shift, &range);
        if (r == -ENOMSG) {
                log_debug("%s is empty, we're in an uninitialized user namespace.", name);
                return true;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to read %s: %m", name);

        if (base == 0 && shift == 0 && range == UINT32_MAX) {
                /* The kernel calls mappings_overlap() and does not allow overlaps */
                log_debug("%s has a full 1:1 mapping", name);
                return false;
        }

        /* Anything else implies that we are in a user namespace */
        log_debug("Mapping found in %s, we're in a user namespace.", name);
        return true;
}

int running_in_userns(void) {
        _cleanup_free_ char *line = NULL;
        int r;

        r = namespace_is_init(NAMESPACE_USER);
        if (r < 0)
                log_debug_errno(r, "Failed to test if in root user namespace, ignoring: %m");
        else if (r > 0)
                return false;

        // FIXME: We really should drop the heuristics below.

        r = userns_has_mapping("/proc/self/uid_map");
        if (r != 0)
                return r;

        r = userns_has_mapping("/proc/self/gid_map");
        if (r != 0)
                return r;

        /* "setgroups" file was added in kernel v3.18-rc6-15-g9cc46516dd. It is also possible to compile a
         * kernel without CONFIG_USER_NS, in which case "setgroups" also does not exist. We cannot
         * distinguish those two cases, so assume that we're running on a stripped-down recent kernel, rather
         * than on an old one, and if the file is not found, return false. */
        r = read_virtual_file("/proc/self/setgroups", SIZE_MAX, &line, NULL);
        if (r < 0) {
                log_debug_errno(r, "/proc/self/setgroups: %m");
                return r == -ENOENT ? false : r;
        }

        strstrip(line); /* remove trailing newline */

        r = streq(line, "deny");
        /* See user_namespaces(7) for a description of this "setgroups" contents. */
        log_debug("/proc/self/setgroups contains \"%s\", %s user namespace", line, r ? "in" : "not in");
        return r;
}

int running_in_chroot(void) {
        int r;

        /* If we're PID1, /proc may not be mounted (and most likely we're not in a chroot). But PID1 will
         * mount /proc, so all other programs can assume that if /proc is *not* available, we're in some
         * chroot. */

        r = getenv_bool("SYSTEMD_IN_CHROOT");
        if (r >= 0)
                return r > 0;
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_IN_CHROOT, ignoring: %m");

        /* Deprecated but kept for backwards compatibility. */
        if (getenv_bool("SYSTEMD_IGNORE_CHROOT") > 0)
                return 0;

        r = inode_same("/proc/1/root", "/", 0);
        if (r == -ENOENT) {
                r = proc_mounted();
                if (r == 0) {
                        if (getpid_cached() == 1)
                                return false; /* We will mount /proc, assuming we're not in a chroot. */

                        log_debug("/proc is not mounted, assuming we're in a chroot.");
                        return true;
                }
                if (r > 0)  /* If we have fake /proc/, we can't do the check properly. */
                        return -ENOSYS;
        }
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
        {  0, "fpu"     },
        {  1, "vme"     },
        {  2, "de"      },
        {  3, "pse"     },
        {  4, "tsc"     },
        {  5, "msr"     },
        {  6, "pae"     },
        {  7, "mce"     },
        {  8, "cx8"     },
        {  9, "apic"    },
        { 11, "sep"     },
        { 12, "mtrr"    },
        { 13, "pge"     },
        { 14, "mca"     },
        { 15, "cmov"    },
        { 16, "pat"     },
        { 17, "pse36"   },
        { 19, "clflush" },
        { 23, "mmx"     },
        { 24, "fxsr"    },
        { 25, "sse"     },
        { 26, "sse2"    },
        { 28, "ht"      },
};

static const struct cpuid_table_entry leaf1_ecx[] = {
        {  0, "pni"     },
        {  1, "pclmul"  },
        {  3, "monitor" },
        {  9, "ssse3"   },
        { 12, "fma3"    },
        { 13, "cx16"    },
        { 19, "sse4_1"  },
        { 20, "sse4_2"  },
        { 22, "movbe"   },
        { 23, "popcnt"  },
        { 25, "aes"     },
        { 26, "xsave"   },
        { 27, "osxsave" },
        { 28, "avx"     },
        { 29, "f16c"    },
        { 30, "rdrand"  },
};

static const struct cpuid_table_entry leaf7_ebx[] = {
        {  3, "bmi1"   },
        {  5, "avx2"   },
        {  8, "bmi2"   },
        { 18, "rdseed" },
        { 19, "adx"    },
        { 29, "sha_ni" },
};

static const struct cpuid_table_entry leaf81_edx[] = {
        { 11, "syscall" },
        { 27, "rdtscp"  },
        { 29, "lm"      },
};

static const struct cpuid_table_entry leaf81_ecx[] = {
        {  0, "lahf_lm" },
        {  5, "abm"     },
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

        if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
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
        [VIRTUALIZATION_NONE]            = "none",
        [VIRTUALIZATION_KVM]             = "kvm",
        [VIRTUALIZATION_AMAZON]          = "amazon",
        [VIRTUALIZATION_QEMU]            = "qemu",
        [VIRTUALIZATION_BOCHS]           = "bochs",
        [VIRTUALIZATION_XEN]             = "xen",
        [VIRTUALIZATION_UML]             = "uml",
        [VIRTUALIZATION_VMWARE]          = "vmware",
        [VIRTUALIZATION_ORACLE]          = "oracle",
        [VIRTUALIZATION_MICROSOFT]       = "microsoft",
        [VIRTUALIZATION_ZVM]             = "zvm",
        [VIRTUALIZATION_PARALLELS]       = "parallels",
        [VIRTUALIZATION_BHYVE]           = "bhyve",
        [VIRTUALIZATION_QNX]             = "qnx",
        [VIRTUALIZATION_ACRN]            = "acrn",
        [VIRTUALIZATION_POWERVM]         = "powervm",
        [VIRTUALIZATION_APPLE]           = "apple",
        [VIRTUALIZATION_SRE]             = "sre",
        [VIRTUALIZATION_GOOGLE]          = "google",
        [VIRTUALIZATION_VM_OTHER]        = "vm-other",

        [VIRTUALIZATION_SYSTEMD_NSPAWN]  = "systemd-nspawn",
        [VIRTUALIZATION_LXC_LIBVIRT]     = "lxc-libvirt",
        [VIRTUALIZATION_LXC]             = "lxc",
        [VIRTUALIZATION_OPENVZ]          = "openvz",
        [VIRTUALIZATION_DOCKER]          = "docker",
        [VIRTUALIZATION_PODMAN]          = "podman",
        [VIRTUALIZATION_RKT]             = "rkt",
        [VIRTUALIZATION_WSL]             = "wsl",
        [VIRTUALIZATION_PROOT]           = "proot",
        [VIRTUALIZATION_POUCH]           = "pouch",
        [VIRTUALIZATION_CONTAINER_OTHER] = "container-other",
};

DEFINE_STRING_TABLE_LOOKUP(virtualization, Virtualization);
