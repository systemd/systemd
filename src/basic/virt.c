/* SPDX-License-Identifier: LGPL-2.1+ */

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
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

static int detect_vm_cpuid(void) {

        /* CPUID is an x86 specific interface. */
#if defined(__i386__) || defined(__x86_64__)

        static const struct {
                const char *cpuid;
                int id;
        } cpuid_vendor_table[] = {
                { "XenVMMXenVMM", VIRTUALIZATION_XEN       },
                { "KVMKVMKVM",    VIRTUALIZATION_KVM       },
                { "TCGTCGTCGTCG", VIRTUALIZATION_QEMU      },
                /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
                { "VMwareVMware", VIRTUALIZATION_VMWARE    },
                /* https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs */
                { "Microsoft Hv", VIRTUALIZATION_MICROSOFT },
                /* https://wiki.freebsd.org/bhyve */
                { "bhyve bhyve ", VIRTUALIZATION_BHYVE     },
                { "QNXQVMBSQG",   VIRTUALIZATION_QNX       },
                /* https://projectacrn.org */
                { "ACRNACRNACRN", VIRTUALIZATION_ACRN      },
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
                unsigned j;

                /* There is a hypervisor, see what it is */
                __cpuid(0x40000000U, eax, ebx, ecx, edx);

                sig.sig32[0] = ebx;
                sig.sig32[1] = ecx;
                sig.sig32[2] = edx;

                log_debug("Virtualization found, CPUID=%s", sig.text);

                for (j = 0; j < ELEMENTSOF(cpuid_vendor_table); j ++)
                        if (streq(sig.text, cpuid_vendor_table[j].cpuid))
                                return cpuid_vendor_table[j].id;

                return VIRTUALIZATION_VM_OTHER;
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
        else
                return VIRTUALIZATION_VM_OTHER;
#else
        log_debug("This platform does not support /proc/device-tree");
        return VIRTUALIZATION_NONE;
#endif
}

static int detect_vm_dmi(void) {
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)

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
                        if (startswith(s, dmi_vendor_table[j].vendor)) {
                                log_debug("Virtualization %s found in DMI (%s)", s, dmi_vendors[i]);
                                return dmi_vendor_table[j].id;
                        }
        }
#endif

        log_debug("No virtualization found in DMI");

        return VIRTUALIZATION_NONE;
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
         * → First, try to detect Oracle Virtualbox, even if it uses KVM, as well as Xen even if it cloaks as Microsoft
         *   Hyper-V.
         *
         * → Second, try to detect from CPUID, this will report KVM for whatever software is used even if info in DMI is
         *   overwritten.
         *
         * → Third, try to detect from DMI. */

        dmi = detect_vm_dmi();
        if (IN_SET(dmi, VIRTUALIZATION_ORACLE, VIRTUALIZATION_XEN)) {
                r = dmi;
                goto finish;
        }

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

        r = detect_vm_uml();
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

int detect_container(void) {
        static const struct {
                const char *value;
                int id;
        } value_table[] = {
                { "lxc",            VIRTUALIZATION_LXC            },
                { "lxc-libvirt",    VIRTUALIZATION_LXC_LIBVIRT    },
                { "systemd-nspawn", VIRTUALIZATION_SYSTEMD_NSPAWN },
                { "docker",         VIRTUALIZATION_DOCKER         },
                { "podman",         VIRTUALIZATION_PODMAN         },
                { "rkt",            VIRTUALIZATION_RKT            },
                { "wsl",            VIRTUALIZATION_WSL            },
        };

        static thread_local int cached_found = _VIRTUALIZATION_INVALID;
        _cleanup_free_ char *m = NULL;
        _cleanup_free_ char *o = NULL;
        const char *e = NULL;
        unsigned j;
        int r;

        if (cached_found >= 0)
                return cached_found;

        /* /proc/vz exists in container and outside of the container, /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) >= 0 &&
            access("/proc/bc", F_OK) < 0) {
                r = VIRTUALIZATION_OPENVZ;
                goto finish;
        }

        /* "Official" way of detecting WSL https://github.com/Microsoft/WSL/issues/423#issuecomment-221627364 */
        r = read_one_line_file("/proc/sys/kernel/osrelease", &o);
        if (r >= 0) {
                if (strstr(o, "Microsoft") || strstr(o, "WSL")) {
                        r = VIRTUALIZATION_WSL;
                        goto finish;
                }
        }

        if (getpid_cached() == 1) {
                /* If we are PID 1 we can just check our own environment variable, and that's authoritative.
                 * We distinguish three cases:
                 * - the variable is not defined → we jump to other checks
                 * - the variable is defined to an empty value → we are not in a container
                 * - anything else → some container, either one of the known ones or "container-other"
                 */
                e = getenv("container");
                if (!e)
                        goto check_sched;
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

        /* Interestingly /proc/1/sched actually shows the host's PID for what we see as PID 1. If the PID
         * shown there is not 1, we know we are in a PID namespace and hence a container. */
 check_sched:
        r = read_one_line_file("/proc/1/sched", &m);
        if (r >= 0) {
                const char *t;

                t = strrchr(m, '(');
                if (!t)
                        return -EIO;

                if (!startswith(t, "(1,")) {
                        r = VIRTUALIZATION_CONTAINER_OTHER;
                        goto finish;
                }
        } else if (r != -ENOENT)
                return r;

        /* If that didn't work, give up, assume no container manager. */
        r = VIRTUALIZATION_NONE;
        goto finish;

translate_name:
        for (j = 0; j < ELEMENTSOF(value_table); j++)
                if (streq(e, value_table[j].value)) {
                        r = value_table[j].id;
                        goto finish;
                }

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
        [VIRTUALIZATION_BHYVE] = "bhyve",
        [VIRTUALIZATION_QNX] = "qnx",
        [VIRTUALIZATION_ACRN] = "acrn",
        [VIRTUALIZATION_VM_OTHER] = "vm-other",

        [VIRTUALIZATION_SYSTEMD_NSPAWN] = "systemd-nspawn",
        [VIRTUALIZATION_LXC_LIBVIRT] = "lxc-libvirt",
        [VIRTUALIZATION_LXC] = "lxc",
        [VIRTUALIZATION_OPENVZ] = "openvz",
        [VIRTUALIZATION_DOCKER] = "docker",
        [VIRTUALIZATION_PODMAN] = "podman",
        [VIRTUALIZATION_RKT] = "rkt",
        [VIRTUALIZATION_WSL] = "wsl",
        [VIRTUALIZATION_CONTAINER_OTHER] = "container-other",
};

DEFINE_STRING_TABLE_LOOKUP(virtualization, int);
