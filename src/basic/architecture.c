/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "architecture.h"
#include "macro.h"
#include "string-table.h"
#include "string-util.h"

Architecture uname_architecture(void) {

        /* Return a sanitized enum identifying the architecture we are running on. This
         * is based on uname(), and the user may hence control what this returns by using
         * personality(). This puts the user in control on systems that can run binaries
         * of multiple architectures.
         *
         * We do not translate the string returned by uname() 1:1. Instead we try to
         * clean it up and break down the confusion on x86 and arm in particular.
         *
         * We try to distinguish CPUs, not CPU features, i.e. actual architectures that
         * have genuinely different code. This does not include userspace ABI, so in most
         * cases you do not want to use this, unless it is purely to compare CPUs (for
         * example for QEMU), and instead use uname_abi() below. */

        static const struct {
                const char *machine;
                Architecture arch;
        } arch_map[] = {
#if defined(__aarch64__) || defined(__arm__)
                { "aarch64",    ARCHITECTURE_ARM64    },
                { "aarch64_be", ARCHITECTURE_ARM64_BE },
                { "armv8l",     ARCHITECTURE_ARM      },
                { "armv8b",     ARCHITECTURE_ARM_BE   },
                { "armv7ml",    ARCHITECTURE_ARM      },
                { "armv7mb",    ARCHITECTURE_ARM_BE   },
                { "armv7l",     ARCHITECTURE_ARM      },
                { "armv7b",     ARCHITECTURE_ARM_BE   },
                { "armv6l",     ARCHITECTURE_ARM      },
                { "armv6b",     ARCHITECTURE_ARM_BE   },
                { "armv5tl",    ARCHITECTURE_ARM      },
                { "armv5tel",   ARCHITECTURE_ARM      },
                { "armv5tejl",  ARCHITECTURE_ARM      },
                { "armv5tejb",  ARCHITECTURE_ARM_BE   },
                { "armv5teb",   ARCHITECTURE_ARM_BE   },
                { "armv5tb",    ARCHITECTURE_ARM_BE   },
                { "armv4tl",    ARCHITECTURE_ARM      },
                { "armv4tb",    ARCHITECTURE_ARM_BE   },
                { "armv4l",     ARCHITECTURE_ARM      },
                { "armv4b",     ARCHITECTURE_ARM_BE   },

#elif defined(__alpha__)
                { "alpha" ,     ARCHITECTURE_ALPHA    },

#elif defined(__arc__)
                { "arc",        ARCHITECTURE_ARC      },
                { "arceb",      ARCHITECTURE_ARC_BE   },

#elif defined(__cris__)
                { "crisv32",    ARCHITECTURE_CRIS     },

#elif defined(__i386__) || defined(__x86_64__)
                { "x86_64",     ARCHITECTURE_X86_64   },
                { "i686",       ARCHITECTURE_X86      },
                { "i586",       ARCHITECTURE_X86      },
                { "i486",       ARCHITECTURE_X86      },
                { "i386",       ARCHITECTURE_X86      },

#elif defined(__ia64__)
                { "ia64",       ARCHITECTURE_IA64     },

#elif defined(__hppa__) || defined(__hppa64__)
                { "parisc64",   ARCHITECTURE_PARISC64 },
                { "parisc",     ARCHITECTURE_PARISC   },

#elif defined(__loongarch_lp64)
                { "loongarch64", ARCHITECTURE_LOONGARCH64 },

#elif defined(__m68k__)
                { "m68k",       ARCHITECTURE_M68K     },

#elif defined(__mips__) || defined(__mips64__)
                { "mips64",     ARCHITECTURE_MIPS64   },
                { "mips",       ARCHITECTURE_MIPS     },

#elif defined(__nios2__)
                { "nios2",      ARCHITECTURE_NIOS2    },

#elif defined(__powerpc__) || defined(__powerpc64__)
                { "ppc64le",    ARCHITECTURE_PPC64_LE },
                { "ppc64",      ARCHITECTURE_PPC64    },
                { "ppcle",      ARCHITECTURE_PPC_LE   },
                { "ppc",        ARCHITECTURE_PPC      },

#elif defined(__riscv)
                { "riscv64",    ARCHITECTURE_RISCV64  },
                { "riscv32",    ARCHITECTURE_RISCV32  },
#  if __SIZEOF_POINTER__ == 4
                { "riscv",      ARCHITECTURE_RISCV32  },
#  elif __SIZEOF_POINTER__ == 8
                { "riscv",      ARCHITECTURE_RISCV64  },
#  endif

#elif defined(__s390__) || defined(__s390x__)
                { "s390x",      ARCHITECTURE_S390X    },
                { "s390",       ARCHITECTURE_S390     },

#elif defined(__sh__) || defined(__sh64__)
                { "sh5",        ARCHITECTURE_SH64     },
                { "sh4a",       ARCHITECTURE_SH       },
                { "sh4",        ARCHITECTURE_SH       },
                { "sh3",        ARCHITECTURE_SH       },
                { "sh2a",       ARCHITECTURE_SH       },
                { "sh2",        ARCHITECTURE_SH       },

#elif defined(__sparc__)
                { "sparc64",    ARCHITECTURE_SPARC64  },
                { "sparc",      ARCHITECTURE_SPARC    },

#elif defined(__tilegx__)
                { "tilegx",     ARCHITECTURE_TILEGX   },

#else
#  error "Please register your architecture here!"
#endif
        };

        static Architecture cached = _ARCHITECTURE_INVALID;
        struct utsname u;

        if (cached != _ARCHITECTURE_INVALID)
                return cached;

        assert_se(uname(&u) >= 0);

        for (size_t i = 0; i < ELEMENTSOF(arch_map); i++)
                if (streq(arch_map[i].machine, u.machine))
                        return cached = arch_map[i].arch;

        assert_not_reached();
        return _ARCHITECTURE_INVALID;
}

/* Maintain same order as in the table above. */
static const char *const architecture_table[_ARCHITECTURE_MAX] = {
        [ARCHITECTURE_ARM64]       = "arm64",
        [ARCHITECTURE_ARM64_BE]    = "arm64-be",
        [ARCHITECTURE_ARM]         = "arm",
        [ARCHITECTURE_ARM_BE]      = "arm-be",
        [ARCHITECTURE_ALPHA]       = "alpha",
        [ARCHITECTURE_ARC]         = "arc",
        [ARCHITECTURE_ARC_BE]      = "arc-be",
        [ARCHITECTURE_CRIS]        = "cris",
        [ARCHITECTURE_X86_64]      = "x86-64",
        [ARCHITECTURE_X86]         = "x86",
        [ARCHITECTURE_IA64]        = "ia64",
        [ARCHITECTURE_LOONGARCH64] = "loongarch64",
        [ARCHITECTURE_M68K]        = "m68k",
        [ARCHITECTURE_MIPS64_LE]   = "mips64-le",
        [ARCHITECTURE_MIPS64]      = "mips64",
        [ARCHITECTURE_MIPS_LE]     = "mips-le",
        [ARCHITECTURE_MIPS]        = "mips",
        [ARCHITECTURE_NIOS2]       = "nios2",
        [ARCHITECTURE_PARISC64]    = "parisc64",
        [ARCHITECTURE_PARISC]      = "parisc",
        [ARCHITECTURE_PPC64_LE]    = "ppc64-le",
        [ARCHITECTURE_PPC64]       = "ppc64",
        [ARCHITECTURE_PPC]         = "ppc",
        [ARCHITECTURE_PPC_LE]      = "ppc-le",
        [ARCHITECTURE_RISCV32]     = "riscv32",
        [ARCHITECTURE_RISCV64]     = "riscv64",
        [ARCHITECTURE_S390X]       = "s390x",
        [ARCHITECTURE_S390]        = "s390",
        [ARCHITECTURE_SH64]        = "sh64",
        [ARCHITECTURE_SH]          = "sh",
        [ARCHITECTURE_SPARC64]     = "sparc64",
        [ARCHITECTURE_SPARC]       = "sparc",
        [ARCHITECTURE_TILEGX]      = "tilegx",
};

DEFINE_STRING_TABLE_LOOKUP(architecture, Architecture);

Abi uname_abi(void) {

        /* Return a usable enum identifying the architecture we are running on. This
         * is based on uname(), and the user may hence control what this returns by using
         * personality(). This puts the user in control on systems that can run binaries
         * of multiple architectures.
         *
         * We do not translate the string returned by uname() 1:1. Instead we try to
         * clean it up and break down the confusion on x86 and arm in particular.
         *
         * We try to distinguish CPUs, not CPU features, i.e. actual architectures that
         * have genuinely different code. This includes different userspace ABI, as used
         * for LIB_ARCH_TUPLE and defined in https://wiki.debian.org/Multiarch/Tuples as
         * ooposed to uname_architecture() above, which is solely and exclusively for CPU
         * comparisons. In most cases, especially when comparing images, you want to use
         * this instead. */

        static const struct {
                const char *machine;
                Abi abi;
        } abi_map[] = {
#if defined(__aarch64__) || defined(__arm__)
                { "aarch64",    ABI_ARM64    },
                { "aarch64_be", ABI_ARM64_BE },
#  if defined(__ARM_EABI__)
#    if defined(__ARM_PCS_VFP)
                { "armv8l",     ABI_ARMHF    },
                { "armv8b",     ABI_ARMHF_BE },
                { "armv7ml",    ABI_ARMHF    },
                { "armv7mb",    ABI_ARMHF_BE },
                { "armv7l",     ABI_ARMHF    },
                { "armv7b",     ABI_ARMHF_BE },
                { "armv6l",     ABI_ARMHF    },
                { "armv6b",     ABI_ARMHF_BE },
                { "armv5tl",    ABI_ARMHF    },
                { "armv5tel",   ABI_ARMHF    },
                { "armv5tejl",  ABI_ARMHF    },
                { "armv5tejb",  ABI_ARMHF_BE },
                { "armv5teb",   ABI_ARMHF_BE },
                { "armv5tb",    ABI_ARMHF_BE },
                { "armv4tl",    ABI_ARMHF    },
                { "armv4tb",    ABI_ARMHF_BE },
                { "armv4l",     ABI_ARMHF    },
                { "armv4b",     ABI_ARMHF_BE },
#    else
                { "armv8l",     ABI_ARMEL    },
                { "armv8b",     ABI_ARMEL_BE },
                { "armv7ml",    ABI_ARMEL    },
                { "armv7mb",    ABI_ARMEL_BE },
                { "armv7l",     ABI_ARMEL    },
                { "armv7b",     ABI_ARMEL_BE },
                { "armv6l",     ABI_ARMEL    },
                { "armv6b",     ABI_ARMEL_BE },
                { "armv5tl",    ABI_ARMEL    },
                { "armv5tel",   ABI_ARMEL    },
                { "armv5tejl",  ABI_ARMEL    },
                { "armv5tejb",  ABI_ARMEL_BE },
                { "armv5teb",   ABI_ARMEL_BE },
                { "armv5tb",    ABI_ARMEL_BE },
                { "armv4tl",    ABI_ARMEL    },
                { "armv4tb",    ABI_ARMEL_BE },
                { "armv4l",     ABI_ARMEL    },
                { "armv4b",     ABI_ARMEL_BE },
#    endif
#  else
                { "armv8l",     ABI_ARM      },
                { "armv8b",     ABI_ARM_BE   },
                { "armv7ml",    ABI_ARM      },
                { "armv7mb",    ABI_ARM_BE   },
                { "armv7l",     ABI_ARM      },
                { "armv7b",     ABI_ARM_BE   },
                { "armv6l",     ABI_ARM      },
                { "armv6b",     ABI_ARM_BE   },
                { "armv5tl",    ABI_ARM      },
                { "armv5tel",   ABI_ARM      },
                { "armv5tejl",  ABI_ARM      },
                { "armv5tejb",  ABI_ARM_BE   },
                { "armv5teb",   ABI_ARM_BE   },
                { "armv5tb",    ABI_ARM_BE   },
                { "armv4tl",    ABI_ARM      },
                { "armv4tb",    ABI_ARM_BE   },
                { "armv4l",     ABI_ARM      },
                { "armv4b",     ABI_ARM_BE   },
#  endif

#elif defined(__alpha__)
                { "alpha" ,     ABI_ALPHA    },

#elif defined(__arc__)
                { "arc",        ABI_ARC      },
                { "arceb",      ABI_ARC_BE   },

#elif defined(__cris__)
                { "crisv32",    ABI_CRIS     },

#elif defined(__i386__) || defined(__x86_64__)
#  if defined(__ILP32__)
                { "x86_64",     ABI_X32      },
#  else
                { "x86_64",     ABI_X86_64   },
#  endif
                { "i686",       ABI_X86      },
                { "i586",       ABI_X86      },
                { "i486",       ABI_X86      },
                { "i386",       ABI_X86      },

#elif defined(__ia64__)
                { "ia64",       ABI_IA64     },

#elif defined(__hppa__) || defined(__hppa64__)
                { "parisc64",   ABI_PARISC64 },
                { "parisc",     ABI_PARISC   },

#elif defined(__loongarch_lp64)
                { "loongarch64", ABI_LOONGARCH64 },

#elif defined(__m68k__)
                { "m68k",       ABI_M68K     },

#elif defined(__mips__) || defined(__mips64__)
                { "mips64",     ABI_MIPS64   },
                { "mips",       ABI_MIPS     },

#elif defined(__nios2__)
                { "nios2",      ABI_NIOS2    },

#elif defined(__powerpc__) || defined(__powerpc64__)
                { "ppc64le",    ABI_PPC64_LE },
                { "ppc64",      ABI_PPC64    },
                { "ppcle",      ABI_PPC_LE   },
                { "ppc",        ABI_PPC      },

#elif defined(__riscv)
                { "riscv64",    ABI_RISCV64  },
                { "riscv32",    ABI_RISCV32  },
#  if __SIZEOF_POINTER__ == 4
                { "riscv",      ABI_RISCV32  },
#  elif __SIZEOF_POINTER__ == 8
                { "riscv",      ABI_RISCV64  },
#  endif

#elif defined(__s390__) || defined(__s390x__)
                { "s390x",      ABI_S390X    },
                { "s390",       ABI_S390     },

#elif defined(__sh__) || defined(__sh64__)
                { "sh5",        ABI_SH64     },
                { "sh4a",       ABI_SH       },
                { "sh4",        ABI_SH       },
                { "sh3",        ABI_SH       },
                { "sh2a",       ABI_SH       },
                { "sh2",        ABI_SH       },

#elif defined(__sparc__)
                { "sparc64",    ABI_SPARC64  },
                { "sparc",      ABI_SPARC    },

#elif defined(__tilegx__)
                { "tilegx",     ABI_TILEGX   },

#else
#  error "Please register your ABI here!"
#endif
        };

        static Abi cached = _ABI_INVALID;
        struct utsname u;

        if (cached != _ABI_INVALID)
                return cached;

        assert_se(uname(&u) >= 0);

        for (size_t i = 0; i < ELEMENTSOF(abi_map); i++)
                if (streq(abi_map[i].machine, u.machine))
                        return cached = abi_map[i].abi;

        assert_not_reached();
        return _ABI_INVALID;
}

/* Maintain same order and names as in the table above. */
static const char *const abi_table[_ABI_MAX] = {
        [ABI_ARM64]       = "arm64",
        [ABI_ARM64_BE]    = "arm64-be",
        [ABI_ARM]         = "arm",
        [ABI_ARM_BE]      = "arm-be",
        [ABI_ARMEL]       = "armel",
        [ABI_ARMEL_BE]    = "armel-be",
        [ABI_ARMHF]       = "armhf",
        [ABI_ARMHF_BE]    = "armhf-be",
        [ABI_ALPHA]       = "alpha",
        [ABI_ARC]         = "arc",
        [ABI_ARC_BE]      = "arc-be",
        [ABI_CRIS]        = "cris",
        [ABI_X86_64]      = "x86-64",
        [ABI_X86]         = "x86",
        [ABI_X32]         = "x32",
        [ABI_IA64]        = "ia64",
        [ABI_LOONGARCH64] = "loongarch64",
        [ABI_M68K]        = "m68k",
        [ABI_MIPS64_LE]   = "mips64-le",
        [ABI_MIPS64]      = "mips64",
        [ABI_MIPS_LE]     = "mips-le",
        [ABI_MIPS]        = "mips",
        [ABI_NIOS2]       = "nios2",
        [ABI_PARISC64]    = "parisc64",
        [ABI_PARISC]      = "parisc",
        [ABI_PPC64_LE]    = "ppc64-le",
        [ABI_PPC64]       = "ppc64",
        [ABI_PPC]         = "ppc",
        [ABI_PPC_LE]      = "ppc-le",
        [ABI_RISCV32]     = "riscv32",
        [ABI_RISCV64]     = "riscv64",
        [ABI_S390X]       = "s390x",
        [ABI_S390]        = "s390",
        [ABI_SH64]        = "sh64",
        [ABI_SH]          = "sh",
        [ABI_SPARC64]     = "sparc64",
        [ABI_SPARC]       = "sparc",
        [ABI_TILEGX]      = "tilegx",
};

DEFINE_STRING_TABLE_LOOKUP(abi, Abi);
