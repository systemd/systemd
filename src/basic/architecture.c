/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/utsname.h>

#include "architecture.h"
#include "macro.h"
#include "string-table.h"
#include "string-util.h"

int uname_architecture(void) {

        /* Return a sanitized enum identifying the architecture we are
         * running on. This is based on uname(), and the user may
         * hence control what this returns by using
         * personality(). This puts the user in control on systems
         * that can run binaries of multiple architectures.
         *
         * We do not translate the string returned by uname()
         * 1:1. Instead we try to clean it up and break down the
         * confusion on x86 and arm in particular.
         *
         * We do not try to distinguish CPUs not CPU features, but
         * actual architectures, i.e. that have genuinely different
         * code. */

        static const struct {
                const char *machine;
                int arch;
        } arch_map[] = {
#if defined(__x86_64__) || defined(__i386__)
                { "x86_64",     ARCHITECTURE_X86_64   },
                { "i686",       ARCHITECTURE_X86      },
                { "i586",       ARCHITECTURE_X86      },
                { "i486",       ARCHITECTURE_X86      },
                { "i386",       ARCHITECTURE_X86      },
#elif defined(__powerpc__) || defined(__powerpc64__)
                { "ppc64",      ARCHITECTURE_PPC64    },
                { "ppc64le",    ARCHITECTURE_PPC64_LE },
                { "ppc",        ARCHITECTURE_PPC      },
                { "ppcle",      ARCHITECTURE_PPC_LE   },
#elif defined(__ia64__)
                { "ia64",       ARCHITECTURE_IA64     },
#elif defined(__hppa__) || defined(__hppa64__)
                { "parisc64",   ARCHITECTURE_PARISC64 },
                { "parisc",     ARCHITECTURE_PARISC   },
#elif defined(__s390__) || defined(__s390x__)
                { "s390x",      ARCHITECTURE_S390X    },
                { "s390",       ARCHITECTURE_S390     },
#elif defined(__sparc__)
                { "sparc64",    ARCHITECTURE_SPARC64  },
                { "sparc",      ARCHITECTURE_SPARC    },
#elif defined(__mips__) || defined(__mips64__)
                { "mips64",     ARCHITECTURE_MIPS64   },
                { "mips",       ARCHITECTURE_MIPS     },
#elif defined(__alpha__)
                { "alpha" ,     ARCHITECTURE_ALPHA    },
#elif defined(__arm__) || defined(__aarch64__)
                { "aarch64",    ARCHITECTURE_ARM64    },
                { "aarch64_be", ARCHITECTURE_ARM64_BE },
                { "armv4l",     ARCHITECTURE_ARM      },
                { "armv4b",     ARCHITECTURE_ARM_BE   },
                { "armv4tl",    ARCHITECTURE_ARM      },
                { "armv4tb",    ARCHITECTURE_ARM_BE   },
                { "armv5tl",    ARCHITECTURE_ARM      },
                { "armv5tb",    ARCHITECTURE_ARM_BE   },
                { "armv5tel",   ARCHITECTURE_ARM      },
                { "armv5teb" ,  ARCHITECTURE_ARM_BE   },
                { "armv5tejl",  ARCHITECTURE_ARM      },
                { "armv5tejb",  ARCHITECTURE_ARM_BE   },
                { "armv6l",     ARCHITECTURE_ARM      },
                { "armv6b",     ARCHITECTURE_ARM_BE   },
                { "armv7l",     ARCHITECTURE_ARM      },
                { "armv7b",     ARCHITECTURE_ARM_BE   },
                { "armv7ml",    ARCHITECTURE_ARM      },
                { "armv7mb",    ARCHITECTURE_ARM_BE   },
                { "armv4l",     ARCHITECTURE_ARM      },
                { "armv4b",     ARCHITECTURE_ARM_BE   },
                { "armv4tl",    ARCHITECTURE_ARM      },
                { "armv4tb",    ARCHITECTURE_ARM_BE   },
                { "armv5tl",    ARCHITECTURE_ARM      },
                { "armv5tb",    ARCHITECTURE_ARM_BE   },
                { "armv5tel",   ARCHITECTURE_ARM      },
                { "armv5teb",   ARCHITECTURE_ARM_BE   },
                { "armv5tejl",  ARCHITECTURE_ARM      },
                { "armv5tejb",  ARCHITECTURE_ARM_BE   },
                { "armv6l",     ARCHITECTURE_ARM      },
                { "armv6b",     ARCHITECTURE_ARM_BE   },
                { "armv7l",     ARCHITECTURE_ARM      },
                { "armv7b",     ARCHITECTURE_ARM_BE   },
                { "armv7ml",    ARCHITECTURE_ARM      },
                { "armv7mb",    ARCHITECTURE_ARM_BE   },
                { "armv8l",     ARCHITECTURE_ARM      },
                { "armv8b",     ARCHITECTURE_ARM_BE   },
#elif defined(__sh__) || defined(__sh64__)
                { "sh5",        ARCHITECTURE_SH64     },
                { "sh2",        ARCHITECTURE_SH       },
                { "sh2a",       ARCHITECTURE_SH       },
                { "sh3",        ARCHITECTURE_SH       },
                { "sh4",        ARCHITECTURE_SH       },
                { "sh4a",       ARCHITECTURE_SH       },
#elif defined(__m68k__)
                { "m68k",       ARCHITECTURE_M68K     },
#elif defined(__tilegx__)
                { "tilegx",     ARCHITECTURE_TILEGX   },
#elif defined(__cris__)
                { "crisv32",    ARCHITECTURE_CRIS     },
#elif defined(__nios2__)
                { "nios2",      ARCHITECTURE_NIOS2    },
#elif defined(__riscv__) || defined(__riscv)
        /* __riscv__ is obsolete, remove in 2018 */
                { "riscv32",    ARCHITECTURE_RISCV32  },
                { "riscv64",    ARCHITECTURE_RISCV64  },
#  if __SIZEOF_POINTER__ == 4
                { "riscv",      ARCHITECTURE_RISCV32  },
#  elif __SIZEOF_POINTER__ == 8
                { "riscv",      ARCHITECTURE_RISCV64  },
#  endif
#elif defined(__arc__)
                { "arc",        ARCHITECTURE_ARC      },
                { "arceb",      ARCHITECTURE_ARC_BE   },
#else
#error "Please register your architecture here!"
#endif
        };

        static int cached = _ARCHITECTURE_INVALID;
        struct utsname u;
        unsigned i;

        if (cached != _ARCHITECTURE_INVALID)
                return cached;

        assert_se(uname(&u) >= 0);

        for (i = 0; i < ELEMENTSOF(arch_map); i++)
                if (streq(arch_map[i].machine, u.machine))
                        return cached = arch_map[i].arch;

        assert_not_reached("Couldn't identify architecture. You need to patch systemd.");
        return _ARCHITECTURE_INVALID;
}

static const char *const architecture_table[_ARCHITECTURE_MAX] = {
        [ARCHITECTURE_X86] = "x86",
        [ARCHITECTURE_X86_64] = "x86-64",
        [ARCHITECTURE_PPC] = "ppc",
        [ARCHITECTURE_PPC_LE] = "ppc-le",
        [ARCHITECTURE_PPC64] = "ppc64",
        [ARCHITECTURE_PPC64_LE] = "ppc64-le",
        [ARCHITECTURE_IA64] = "ia64",
        [ARCHITECTURE_PARISC] = "parisc",
        [ARCHITECTURE_PARISC64] = "parisc64",
        [ARCHITECTURE_S390] = "s390",
        [ARCHITECTURE_S390X] = "s390x",
        [ARCHITECTURE_SPARC] = "sparc",
        [ARCHITECTURE_SPARC64] = "sparc64",
        [ARCHITECTURE_MIPS] = "mips",
        [ARCHITECTURE_MIPS_LE] = "mips-le",
        [ARCHITECTURE_MIPS64] = "mips64",
        [ARCHITECTURE_MIPS64_LE] = "mips64-le",
        [ARCHITECTURE_ALPHA] = "alpha",
        [ARCHITECTURE_ARM] = "arm",
        [ARCHITECTURE_ARM_BE] = "arm-be",
        [ARCHITECTURE_ARM64] = "arm64",
        [ARCHITECTURE_ARM64_BE] = "arm64-be",
        [ARCHITECTURE_SH] = "sh",
        [ARCHITECTURE_SH64] = "sh64",
        [ARCHITECTURE_M68K] = "m68k",
        [ARCHITECTURE_TILEGX] = "tilegx",
        [ARCHITECTURE_CRIS] = "cris",
        [ARCHITECTURE_NIOS2] = "nios2",
        [ARCHITECTURE_RISCV32] = "riscv32",
        [ARCHITECTURE_RISCV64] = "riscv64",
        [ARCHITECTURE_ARC] = "arc",
        [ARCHITECTURE_ARC_BE] = "arc-be",
};

DEFINE_STRING_TABLE_LOOKUP(architecture, int);
