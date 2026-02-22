/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "gpt.h"
#include "string-table.h"
#include "string-util.h"
#include "utf8.h"

/* Gently push people towards defining GPT type UUIDs for all architectures we know */
#if !defined(SD_GPT_ROOT_NATIVE) ||                                        \
        !defined(SD_GPT_ROOT_NATIVE_VERITY) ||                             \
        !defined(SD_GPT_ROOT_NATIVE_VERITY_SIG) ||                         \
        !defined(SD_GPT_USR_NATIVE) ||                                     \
        !defined(SD_GPT_USR_NATIVE_VERITY) ||                              \
        !defined(SD_GPT_USR_NATIVE_VERITY_SIG)
#pragma message "Please define GPT partition types for your architecture."
#endif

bool partition_designator_is_versioned(PartitionDesignator d) {
        /* Returns true for all designators where we want to support a concept of "versioning", i.e. which
         * likely contain software binaries (or hashes thereof) that make sense to be versioned as a
         * whole. We use this check to automatically pick the newest version of these partitions, by version
         * comparing the partition labels. */

        return IN_SET(d,
                      PARTITION_ROOT,
                      PARTITION_USR,
                      PARTITION_ROOT_VERITY,
                      PARTITION_USR_VERITY,
                      PARTITION_ROOT_VERITY_SIG,
                      PARTITION_USR_VERITY_SIG);
}

PartitionDesignator partition_verity_hash_of(PartitionDesignator p) {
        switch (p) {

        case PARTITION_ROOT:
                return PARTITION_ROOT_VERITY;

        case PARTITION_USR:
                return PARTITION_USR_VERITY;

        default:
                return _PARTITION_DESIGNATOR_INVALID;
        }
}

PartitionDesignator partition_verity_sig_of(PartitionDesignator p) {
        switch (p) {

        case PARTITION_ROOT:
                return PARTITION_ROOT_VERITY_SIG;

        case PARTITION_USR:
                return PARTITION_USR_VERITY_SIG;

        default:
                return _PARTITION_DESIGNATOR_INVALID;
        }
}

PartitionDesignator partition_verity_hash_to_data(PartitionDesignator d) {
        switch (d) {

        case PARTITION_ROOT_VERITY:
                return PARTITION_ROOT;

        case PARTITION_USR_VERITY:
                return PARTITION_USR;

        default:
                return _PARTITION_DESIGNATOR_INVALID;
        }
}

PartitionDesignator partition_verity_sig_to_data(PartitionDesignator d) {
        switch (d) {

        case PARTITION_ROOT_VERITY_SIG:
                return PARTITION_ROOT;

        case PARTITION_USR_VERITY_SIG:
                return PARTITION_USR;

        default:
                return _PARTITION_DESIGNATOR_INVALID;
        }
}

PartitionDesignator partition_verity_to_data(PartitionDesignator d) {
        PartitionDesignator e = partition_verity_hash_to_data(d);
        if (e >= 0)
                return e;

        return partition_verity_sig_to_data(d);
}

static const char *const partition_designator_table[_PARTITION_DESIGNATOR_MAX] = {
        [PARTITION_ROOT]                      = "root",
        [PARTITION_USR]                       = "usr",
        [PARTITION_HOME]                      = "home",
        [PARTITION_SRV]                       = "srv",
        [PARTITION_ESP]                       = "esp",
        [PARTITION_XBOOTLDR]                  = "xbootldr",
        [PARTITION_SWAP]                      = "swap",
        [PARTITION_ROOT_VERITY]               = "root-verity",
        [PARTITION_USR_VERITY]                = "usr-verity",
        [PARTITION_ROOT_VERITY_SIG]           = "root-verity-sig",
        [PARTITION_USR_VERITY_SIG]            = "usr-verity-sig",
        [PARTITION_TMP]                       = "tmp",
        [PARTITION_VAR]                       = "var",
};

DEFINE_STRING_TABLE_LOOKUP(partition_designator, PartitionDesignator);

static const char *const partition_mountpoint_table[_PARTITION_DESIGNATOR_MAX] = {
        [PARTITION_ROOT]                      = "/\0",
        [PARTITION_USR]                       = "/usr\0",
        [PARTITION_HOME]                      = "/home\0",
        [PARTITION_SRV]                       = "/srv\0",
        [PARTITION_ESP]                       = "/efi\0/boot\0",
        [PARTITION_XBOOTLDR]                  = "/boot\0",
        [PARTITION_TMP]                       = "/var/tmp\0",
        [PARTITION_VAR]                       = "/var\0",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(partition_mountpoint, PartitionDesignator);

#define _GPT_ARCH_SEXTET(arch, name)                                   \
        { SD_GPT_ROOT_##arch,              "root-" name,               ARCHITECTURE_##arch, .designator = PARTITION_ROOT            },  \
        { SD_GPT_ROOT_##arch##_VERITY,     "root-" name "-verity",     ARCHITECTURE_##arch, .designator = PARTITION_ROOT_VERITY     },  \
        { SD_GPT_ROOT_##arch##_VERITY_SIG, "root-" name "-verity-sig", ARCHITECTURE_##arch, .designator = PARTITION_ROOT_VERITY_SIG },  \
        { SD_GPT_USR_##arch,               "usr-" name,                ARCHITECTURE_##arch, .designator = PARTITION_USR             },  \
        { SD_GPT_USR_##arch##_VERITY,      "usr-" name "-verity",      ARCHITECTURE_##arch, .designator = PARTITION_USR_VERITY      },  \
        { SD_GPT_USR_##arch##_VERITY_SIG,  "usr-" name "-verity-sig",  ARCHITECTURE_##arch, .designator = PARTITION_USR_VERITY_SIG  }

/* Two special cases: alias aarch64 to arm64, and amd64 to x86-64. The DSP mixes debianisms and CPUisms: for
 * x86, it uses x86 and x86_64, but for aarch64 it uses arm64. This is confusing, and leads to issues for
 * callers that have to know which -ism to use for which architecture. But we also don't really want to
 * change the spec and add new partition labels, so add a user-friendly aliasing here, so that both are
 * accepted but the end result on disk (ie: the partition label).
 * So always list the canonical name FIRST, and then any aliases later, so that we can match on aliases,
 * but always return the canonical name. And never return directly a match on the name, always re-resolve
 * by UUID so that the canonical entry is always found. */

const GptPartitionType gpt_partition_type_table[] = {
        _GPT_ARCH_SEXTET(ALPHA,       "alpha"),
        _GPT_ARCH_SEXTET(ARC,         "arc"),
        _GPT_ARCH_SEXTET(ARM,         "arm"),
        _GPT_ARCH_SEXTET(ARM,         "armv7l"), /* Alias: must be listed after arm */
        _GPT_ARCH_SEXTET(ARM64,       "arm64"),
        _GPT_ARCH_SEXTET(ARM64,       "aarch64"), /* Alias: must be listed after arm64 */
        _GPT_ARCH_SEXTET(IA64,        "ia64"),
        _GPT_ARCH_SEXTET(LOONGARCH64, "loongarch64"),
        _GPT_ARCH_SEXTET(LOONGARCH64, "loong64"), /* Alias: must be listed after loongarch64 */
        _GPT_ARCH_SEXTET(MIPS,        "mips"),
        _GPT_ARCH_SEXTET(MIPS64,      "mips64"),
        _GPT_ARCH_SEXTET(MIPS_LE,     "mips-le"),
        _GPT_ARCH_SEXTET(MIPS_LE,     "mipsel"), /* Alias: must be listed after mips-le */
        _GPT_ARCH_SEXTET(MIPS64_LE,   "mips64-le"),
        _GPT_ARCH_SEXTET(MIPS64_LE,   "mips64el"), /* Alias: must be listed after mips64-le */
        _GPT_ARCH_SEXTET(PARISC,      "parisc"),
        _GPT_ARCH_SEXTET(PARISC,      "hppa"), /* Alias: must be listed after parisc */
        _GPT_ARCH_SEXTET(PPC,         "ppc"),
        _GPT_ARCH_SEXTET(PPC64,       "ppc64"),
        _GPT_ARCH_SEXTET(PPC64_LE,    "ppc64-le"),
        _GPT_ARCH_SEXTET(PPC64_LE,    "ppc64le"), /* Alias: must be listed after ppc64-le */
        _GPT_ARCH_SEXTET(PPC64_LE,    "ppc64el"), /* Alias: must be listed after ppc64-le */
        _GPT_ARCH_SEXTET(RISCV32,     "riscv32"),
        _GPT_ARCH_SEXTET(RISCV64,     "riscv64"),
        _GPT_ARCH_SEXTET(S390,        "s390"),
        _GPT_ARCH_SEXTET(S390X,       "s390x"),
        _GPT_ARCH_SEXTET(TILEGX,      "tilegx"),
        _GPT_ARCH_SEXTET(X86,         "x86"),
        _GPT_ARCH_SEXTET(X86,         "i386"), /* Alias: must be listed after x86 */
        _GPT_ARCH_SEXTET(X86,         "i486"), /* Alias: must be listed after x86 */
        _GPT_ARCH_SEXTET(X86,         "i586"), /* Alias: must be listed after x86 */
        _GPT_ARCH_SEXTET(X86,         "i686"), /* Alias: must be listed after x86 */
        _GPT_ARCH_SEXTET(X86_64,      "x86-64"),
        _GPT_ARCH_SEXTET(X86_64,      "x86_64"), /* Alias: must be listed after x86-64 */
        _GPT_ARCH_SEXTET(X86_64,      "amd64"), /* Alias: must be listed after x86-64 */
#ifdef SD_GPT_ROOT_NATIVE
        { SD_GPT_ROOT_NATIVE,            "root",            native_architecture(), .designator = PARTITION_ROOT            },
        { SD_GPT_ROOT_NATIVE_VERITY,     "root-verity",     native_architecture(), .designator = PARTITION_ROOT_VERITY     },
        { SD_GPT_ROOT_NATIVE_VERITY_SIG, "root-verity-sig", native_architecture(), .designator = PARTITION_ROOT_VERITY_SIG },
        { SD_GPT_USR_NATIVE,             "usr",             native_architecture(), .designator = PARTITION_USR             },
        { SD_GPT_USR_NATIVE_VERITY,      "usr-verity",      native_architecture(), .designator = PARTITION_USR_VERITY      },
        { SD_GPT_USR_NATIVE_VERITY_SIG,  "usr-verity-sig",  native_architecture(), .designator = PARTITION_USR_VERITY_SIG  },
#endif
#ifdef SD_GPT_ROOT_SECONDARY
        { SD_GPT_ROOT_SECONDARY,            "root-secondary",            ARCHITECTURE_SECONDARY, .designator = PARTITION_ROOT            },
        { SD_GPT_ROOT_SECONDARY_VERITY,     "root-secondary-verity",     ARCHITECTURE_SECONDARY, .designator = PARTITION_ROOT_VERITY     },
        { SD_GPT_ROOT_SECONDARY_VERITY_SIG, "root-secondary-verity-sig", ARCHITECTURE_SECONDARY, .designator = PARTITION_ROOT_VERITY_SIG },
        { SD_GPT_USR_SECONDARY,             "usr-secondary",             ARCHITECTURE_SECONDARY, .designator = PARTITION_USR             },
        { SD_GPT_USR_SECONDARY_VERITY,      "usr-secondary-verity",      ARCHITECTURE_SECONDARY, .designator = PARTITION_USR_VERITY      },
        { SD_GPT_USR_SECONDARY_VERITY_SIG,  "usr-secondary-verity-sig",  ARCHITECTURE_SECONDARY, .designator = PARTITION_USR_VERITY_SIG  },
#endif

        { SD_GPT_ESP,                    "esp",           _ARCHITECTURE_INVALID, .designator = PARTITION_ESP },
        { SD_GPT_XBOOTLDR,               "xbootldr",      _ARCHITECTURE_INVALID, .designator = PARTITION_XBOOTLDR },
        { SD_GPT_SWAP,                   "swap",          _ARCHITECTURE_INVALID, .designator = PARTITION_SWAP },
        { SD_GPT_HOME,                   "home",          _ARCHITECTURE_INVALID, .designator = PARTITION_HOME },
        { SD_GPT_SRV,                    "srv",           _ARCHITECTURE_INVALID, .designator = PARTITION_SRV },
        { SD_GPT_VAR,                    "var",           _ARCHITECTURE_INVALID, .designator = PARTITION_VAR },
        { SD_GPT_TMP,                    "tmp",           _ARCHITECTURE_INVALID, .designator = PARTITION_TMP },
        { SD_GPT_USER_HOME,              "user-home",     _ARCHITECTURE_INVALID, .designator = _PARTITION_DESIGNATOR_INVALID },
        { SD_GPT_LINUX_GENERIC,          "linux-generic", _ARCHITECTURE_INVALID, .designator = _PARTITION_DESIGNATOR_INVALID },
        {}
};

static const GptPartitionType *gpt_partition_type_find_by_uuid(sd_id128_t id) {

        FOREACH_ARRAY(t, gpt_partition_type_table, ELEMENTSOF(gpt_partition_type_table) - 1)
                if (sd_id128_equal(id, t->uuid))
                        return t;

        return NULL;
}

const char* gpt_partition_type_uuid_to_string(sd_id128_t id) {
        const GptPartitionType *pt;

        pt = gpt_partition_type_find_by_uuid(id);
        if (!pt)
                return NULL;

        return pt->name;
}

const char* gpt_partition_type_uuid_to_string_harder(
                sd_id128_t id,
                char buffer[static SD_ID128_UUID_STRING_MAX]) {

        const char *s;

        assert(buffer);

        s = gpt_partition_type_uuid_to_string(id);
        if (s)
                return s;

        return sd_id128_to_uuid_string(id, buffer);
}

int gpt_partition_type_from_string(const char *s, GptPartitionType *ret) {
        sd_id128_t id = SD_ID128_NULL;
        int r;

        assert(s);

        FOREACH_ARRAY(t, gpt_partition_type_table, ELEMENTSOF(gpt_partition_type_table) - 1)
                if (streq(s, t->name)) {
                        /* Don't return immediately, instead re-resolve by UUID so that we can support
                        * aliases like aarch64 -> arm64 transparently. */
                        id = t->uuid;
                        break;
                }

        if (sd_id128_is_null(id)) {
                r = sd_id128_from_string(s, &id);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = gpt_partition_type_from_uuid(id);

        return 0;
}

GptPartitionType gpt_partition_type_override_architecture(GptPartitionType type, Architecture arch) {
        assert(arch >= 0);

        FOREACH_ARRAY(t, gpt_partition_type_table, ELEMENTSOF(gpt_partition_type_table) - 1)
                if (t->designator == type.designator && t->arch == arch)
                        return *t;

        /* If we can't find an entry with the same designator and the requested architecture, just return the
         * original partition type. */
        return type;
}

Architecture gpt_partition_type_uuid_to_arch(sd_id128_t id) {
        const GptPartitionType *pt;

        pt = gpt_partition_type_find_by_uuid(id);
        if (!pt)
                return _ARCHITECTURE_INVALID;

        return pt->arch;
}

int gpt_partition_label_valid(const char *s) {
        _cleanup_free_ char16_t *recoded = NULL;

        recoded = utf8_to_utf16(s, SIZE_MAX);
        if (!recoded)
                return -ENOMEM;

        return char16_strlen(recoded) <= GPT_LABEL_MAX;
}

GptPartitionType gpt_partition_type_from_uuid(sd_id128_t id) {
        const GptPartitionType *pt;

        pt = gpt_partition_type_find_by_uuid(id);
        if (pt)
                return *pt;

        return (GptPartitionType) {
                .uuid = id,
                .arch = _ARCHITECTURE_INVALID,
                .designator = _PARTITION_DESIGNATOR_INVALID,
        };
}

const char* gpt_partition_type_mountpoint_nulstr(GptPartitionType type) {
        return partition_mountpoint_to_string(type.designator);
}

bool gpt_partition_type_knows_read_only(GptPartitionType type) {
        return IN_SET(type.designator,
                      PARTITION_ROOT,
                      PARTITION_USR,
                      /* pretty much implied, but let's set the bit to make things really clear */
                      PARTITION_ROOT_VERITY,
                      PARTITION_USR_VERITY,
                      PARTITION_ROOT_VERITY_SIG,
                      PARTITION_USR_VERITY_SIG,
                      PARTITION_HOME,
                      PARTITION_SRV,
                      PARTITION_VAR,
                      PARTITION_TMP,
                      PARTITION_XBOOTLDR);
}

bool gpt_partition_type_knows_growfs(GptPartitionType type) {
        return IN_SET(type.designator,
                      PARTITION_ROOT,
                      PARTITION_USR,
                      PARTITION_HOME,
                      PARTITION_SRV,
                      PARTITION_VAR,
                      PARTITION_TMP,
                      PARTITION_XBOOTLDR);
}

bool gpt_partition_type_knows_no_auto(GptPartitionType type) {
        return IN_SET(type.designator,
                      PARTITION_ROOT,
                      PARTITION_ROOT_VERITY,
                      PARTITION_USR,
                      PARTITION_USR_VERITY,
                      PARTITION_HOME,
                      PARTITION_SRV,
                      PARTITION_VAR,
                      PARTITION_TMP,
                      PARTITION_XBOOTLDR,
                      PARTITION_SWAP);
}

bool gpt_partition_type_has_filesystem(GptPartitionType type) {
        return IN_SET(type.designator,
                      PARTITION_ROOT,
                      PARTITION_USR,
                      PARTITION_HOME,
                      PARTITION_SRV,
                      PARTITION_ESP,
                      PARTITION_XBOOTLDR,
                      PARTITION_TMP,
                      PARTITION_VAR);
}

bool gpt_header_has_signature(const GptHeader *p) {
        assert(p);

        if (memcmp(p->signature, (const char[8]) { 'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T' }, 8) != 0)
                return false;

        if (le32toh(p->revision) != UINT32_C(0x00010000)) /* the only known revision of the spec: 1.0 */
                return false;

        if (le32toh(p->header_size) < sizeof(GptHeader))
                return false;

        if (le32toh(p->header_size) > 4096) /* larger than a sector? something is off… */
                return false;

        if (le64toh(p->my_lba) != 1) /* this sector must claim to be at sector offset 1 */
                return false;

        return true;
}
