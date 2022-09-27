/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
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

#define _GPT_ARCH_SEXTET(arch, name)                                   \
        { SD_GPT_ROOT_##arch,              "root-" name,               ARCHITECTURE_##arch, .id = GPT_ROOT            },  \
        { SD_GPT_ROOT_##arch##_VERITY,     "root-" name "-verity",     ARCHITECTURE_##arch, .id = GPT_ROOT_VERITY     },  \
        { SD_GPT_ROOT_##arch##_VERITY_SIG, "root-" name "-verity-sig", ARCHITECTURE_##arch, .id = GPT_ROOT_VERITY_SIG },  \
        { SD_GPT_USR_##arch,               "usr-" name,                ARCHITECTURE_##arch, .id = GPT_USR             },  \
        { SD_GPT_USR_##arch##_VERITY,      "usr-" name "-verity",      ARCHITECTURE_##arch, .id = GPT_USR_VERITY      },  \
        { SD_GPT_USR_##arch##_VERITY_SIG,  "usr-" name "-verity-sig",  ARCHITECTURE_##arch, .id = GPT_USR_VERITY_SIG  }

const GptPartitionType gpt_partition_type_table[] = {
        _GPT_ARCH_SEXTET(ALPHA,       "alpha"),
        _GPT_ARCH_SEXTET(ARC,         "arc"),
        _GPT_ARCH_SEXTET(ARM,         "arm"),
        _GPT_ARCH_SEXTET(ARM64,       "arm64"),
        _GPT_ARCH_SEXTET(IA64,        "ia64"),
        _GPT_ARCH_SEXTET(LOONGARCH64, "loongarch64"),
        _GPT_ARCH_SEXTET(MIPS_LE,     "mips-le"),
        _GPT_ARCH_SEXTET(MIPS64_LE,   "mips64-le"),
        _GPT_ARCH_SEXTET(PARISC,      "parisc"),
        _GPT_ARCH_SEXTET(PPC,         "ppc"),
        _GPT_ARCH_SEXTET(PPC64,       "ppc64"),
        _GPT_ARCH_SEXTET(PPC64_LE,    "ppc64-le"),
        _GPT_ARCH_SEXTET(RISCV32,     "riscv32"),
        _GPT_ARCH_SEXTET(RISCV64,     "riscv64"),
        _GPT_ARCH_SEXTET(S390,        "s390"),
        _GPT_ARCH_SEXTET(S390X,       "s390x"),
        _GPT_ARCH_SEXTET(TILEGX,      "tilegx"),
        _GPT_ARCH_SEXTET(X86,         "x86"),
        _GPT_ARCH_SEXTET(X86_64,      "x86-64"),
#ifdef SD_GPT_ROOT_NATIVE
        { SD_GPT_ROOT_NATIVE,            "root",            native_architecture(), .id = GPT_ROOT            },
        { SD_GPT_ROOT_NATIVE_VERITY,     "root-verity",     native_architecture(), .id = GPT_ROOT_VERITY     },
        { SD_GPT_ROOT_NATIVE_VERITY_SIG, "root-verity-sig", native_architecture(), .id = GPT_ROOT_VERITY_SIG },
        { SD_GPT_USR_NATIVE,             "usr",             native_architecture(), .id = GPT_USR             },
        { SD_GPT_USR_NATIVE_VERITY,      "usr-verity",      native_architecture(), .id = GPT_USR_VERITY      },
        { SD_GPT_USR_NATIVE_VERITY_SIG,  "usr-verity-sig",  native_architecture(), .id = GPT_USR_VERITY_SIG  },
#endif
#ifdef SD_GPT_ROOT_SECONDARY
        _GPT_ARCH_SEXTET(SECONDARY,   "secondary"),
#endif

        { SD_GPT_ESP,                    "esp",           _ARCHITECTURE_INVALID, .id = GPT_ESP },
        { SD_GPT_XBOOTLDR,               "xbootldr",      _ARCHITECTURE_INVALID, .id = GPT_XBOOTLDR },
        { SD_GPT_SWAP,                   "swap",          _ARCHITECTURE_INVALID, .id = GPT_SWAP },
        { SD_GPT_HOME,                   "home",          _ARCHITECTURE_INVALID, .id = GPT_HOME },
        { SD_GPT_SRV,                    "srv",           _ARCHITECTURE_INVALID, .id = GPT_SRV },
        { SD_GPT_VAR,                    "var",           _ARCHITECTURE_INVALID, .id = GPT_VAR },
        { SD_GPT_TMP,                    "tmp",           _ARCHITECTURE_INVALID, .id = GPT_TMP },
        { SD_GPT_USER_HOME,              "user-home",     _ARCHITECTURE_INVALID, .id = GPT_USER_HOME },
        { SD_GPT_LINUX_GENERIC,          "linux-generic", _ARCHITECTURE_INVALID, .id = GPT_LINUX_GENERIC },
        {}
};

static const GptPartitionType *gpt_partition_type_find_by_uuid(sd_id128_t id) {

        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (sd_id128_equal(id, gpt_partition_type_table[i].uuid))
                        return gpt_partition_type_table + i;

        return NULL;
}

const char *gpt_partition_type_uuid_to_string(sd_id128_t id) {
        const GptPartitionType *pt;

        pt = gpt_partition_type_find_by_uuid(id);
        if (!pt)
                return NULL;

        return pt->name;
}

const char *gpt_partition_type_uuid_to_string_harder(
                sd_id128_t id,
                char buffer[static SD_ID128_UUID_STRING_MAX]) {

        const char *s;

        assert(buffer);

        s = gpt_partition_type_uuid_to_string(id);
        if (s)
                return s;

        return sd_id128_to_uuid_string(id, buffer);
}

int gpt_partition_type_uuid_from_string(const char *s, sd_id128_t *ret) {
        assert(s);

        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (streq(s, gpt_partition_type_table[i].name)) {
                        if (ret)
                                *ret = gpt_partition_type_table[i].uuid;
                        return 0;
                }

        return sd_id128_from_string(s, ret);
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

        recoded = utf8_to_utf16(s, strlen(s));
        if (!recoded)
                return -ENOMEM;

        return char16_strlen(recoded) <= GPT_LABEL_MAX;
}

static GptPartitionType gpt_partition_type_from_uuid(sd_id128_t id) {
        const GptPartitionType *pt;

        pt = gpt_partition_type_find_by_uuid(id);
        if (pt)
                return *pt;

        return (GptPartitionType) {
                .uuid = id,
                .arch = _ARCHITECTURE_INVALID,
                .id = _GPT_PARTITION_IDENTIFIER_INVALID,
        };
}

bool gpt_partition_type_is_root(sd_id128_t id) {
        return gpt_partition_type_from_uuid(id).id == GPT_ROOT;
}

bool gpt_partition_type_is_root_verity(sd_id128_t id) {
        return gpt_partition_type_from_uuid(id).id == GPT_ROOT_VERITY;
}

bool gpt_partition_type_is_root_verity_sig(sd_id128_t id) {
        return gpt_partition_type_from_uuid(id).id == GPT_ROOT_VERITY_SIG;
}

bool gpt_partition_type_is_usr(sd_id128_t id) {
        return gpt_partition_type_from_uuid(id).id == GPT_USR;
}

bool gpt_partition_type_is_usr_verity(sd_id128_t id) {
        return gpt_partition_type_from_uuid(id).id == GPT_USR_VERITY;
}

bool gpt_partition_type_is_usr_verity_sig(sd_id128_t id) {
        return gpt_partition_type_from_uuid(id).id == GPT_USR_VERITY_SIG;
}

bool gpt_partition_type_knows_read_only(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).id,
                      GPT_ROOT,
                      GPT_USR,
                      GPT_ROOT_VERITY, /* pretty much implied, but let's set the
                                          bit to make things really clear */
                      GPT_USR_VERITY,  /* ditto */
                      GPT_HOME,
                      GPT_SRV,
                      GPT_VAR,
                      GPT_TMP,
                      GPT_XBOOTLDR);
}

bool gpt_partition_type_knows_growfs(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).id,
                      GPT_ROOT,
                      GPT_USR,
                      GPT_HOME,
                      GPT_SRV,
                      GPT_VAR,
                      GPT_TMP,
                      GPT_XBOOTLDR);
}

bool gpt_partition_type_knows_no_auto(sd_id128_t id) {
        return IN_SET(gpt_partition_type_from_uuid(id).id,
                      GPT_ROOT,
                      GPT_USR,
                      GPT_ROOT_VERITY, /* pretty much implied, but let's set the
                                          bit to make things really clear */
                      GPT_USR_VERITY,  /* ditto */
                      GPT_HOME,
                      GPT_SRV,
                      GPT_VAR,
                      GPT_TMP,
                      GPT_XBOOTLDR,
                      GPT_SWAP);
}
