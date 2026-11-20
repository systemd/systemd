/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int binfmt_mounted_and_writable(void);
int disable_binfmt(void);

typedef enum BinfmtRuleType {
        BINFMT_RULE_MAGIC,              /* 'M' */
        BINFMT_RULE_EXTENSION,          /* 'E' */
        BINFMT_RULE_BPF,                /* 'B' */
        _BINFMT_RULE_TYPE_MAX,
        _BINFMT_RULE_TYPE_INVALID = -EINVAL,
} BinfmtRuleType;

/* A binfmt_misc rule ":name:type:offset:magic:mask:interpreter:flags", split into the fields systemd-binfmt
 * looks at. Everything else is left to the kernel to validate. Like the kernel's struct
 * binfmt_misc_entry, a bpf-backed rule has a handler instead of an interpreter. */
typedef struct BinfmtRule {
        char *buffer;                   /* Copy of the rule, the fields point into it */
        const char *name;
        BinfmtRuleType type;
        const char *interpreter;        /* NULL for BINFMT_RULE_BPF */
        const char *bpf_handler;        /* Only set for BINFMT_RULE_BPF */
} BinfmtRule;

void binfmt_rule_done(BinfmtRule *rule);
int binfmt_rule_parse(const char *s, BinfmtRule *ret);
