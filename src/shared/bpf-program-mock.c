/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "bpf-program.h"
#include "macro.h"

static BPFProgram *bpf_program_mock_free(BPFProgram *program) {
        return mfree(program);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(BPFProgram, bpf_program, bpf_program_mock_free);
