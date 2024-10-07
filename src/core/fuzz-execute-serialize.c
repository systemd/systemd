/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Notes on how to run the fuzzer manually:
 *  1) Build the fuzzers with LLVM's libFuzzer and ASan+UBSan:
 *    $ CC=clang CXX=clang++ meson build-libfuzz -Db_sanitize=address,undefined -Dllvm-fuzz=true -Db_lundef=false
 *
 *  2) Collect some valid inputs:
 *
 * OUT=test/fuzz/fuzz-execute-serialize/initial
 * for section in context command parameters runtime cgroup; do
 *     awk "match(\$0, /startswith\\(.+, \"(exec-${section}-[^\"]+=)\"/, m) { print m[1]; }" \
 *         src/core/execute-serialize.c >>"$OUT"
 *     # Each "section" is delimited by an empty line
 *     echo >>"$OUT"
 * done
 *
 *  3) Run the fuzzer:
 *    $ build-libfuzz/fuzz-execute-serialize test/fuzz/fuzz-execute-serialize
 */

#include <stdio.h>

#include "alloc-util.h"
#include "execute-serialize.h"
#include "fd-util.h"
#include "fuzz.h"
#include "service.h"

static void exec_fuzz_one(FILE *f, FDSet *fdset) {
        _cleanup_(exec_params_deep_clear) ExecParameters params = EXEC_PARAMETERS_INIT(/* flags= */ 0);
        _cleanup_(exec_context_done) ExecContext exec_context = {};
        _cleanup_(cgroup_context_done) CGroupContext cgroup_context = {};
        DynamicCreds dynamic_creds = {};
        ExecCommand command = {};
        ExecSharedRuntime shared = {
                .netns_storage_socket = EBADF_PAIR,
                .ipcns_storage_socket = EBADF_PAIR,
        };
        ExecRuntime runtime = {
                .ephemeral_storage_socket = EBADF_PAIR,
                .shared = &shared,
                .dynamic_creds = &dynamic_creds,
        };

        exec_context_init(&exec_context);
        cgroup_context_init(&cgroup_context);

        (void) exec_deserialize_invocation(f, fdset, &exec_context, &command, &params, &runtime, &cgroup_context);
        (void) exec_serialize_invocation(f, fdset, &exec_context, &command, &params, &runtime, &cgroup_context);
        (void) exec_deserialize_invocation(f, fdset, &exec_context, &command, &params, &runtime, &cgroup_context);

        /* We definitely didn't provide valid FDs during deserialization, so
         * wipe the FDs before exec_params_serialized_clear() kicks in, otherwise
         * we'll hit the assert in safe_close() */
        params.stdin_fd = -EBADF;
        params.stdout_fd = -EBADF;
        params.stderr_fd = -EBADF;
        params.exec_fd = -EBADF;
        params.user_lookup_fd = -EBADF;
        params.bpf_restrict_fs_map_fd = -EBADF;
        if (!params.fds)
                params.n_socket_fds = params.n_storage_fds = params.n_extra_fds = 0;
        for (size_t i = 0; params.fds && i < params.n_socket_fds + params.n_storage_fds + params.n_extra_fds; i++)
                params.fds[i] = -EBADF;

        exec_command_done_array(&command, /* n= */ 1);
        exec_shared_runtime_done(&shared);
        if (dynamic_creds.group != dynamic_creds.user)
                dynamic_user_free(dynamic_creds.group);
        dynamic_user_free(dynamic_creds.user);
        free(runtime.ephemeral_copy);
        safe_close_pair(runtime.ephemeral_storage_socket);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_fdset_free_ FDSet *fdset = NULL;

        if (outside_size_range(size, 0, 128 * 1024))
                return 0;

        fuzz_setup_logging();

        assert_se(fdset = fdset_new());
        assert_se(f = data_to_file(data, size));

        exec_fuzz_one(f, fdset);

        return 0;
}
