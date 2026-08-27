# SPDX-License-Identifier: LGPL-2.1-or-later

# This is a meson subproject rather than a subdir on purpose: the rust module's bindgen() integration
# needs a newer meson than the rest of the tree and meson checks feature warnings against the minimum
# version of the project that uses them, so keeping the Rust bits in their own project lets the tree stay
# at its own minimum. The parent hands us libsystemd-shared together with its include directories and
# compile arguments as the 'systemd-shared-internal' dependency, and its C warning and hardening flags as
# 'systemd-common-c-args' (add_project_arguments() does not cross project boundaries).
#
# The floor is 1.8.0: bindgen() looks up this subproject's c_args option, which older versions only know
# about when it was set on the command line.

project('systemd-shared-rust', ['rust', 'c'],
        license : 'LGPLv2+',
        default_options : ['rust_std=2021'],
        meson_version : '>= 1.8.0')

rust = import('rust')

# Version checks happen in the parent project.
bindgen = find_program('bindgen')

shared_dep = dependency('systemd-shared-internal')
common_c_args_dep = dependency('systemd-common-c-args')
# Rust targets only take the link side of it: meson < 1.9 refuses a Rust target that is handed C sources
# through a dependency.
shared_link_dep = shared_dep.partial_dependency(links : true, link_args : true)

# The C compiler searches the libc, override and uapi directories in that order, and meson's C backend
# lists them reversed for that reason. The rust module passes dependency include directories to bindgen
# in the order they were declared, which puts uapi first and hides every #include_next override. c_args
# come before everything else and the first occurrence of a directory wins.
system_include_args = []
foreach dir : ['src/include' / get_option('libc'), 'src/include/override', 'src/include/uapi']
        system_include_args += ['-isystem', meson.global_build_root() / dir,
                                '-isystem', meson.global_source_root() / dir]
endforeach

############################################################

# systemd_shared_sys: raw FFI bindings for everything libsystemd-shared exports. Static inline helpers only
# exist in headers, so bindgen also writes C trampolines for them. Those are compiled into the Rust
# consumers, which is exactly what happens with C consumers (inlining), hence the shared library itself
# stays untouched.
systemd_shared_sys_gen = rust.bindgen(
        input : 'bindings.h',
        output : 'systemd_shared_sys_generated.rs',
        output_inline_wrapper : 'systemd_shared_sys_wrappers.c',
        # libsystemd-shared is compiled with default visibility, but the tree-wide -fvisibility=hidden arrives
        # here via the parent dependency and would make bindgen drop every non-static function. Dependency
        # compile arguments are emitted in list order, so the override must come last.
        dependencies : [shared_dep,
                        declare_dependency(compile_args : ['-fvisibility=default'])],
        # meson < 1.11 does not forward its own -D_FILE_OFFSET_BITS=64 to bindgen, dirent-util.h asserts on it.
        # Without -fno-builtin clang's own prototypes of malloc(), fwrite() & co. win, which spell size_t as
        # unsigned long. The headers silence GCC-only warnings by name, like the C build with clang does.
        c_args : system_include_args + ['-D_FILE_OFFSET_BITS=64',
                                        '-fno-builtin',
                                        '-Wno-unknown-warning-option'],
        args : [
                '--use-core',
                '--ctypes-prefix', 'core::ffi',
                '--generate-cstr',
                '--with-derive-default',
                '--enable-function-attribute-detection',
                '--no-doc-comments',
                '--no-prepend-enum-name',
                '--merge-extern-blocks',
                '--formatter', 'none',
                '--rust-target', get_option('rust-target'),
                '--rust-edition', '2021',
                # The tree, plus its copies of the kernel and libc headers.
                '--allowlist-file', '.*/src/(fundamental|basic|shared|libsystemd|systemd|include)/.*',
                # The const helpers at the end of bindings.h.
                '--allowlist-var', 'RUST_CONST_HELPER_.*',
                # The libc constants systemd code passes around, by family. Functions and types arrive with
                # the tree's own declarations that use them.
                '--allowlist-var', 'LOG_(EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO|DEBUG)',
                '--allowlist-var', 'E[A-Z0-9]+',
                '--allowlist-var', 'EXIT_(SUCCESS|FAILURE)|EX_[A-Z]+',
                '--allowlist-var', 'CLOCK_[A-Z_]+',
                '--allowlist-var', 'AT_[A-Z_]+|O_[A-Z_]+|F_[A-Z_]+|SEEK_[A-Z]+|LOCK_[A-Z]+|RENAME_[A-Z_]+|DT_[A-Z]+',
                '--allowlist-var', 'S_I[A-Z]+|STATX_[A-Z_]+|UTIME_[A-Z]+',
                '--allowlist-var', 'SIG[A-Z0-9]+|SA_[A-Z_]+|SFD_[A-Z_]+|SI_[A-Z]+',
                '--allowlist-var', 'W[A-Z]+|P_[A-Z]+|RUSAGE_[A-Z]+|PIDFD_[A-Z_]+',
                '--allowlist-var', 'PR_[A-Z_]+|CLONE_[A-Z_]+|NS_[A-Z_]+',
                '--allowlist-var', 'MS_[A-Z_]+|MNT_[A-Z_]+|UMOUNT_[A-Z_]+|MOUNT_ATTR_[A-Z_]+|OPEN_TREE_[A-Z_]+|MOVE_MOUNT_[A-Z_]+|FSOPEN_[A-Z_]+|FSMOUNT_[A-Z_]+|FSCONFIG_[A-Z_]+',
                '--allowlist-var', 'MAP_[A-Z_]+|PROT_[A-Z_]+|MADV_[A-Z_]+|MFD_[A-Z_]+|MREMAP_[A-Z_]+',
                '--allowlist-var', 'SOCK_[A-Z_]+|AF_[A-Z0-9_]+|PF_[A-Z0-9_]+|SOL_[A-Z_]+|SO_[A-Z_]+|MSG_[A-Z_]+|SCM_[A-Z_]+|IPPROTO_[A-Z0-9]+|SHUT_[A-Z]+',
                '--allowlist-var', 'POLL[A-Z]+|EPOLL[A-Z_]*|IN_[A-Z_]+|TFD_[A-Z_]+|EFD_[A-Z_]+',
                '--allowlist-var', 'RLIMIT_[A-Z_]+|RLIM_[A-Z_]+|CAP_[A-Z_]+',
                '--allowlist-var', 'PATH_MAX|NAME_MAX|LINE_MAX|ARG_MAX|HOST_NAME_MAX|IOV_MAX|NGROUPS_MAX|[A-Z0-9_]+_MAGIC',
                # What the allocator, the panic handler and print!() are built on, plus helpers that C code
                # gets from libc directly.
                '--allowlist-function', 'malloc|calloc|realloc|posix_memalign|free|abort|fwrite|strdup',
                '--allowlist-var', 'stdout',
                # bindgen mis-serializes pointer-to-array parameters of static inline functions, see
                # https://github.com/rust-lang/rust-bindgen/issues/3403.
                '--blocklist-function', 'close_pairp|locale_variables_freep',
                # Refers to the linker-generated bounds of the SYSTEMD_VERBS section, which only exists in
                # programs defining verbs in C.
                '--blocklist-function', 'verb_help_auto',
                # Journal objects are packed structs with flexible array members, bindgen derives Debug for
                # them inconsistently.
                '--no-debug', 'ObjectHeader|Object|.*Object',
                # bindgen >= 0.73 aligns the unions in these packed structs, which rustc refuses (E0588). Rust
                # code has no use for them.
                '--opaque-type', 'EntryObject__packed|EntryArrayObject|_IMAGE_OPTIONAL_HEADER|PeHeader',
        ])

libsystemd_shared_sys_wrappers = static_library(
        'systemd-shared-sys-wrappers',
        systemd_shared_sys_gen[1],
        dependencies : [shared_dep, common_c_args_dep],
        # bindgen includes bindings.h by a path relative to the build root. The archive is consumed by
        # rustc's linker, which cannot read GCC LTO bytecode, hence never build it with -flto. Function
        # sections let the linker drop the trampolines a program does not call. The trampolines are
        # generated without prototypes, and with libclang >= 22 bindgen repeats the const of a pointee,
        # which is valid C.
        c_args : ['-fno-lto',
                  '-ffunction-sections',
                  '-fdata-sections',
                  '-Wno-missing-prototypes',
                  '-Wno-missing-declarations',
                  '-Wno-duplicate-decl-specifier',
                  '-I' + meson.global_build_root()],
        build_by_default : false)

# Generated code does not get to fail the build over lints, whichever rustc version adds them. The whole
# bindgen target goes into structured_sources(), meson < 1.10 crashes on one of its outputs.
libsystemd_shared_sys = static_library(
        'systemd_shared_sys',
        structured_sources(['systemd_shared_sys.rs', systemd_shared_sys_gen]),
        rust_abi : 'rust',
        rust_args : ['--cap-lints', 'allow'],
        link_with : [libsystemd_shared_sys_wrappers],
        dependencies : [shared_link_dep],
        build_by_default : false)

############################################################

# systemd_shared: what Rust code is supposed to use.
systemd_shared_sources = files(
        'lib.rs',
        'alloc.rs',
        'command.rs',
        'cstr.rs',
        'errno.rs',
        'event.rs',
        'fd.rs',
        'json.rs',
        'log.rs',
        'panic.rs',
        'prelude.rs',
        'program.rs',
        'refcount.rs',
        'stdio.rs',
        'strv.rs',
        'tests.rs',
)

# The parent registers the tests, a subproject with tests of its own breaks meson test --setup= for setups
# only the parent defines.
bindings_h = files('bindings.h')
check_bindings_header_py = files('check-bindings-header.py')

libsystemd_shared_rs = static_library(
        'systemd_shared',
        systemd_shared_sources,
        rust_abi : 'rust',
        link_with : [libsystemd_shared_sys],
        build_by_default : false)
