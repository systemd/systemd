# SPDX-License-Identifier: LGPL-2.1-or-later

if not have_rust
        subdir_done()
endif

rust = import('rust')

# The config.h conditions, so that Rust code says #[cfg(HAVE_FOO)] where C code says #if HAVE_FOO, and a
# misspelled one is reported.
rust_cfg_args = []
foreach key : conf.keys()
        if key.startswith('HAVE_') or key.startswith('ENABLE_')
                rust_cfg_args += '--check-cfg=cfg(@0@)'.format(key)
                if '@0@'.format(conf.get(key)) == '1'
                        rust_cfg_args += '--cfg=' + key
                endif
        endif
endforeach
# And the one C code gets from the compiler.
rust_cfg_args += '--check-cfg=cfg(HAS_FEATURE_ADDRESS_SANITIZER)'
if get_option('b_sanitize').contains('address')
        rust_cfg_args += '--cfg=HAS_FEATURE_ADDRESS_SANITIZER'
endif

# Everything Rust code needs to use libsystemd-shared.
shared_dep = declare_dependency(
        link_with : libshared,
        include_directories : includes,
        dependencies : [libshared_deps, userspace])
# Rust targets only take the link side of it: meson < 1.9 refuses a Rust target that is handed C sources
# through a dependency.
shared_link_dep = shared_dep.partial_dependency(links : true, link_args : true)

# The C compiler searches the libc, override and uapi directories in that order, and meson's C backend
# lists them reversed for that reason. The rust module passes dependency include directories to bindgen
# in the order they were declared, which puts uapi first and hides every #include_next override. c_args
# come before everything else and the first occurrence of a directory wins.
system_include_args = []
foreach dir : ['src/include' / get_option('libc'), 'src/include/override', 'src/include/uapi']
        system_include_args += ['-isystem', meson.project_build_root() / dir,
                                '-isystem', meson.project_source_root() / dir]
endforeach

############################################################

# systemd_shared_sys: raw FFI bindings for the libsystemd-shared helpers Rust code uses, bindings.h lists
# their headers. Static inline helpers only exist in headers, so bindgen also writes C trampolines for them.
# Those are compiled into the Rust consumers, which is exactly what happens with C consumers (inlining),
# hence the shared library itself stays untouched.
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
                '--rust-target', rust_msrv,
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
                # The X.509 bits crypto-util.h users look at.
                '--allowlist-var', 'EXFLAG_[A-Z_]+|X?KU_[A-Z_]+|V_ASN1_NEG_INTEGER',
                # What the allocator, the panic handler, print!() and the log macros are built on, plus helpers
                # that C code gets from libc directly.
                '--allowlist-function', 'malloc|calloc|realloc|posix_memalign|free|abort|fwrite|strdup|fchmod|__errno_location',
                '--allowlist-var', 'stdout',
                # bindgen mis-serializes pointer-to-array parameters of static inline functions, see
                # https://github.com/rust-lang/rust-bindgen/issues/3403.
                '--blocklist-function', 'close_pairp',
                # Refers to the linker-generated bounds of the SYSTEMD_VERBS section, which only exists in
                # programs defining verbs in C.
                '--blocklist-function', 'verb_help_auto',
        ])

libsystemd_shared_sys_wrappers = static_library(
        'systemd-shared-sys-wrappers',
        systemd_shared_sys_gen[1],
        dependencies : [shared_dep],
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
                  '-I' + meson.project_build_root()])

# Generated code does not get to fail the build over lints, whichever rustc version adds them. The whole
# bindgen target goes into structured_sources(), meson < 1.10 crashes on one of its outputs.
libsystemd_shared_sys = static_library(
        'systemd_shared_sys',
        structured_sources(['systemd_shared_sys.rs', systemd_shared_sys_gen]),
        rust_abi : 'rust',
        rust_args : ['--cap-lints', 'allow'],
        link_with : [libsystemd_shared_sys_wrappers],
        dependencies : [shared_link_dep])

############################################################

# systemd_shared: what Rust code is supposed to use.
systemd_shared_sources = files(
        'lib.rs',
        'alloc.rs',
        'chase.rs',
        'command.rs',
        'conf_files.rs',
        'creds.rs',
        'cstr.rs',
        'dlopen.rs',
        'errno.rs',
        'fd.rs',
        'fileio.rs',
        'json.rs',
        'keyring.rs',
        'kmod.rs',
        'log.rs',
        'panic.rs',
        'path.rs',
        'prelude.rs',
        'program.rs',
        'recurse_dir.rs',
        'stdio.rs',
        'strv.rs',
        'table.rs',
        'tests.rs',
        'tmpfile.rs',
        'voa.rs',
        'x509.rs',
)

systemd_shared_rust_sources = systemd_shared_sources + files('systemd_shared_sys.rs')
rust_sources += systemd_shared_rust_sources

libsystemd_shared_rs = static_library(
        'systemd_shared',
        systemd_shared_sources,
        rust_abi : 'rust',
        rust_args : rust_cfg_args,
        link_with : [libsystemd_shared_sys])
