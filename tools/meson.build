# SPDX-License-Identifier: LGPL-2.1-or-later

check_api_docs_sh              = files('check-api-docs.sh')
check_argument_comments_py     = files('check-argument-comments.py')
check_coccinelle_sh            = files('check-coccinelle.sh')
check_efi_alignment_py         = files('check-efi-alignment.py')
check_help_sh                  = files('check-help.sh')
check_version_history_py       = files('check-version-history.py')
check_version_sh               = files('check-version.sh')
elf2efi_py                     = files('elf2efi.py')
dbus_exporter_py               = files('dbus_exporter.py')
find_unused_library_symbols_py = files('find-unused-library-symbols.py')
fix_rust_rpath_py              = files('fix-rust-rpath.py')
generate_gperfs                = files('generate-gperfs.py')
git_contrib_sh                 = files('git-contrib.sh')
make_autosuspend_rules_py      = files('make-autosuspend-rules.py')
make_directive_index_py        = files('make-directive-index.py')
make_man_index_py              = files('make-man-index.py')
meson_build_sh                 = files('meson-build.sh')
meson_extract_unit_files_py    = files('meson-extract-unit-files.py')
meson_gperf_py                 = files('meson-gperf.py')
meson_render_jinja2_py         = files('meson-render-jinja2.py')
msgmerge_no_fuzzy_py           = files('msgmerge-no-fuzzy.py')
sync_docs_py                   = files('sync-docs.py')
update_dbus_docs_py            = files('update-dbus-docs.py')
update_hwdb_autosuspend_sh     = files('update-hwdb-autosuspend.sh')
update_hwdb_sh                 = files('update-hwdb.sh')
update_man_rules_py            = files('update-man-rules.py')
update_syscall_tables_sh       = files('update-syscall-tables.sh')
vcs_tag_sh                     = files('vcs-tag.sh')
xml_helper_py                  = files('xml_helper.py')

#####################################################################

suspend_check = get_option('suspend-check')
if not suspend_check.disabled() and add_languages('cpp', native : true, required : suspend_check)
        suspend_cxx = meson.get_compiler('cpp', native : true)
        suspend_llvm = dependency('llvm', native : true, modules : ['support'], static : false, required : suspend_check)
        suspend_clang = suspend_cxx.find_library('clang-cpp', required : suspend_check)
        suspend_tidy_program = find_program('clang-tidy', native : true, required : suspend_check)
        if suspend_llvm.found() and suspend_clang.found() and suspend_tidy_program.found()
                suspend_tidy_version = run_command(suspend_tidy_program, '--version', check : true).stdout().split('LLVM version ')[-1].strip().split('\n')[0]
                suspend_tidy_headers = suspend_cxx.has_header('clang-tidy/ClangTidyCheck.h', dependencies : suspend_llvm)
                suspend_tidy_compatible = suspend_tidy_version == suspend_llvm.version() and suspend_tidy_headers
                if not suspend_tidy_compatible and suspend_check.enabled()
                        error('The suspension plugin requires matching clang-tidy and LLVM versions and clang-tidy development headers')
                endif
                if suspend_tidy_compatible
                        suspend_tidy = shared_module(
                                'suspend-tidy',
                                'suspend-tidy.cpp',
                                native : true,
                                dependencies : [suspend_clang, suspend_llvm],
                                gnu_symbol_visibility : 'hidden',
                                # clang-tidy exports its plugin API from its executable.
                                override_options : ['cpp_std=c++17', 'warning_level=1', 'optimization=2', 'b_lundef=false'],
                                install : false,
                        )
                        test('suspend-tidy',
                             python,
                             args : [files('test-suspend-check.py'), suspend_tidy, meson.project_source_root(),
                                     suspend_tidy_program.full_path()],
                             timeout : 180)
                endif
        endif
endif

#####################################################################

# Try to install the git pre-commit hook
git_setup_sh = find_program('./git-setup.sh', required : false)
if git_setup_sh.found()
        git_hook = run_command(git_setup_sh, check : false)
        if git_hook.returncode() == 0
                message(git_hook.stdout().strip())
        endif
endif
