# SPDX-License-Identifier: LGPL-2.1-or-later

check_api_docs_sh              = files('check-api-docs.sh')
check_efi_alignment_py         = files('check-efi-alignment.py')
check_help_sh                  = files('check-help.sh')
check_version_history_py       = files('check-version-history.py')
check_version_sh               = files('check-version.sh')
elf2efi_py                     = files('elf2efi.py')
dbus_exporter_py               = files('dbus_exporter.py')
find_unused_library_symbols_py = files('find-unused-library-symbols.py')
generate_gperfs                = files('generate-gperfs.py')
git_contrib_sh                 = files('git-contrib.sh')
make_autosuspend_rules_py      = files('make-autosuspend-rules.py')
make_directive_index_py        = files('make-directive-index.py')
make_man_index_py              = files('make-man-index.py')
meson_build_sh                 = files('meson-build.sh')
meson_extract_unit_files_py    = files('meson-extract-unit-files.py')
meson_render_jinja2_py         = files('meson-render-jinja2.py')
sync_docs_py                   = files('sync-docs.py')
update_dbus_docs_py            = files('update-dbus-docs.py')
update_hwdb_autosuspend_sh     = files('update-hwdb-autosuspend.sh')
update_hwdb_sh                 = files('update-hwdb.sh')
update_man_rules_py            = files('update-man-rules.py')
update_syscall_tables_sh       = files('update-syscall-tables.sh')
vcs_tag_sh                     = files('vcs-tag.sh')
xml_helper_py                  = files('xml_helper.py')

#####################################################################

# Try to install the git pre-commit hook
git_setup_sh = find_program('./git-setup.sh', required : false)
if git_setup_sh.found()
        git_hook = run_command(git_setup_sh, check : false)
        if git_hook.returncode() == 0
                message(git_hook.stdout().strip())
        endif
endif
