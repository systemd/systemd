i18n = import('i18n')
i18n.gettext(meson.project_name())

#####################################################################

intltool_merge = find_program('intltool-merge')
po_dir = meson.current_source_dir()

intltool_cache = join_paths(meson.current_build_dir(), 'intltool-merge-cache')
intltool_command = [intltool_merge, '-x', '-u',
                    '-c', intltool_cache,
                    po_dir, '@INPUT@', '@OUTPUT@']
