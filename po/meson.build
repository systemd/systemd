# SPDX-License-Identifier: LGPL-2.1-or-later

want_translations = get_option('translations')

if want_translations
        # The msgmerge invocation hidden behind i18n.gettext()'s update-po target inserts auto-guessed
        # "fuzzy" translations for new strings, which are almost always wrong, use a wrapper to skip it.
        meson.override_find_program('msgmerge', msgmerge_no_fuzzy_py)

        i18n = import('i18n')
        i18n.gettext(meson.project_name(),
                     preset : 'glib',
                     data_dirs : '.')
endif
