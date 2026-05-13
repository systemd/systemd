# SPDX-License-Identifier: LGPL-2.1-or-later

want_translations = get_option('translations')

if want_translations
        i18n = import('i18n')
        i18n.gettext(meson.project_name(),
                     preset : 'glib',
                     data_dirs : '.')
endif
