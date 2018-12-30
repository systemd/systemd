# SPDX-License-Identifier: LGPL-2.1+

i18n = import('i18n')
if find_program('xgettext', required : false).found()
        i18n.gettext(meson.project_name(),
                     preset : 'glib',
                     data_dirs : '.')
else
        warning('Can not do gettext because xgettext is not installed.')
endif
