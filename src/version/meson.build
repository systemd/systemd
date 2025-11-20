# SPDX-License-Identifier: LGPL-2.1-or-later

vcs_tag = get_option('vcs-tag')
version_h = custom_target('version',
        build_always_stale : vcs_tag,
        input : 'version.h.in',
        output : 'version.h',
        capture : true,
        command : [
                meson.project_source_root() / 'tools/vcs-tag.sh',
                '@INPUT@',
                get_option('mode'),
                vcs_tag ? '1' : '0',
        ])
version_include = include_directories('.')
userspace_sources += [version_h]
