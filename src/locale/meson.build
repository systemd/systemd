# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_LOCALED') != 1
        subdir_done()
endif

systemd_localed_sources = files(
        'localed.c'
)
systemd_localed_extract_sources = files(
        'localed-util.c',
        'xkbcommon-util.c',
)

localectl_sources = files('localectl.c')

# logind will load libxkbcommon.so dynamically on its own, but we still need to
# specify where the headers are.
if conf.get('HAVE_XKBCOMMON') == 1
        libxkbcommon_deps = [
                libdl,
                libxkbcommon.partial_dependency(compile_args: true),
        ]
else
        libxkbcommon_deps = []
endif

executables += [
        libexec_template + {
                'name' : 'systemd-localed',
                'dbus' : true,
                'sources' : systemd_localed_sources + systemd_localed_extract_sources,
                'extract' : systemd_localed_extract_sources,
                'dependencies' : libxkbcommon_deps,
        },
        executable_template + {
                'name' : 'localectl',
                'public' : true,
                'sources' : files('localectl.c'),
        },
        test_template + {
                'sources' : files('test-localed-util.c'),
                'objects' : ['systemd-localed'],
                'dependencies' : libxkbcommon_deps,
        },
]

# If you know a way that allows the same variables to be used
# in sources list and concatenated to a string for test_env,
# let me know.
kbd_model_map = meson.current_source_dir() / 'kbd-model-map'
language_fallback_map = meson.current_source_dir() / 'language-fallback-map'

install_data('org.freedesktop.locale1.conf',
                install_dir : dbuspolicydir)
install_data('org.freedesktop.locale1.service',
                install_dir : dbussystemservicedir)
install_data('org.freedesktop.locale1.policy',
                install_dir : polkitpolicydir)
install_data('kbd-model-map',
                'language-fallback-map',
                install_dir : pkgdatadir)
