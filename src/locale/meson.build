# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_localed_sources = files(
        'localed-util.c',
        'localed.c',
        'xkbcommon-util.c',
)

localectl_sources = files('localectl.c')

if conf.get('ENABLE_LOCALED') == 1
        install_data('org.freedesktop.locale1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.locale1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.locale1.policy',
                     install_dir : polkitpolicydir)
endif

# If you know a way that allows the same variables to be used
# in sources list and concatenated to a string for test_env,
# let me know.
kbd_model_map = meson.current_source_dir() / 'kbd-model-map'
language_fallback_map = meson.current_source_dir() / 'language-fallback-map'

if conf.get('ENABLE_LOCALED') == 1
        install_data('kbd-model-map',
                     'language-fallback-map',
                     install_dir : pkgdatadir)
endif

# logind will load libxkbcommon.so dynamically on its own, but we still need to
# specify where the headers are.
if conf.get('HAVE_XKBCOMMON') == 1
        libxkbcommon_deps = [libdl,
                             libxkbcommon.partial_dependency(compile_args: true)]
else
        libxkbcommon_deps = []
endif

tests += [
        {
                'sources' : files(
                        'test-localed-util.c',
                        'localed-util.c',
                        'xkbcommon-util.c',
                ),
                'dependencies' : libxkbcommon_deps,
        },
]
