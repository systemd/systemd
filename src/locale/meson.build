systemd_localed_sources = files('''
        localed.c
        keymap-util.c
        keymap-util.h
'''.split())

localectl_sources = files('localectl.c')

if conf.get('ENABLE_LOCALED', false)
        install_data('org.freedesktop.locale1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.locale1.service',
                     install_dir : dbussystemservicedir)

        custom_target(
                'org.freedesktop.locale1.policy',
                input : 'org.freedesktop.locale1.policy.in',
                output : 'org.freedesktop.locale1.policy',
                command : intltool_command,
                install : install_polkit,
                install_dir : polkitpolicydir)
endif

# If you know a way that allows the same variables to be used
# in sources list and concatenated to a string for test_env,
# let me know.
kbd_model_map = join_paths(meson.current_source_dir(),  'kbd-model-map')
language_fallback_map = join_paths(meson.current_source_dir(), 'language-fallback-map')

if conf.get('ENABLE_LOCALED', false)
        install_data('kbd-model-map',
                     'language-fallback-map',
                     install_dir : pkgdatadir)
endif

tests += [
        [['src/locale/test-keymap-util.c',
          'src/locale/keymap-util.c',
          'src/locale/keymap-util.h'],
         [libshared],
         [libdl]],
]
