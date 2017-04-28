systemd_importd_sources = files('''
        importd.c
'''.split())

systemd_pull_sources = files('''
        pull.c
        pull-raw.c
        pull-raw.h
        pull-tar.c
        pull-tar.h
        pull-job.c
        pull-job.h
        pull-common.c
        pull-common.h
        import-common.c
        import-common.h
        import-compress.c
        import-compress.h
        curl-util.c
        curl-util.h
        qcow2-util.c
        qcow2-util.h
'''.split())

systemd_import_sources = files('''
        import.c
        import-raw.c
        import-raw.h
        import-tar.c
        import-tar.h
        import-common.c
        import-common.h
        import-compress.c
        import-compress.h
        qcow2-util.c
        qcow2-util.h
'''.split())

systemd_export_sources = files('''
        export.c
        export-tar.c
        export-tar.h
        export-raw.c
        export-raw.h
        import-common.c
        import-common.h
        import-compress.c
        import-compress.h
'''.split())

if conf.get('ENABLE_IMPORTD', false)
        install_data('org.freedesktop.import1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.import1.service',
                     install_dir : dbussystemservicedir)

        custom_target(
                'org.freedesktop.import1.policy',
                input : 'org.freedesktop.import1.policy.in',
                output : 'org.freedesktop.import1.policy',
                command : intltool_command,
                install : install_polkit,
                install_dir : polkitpolicydir)

        install_data('import-pubring.gpg',
                     install_dir : rootlibexecdir)
        # TODO: shouldn't this be in pkgdatadir?
endif

tests += [
        [['src/import/test-qcow2.c',
          'src/import/qcow2-util.c',
          'src/import/qcow2-util.h'],
         [libshared],
         [libz],
         'HAVE_ZLIB', 'manual'],
]
