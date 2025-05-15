# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_REMOTE') != 1
        subdir_done()
endif

systemd_journal_upload_sources = files(
        'journal-compression-util.c',
        'journal-upload-journal.c',
        'journal-upload.c',
)
systemd_journal_upload_extract_sources = files(
        'journal-header-util.c',
)

systemd_journal_remote_sources = files('journal-remote-main.c')
systemd_journal_remote_extract_sources = files(
        'journal-compression-util.c',
        'journal-remote-parse.c',
        'journal-remote-write.c',
        'journal-remote.c',
)

if conf.get('HAVE_MICROHTTPD') == 1
        systemd_journal_remote_extract_sources += files(
                'microhttpd-util.c',
        )
endif

systemd_journal_gatewayd_sources = files(
        'journal-gatewayd.c',
        'microhttpd-util.c',
)

common_deps = [
        libgnutls,
        liblz4_cflags,
        libxz_cflags,
        libzstd_cflags,
        threads,
]

executables += [
        libexec_template + {
                'name' : 'systemd-journal-upload',
                'public' : true,
                'conditions' : ['HAVE_LIBCURL'],
                'sources' : [systemd_journal_upload_sources, systemd_journal_upload_extract_sources],
                'extract' : systemd_journal_upload_extract_sources,
                'dependencies' : common_deps + [libcurl],
        },
        libexec_template + {
                'name' : 'systemd-journal-remote',
                'public' : true,
                'sources' : [systemd_journal_remote_sources, systemd_journal_remote_extract_sources],
                'extract' : systemd_journal_remote_extract_sources,
                'dependencies' : common_deps + [libmicrohttpd],
        },
        libexec_template + {
                'name' : 'systemd-journal-gatewayd',
                'public' : true,
                'conditions' : ['HAVE_MICROHTTPD'],
                'sources' : systemd_journal_gatewayd_sources,
                'dependencies' : common_deps + [libmicrohttpd],
        },
        test_template + {
                'sources' : files('test-journal-header-util.c'),
                'conditions' : ['HAVE_LIBCURL'],
                'objects' : ['systemd-journal-upload'],
        },
        fuzz_template + {
                'sources' : files('fuzz-journal-remote.c'),
                'objects' : ['systemd-journal-remote'],
                'dependencies' : common_deps + [libmicrohttpd],
        },
]

in_files = [
        ['journal-upload.conf', conf.get('HAVE_LIBCURL') == 1 and install_sysconfdir_samples],
        ['journal-remote.conf', conf.get('HAVE_MICROHTTPD') == 1 and install_sysconfdir_samples]]

foreach tuple : in_files
        file = tuple[0]
        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : tuple[1],
                install_dir : pkgconfigfiledir)
endforeach

if conf.get('HAVE_MICROHTTPD') == 1
        install_data('browse.html',
                     install_dir : pkgdatadir / 'gatewayd')

        if get_option('create-log-dirs')
                install_emptydir('/var/log/journal/remote',
                                 install_mode : 'rwxr-xr-x')
        endif
endif
