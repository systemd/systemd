journal_internal_sources = files('''
        audit-type.c
        audit-type.h
        catalog.c
        catalog.h
        compress.c
        compress.h
        journal-def.h
        journal-file.c
        journal-file.h
        journal-send.c
        journal-vacuum.c
        journal-vacuum.h
        journal-verify.c
        journal-verify.h
        lookup3.c
        lookup3.h
        mmap-cache.c
        mmap-cache.h
        sd-journal.c
'''.split())

if conf.get('HAVE_GCRYPT', false)
        journal_internal_sources += files('''
                journal-authenticate.c
                journal-authenticate.h
                fsprg.c
                fsprg.h
        '''.split())

        journal_internal_sources += gcrypt_util_sources
endif

############################################################

audit_type_includes = [config_h,
                       missing_h,
                       'linux/audit.h']
if conf.get('HAVE_AUDIT', false)
        audit_type_includes += 'libaudit.h'
endif

generate_audit_type_list = find_program('generate-audit_type-list.sh')
audit_type_list_txt = custom_target(
        'audit_type-list.txt',
        output : 'audit_type-list.txt',
        command : [generate_audit_type_list, cpp] + audit_type_includes,
        capture : true)

audit_type_to_name = custom_target(
        'audit_type-to-name.h',
        input : ['audit_type-to-name.awk', audit_type_list_txt],
        output : 'audit_type-to-name.h',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

journal_internal_sources += [audit_type_to_name]

############################################################

libjournal_core_sources = files('''
        journald-kmsg.c
        journald-kmsg.h
        journald-syslog.c
        journald-syslog.h
        journald-stream.c
        journald-stream.h
        journald-server.c
        journald-server.h
        journald-console.c
        journald-console.h
        journald-wall.c
        journald-wall.h
        journald-native.c
        journald-native.h
        journald-audit.c
        journald-audit.h
        journald-rate-limit.c
        journald-rate-limit.h
        journal-internal.h
'''.split())

systemd_journald_sources = files('''
        journald.c
        journald-server.h
'''.split())

journald_gperf_c = custom_target(
        'journald-gperf.c',
        input : 'journald-gperf.gperf',
        output : 'journald-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_cat_sources = files('cat.c')

journalctl_sources = files('journalctl.c')

if conf.get('HAVE_QRENCODE', false)
        journalctl_sources += files('journal-qrcode.c',
                                    'journal-qrcode.h')
endif

install_data('journald.conf',
             install_dir : pkgsysconfdir)

meson.add_install_script(
        'sh', '-c',
        mkdir_p.format('/var/log/journal'))
meson.add_install_script(
        'sh', '-c',
        'chown 0:0 $DESTDIR/var/log/journal &&
         chmod 755 $DESTDIR/var/log/journal || :')
if get_option('adm-group')
        meson.add_install_script(
                'sh', '-c',
                'setfacl -nm g:adm:rx,d:g:adm:rx $DESTDIR/var/log/journal || :')
endif
if get_option('wheel-group')
        meson.add_install_script(
                'sh', '-c',
                'setfacl -nm g:wheel:rx,d:g:wheel:rx $DESTDIR/var/log/journal || :')
endif
