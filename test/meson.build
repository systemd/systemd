# SPDX-License-Identifier: LGPL-2.1+

test_data_files = '''
        a.service
        b.service
        basic.target
        c.service
        d.service
        daughter.service
        e.service
        end.service
        f.service
        g.service
        grandchild.service
        h.service
        hello-after-sleep.target
        hello.service
        hwdb/10-bad.hwdb
        journal-data/journal-1.txt
        journal-data/journal-2.txt
        parent-deep.slice
        parent.slice
        sched_idle_bad.service
        sched_idle_ok.service
        sched_rr_bad.service
        sched_rr_change.service
        sched_rr_ok.service
        shutdown.target
        sleep.service
        sockets.target
        son.service
        sysinit.target
        test-path/basic.target
        test-path/path-changed.path
        test-path/path-changed.service
        test-path/path-directorynotempty.path
        test-path/path-directorynotempty.service
        test-path/path-exists.path
        test-path/path-exists.service
        test-path/path-existsglob.path
        test-path/path-existsglob.service
        test-path/path-makedirectory.path
        test-path/path-makedirectory.service
        test-path/path-modified.path
        test-path/path-modified.service
        test-path/path-mycustomunit.service
        test-path/path-service.service
        test-path/path-unit.path
        test-path/paths.target
        test-path/sysinit.target
        test-umount/empty.mountinfo
        test-umount/example.swaps
        test-umount/garbled.mountinfo
        test-umount/rhbug-1554943.mountinfo
        testsuite.target
        timers.target
        unit-with-.service.d/20-override.conf
        unit-with-multiple-.service.d/20-override.conf
        unit-with-multiple-.service.d/30-override.conf
        unit-with-multiple-dashes.service
        unit-with-multiple-dashes.service.d/10-override.conf
        unstoppable.service
'''.split()

if git.found()
        out = run_command(
                git,
                '--git-dir=@0@/.git'.format(meson.source_root()),
                 'ls-files', ':/test/test-execute/*.service')
else
        out = run_command(
                'sh', '-c', 'ls @0@/test-execute/*.service'.format(meson.current_source_dir()))
endif

foreach p : out.stdout().split()
        test_data_files += 'test-execute/@0@'.format(p.split('/')[-1])
endforeach

if conf.get('ENABLE_RESOLVE') == 1
        test_data_files += '''
                test-resolve/_openpgpkey.fedoraproject.org.pkts
                test-resolve/fedoraproject.org.pkts
                test-resolve/gandi.net.pkts
                test-resolve/google.com.pkts
                test-resolve/root.pkts
                test-resolve/sw1a1aa-sw1a2aa-sw1a2ab-sw1a2ac.find.me.uk.pkts
                test-resolve/teamits.com.pkts
                test-resolve/zbyszek@fedoraproject.org.pkts
                test-resolve/_443._tcp.fedoraproject.org.pkts
                test-resolve/kyhwana.org.pkts
                test-resolve/fake-caa.pkts
        '''.split()
endif

if install_tests
        foreach file : test_data_files
                subdir = file.split('/')[0]
                if subdir == file
                        subdir = ''
                endif

                install_data(file,
                             install_dir : testsdir + '/testdata/' + subdir)
        endforeach
endif

############################################################

rule_syntax_check_py = find_program('rule-syntax-check.py')
if want_tests != 'false'
        test('rule-syntax-check',
             rule_syntax_check_py,
             args : all_rules)
endif

############################################################

if conf.get('HAVE_SYSV_COMPAT') == 1
        sysv_generator_test_py = find_program('sysv-generator-test.py')
        if want_tests != 'false'
                test('sysv-generator-test',
                     sysv_generator_test_py)
        endif
endif

############################################################

# prepare test/sys tree
sys_script_py = find_program('sys-script.py')
custom_target(
        'sys',
        command : [sys_script_py, meson.current_build_dir()],
        output : 'sys',
        build_by_default : want_tests != 'false')

if perl.found()
        udev_test_pl = find_program('udev-test.pl')
        if want_tests != 'false'
                test('udev-test',
                     udev_test_pl)
        endif
else
        message('Skipping udev-test because perl is not available')
endif

if conf.get('ENABLE_HWDB') == 1
        hwdb_test_sh = find_program('hwdb-test.sh')
        if want_tests != 'false'
                test('hwdb-test',
                     hwdb_test_sh,
                     timeout : 90)
        endif
endif

subdir('fuzz')
