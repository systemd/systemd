# SPDX-License-Identifier: LGPL-2.1+

test_data_files = '''
        a.service
        a-conj.service
        b.service
        basic.target
        c.service
        d.service
        daughter.service
        dml.slice
        dml-passthrough.slice
        dml-passthrough-empty.service
        dml-passthrough-set-dml.service
        dml-passthrough-set-ml.service
        dml-override.slice
        dml-override-empty.service
        dml-discard.slice
        dml-discard-empty.service
        dml-discard-set-ml.service
        e.service
        end.service
        f.service
        g.service
        grandchild.service
        h.service
        hello-after-sleep.target
        hello.service
        hwdb/10-bad.hwdb
        i.service
        journal-data/journal-1.txt
        journal-data/journal-2.txt
        nomem.slice
        nomemleaf.service
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
        test-execute/exec-basic.service
        test-execute/exec-ambientcapabilities-merge-nfsnobody.service
        test-execute/exec-ambientcapabilities-merge-nobody.service
        test-execute/exec-ambientcapabilities-merge.service
        test-execute/exec-ambientcapabilities-nfsnobody.service
        test-execute/exec-ambientcapabilities-nobody.service
        test-execute/exec-ambientcapabilities.service
        test-execute/exec-bindpaths.service
        test-execute/exec-capabilityboundingset-invert.service
        test-execute/exec-capabilityboundingset-merge.service
        test-execute/exec-capabilityboundingset-reset.service
        test-execute/exec-capabilityboundingset-simple.service
        test-execute/exec-condition-failed.service
        test-execute/exec-condition-skip.service
        test-execute/exec-cpuaffinity1.service
        test-execute/exec-cpuaffinity2.service
        test-execute/exec-cpuaffinity3.service
        test-execute/exec-dynamicuser-fixeduser-adm.service
        test-execute/exec-dynamicuser-fixeduser-games.service
        test-execute/exec-dynamicuser-fixeduser-one-supplementarygroup.service
        test-execute/exec-dynamicuser-fixeduser.service
        test-execute/exec-dynamicuser-statedir-migrate-step1.service
        test-execute/exec-dynamicuser-statedir-migrate-step2.service
        test-execute/exec-dynamicuser-statedir.service
        test-execute/exec-dynamicuser-supplementarygroups.service
        test-execute/exec-environment-no-substitute.service
        test-execute/exec-environment-empty.service
        test-execute/exec-environment-multiple.service
        test-execute/exec-environment.service
        test-execute/exec-environmentfile.service
        test-execute/exec-group-nfsnobody.service
        test-execute/exec-group-nobody.service
        test-execute/exec-group-nogroup.service
        test-execute/exec-group.service
        test-execute/exec-ignoresigpipe-no.service
        test-execute/exec-ignoresigpipe-yes.service
        test-execute/exec-inaccessiblepaths-mount-propagation.service
        test-execute/exec-inaccessiblepaths-sys.service
        test-execute/exec-ioschedulingclass-best-effort.service
        test-execute/exec-ioschedulingclass-idle.service
        test-execute/exec-ioschedulingclass-none.service
        test-execute/exec-ioschedulingclass-realtime.service
        test-execute/exec-oomscoreadjust-negative.service
        test-execute/exec-oomscoreadjust-positive.service
        test-execute/exec-passenvironment-absent.service
        test-execute/exec-passenvironment-empty.service
        test-execute/exec-passenvironment-repeated.service
        test-execute/exec-passenvironment.service
        test-execute/exec-personality-aarch64.service
        test-execute/exec-personality-ppc64.service
        test-execute/exec-personality-ppc64le.service
        test-execute/exec-personality-s390.service
        test-execute/exec-personality-x86-64.service
        test-execute/exec-personality-x86.service
        test-execute/exec-privatedevices-disabled-by-prefix.service
        test-execute/exec-privatedevices-no-capability-mknod.service
        test-execute/exec-privatedevices-no-capability-sys-rawio.service
        test-execute/exec-privatedevices-no.service
        test-execute/exec-privatedevices-yes-capability-mknod.service
        test-execute/exec-privatedevices-yes-capability-sys-rawio.service
        test-execute/exec-privatedevices-yes.service
        test-execute/exec-privatenetwork-yes.service
        test-execute/exec-privatetmp-no.service
        test-execute/exec-privatetmp-yes.service
        test-execute/exec-protecthome-tmpfs-vs-protectsystem-strict.service
        test-execute/exec-protectkernelmodules-no-capabilities.service
        test-execute/exec-protectkernelmodules-yes-capabilities.service
        test-execute/exec-protectkernelmodules-yes-mount-propagation.service
        test-execute/exec-readonlypaths-mount-propagation.service
        test-execute/exec-readonlypaths-simple.service
        test-execute/exec-readonlypaths-with-bindpaths.service
        test-execute/exec-readonlypaths.service
        test-execute/exec-readwritepaths-mount-propagation.service
        test-execute/exec-restrictnamespaces-merge-all.service
        test-execute/exec-restrictnamespaces-merge-and.service
        test-execute/exec-restrictnamespaces-merge-or.service
        test-execute/exec-restrictnamespaces-mnt-blacklist.service
        test-execute/exec-restrictnamespaces-mnt.service
        test-execute/exec-restrictnamespaces-no.service
        test-execute/exec-restrictnamespaces-yes.service
        test-execute/exec-runtimedirectory-mode.service
        test-execute/exec-runtimedirectory-owner-nfsnobody.service
        test-execute/exec-runtimedirectory-owner-nobody.service
        test-execute/exec-runtimedirectory-owner-nogroup.service
        test-execute/exec-runtimedirectory-owner.service
        test-execute/exec-runtimedirectory.service
        test-execute/exec-specifier-interpolation.service
        test-execute/exec-specifier.service
        test-execute/exec-specifier@.service
        test-execute/exec-standardinput-data.service
        test-execute/exec-standardinput-file.service
        test-execute/exec-standardoutput-file.service
        test-execute/exec-standardoutput-append.service
        test-execute/exec-supplementarygroups-multiple-groups-default-group-user.service
        test-execute/exec-supplementarygroups-multiple-groups-withgid.service
        test-execute/exec-supplementarygroups-multiple-groups-withuid.service
        test-execute/exec-supplementarygroups-single-group-user.service
        test-execute/exec-supplementarygroups-single-group.service
        test-execute/exec-supplementarygroups.service
        test-execute/exec-systemcallerrornumber-name.service
        test-execute/exec-systemcallerrornumber-number.service
        test-execute/exec-systemcallfilter-failing.service
        test-execute/exec-systemcallfilter-failing2.service
        test-execute/exec-systemcallfilter-not-failing.service
        test-execute/exec-systemcallfilter-not-failing2.service
        test-execute/exec-systemcallfilter-system-user-nfsnobody.service
        test-execute/exec-systemcallfilter-system-user-nobody.service
        test-execute/exec-systemcallfilter-system-user.service
        test-execute/exec-systemcallfilter-with-errno-multi.service
        test-execute/exec-systemcallfilter-with-errno-name.service
        test-execute/exec-systemcallfilter-with-errno-number.service
        test-execute/exec-temporaryfilesystem-options.service
        test-execute/exec-temporaryfilesystem-ro.service
        test-execute/exec-temporaryfilesystem-rw.service
        test-execute/exec-temporaryfilesystem-usr.service
        test-execute/exec-umask-0177.service
        test-execute/exec-umask-default.service
        test-execute/exec-unsetenvironment.service
        test-execute/exec-user-nfsnobody.service
        test-execute/exec-user-nobody.service
        test-execute/exec-user.service
        test-execute/exec-workingdirectory.service
        test-execute/exec-workingdirectory-trailing-dot.service
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

if install_tests
        install_data('run-unit-tests.py',
                     install_mode : 'rwxr-xr-x',
                     install_dir : testsdir)
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
                     udev_test_pl,
                     timeout : 180)
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
