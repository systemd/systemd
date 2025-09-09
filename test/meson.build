# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_SYSUSERS') == 1
        test_sysusers_sh = configure_file(
                input : 'test-sysusers.sh.in',
                output : 'test-sysusers.sh',
                configuration : conf)

        if want_tests != 'false'
                exe = executables_by_name.get('systemd-sysusers')
                test('test-sysusers',
                     test_sysusers_sh,
                     # https://github.com/mesonbuild/meson/issues/2681
                     args : exe.full_path(),
                     depends : exe,
                     env : test_env,
                     suite : 'sysusers')

                if have_standalone_binaries
                        exe = executables_by_name.get('systemd-sysusers.standalone')
                        test('test-sysusers.standalone',
                             test_sysusers_sh,
                             # https://github.com/mesonbuild/meson/issues/2681
                             args : exe.full_path(),
                             depends : exe,
                             env : test_env,
                             suite : 'sysusers')
                endif
        endif

        if install_tests
                install_data(test_sysusers_sh,
                             install_dir : unittestsdir)
                install_subdir('test-sysusers',
                               exclude_files : '.gitattributes',
                               install_dir : testdata_dir)
        endif
endif

############################################################

if want_tests != 'false' and conf.get('ENABLE_HWDB') == 1
        exe = executables_by_name.get('systemd-hwdb')
        test('hwdb-test',
             files('hwdb-test.sh'),
             suite : 'dist',
             args : exe.full_path(),
             depends : exe,
             timeout : 90)
endif

############################################################

if want_tests != 'false'
        systemctl = executables_by_name.get('systemctl')
        systemd_id128 = executables_by_name.get('systemd-id128')
        test('test-systemctl-enable',
             files('test-systemctl-enable.sh'),
             # https://github.com/mesonbuild/meson/issues/2681
             args : [systemctl.full_path(),
                     systemd_id128.full_path()],
             depends : [systemctl, systemd_id128],
             suite : 'systemctl')
endif

############################################################

if want_tests != 'false' and conf.get('HAVE_SYSV_COMPAT') == 1
        exe = executables_by_name.get('systemd-sysv-generator')
        test('sysv-generator-test',
             files('sysv-generator-test.py'),
             depends : exe,
             suite : 'sysv')
endif

############################################################

if want_tests != 'false' and conf.get('HAVE_BLKID') == 1
        exe = executables_by_name.get('bootctl')
        test('test-bootctl-json',
             files('test-bootctl-json.sh'),
             args : exe.full_path(),
             depends : exe,
             suite : 'boot')
endif

############################################################

if want_tests != 'false' and conf.get('ENABLE_TMPFILES') == 1
        test_systemd_tmpfiles_py = files('test-systemd-tmpfiles.py')
        exe = executables_by_name.get('systemd-tmpfiles')
        test('test-systemd-tmpfiles',
             test_systemd_tmpfiles_py,
             args : exe.full_path(),
             depends : exe,
             suite : 'tmpfiles')

        if have_standalone_binaries
                exe = executables_by_name.get('systemd-tmpfiles.standalone')
                test('test-systemd-tmpfiles.standalone',
                     test_systemd_tmpfiles_py,
                     args : exe.full_path(),
                     depends : exe,
                     suite : 'tmpfiles')
        endif
endif

############################################################

test_compare_versions_sh = files('test-compare-versions.sh')
if want_tests != 'false'
        exe = executables_by_name.get('systemd-analyze')
        test('test-compare-versions',
             test_compare_versions_sh,
             args : exe.full_path(),
             depends : exe,
             suite : 'test')
endif
if install_tests
        install_data(test_compare_versions_sh,
                     install_dir : unittestsdir)
endif

############################################################

if want_tests != 'false'
        test('rule-syntax-check',
             files('rule-syntax-check.py'),
             suite : 'dist',
             args : all_rules)

        exe = executables_by_name.get('udevadm')
        test('udev-rules-check',
             exe,
             suite : 'udev',
             args : ['verify', '--resolve-names=late', all_rules])
endif

############################################################

if install_tests
        install_data('run-unit-tests.py',
                     install_mode : 'rwxr-xr-x',
                     install_dir : testsdir)

        install_data('integration-test-setup.sh',
                     install_mode : 'rwxr-xr-x',
                     install_dir : testdata_dir)
endif

############################################################

test_fstab_generator_sh = files('test-fstab-generator.sh')
if want_tests != 'false'
        exe = executables_by_name.get('systemd-fstab-generator')
        test('test-fstab-generator',
             test_fstab_generator_sh,
             # https://github.com/mesonbuild/meson/issues/2681
             args : exe.full_path(),
             env : test_env,
             depends : exe,
             suite : 'fstab')
endif
if install_tests
        install_data(test_fstab_generator_sh,
                     install_mode : 'rwxr-xr-x',
                     install_dir : unittestsdir)
endif

############################################################

test_network_generator_conversion_sh = files('test-network-generator-conversion.sh')
if want_tests != 'false'
        exe = executables_by_name.get('systemd-network-generator')
        test('test-network-generator-conversion',
             test_network_generator_conversion_sh,
             # https://github.com/mesonbuild/meson/issues/2681
             args : exe.full_path(),
             depends : exe,
             suite : 'network')
endif
if install_tests
        install_data(test_network_generator_conversion_sh,
                     install_mode : 'rwxr-xr-x',
                     install_dir : unittestsdir)
endif

############################################################

sys_script_py = files('sys-script.py')
test_udev_py = files('test-udev.py')
if want_tests != 'false'
        exe = executables_by_name.get('test-udev-rule-runner')
        test('test-udev',
             test_udev_py,
             args : ['-v'],
             env : test_env + { 'UDEV_RULE_RUNNER' : exe.full_path() },
             depends : exe,
             timeout : 180,
             suite : 'udev')
endif
if install_tests
        install_data(
                sys_script_py,
                test_udev_py,
                install_dir : unittestsdir)
endif

############################################################

rpm = find_program('rpm', required : false)
rpmspec = find_program('rpmspec', required : false)

if rpm.found() and rpmspec.found()
        if want_tests != 'false'
                test('test-rpm-macros',
                     files('test-rpm-macros.sh'),
                     suite : 'dist',
                     args : [meson.project_build_root()],
                     depends : rpm_depends)
        endif
else
      message('Skipping test-rpm-macros since rpm and/or rpmspec are not available')
endif

############################################################

if want_tests != 'false' and conf.get('HAVE_DMI') == 1
        udev_dmi_memory_id_test = files('udev-dmi-memory-id-test.sh')
        exe = executables_by_name.get('dmi_memory_id')

        if git.found() and fs.is_dir(meson.project_source_root() / '.git')
                out = run_command(
                        env, '-u', 'GIT_WORK_TREE',
                        git, '--git-dir=@0@/.git'.format(meson.project_source_root()),
                        'ls-files', ':/test/dmidecode-dumps/*.bin',
                        check: true)
        else
                out = run_command(
                        sh, '-c', 'cd "$1"; echo test/dmidecode-dumps/*.bin', '_', meson.project_source_root(),
                        check: true)
        endif

        foreach p : out.stdout().split()
                source = meson.project_source_root() / p
                test('dmidecode_' + fs.stem(p),
                     udev_dmi_memory_id_test,
                     suite : 'udev',
                     args : [exe.full_path(),
                             source,
                             source + '.txt'],
                     depends : exe)
        endforeach
endif

############################################################

if want_tests != 'false' and conf.get('ENABLE_KERNEL_INSTALL') == 1
        kernel_install = executables_by_name.get('kernel-install')
        args = [kernel_install.full_path(), loaderentry_install.full_path(), uki_copy_install]
        deps = [kernel_install, loaderentry_install]
        if want_ukify and boot_stubs.length() > 0
                args += [ukify.full_path(), ukify_install.full_path(), boot_stubs[0]]
                deps += [ukify, ukify_install, boot_stubs[0]]
        endif

        test('test-kernel-install',
             test_kernel_install_sh,
             env : test_env,
             args : args,
             depends : deps,
             suite : 'kernel-install')
endif

############################################################

if want_tests != 'false'
        subdir('integration-tests')
endif

if install_tests
        if meson.version().version_compare('<1.3.0')
                if not rsync.found()
                        error('rsync is required to install the integration test data')
                endif

                rsync_r = rsync.full_path() + ' -rlpt --exclude .gitattributes -- "@0@" "${DESTDIR:-}@1@"'
        endif

        if meson.version().version_compare('>=1.3.0')
                # Installing symlinks to directories is broken in install_subdir() so we exclude the
                # standalone directory from install_subdir() and handle it manually.
                # TODO: Remove when https://github.com/mesonbuild/meson/pull/14471 is available in all
                # supported distributions.
                install_subdir('integration-tests',
                               install_dir : testsdir,
                               exclude_directories : ['standalone'],
                               follow_symlinks : false)
                install_emptydir(testsdir / 'integration-tests/standalone')
                install_data('integration-tests/standalone/meson.build',
                             install_dir : testsdir / 'integration-tests/standalone')
                install_symlink('integration-tests',
                                pointing_to : '..',
                                install_dir : testsdir / 'integration-tests/standalone')
        else
                meson.add_install_script(sh, '-c',
                                         rsync_r.format(meson.current_source_dir() / 'integration-tests', testsdir))
        endif

        foreach integration_test : integration_tests
                integration_test_unit_env = []
                integration_test_extra_unit_properties = []
                integration_test_extra_service_properties = []

                foreach key, value : integration_test['configuration']['env']
                        integration_test_unit_env += [f'@key@=@value@']
                endforeach

                foreach key, value : integration_test['configuration']['unit']
                        integration_test_extra_unit_properties += [f'@key@=@value@']
                endforeach

                foreach key, value : integration_test['configuration']['service']
                        integration_test_extra_service_properties += [f'@key@=@value@']
                endforeach

                integration_test_unit = configure_file(
                        input : 'test.service.in',
                        output : '@0@.service'.format(integration_test['name']),
                        configuration : integration_test['configuration'] + {
                                'env' : ' '.join(integration_test_unit_env),
                                'unit' : '\n'.join(integration_test_extra_unit_properties),
                                'service' : '\n'.join(integration_test_extra_service_properties),
                        },
                )

                install_data(integration_test_unit, install_dir : testdata_dir / 'units')
        endforeach

        testdata_subdirs = [
                'auxv',
                'journal-data',
                'knot-data',
                'test-cgroup-mask',
                'test-cgroup-unit-default',
                'test-engine',
                'test-execute',
                'test-fstab-generator',
                'test-journals',
                'test-network',
                'test-network-generator-conversion',
                'test-path',
                'test-path-util',
                'test-sched-prio',
                'test-umount',
                'integration-tests/TEST-07-PID1/TEST-07-PID1.units',
                'integration-tests/TEST-03-JOBS/TEST-03-JOBS.units',
                'integration-tests/TEST-04-JOURNAL/TEST-04-JOURNAL.units',
                'integration-tests/TEST-06-SELINUX/TEST-06-SELINUX.units',
                'integration-tests/TEST-16-EXTEND-TIMEOUT/TEST-16-EXTEND-TIMEOUT.units',
                'integration-tests/TEST-23-UNIT-FILE/TEST-23-UNIT-FILE.units',
                'integration-tests/TEST-30-ONCLOCKCHANGE/TEST-30-ONCLOCKCHANGE.units',
                'integration-tests/TEST-38-FREEZER/TEST-38-FREEZER.units',
                'integration-tests/TEST-52-HONORFIRSTSHUTDOWN/TEST-52-HONORFIRSTSHUTDOWN.units',
                'integration-tests/TEST-55-OOMD/TEST-55-OOMD.units',
                'integration-tests/TEST-62-RESTRICT-IFACES/TEST-62-RESTRICT-IFACES.units',
                'integration-tests/TEST-63-PATH/TEST-63-PATH.units',
                'integration-tests/TEST-65-ANALYZE/TEST-65-ANALYZE.units',
                'integration-tests/TEST-66-DEVICE-ISOLATION/TEST-66-DEVICE-ISOLATION.units',
                'integration-tests/TEST-80-NOTIFYACCESS/TEST-80-NOTIFYACCESS.units',
                'units',
        ]

        foreach subdir : testdata_subdirs
                # install_subdir() before meson 1.3.0 does not handle symlinks correctly (it follows them
                # instead of copying the symlink) so we use rsync instead.
                if meson.version().version_compare('>=1.3.0')
                        install_subdir(subdir,
                                       exclude_files : ['.gitattributes'],
                                       install_dir : testdata_dir,
                                       follow_symlinks : false)
                else
                        meson.add_install_script(sh, '-c',
                                                 rsync_r.format(meson.current_source_dir() / subdir, testdata_dir))
                endif
        endforeach

        install_data(kbd_model_map,
                     install_dir : testdata_dir + '/test-keymap-util')

        if conf.get('HAVE_ZSTD') == 1 and efi_arch != ''
                install_subdir('test-bcd',
                               exclude_files : '.gitattributes',
                               install_dir : testdata_dir)
        endif
        install_subdir('test-resolve',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)

        # The unit tests implemented as shell scripts expect to find testdata/
        # in the directory where they are stored.
        assert(fs.parent(unittestsdir) / 'testdata' == testdata_dir)
        install_symlink('testdata',
                        pointing_to : '../testdata',
                        install_dir : unittestsdir)
endif
