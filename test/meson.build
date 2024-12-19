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
                     suite : 'sysusers')

                if have_standalone_binaries
                        exe = executables_by_name.get('systemd-sysusers.standalone')
                        test('test-sysusers.standalone',
                             test_sysusers_sh,
                             # https://github.com/mesonbuild/meson/issues/2681
                             args : exe.full_path(),
                             depends : exe,
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
        hwdb_test_sh = find_program('hwdb-test.sh')
        exe = executables_by_name.get('systemd-hwdb')
        test('hwdb-test',
             hwdb_test_sh,
             suite : 'dist',
             args : exe.full_path(),
             depends : exe,
             timeout : 90)
endif

############################################################

if want_tests != 'false'
        test_systemctl_enable_sh = find_program('test-systemctl-enable.sh')
        systemctl = executables_by_name.get('systemctl')
        systemd_id128 = executables_by_name.get('systemd-id128')
        test('test-systemctl-enable',
             test_systemctl_enable_sh,
             # https://github.com/mesonbuild/meson/issues/2681
             args : [systemctl.full_path(),
                     systemd_id128.full_path()],
             depends : [systemctl, systemd_id128],
             suite : 'systemctl')
endif

############################################################

if want_tests != 'false' and conf.get('HAVE_SYSV_COMPAT') == 1
        sysv_generator_test_py = find_program('sysv-generator-test.py')
        exe = executables_by_name.get('systemd-sysv-generator')
        test('sysv-generator-test',
             sysv_generator_test_py,
             depends : exe,
             suite : 'sysv')
endif

############################################################

if want_tests != 'false' and conf.get('HAVE_BLKID') == 1
        test_bootctl_json_sh = find_program('test-bootctl-json.sh')
        exe = executables_by_name.get('bootctl')
        test('test-bootctl-json',
             test_bootctl_json_sh,
             args : exe.full_path(),
             depends : exe,
             suite : 'boot')
endif

############################################################

if want_tests != 'false' and conf.get('ENABLE_TMPFILES') == 1
        test_systemd_tmpfiles_py = find_program('test-systemd-tmpfiles.py')
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

rule_syntax_check_py = find_program('rule-syntax-check.py')
if want_tests != 'false'
        test('rule-syntax-check',
             rule_syntax_check_py,
             suite : 'dist',
             args : all_rules)

        exe = executables_by_name.get('udevadm')
        test('udev-rules-check',
             exe,
             suite : 'udev',
             args : ['verify', '--resolve-names=never', all_rules])
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

test_fstab_generator_sh = find_program('test-fstab-generator.sh')
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
        install_data('test-fstab-generator.sh',
                     install_mode : 'rwxr-xr-x',
                     install_dir : unittestsdir)
endif

############################################################

test_network_generator_conversion_sh = find_program('test-network-generator-conversion.sh')
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
        install_data('test-network-generator-conversion.sh',
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
             env : ['UDEV_RULE_RUNNER=' + exe.full_path()],
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
test_rpm_macros = find_program('test-rpm-macros.sh')

if rpm.found() and rpmspec.found()
        if want_tests != 'false'
                test('test-rpm-macros',
                     test_rpm_macros,
                     suite : 'dist',
                     args : [project_build_root])
        endif
else
      message('Skipping test-rpm-macros since rpm and/or rpmspec are not available')
endif

############################################################

if want_tests != 'false' and conf.get('HAVE_DMI') == 1
        udev_dmi_memory_id_test = find_program('udev-dmi-memory-id-test.sh')
        exe = executables_by_name.get('dmi_memory_id')

        if git.found() and fs.is_dir(project_source_root / '.git')
                out = run_command(
                        env, '-u', 'GIT_WORK_TREE',
                        git, '--git-dir=@0@/.git'.format(project_source_root),
                        'ls-files', ':/test/dmidecode-dumps/*.bin',
                        check: true)
        else
                out = run_command(
                        sh, '-c', 'cd "$1"; echo test/dmidecode-dumps/*.bin', '_', project_source_root,
                        check: true)
        endif

        foreach p : out.stdout().split()
                source = project_source_root / p
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

integration_test_wrapper = find_program('integration-test-wrapper.py')
integration_tests = []
integration_test_template = {
        'mkosi-args' : [],
        'timeout' : 1800,
        'storage' : 'volatile',
        'priority' : 0,
        'firmware' : 'linux',
        'enabled' : true,
        'configuration' : {
                'memory-accounting' : 'no',
                'command' : testdata_dir / 'units/%N.sh',
                'wants' : 'multi-user.target user@4711.service',
                'after' : 'user@4711.service',
        },
        'cmdline' : [],
        'credentials' : [],
        'qemu-args' : [],
        'exit-code' : 123,
        'vm' : false,
        'coredump-exclude-regex' : '',
        'sanitizer-exclude-regex' : '',
}
testdata_subdirs = [
        'auxv',
        'journal-data',
        'knot-data',
        'test-journals',
        'units',
        'test-execute',
        'test-fstab-generator',
        'test-path',
        'test-path-util',
        'test-umount',
        'test-network',
        'test-network-generator-conversion',
]

foreach dirname : [
        'TEST-01-BASIC',
        'TEST-02-UNITTESTS',
        'TEST-03-JOBS',
        'TEST-04-JOURNAL',
        'TEST-05-RLIMITS',
        'TEST-06-SELINUX',
        'TEST-07-PID1',
        'TEST-08-INITRD',
        'TEST-09-REBOOT',
        'TEST-13-NSPAWN',
        'TEST-15-DROPIN',
        'TEST-16-EXTEND-TIMEOUT',
        'TEST-17-UDEV',
        'TEST-18-FAILUREACTION',
        'TEST-19-CGROUP',
        'TEST-21-DFUZZER',
        'TEST-22-TMPFILES',
        'TEST-23-UNIT-FILE',
        'TEST-24-CRYPTSETUP',
        'TEST-25-IMPORT',
        'TEST-26-SYSTEMCTL',
        'TEST-29-PORTABLE',
        'TEST-30-ONCLOCKCHANGE',
        'TEST-31-DEVICE-ENUMERATION',
        'TEST-32-OOMPOLICY',
        'TEST-34-DYNAMICUSERMIGRATE',
        'TEST-35-LOGIN',
        'TEST-36-NUMAPOLICY',
        'TEST-38-FREEZER',
        'TEST-43-PRIVATEUSER-UNPRIV',
        'TEST-44-LOG-NAMESPACE',
        'TEST-45-TIMEDATE',
        'TEST-46-HOMED',
        'TEST-50-DISSECT',
        'TEST-52-HONORFIRSTSHUTDOWN',
        'TEST-53-ISSUE-16347',
        'TEST-54-CREDS',
        'TEST-55-OOMD',
        'TEST-58-REPART',
        'TEST-59-RELOADING-RESTART',
        'TEST-60-MOUNT-RATELIMIT',
        'TEST-62-RESTRICT-IFACES',
        'TEST-63-PATH',
        'TEST-64-UDEV-STORAGE',
        'TEST-65-ANALYZE',
        'TEST-66-DEVICE-ISOLATION',
        'TEST-67-INTEGRITY',
        'TEST-68-PROPAGATE-EXIT-STATUS',
        'TEST-69-SHUTDOWN',
        'TEST-70-TPM2',
        'TEST-71-HOSTNAME',
        'TEST-72-SYSUPDATE',
        'TEST-73-LOCALE',
        'TEST-74-AUX-UTILS',
        'TEST-75-RESOLVED',
        'TEST-76-SYSCTL',
        'TEST-78-SIGQUEUE',
        'TEST-79-MEMPRESS',
        'TEST-80-NOTIFYACCESS',
        'TEST-81-GENERATORS',
        'TEST-82-SOFTREBOOT',
        'TEST-83-BTRFS',
        'TEST-84-STORAGETM',
        'TEST-85-NETWORK',
        'TEST-86-MULTI-PROFILE-UKI',
        'TEST-87-AUX-UTILS-VM',
]
        subdir(dirname)
endforeach

foreach integration_test : integration_tests
        integration_test_args = [
                '--meson-source-dir', meson.project_source_root(),
                '--meson-build-dir', meson.project_build_root(),
                '--name', integration_test['name'],
                '--storage', integration_test['storage'],
                '--firmware', integration_test['firmware'],
                '--exit-code', integration_test['exit-code'].to_string(),
                '--coredump-exclude-regex', integration_test['coredump-exclude-regex'],
                '--sanitizer-exclude-regex', integration_test['sanitizer-exclude-regex'],
        ]

        if 'unit' in integration_test
                integration_test_unit = integration_test['unit']
        else
                integration_test_unit = configure_file(
                        input : 'test.service.in',
                        output : '@0@.service'.format(integration_test['name']),
                        configuration : integration_test['configuration'],
                )
        endif

        integration_test_args += ['--unit', fs.name(integration_test_unit)]
        if install_tests
                install_data(integration_test_unit, install_dir : testdata_dir / 'units')
        endif

        if integration_test['vm']
                integration_test_args += ['--vm']
        endif

        if not mkosi.found()
                continue
        endif

        integration_test_args += ['--mkosi', mkosi.full_path(), '--']

        if integration_test['cmdline'].length() > 0
                integration_test_args += [
                        '--kernel-command-line-extra=@0@'.format(' '.join(integration_test['cmdline']))
                ]
        endif

        foreach credential : integration_test['credentials']
                integration_test_args += ['--credential', credential]
        endforeach

        if integration_test['qemu-args'].length() > 0
                integration_test_args += ['--qemu-args=@0@'.format(' '.join(integration_test['qemu-args']))]
        endif

        integration_test_args += integration_test['mkosi-args']

        integration_test_env = {}

        if want_integration_tests
                integration_test_env += {'SYSTEMD_INTEGRATION_TESTS': '1'}
        endif

        if not integration_test['enabled']
                continue
        endif

        # We don't explicitly depend on the "mkosi" target because that means the image is rebuilt on every
        # "ninja -C build". Instead, the mkosi target has to be rebuilt manually before running the
        # integration tests with mkosi.
        test(
                integration_test['name'],
                integration_test_wrapper,
                env : integration_test_env,
                args : integration_test_args,
                timeout : integration_test['timeout'],
                priority : integration_test['priority'],
                suite : 'integration-tests',
        )
endforeach

if install_tests
        foreach subdir : testdata_subdirs
                # install_subdir() before meson 1.3.0 does not handle symlinks correctly (it follows them
                # instead of copying the symlink) so we use rsync instead.
                if meson.version().version_compare('<1.3.0')
                        if not rsync.found()
                                error('rsync is required to install the integration test data')
                        endif

                        rsync_r = rsync.full_path() + ' -rlpt --exclude .gitattributes --exclude 25-default.link -- "@0@" "${DESTDIR:-}@1@"'
                        meson.add_install_script(sh, '-c',
                                                 rsync_r.format(meson.current_source_dir() / subdir, testdata_dir))
                else
                        install_subdir(subdir,
                                       exclude_files : ['.gitattributes', '25-default.link'],
                                       install_dir : testdata_dir,
                                       follow_symlinks : false)
                endif
        endforeach

        # test-network/conf/25-default.link is a local symlink that becomes dangling when installed, so we
        # exclude it and create the correct symlink here.
        meson.add_install_script(sh, '-c', ln_s.format(networkdir / '99-default.link',
                                                       testdata_dir / 'test-network/conf/25-default.link'))

        install_data(kbd_model_map,
                     install_dir : testdata_dir + '/test-keymap-util')

        if conf.get('HAVE_ZSTD') == 1 and efi_arch != ''
                install_subdir('test-bcd',
                               exclude_files : '.gitattributes',
                               install_dir : testdata_dir)
        endif
        if conf.get('ENABLE_RESOLVE') == 1
                install_subdir('test-resolve',
                               exclude_files : '.gitattributes',
                               install_dir : testdata_dir)
        endif

        # The unit tests implemented as shell scripts expect to find testdata/
        # in the directory where they are stored.
        meson.add_install_script(sh, '-c', ln_s.format(testdata_dir,
                                                       unittestsdir / 'testdata'))
endif
