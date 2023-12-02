# SPDX-License-Identifier: LGPL-2.1-or-later

if install_tests
        foreach subdir : [
                'auxv',
                'journal-data',
                'units',
                'test-execute',
                'test-fstab-generator',
                'test-path',
                'test-path-util',
                'test-umount',
                'test-network',
                'test-network-generator-conversion',
                'testsuite-03.units',
                'testsuite-04.units',
                'testsuite-06.units',
                'testsuite-07.units',
                'testsuite-16.units',
                'testsuite-23.units',
                'testsuite-30.units',
                'testsuite-52.units',
                'testsuite-63.units',
                'testsuite-80.units',
        ]
                # install_subdir() does not handle symlinks correctly which causes a very ugly warning when
                # installing, so if rsync is available we use that instead. TODO: switch to the new option
                # 'follow_symlinks' once we require Meson 1.3.0 or greater, see:
                # https://github.com/mesonbuild/meson/commit/0af126fec798d6dbb0d1ad52168cc1f3f1758acd
                if rsync.found()
                        rsync_r = rsync.full_path() + ' -rlpt --exclude .gitattributes -- "@0@" "${DESTDIR:-}@1@"'
                        meson.add_install_script(sh, '-c',
                                                 rsync_r.format(meson.current_source_dir() / subdir, testdata_dir))
                else
                        install_subdir(subdir,
                                       exclude_files : '.gitattributes',
                                       install_dir : testdata_dir)
                endif
        endforeach

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

############################################################

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
