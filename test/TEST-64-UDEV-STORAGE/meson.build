pre_args = ['--mkosi-image-name', test_params['mkosi_image_name'],
            '--test-number', test_params['test_number']]
common_test_args = {
        'env' : test_env,
        'depends' : test_params['depends'],
        'timeout' : test_params['timeout'],
        'suite' : 'integration-tests',
}

test_functions = {
        'testcase_megasas2_basic' : {},
        'testcase_nvme_basic' : {},
        'testcase_nvme_subsystem' : {},
        # TODO: adjust timeout for coverage and asan
        'testcase_virtio_scsi_identically_named_partitions' : {
                # timeout is 60 for the test itself
                # and 60 for populating /usr on boot
                # but extra logging may slow it further
                'timeout' : 180,
                'depends' : [
                        system_mkosi,
                        # Add repart to build disk images without losetup
                        executables_by_name['systemd-repart'],
                ],
        },
        'testcase_multipath_basic_failover' : {},
        'testcase_simultaneous_events' : {
                # This test is very slow, but if it's slower than this
                # it'll probably be too slow for its timeouts and fail.
                'timeout' : 1200,
        },
        'testcase_lvm_basic' : {},
        'testcase_btrfs_basic' : {},
        'testcase_iscsi_lvm' : {},
        'testcase_long_sysfs_path' : {},
        'testcase_mdadm_basic' : {},
        'testcase_mdadm_lvm' : {},
}
foreach func_name, test_args : test_functions
        test_name = dirname / func_name
        args = pre_args + [
                '--test-name', test_name,
                '--hook-module',
                meson.current_source_dir() / f'hook_@func_name@.py',
                '--',
                '--kernel-command-line-extra',
                f'systemd.setenv=TEST_FUNCTION_NAME=@func_name@']
        args += test_params['mkosi_args']
        test(test_name,
             integration_test_wrapper,
             args : args,
             kwargs : common_test_args + test_args)
endforeach
test_params += {'skip_default_test' : true}
