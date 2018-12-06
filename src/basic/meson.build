# SPDX-License-Identifier: LGPL-2.1+

basic_sources = files('''
        MurmurHash2.c
        MurmurHash2.h
        af-list.c
        af-list.h
        alloc-util.c
        alloc-util.h
        architecture.c
        architecture.h
        arphrd-list.c
        arphrd-list.h
        async.c
        async.h
        audit-util.c
        audit-util.h
        blockdev-util.c
        blockdev-util.h
        btrfs-util.c
        btrfs-util.h
        build.h
        bus-label.c
        bus-label.h
        cap-list.c
        cap-list.h
        capability-util.c
        capability-util.h
        cgroup-util.c
        cgroup-util.h
        chattr-util.c
        chattr-util.h
        conf-files.c
        conf-files.h
        copy.c
        copy.h
        def.h
        device-nodes.c
        device-nodes.h
        dirent-util.c
        dirent-util.h
        env-file.c
        env-file.h
        env-util.c
        env-util.h
        errno-list.c
        errno-list.h
        escape.c
        escape.h
        ether-addr-util.c
        ether-addr-util.h
        extract-word.c
        extract-word.h
        fd-util.c
        fd-util.h
        fileio.c
        fileio.h
        format-util.h
        fs-util.c
        fs-util.h
        glob-util.c
        glob-util.h
        gunicode.c
        gunicode.h
        hash-funcs.c
        hash-funcs.h
        hashmap.c
        hashmap.h
        hexdecoct.c
        hexdecoct.h
        hostname-util.c
        hostname-util.h
        in-addr-util.c
        in-addr-util.h
        io-util.c
        io-util.h
        ioprio.h
        khash.c
        khash.h
        label.c
        label.h
        list.h
        locale-util.c
        locale-util.h
        log.c
        log.h
        login-util.c
        login-util.h
        macro.h
        memfd-util.c
        memfd-util.h
        mempool.c
        mempool.h
        missing_audit.h
        missing_btrfs.h
        missing_btrfs_tree.h
        missing_capability.h
        missing_ethtool.h
        missing_fib_rules.h
        missing_fou.h
        missing_if_bridge.h
        missing_if_link.h
        missing_if_tunnel.h
        missing_input.h
        missing_keyctl.h
        missing_magic.h
        missing_network.h
        missing_prctl.h
        missing_resource.h
        missing_securebits.h
        missing_stat.h
        missing_syscall.h
        missing_type.h
        missing_vxcan.h
        mkdir-label.c
        mkdir.c
        mkdir.h
        mountpoint-util.c
        mountpoint-util.h
        nss-util.h
        ordered-set.c
        ordered-set.h
        parse-util.c
        parse-util.h
        path-util.c
        path-util.h
        prioq.c
        prioq.h
        proc-cmdline.c
        proc-cmdline.h
        process-util.c
        process-util.h
        procfs-util.c
        procfs-util.h
        random-util.c
        random-util.h
        ratelimit.c
        ratelimit.h
        raw-clone.h
        raw-reboot.h
        refcnt.h
        replace-var.c
        replace-var.h
        rm-rf.c
        rm-rf.h
        selinux-util.c
        selinux-util.h
        set.h
        sigbus.c
        sigbus.h
        signal-util.c
        signal-util.h
        siphash24.c
        siphash24.h
        smack-util.c
        smack-util.h
        socket-label.c
        socket-util.c
        socket-util.h
        sparse-endian.h
        special.h
        stat-util.c
        stat-util.h
        static-destruct.h
        stdio-util.h
        strbuf.c
        strbuf.h
        string-table.c
        string-table.h
        string-util.c
        string-util.h
        strv.c
        strv.h
        strxcpyx.c
        strxcpyx.h
        syslog-util.c
        syslog-util.h
        terminal-util.c
        terminal-util.h
        time-util.c
        time-util.h
        tmpfile-util.c
        tmpfile-util.h
        umask-util.h
        unaligned.h
        unit-def.c
        unit-def.h
        unit-name.c
        unit-name.h
        user-util.c
        user-util.h
        utf8.c
        utf8.h
        util.c
        util.h
        virt.c
        virt.h
        xattr-util.c
        xattr-util.h
'''.split())

missing_h = files('missing.h')

generate_af_list = find_program('generate-af-list.sh')
af_list_txt = custom_target(
        'af-list.txt',
        output : 'af-list.txt',
        command : [generate_af_list, cpp],
        capture : true)

generate_arphrd_list = find_program('generate-arphrd-list.sh')
arphrd_list_txt = custom_target(
        'arphrd-list.txt',
        output : 'arphrd-list.txt',
        command : [generate_arphrd_list, cpp],
        capture : true)

generate_cap_list = find_program('generate-cap-list.sh')
cap_list_txt = custom_target(
        'cap-list.txt',
        output : 'cap-list.txt',
        command : [generate_cap_list, cpp, config_h, missing_h],
        capture : true)

generate_errno_list = find_program('generate-errno-list.sh')
errno_list_txt = custom_target(
        'errno-list.txt',
        output : 'errno-list.txt',
        command : [generate_errno_list, cpp],
        capture : true)

generated_gperf_headers = []
foreach item : [['af',     af_list_txt,     'af',         ''],
                ['arphrd', arphrd_list_txt, 'arphrd',     'ARPHRD_'],
                ['cap',    cap_list_txt,    'capability', ''],
                ['errno',  errno_list_txt,  'errno',      '']]

        fname = '@0@-from-name.gperf'.format(item[0])
        gperf_file = custom_target(
                fname,
                input : item[1],
                output : fname,
                command : [generate_gperfs, item[2], item[3], '@INPUT@'],
                capture : true)

        fname = '@0@-from-name.h'.format(item[0])
        target1 = custom_target(
                fname,
                input : gperf_file,
                output : fname,
                command : [gperf,
                           '-L', 'ANSI-C', '-t', '--ignore-case',
                           '-N', 'lookup_@0@'.format(item[2]),
                           '-H', 'hash_@0@_name'.format(item[2]),
                           '-p', '-C',
                           '@INPUT@'],
                capture : true)

        fname = '@0@-to-name.h'.format(item[0])
        awkscript = '@0@-to-name.awk'.format(item[0])
        target2 = custom_target(
                fname,
                input : [awkscript, item[1]],
                output : fname,
                command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
                capture : true)

        generated_gperf_headers += [target1, target2]
endforeach

basic_sources += [missing_h] + generated_gperf_headers
basic_gcrypt_sources = files(
        'gcrypt-util.c',
        'gcrypt-util.h')

libbasic = static_library(
        'basic',
        basic_sources,
        include_directories : includes,
        dependencies : [threads,
                        libcap,
                        libselinux,
                        libm],
        c_args : ['-fvisibility=default'],
        install : false)

# A convenience library that is separate from libbasic to avoid
# unnecessary linking to libgcrypt.
libbasic_gcrypt = static_library(
        'basic-gcrypt',
        basic_gcrypt_sources,
        include_directories : includes,
        dependencies : [libgcrypt],
        c_args : ['-fvisibility=default'])
