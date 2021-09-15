# SPDX-License-Identifier: LGPL-2.1-or-later

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
        build.c
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
        creds-util.c
        creds-util.h
        def.h
        dirent-util.c
        dirent-util.h
        dns-def.h
        efivars.c
        efivars.h
        env-file.c
        env-file.h
        env-util.c
        env-util.h
        errno-list.c
        errno-list.h
        errno-util.h
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
        format-util.c
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
        limits-util.c
        limits-util.h
        linux/btrfs.h
        linux/btrfs_tree.h
        linux/can/netlink.h
        linux/can/vxcan.h
        linux/fib_rules.h
        linux/fou.h
        linux/hdlc/ioctl.h
        linux/if.h
        linux/if_addr.h
        linux/if_bonding.h
        linux/if_bridge.h
        linux/if_ether.h
        linux/if_link.h
        linux/if_macsec.h
        linux/if_tun.h
        linux/if_tunnel.h
        linux/in.h
        linux/in6.h
        linux/ipv6_route.h
        linux/l2tp.h
        linux/libc-compat.h
        linux/loadavg.h
        linux/netdevice.h
        linux/netfilter/nf_tables.h
        linux/netfilter/nfnetlink.h
        linux/netlink.h
        linux/nexthop.h
        linux/nl80211.h
        linux/pkt_sched.h
        linux/rtnetlink.h
        linux/wireguard.h
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
        memory-util.c
        memory-util.h
        mempool.c
        mempool.h
        missing_audit.h
        missing_capability.h
        missing_drm.h
        missing_fcntl.h
        missing_fs.h
        missing_input.h
        missing_keyctl.h
        missing_magic.h
        missing_mman.h
        missing_mount.h
        missing_network.h
        missing_prctl.h
        missing_random.h
        missing_resource.h
        missing_sched.h
        missing_securebits.h
        missing_socket.h
        missing_stat.h
        missing_stdlib.h
        missing_syscall.h
        missing_timerfd.h
        missing_type.h
        mkdir.c
        mkdir.h
        mountpoint-util.c
        mountpoint-util.h
        namespace-util.c
        namespace-util.h
        nss-util.h
        nulstr-util.c
        nulstr-util.h
        ordered-set.c
        ordered-set.h
        os-util.c
        os-util.h
        parse-util.c
        parse-util.h
        path-lookup.c
        path-lookup.h
        path-util.c
        path-util.h
        percent-util.c
        percent-util.h
        prioq.c
        prioq.h
        proc-cmdline.c
        proc-cmdline.h
        process-util.c
        process-util.h
        procfs-util.c
        procfs-util.h
        pthread-util.h
        random-util.c
        random-util.h
        ratelimit.c
        ratelimit.h
        raw-clone.h
        raw-reboot.h
        recovery-key.c
        recovery-key.h
        replace-var.c
        replace-var.h
        rlimit-util.c
        rlimit-util.h
        set.h
        sigbus.c
        sigbus.h
        signal-util.c
        signal-util.h
        siphash24.c
        siphash24.h
        socket-util.c
        socket-util.h
        sort-util.c
        sort-util.h
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
        sysctl-util.c
        sysctl-util.h
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
        unit-file.c
        unit-file.h
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

missing_audit_h = files('missing_audit.h')
missing_capability_h = files('missing_capability.h')
missing_socket_h = files('missing_socket.h')

missing_syscall_def_h = files('missing_syscall_def.h')
basic_sources += missing_syscall_def_h

generate_af_list = find_program('generate-af-list.sh')
af_list_txt = custom_target(
        'af-list.txt',
        output : 'af-list.txt',
        command : [generate_af_list, cpp, config_h, missing_socket_h],
        capture : true)

generate_arphrd_list = find_program('generate-arphrd-list.sh')
arphrd_list_txt = custom_target(
        'arphrd-list.txt',
        output : 'arphrd-list.txt',
        command : [generate_arphrd_list, cpp, config_h],
        capture : true)

generate_cap_list = find_program('generate-cap-list.sh')
cap_list_txt = custom_target(
        'cap-list.txt',
        output : 'cap-list.txt',
        command : [generate_cap_list, cpp, config_h, missing_capability_h],
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

basic_sources += generated_gperf_headers

############################################################

arch_list = [
        'alpha',
        'arc',
        'arm',
        'arm64',
        'i386',
        'ia64',
        'm68k',
        'mips64',
        'mips64n32',
        'mipso32',
        'powerpc',
        'powerpc64',
        'riscv32',
        'riscv64',
        's390',
        's390x',
        'sparc',
        'x86_64'
]

run_target(
        'update-syscall-tables',
        command : [update_syscall_tables_sh, meson.current_source_dir()] + arch_list)

syscall_list_txt = files('syscall-list.txt')

syscall_lists = []
foreach arch: arch_list
        syscall_lists += files('syscalls-@0@.txt'.format(arch))
endforeach

missing_syscalls_py = find_program('missing_syscalls.py')

run_target(
        'update-syscall-header',
        command : [missing_syscalls_py,
                   missing_syscall_def_h,
                   syscall_lists])

############################################################

libbasic = static_library(
        'basic',
        basic_sources,
        fundamental_sources,
        include_directories : basic_includes,
        dependencies : [versiondep,
                        threads,
                        libcap,
                        libm],
        c_args : ['-fvisibility=default'],
        install : false)

############################################################

basic_gcrypt_sources = files(
        'gcrypt-util.c',
        'gcrypt-util.h')

# A convenience library that is separate from libbasic to avoid
# unnecessary linking to libgcrypt.
libbasic_gcrypt = static_library(
        'basic-gcrypt',
        basic_gcrypt_sources,
        include_directories : basic_includes,
        dependencies : [libgcrypt],
        c_args : ['-fvisibility=default'])
