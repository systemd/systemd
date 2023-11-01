# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

logind_revoke_bpf_o_unstripped = custom_target(
        'logind-revoke.bpf.unstripped.o',
        input : 'logind-revoke.bpf.c',
        output : 'logind-revoke.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd)

logind_revoke_bpf_o = custom_target(
        'logind-revoke.bpf.o',
        input : logind_revoke_bpf_o_unstripped,
        output : 'logind-revoke.bpf.o',
        command : bpf_o_cmd)

logind_revoke_skel_h = custom_target(
        'logind-revoke.skel.h',
        input : logind_revoke_bpf_o,
        output : 'logind-revoke.skel.h',
        command : skel_h_cmd,
        capture : true)
