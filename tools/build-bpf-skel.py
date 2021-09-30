#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import logging
import pathlib
import re
import subprocess
import sys

def clang_arch_flag(arch):
    return '-D__{}__'.format(arch)


def target_triplet():
    gcc_exec = 'gcc'

    try:
        return subprocess.check_output([gcc_exec, '-dumpmachine'],
                universal_newlines=True).strip()
    except subprocess.CalledProcessError as e:
        logging.error('Failed to get target triplet: {}'.format(e))
    except FileNotFoundError:
        logging.error('gcc not installed')
    return None


def clang_compile(clang_exec, clang_flags, src_c, out_file, target_arch,
        target_triplet):
    clang_args = [clang_exec, *clang_flags, target_arch, '-I.']

    if target_triplet:
        clang_args += [
            '-isystem',
            '/usr/include/{}'.format(target_triplet)]

    clang_args += [
        '-idirafter',
        '/usr/local/include',
        '-idirafter',
        '/usr/include']

    clang_args += [src_c, '-o', out_file]

    logging.debug('{}'.format(' '.join(clang_args)))
    subprocess.check_call(clang_args)


def llvm_strip(llvm_strip_exec, in_file):
    llvm_strip_args = [llvm_strip_exec, '-g', in_file]

    logging.debug('Stripping useless DWARF info:')
    logging.debug('{}'.format(' '.join(llvm_strip_args)))

    subprocess.check_call(llvm_strip_args)


def gen_bpf_skeleton(bpftool_exec, in_file, out_fd):
    bpftool_args = [bpftool_exec, 'g', 's', in_file]

    logging.debug('Generating BPF skeleton:')
    logging.debug('{}'.format(' '.join(bpftool_args)))
    skel = subprocess.check_output(bpftool_args, universal_newlines=True)
    # libbpf is used via dlopen(), so rename symbols as defined
    # in src/shared/bpf-dlopen.h
    skel = re.sub(r'(bpf_object__\w+_skeleton)', r'sym_\1', skel)
    out_fd.write(skel)


def bpf_build(args):
    clang_flags = [
            '-Wno-compare-distinct-pointer-types',
            '-O2',
            '-target',
            'bpf',
            '-g',
            '-c',
    ]

    clang_out_path = pathlib.Path(args.bpf_src_c).with_suffix('.o')
    with clang_out_path.open(mode='w') as clang_out, \
            open(args.bpf_skel_h, mode='w') as bpf_skel_h:
        clang_compile(clang_exec=args.clang_exec,
                clang_flags=clang_flags,
                src_c=args.bpf_src_c,
                out_file=clang_out.name,
                target_arch=clang_arch_flag(args.arch),
                target_triplet=target_triplet())

        llvm_strip(llvm_strip_exec=args.llvm_strip_exec, in_file=clang_out.name)

        gen_bpf_skeleton(bpftool_exec=args.bpftool_exec,
                in_file=clang_out.name,
                out_fd=bpf_skel_h)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
            'bpf_src_c',
            help='Path to *.c source of BPF program in systemd source tree \
                    relative to the work directory')

    parser.add_argument(
            'bpf_skel_h',
            help='Path to C header file')

    parser.add_argument(
            '--clang_exec',
            help='Path to clang exec')

    parser.add_argument(
            '--llvm_strip_exec',
            help='Path to llvm-strip exec')

    parser.add_argument(
            '--bpftool_exec',
            help='Path to bpftool exec')

    parser.add_argument(
            '--arch',
            help='Target CPU architecture',
            default='x86_64')

    args = parser.parse_args();

    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    bpf_build(args)
