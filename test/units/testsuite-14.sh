#!/usr/bin/env bash
set -e
set -x

function setup_root {
    local _root="$1"
    mkdir -p "$_root"
    mount -t tmpfs tmpfs "$_root"
    mkdir -p "$_root/etc" "$_root/run"
}

function check {
    printf "Expected\n"
    cat "$1"
    printf "\nGot\n"
    cat "$2"
    cmp "$1" "$2"
}

r="$(pwd)/overwrite-broken-machine-id"
setup_root "$r"
systemd-machine-id-setup --print --root "$r"
echo abc >>"$r/etc/machine-id"
id=$(systemd-machine-id-setup --print --root "$r")
echo $id >expected
check expected "$r/etc/machine-id"

r="$(pwd)/transient-machine-id"
setup_root "$r"
systemd-machine-id-setup --print --root "$r"
echo abc >>"$r/etc/machine-id"
mount -o remount,ro "$r"
mount -t tmpfs tmpfs "$r/run"
transient_id=$(systemd-machine-id-setup --print --root "$r")
mount -o remount,rw "$r"
commited_id=$(systemd-machine-id-setup --print --commit --root "$r")
[[ "$transient_id" = "$commited_id" ]]
check "$r/etc/machine-id" "$r/run/machine-id"
