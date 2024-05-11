#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

USER_DIRS_CONF="/root/.config/user-dirs.dirs"

at_exit() {
    set +e

    rm -fv "${USER_DIRS_CONF:?}"
}

trap at_exit EXIT

# Check that we indeed run under root to make the rest of the test work
[[ "$(id -u)" -eq 0 ]]

# Create a custom user-dirs.dir file to exercise the xdg-user-dirs part
# of sd-path/from_user_dir()
mkdir -p "/root/.config"
cat >"${USER_DIRS_CONF:?}" <<\EOF
XDG_DESKTOP_DIR="$HOME/my-fancy-desktop"
XDG_INVALID

XDG_DOWNLOAD_DIR   = "$HOME"
XDG_TEMPLATES_DIR="/templates"
# Invalid records
XDG_TEMPLATES_DIR=/not-templates"
XDG_TEMPLATES_DIR="/also-not-teplates
XDG_TEMPLATES_DIR=""
XDG_TEMPLATES_DIR="../"

XDG_PUBLICSHARE_DIR="$HOME/cat-pictures"
XDG_DOCUMENTS_DIR="$HOME/top/secret/documents"
XDG_MUSIC_DIR="/tmp/vaporwave"
XDG_PICTURES_DIR="$HOME/Pictures"
XDG_VIDEOS_DIR="$HOME/🤔"
EOF

systemd-path --help
systemd-path --version
systemd-path
systemd-path temporary system-binaries user binfmt

assert_eq "$(systemd-path system-runtime)" "/run"
assert_eq "$(systemd-path --suffix='' system-runtime)" "/run"
assert_eq "$(systemd-path --suffix='🤔' system-runtime)" "/run/🤔"
assert_eq "$(systemd-path --suffix=hello system-runtime)" "/run/hello"

# Note for the stuff below: everything defaults to $HOME, only the desktop
# directory defaults to $HOME/Desktop.
#
# Check the user-dirs.dir stuff from above
assert_eq "$(systemd-path user)" "/root"
assert_eq "$(systemd-path user-desktop)" "/root/my-fancy-desktop"
assert_eq "$(systemd-path user-documents)" "/root/top/secret/documents"
assert_eq "$(systemd-path user-download)" "/root"
assert_eq "$(systemd-path user-music)" "/tmp/vaporwave"
assert_eq "$(systemd-path user-pictures)" "/root/Pictures"
assert_eq "$(systemd-path user-public)" "/root/cat-pictures"
assert_eq "$(systemd-path user-templates)" "/templates"
assert_eq "$(systemd-path user-videos)" "/root/🤔"

# Remove the user-dirs.dir file and check the defaults
rm -fv "$USER_DIRS_CONF"
[[ ! -e "$USER_DIRS_CONF" ]]
assert_eq "$(systemd-path user-desktop)" "/root/Desktop"
for dir in "" documents download music pictures public templates videos; do
    assert_eq "$(systemd-path "user${dir:+-$dir}")" "/root"
done

# sd-path should consider only absolute $HOME
assert_eq "$(HOME=/hello-world systemd-path user)" "/hello-world"
assert_eq "$(HOME=hello-world systemd-path user)" "/root"
assert_eq "$(HOME=/hello systemd-path --suffix=world user)" "/hello/world"
assert_eq "$(HOME=hello systemd-path --suffix=world user)" "/root/world"
# Same with some other env variables
assert_in "/my-config" "$(HOME='' XDG_CONFIG_HOME=/my-config systemd-path search-configuration)"
assert_in "/my-config/foo" "$(HOME='' XDG_CONFIG_HOME=/my-config systemd-path --suffix=foo search-configuration)"
assert_in "/my-home/.config/foo" "$(HOME=/my-home XDG_CONFIG_HOME=my-config systemd-path --suffix=foo search-configuration)"
assert_not_in "my-config" "$(HOME=my-config XDG_CONFIG_HOME=my-config systemd-path search-configuration)"

(! systemd-path '')
(! systemd-path system-binaries 🤔 user)
(! systemd-path --xyz)
