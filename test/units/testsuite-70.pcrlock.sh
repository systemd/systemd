#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
export PAGER=
SD_PCREXTEND="/usr/lib/systemd/systemd-pcrextend"
SD_PCRLOCK="/usr/lib/systemd/systemd-pcrlock"

if [[ ! -x "${SD_PCREXTEND:?}" ]] || [[ ! -x "${SD_PCRLOCK:?}" ]] ; then
    echo "$SD_PCREXTEND or $SD_PCRLOCK not found, skipping pcrlock tests"
    exit 0
fi

at_exit() {
    if [[ $? -ne 0 ]]; then
        # Dump the event log on fail, to make debugging a bit easier
        [[ -e /run/log/systemd/tpm2-measure.log ]] && jq --seq --slurp </run/log/systemd/tpm2-measure.log
    fi

    return 0
}

trap at_exit EXIT

# Temporarily override sd-pcrextend's sanity checks
export SYSTEMD_FORCE_MEASURE=1

# The PCRs we are going to lock to. We exclude the various PCRs we touched
# above where no event log record was written, because we cannot analyze
# things without event log. We include debug PCR 16, see below.
PCRS="1+2+3+4+5+16"

# Remove the old measurement log, as it contains all kinds of nonsense from the
# previous test, which will fail our consistency checks. Removing the file also
# means we'll fail consistency check, but at least we'll fail them consistently
# (as the PCR values simply won't match the log).
rm -f /run/log/systemd/tpm2-measure.log

# Ensure a truncated log doesn't crash pcrlock
echo -n -e \\x1e >/tmp/borked
set +e
SYSTEMD_MEASURE_LOG_USERSPACE=/tmp/borked "$SD_PCRLOCK" cel --no-pager --json=pretty
ret=$?
set -e
# If it crashes the exit code will be 149
test $ret -eq 1

SYSTEMD_COLORS=256 "$SD_PCRLOCK"
"$SD_PCRLOCK" cel --no-pager --json=pretty
"$SD_PCRLOCK" log --pcr="$PCRS"
"$SD_PCRLOCK" log --json=pretty --pcr="$PCRS"
"$SD_PCRLOCK" list-components
"$SD_PCRLOCK" list-components --location=250-
"$SD_PCRLOCK" list-components --location=250-:350-
"$SD_PCRLOCK" lock-firmware-config
"$SD_PCRLOCK" lock-gpt
"$SD_PCRLOCK" lock-machine-id
"$SD_PCRLOCK" lock-file-system
"$SD_PCRLOCK" lock-file-system /
"$SD_PCRLOCK" predict --pcr="$PCRS"
"$SD_PCRLOCK" predict --pcr="0x1+0x3+4"
"$SD_PCRLOCK" predict --json=pretty --pcr="$PCRS"

SD_STUB="$(find /usr/lib/systemd/boot/efi/ -name "systemd-boot*.efi" | head -n1)"
if [[ -n "$SD_STUB" ]]; then
    "$SD_PCRLOCK" lock-pe "$SD_STUB"
    "$SD_PCRLOCK" lock-pe <"$SD_STUB"
    "$SD_PCRLOCK" lock-uki "$SD_STUB"
    "$SD_PCRLOCK" lock-uki <"$SD_STUB"
fi

PIN=huhu "$SD_PCRLOCK" make-policy --pcr="$PCRS" --recovery-pin=yes
# Repeat immediately (this call will have to reuse the nvindex, rather than create it)
"$SD_PCRLOCK" make-policy --pcr="$PCRS"
"$SD_PCRLOCK" make-policy --pcr="$PCRS" --force

img="/tmp/pcrlock.img"
truncate -s 20M "$img"
echo -n hoho >/tmp/pcrlockpwd
chmod 0600 /tmp/pcrlockpwd
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$img" /tmp/pcrlockpwd

systemd-cryptenroll --unlock-key-file=/tmp/pcrlockpwd --tpm2-device=auto --tpm2-pcrlock=/var/lib/systemd/pcrlock.json --tpm2-public-key= --wipe-slot=tpm2 "$img"
systemd-cryptsetup attach pcrlock "$img" - tpm2-device=auto,tpm2-pcrlock=/var/lib/systemd/pcrlock.json,headless
systemd-cryptsetup detach pcrlock

# Measure something into PCR 16 (the "debug" PCR), which should make the activation fail
"$SD_PCREXTEND" --pcr=16 test70

"$SD_PCRLOCK" cel --json=pretty

(! systemd-cryptsetup attach pcrlock "$img" - tpm2-device=auto,tpm2-pcrlock=/var/lib/systemd/pcrlock.json,headless )

# Now add a component for it, rebuild policy and it should work (we'll rebuild
# once like that, but don't provide the recovery pin. This should fail, since
# the PCR is hosed after all. But then we'll use recovery pin, and it should
# work.
echo -n test70 | "$SD_PCRLOCK" lock-raw --pcrlock=/var/lib/pcrlock.d/910-test70.pcrlock --pcr=16
(! "$SD_PCRLOCK" make-policy --pcr="$PCRS")
PIN=huhu "$SD_PCRLOCK" make-policy --pcr="$PCRS" --recovery-pin=yes

systemd-cryptsetup attach pcrlock "$img" - tpm2-device=auto,tpm2-pcrlock=/var/lib/systemd/pcrlock.json,headless
systemd-cryptsetup detach pcrlock

# And now let's do it the clean way, and generate the right policy ahead of time.
echo -n test70-take-two | "$SD_PCRLOCK" lock-raw --pcrlock=/var/lib/pcrlock.d/920-test70.pcrlock --pcr=16
"$SD_PCRLOCK" make-policy --pcr="$PCRS"

"$SD_PCREXTEND" --pcr=16 test70-take-two

"$SD_PCRLOCK" cel --json=pretty

systemd-cryptsetup attach pcrlock "$img" - tpm2-device=auto,tpm2-pcrlock=/var/lib/systemd/pcrlock.json,headless
systemd-cryptsetup detach pcrlock

# Now use the root fs support, i.e. make the tool write a copy of the pcrlock
# file as service credential to some temporary dir and remove the local copy, so that
# it has to use the credential version.
mkdir /tmp/fakexbootldr
SYSTEMD_XBOOTLDR_PATH=/tmp/fakexbootldr SYSTEMD_RELAX_XBOOTLDR_CHECKS=1 "$SD_PCRLOCK" make-policy --pcr="$PCRS" --force
mv /var/lib/systemd/pcrlock.json /var/lib/systemd/pcrlock.json.gone

systemd-creds decrypt /tmp/fakexbootldr/loader/credentials/pcrlock.*.cred

SYSTEMD_ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY=/tmp/fakexbootldr/loader/credentials systemd-cryptsetup attach pcrlock "$img" - tpm2-device=auto,headless
systemd-cryptsetup detach pcrlock

mv /var/lib/systemd/pcrlock.json.gone /var/lib/systemd/pcrlock.json
SYSTEMD_XBOOTLDR_PATH=/tmp/fakexbootldr SYSTEMD_RELAX_XBOOTLDR_CHECKS=1 "$SD_PCRLOCK" remove-policy

"$SD_PCRLOCK" unlock-firmware-config
"$SD_PCRLOCK" unlock-gpt
"$SD_PCRLOCK" unlock-machine-id
"$SD_PCRLOCK" unlock-file-system
"$SD_PCRLOCK" unlock-raw --pcrlock=/var/lib/pcrlock.d/910-test70.pcrlock
"$SD_PCRLOCK" unlock-raw --pcrlock=/var/lib/pcrlock.d/920-test70.pcrlock

(! "$SD_PCRLOCK" "")
(! "$SD_PCRLOCK" predict --pcr=-1)
(! "$SD_PCRLOCK" predict --pcr=foo)
(! "$SD_PCRLOCK" predict --pcr=1+1)
(! "$SD_PCRLOCK" predict --pcr=1+++++1)
(! "$SD_PCRLOCK" make-policy --nv-index=0)
(! "$SD_PCRLOCK" make-policy --nv-index=foo)
(! "$SD_PCRLOCK" list-components --location=:)
(! "$SD_PCRLOCK" lock-gpt "")
(! "$SD_PCRLOCK" lock-gpt /dev/sr0)
(! "$SD_PCRLOCK" lock-pe /dev/full)
(! "$SD_PCRLOCK" lock-pe /bin/true)
(! "$SD_PCRLOCK" lock-uki /dev/full)
(! "$SD_PCRLOCK" lock-uki /bin/true)
(! "$SD_PCRLOCK" lock-file-system "")

rm "$img" /tmp/pcrlockpwd
