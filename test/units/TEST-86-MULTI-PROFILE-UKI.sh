#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

if ! systemd-analyze has-tpm2; then
    echo "Full TPM2 support not available, skipping the test"
    exit 0
fi

bootctl

STUB_PATH=$(bootctl --print-stub-path)
CURRENT_UKI=$STUB_PATH
# With boot counting, systemd-bless-boot may already have renamed the UKI.
if [[ ! -f "$CURRENT_UKI" ]]; then
    CURRENT_UKI="${CURRENT_UKI%+*}.efi"
fi
MEASURE=/usr/lib/systemd/systemd-measure
SD_PCRLOCK=/usr/lib/systemd/systemd-pcrlock
PCRLOCK_UKI=/var/lib/pcrlock.d/650-uki.pcrlock.d/multi-profile.pcrlock
PCRLOCK_POLICY=/var/lib/systemd/pcrlock.json
PCRLOCK_SHIM=/var/lib/pcrlock.d/625-shim.pcrlock.d/test86.pcrlock
PCRLOCK_LOADER=/var/lib/pcrlock.d/630-boot-loader-code.pcrlock.d/test86.pcrlock
PCRLOCK_ADDON=/var/lib/pcrlock.d/660-addon.pcrlock
# This policy covers PCR 4 and PCR 7, but not PCR 11.
PCRLOCK_POLICY_PCR4=/var/lib/systemd/pcrlock-pcr4.json
# This disk image is bound to the systemd-pcrlock policy. It only exists if systemd-pcrlock is supported.
PCRLOCK_IMAGE=/root/pcrlocked.raw
LOADER_GUID=4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
TOFU_STAGE=/root/tofu-stage
# The TOFU record is in NVRAM and cannot be removed from the OS, hence remember that the TOFU stages ran, so
# that a rerun of the test doesn't expect to enroll again. Not removed by tofu_cleanup on purpose.
TOFU_TESTED=/root/tofu-tested
# The test provisions this certificate via the key addon. The TOFU stages only check the keyring if this
# file exists, because systemd-keyring-setup is not built everywhere.
TOFU_CRT=/root/tofu-keyring.crt
# The modified stage replaces the key addon with one that contains this certificate instead.
TOFU_PLANTED_CRT=/root/tofu-planted.crt

# Prints a string (list) EFI variable of systemd-stub, one entry per line
stub_variable() {
    local f="/sys/firmware/efi/efivars/$1-$LOADER_GUID"

    [[ -f "$f" ]] || return 1
    # Skip the 4 byte attribute header, the rest is UTF-16, possibly a list of NUL terminated strings.
    # NB: dd, because efivarfs does not support seeking on older kernels, which tail -c +5 would do.
    dd if="$f" bs=1 skip=4 status=none | iconv -f UTF-16LE -t UTF-8 | tr '\0' '\n' | sed '/^$/d'
}

# Whether trusting addons on first use can be tested: it needs Secure Boot (unsigned addons are loaded by the
# firmware otherwise), a stub that supports it, and the tools to build addons.
tofu_supported() {
    local sb="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    local features="/sys/firmware/efi/efivars/StubFeatures-$LOADER_GUID"

    [[ -f "$sb" && "$(od -An -tu1 -j4 -N1 "$sb" | tr -d ' ')" == 1 ]] || return 1
    [[ -f "$features" ]] || return 1
    (( ($(od -An -tu8 -j4 -N8 "$features" | tr -d ' ') >> 14) & 1 )) || return 1
    [[ -f "/usr/lib/systemd/boot/efi/addon$(bootctl --print-efi-architecture).efi.stub" ]] || return 1
    command -v openssl >/dev/null || return 1
    command -v systemd-sbsign >/dev/null || command -v /usr/lib/systemd/systemd-sbsign >/dev/null || return 1
}

tofu_addon() {
    local name="${1:?}" cmdline="${2:?}"
    shift 2

    ukify build \
        --stub="/usr/lib/systemd/boot/efi/addon$(bootctl --print-efi-architecture).efi.stub" \
        --cmdline="$cmdline" \
        --output="$(bootctl --print-esp-path)/loader/addons/$name.addon.efi" \
        "$@"
}

# This function succeeds if the test can provision a certificate in an addon and check that it arrives in
# the kernel keyring. That needs systemd-keyring-setup, a kernel with a .dm-verity keyring, and the tools to
# build the addon with systemd-firstboot.
tofu_keys_supported() {
    [[ -x /usr/lib/systemd/systemd-keyring-setup ]] || return 1
    # The tofu profile boots with dm_verity.keyring_unsealed=1, so that systemd-keyring-setup may provision
    # the keyring. The parameter only exists if the kernel has a .dm-verity keyring.
    modinfo -p dm_verity 2>/dev/null | grep keyring_unsealed >/dev/null \
        || [[ -e /sys/module/dm_verity/parameters/keyring_unsealed ]] || return 1
    command -v systemd-firstboot >/dev/null || return 1
    command -v systemd-repart >/dev/null || return 1
    command -v keyctl >/dev/null || return 1
    command -v mcopy >/dev/null || return 1
    command -v sfdisk >/dev/null || return 1
    command -v jq >/dev/null || return 1
}

# This function provisions a certificate for the .dm-verity keyring in an unsigned addon that
# systemd-firstboot builds. systemd-firstboot --addon= only writes into a disk image file, hence the function
# builds the addon in a scratch image and copies it onto the mounted ESP.
tofu_key_addon() {
    local crt="${1:?}" wrk start
    wrk="$(mktemp -d)"

    mkdir "$wrk/defs"
    cat >"$wrk/defs/10-esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
EOF
    systemd-repart --empty=create --size=auto --dry-run=no --offline=yes \
        --definitions="$wrk/defs" "$wrk/image.raw"
    systemd-firstboot --image="$wrk/image.raw" --addon=tofu-keys --key=dm-verity:tofu-key="$crt"

    start="$(sfdisk --json "$wrk/image.raw" | jq -r '.partitiontable.partitions[0].start')"
    mcopy -n -i "$wrk/image.raw@@$((start * 512))" ::/loader/addons/tofu-keys.addon.efi \
        "$(bootctl --print-esp-path)/loader/addons/tofu-keys.addon.efi"
    rm -rf "$wrk"
}

# This function checks that the certificate from the trusted key addon is a system credential, and that
# systemd-keyring-setup enrolled it into the .dm-verity keyring before the switch to the host.
tofu_keys_check() {
    local enrolled switched
    local pem="/run/voa/[^/]+/kernel-keyring/dm-verity/x509/tofu-key-certificate.pem"
    local re="^Enrolled .$pem. into keyring .dm-verity"

    cmp <(systemd-creds --system cat keyring-setup.dm-verity.tofu-key) "$TOFU_CRT"
    keyctl list %:.dm-verity >/tmp/tofu-keyring.list
    grep -F tofu-enrolled-key /tmp/tofu-keyring.list >/dev/null

    # journalctl -u does not find the messages of the initrd run, because the process has exited by the
    # time journald reads them, and they hence carry no _SYSTEMD_UNIT= field.
    journalctl -b -o json -t systemd-keyring-setup >/tmp/tofu-keyring-setup.json
    enrolled="$(jq -rn --arg re "$re" 'first(inputs | select(.MESSAGE | test($re)) | .__MONOTONIC_TIMESTAMP)' \
        /tmp/tofu-keyring-setup.json)"
    journalctl -b -o json _PID=1 >/tmp/tofu-pid1.json
    switched="$(jq -rn 'first(inputs | select(.MESSAGE | startswith("Switching root")) | .__MONOTONIC_TIMESTAMP)' \
        /tmp/tofu-pid1.json)"
    rm -f /tmp/tofu-keyring.list /tmp/tofu-keyring-setup.json /tmp/tofu-pid1.json
    [[ -n "$enrolled" && -n "$switched" && "$enrolled" -lt "$switched" ]]
}

# The boot manager applies pending fwupd capsules (fwupd-efi protocol) on every boot, before the OS
# starts: it enumerates the fwupd-* variables of the FWUPDATE GUID, loads the capsules they point to
# from the ESP, marks the variables as attempted, and calls UpdateCapsule(). This scenario queues one
# capsule from the OS, reboots, and checks the variable state the boot manager left behind. The helper
# script is kept on the persistent root so it survives the reboots of the state machine.
fwupdate_helper() {
    cat >/root/fwupdate-helper.py <<'PYEOF'
#!/usr/bin/env python3
"""Build and check the fwupd-efi capsule fixtures used by the firmware update stages of TEST-86."""
import fcntl
import json
import os
import re
import struct
import subprocess
import sys
import uuid

FWUPDATE = "0abba7dc-e516-4167-bbf5-4d9d1c739416"
# A GUID no firmware (including OVMF) claims, so RT->UpdateCapsule() must reject the capsule and the
# boot manager must carry on with the normal boot.
CAPSULE = uuid.UUID("deadbeef-cafe-4a67-9416-8327f5b40ab2")
DIR = "/boot/fwupd-test"
# efivarfs marks variables not on the firmware's allow list immutable, and the flag must be lifted
# before the variable can be removed (cf. efi_set_variable() in src/basic/efivars.c).
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x10

def var(n):
    return f"/sys/firmware/efi/efivars/{n}-{FWUPDATE}"

def esp():
    # /boot carries the ESP (vfat) automounted over an autofs placeholder, hence filter to a /dev/
    # source.
    lines = subprocess.check_output(["findmnt", "-no", "SOURCE", "/boot"]).decode().splitlines()
    src = next((l.strip() for l in lines if l.strip().startswith("/dev/")), None)
    if not src:
        raise SystemExit(f"could not determine the ESP device from: {lines!r}")
    disk, part = re.fullmatch(r"(/dev/.+?)(p?\d+)", src).groups()
    t = json.loads(subprocess.check_output(["sfdisk", "--json", disk]))
    n = int(part.lstrip("p"))
    # sfdisk omits "number" where it can be inferred from the position in the array, hence fall
    # back to the 1-based index and normalize the field for the caller.
    for i, p in enumerate(t["partitiontable"]["partitions"], 1):
        if p.get("number", i) == n:
            p = dict(p, number=p.get("number", i))
            break
    else:
        raise SystemExit(f"partition {n} of {disk} not found in sfdisk output")
    with open(disk, "rb") as f:
        f.seek(512)
        sig = f.read(16)
    print(f"DIAG-ESP src={src!r} disk={disk} part={part} sig512={sig.hex()}")
    if sig[:8] != b"EFI PART":
        raise SystemExit(f"{disk} is not a GPT disk")
    return p

def dp(p):
    # HARDDRIVE node byte-identical to the one OVMF's PartitionDxe builds for this partition
    # (edk2 MdeModulePkg/Universal/Disk/PartitionDxe/Gpt.c): the partition number is the GPT
    # table index + 1, the signature is the partition's unique GUID — p["uuid"] decoded to the
    # same mixed-endian byte order the firmware stores — with MBR type 0x02 (EFI partition
    # table header) and signature type GUID. The boot manager prepends the boot disk's own
    # device path before matching, matching the layout fwupd writes.
    hd = struct.pack("<BBHIQQ16sBB", 4, 1, 42, p["number"], p["start"], p["size"],
                     uuid.UUID(p["uuid"]).bytes_le, 2, 2)
    # The FILEPATH node is the four-byte device path header followed directly by the
    # NUL-terminated UTF-16 path name; there is no separate length field.
    u16 = "\\fwupd-test\\capsule.cap".encode("utf-16-le") + b"\x00\x00"
    return hd + struct.pack("<BBH", 4, 4, 4 + len(u16)) + u16 + b"\x7f\xff\x04\x00"

def write_var(n, status, p):
    # FWUP_UPDATE_INFO: version(4), GUID(16), flags(4), hw_inst(8), time_attempted(16), status(4).
    info = struct.pack("<I16sIQ16sI", 7, CAPSULE.bytes_le, 0, 0, b"\x00" * 16, status)
    with open(var(n), "wb") as f:
        f.write(struct.pack("<I", 7))  # NV | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
        f.write(info + dp(p))

def setup():
    p = esp()
    os.makedirs(DIR, exist_ok=True)
    payload = b"\xaa" * 32
    with open(DIR + "/capsule.cap", "wb") as f:
        # EFI_CAPSULE_HEADER: GUID(16), HeaderSize(4), Flags(4), CapsuleImageSize(4).
        f.write(struct.pack("<16sIII", CAPSULE.bytes_le, 28, 0, 28 + len(payload)) + payload)
    write_var("fwupd-test", 1, p)  # ATTEMPT_UPDATE
    write_var("fwupd-skip", 0, p)  # negative control: no ATTEMPT_UPDATE
    # Print the written variable so the device path can be inspected byte-wise in the log.
    print("fwupd-test variable:", open(var("fwupd-test"), "rb").read().hex())
    with open("/root/fwupd-skip.orig", "wb") as f:
        f.write(open(var("fwupd-skip"), "rb").read())

def assert_attempted():
    d = open(var("fwupd-test"), "rb").read()
    # In the efivar file the 4 byte attribute header precedes FWUP_UPDATE_INFO, hence
    # time_attempted is at 4+4+16+4+8=36 and status at 4+4+16+4+8+16=52.
    status = struct.unpack_from("<I", d, 52)[0]
    assert status == 2, f"fwupd-test status is {status}, want ATTEMPTED (2)"
    assert d[36:52] != b"\x00" * 16, "fwupd-test time_attempted is zero"

def assert_untouched():
    a = open(var("fwupd-skip"), "rb").read()
    b = open("/root/fwupd-skip.orig", "rb").read()
    assert a == b, "fwupd-skip variable was modified by the boot manager"
    # The processed capsule must keep its attempted status, not be retried.
    s = struct.unpack_from("<I", open(var("fwupd-test"), "rb").read(), 52)[0]
    assert s == 2, f"fwupd-test status is {s}, want ATTEMPTED (2)"

def remove_var(n):
    p = var(n)
    try:
        fd = os.open(p, os.O_RDONLY)
    except FileNotFoundError:
        return
    with os.fdopen(fd, "rb") as f:
        flags = struct.unpack("<I", fcntl.ioctl(f.fileno(), FS_IOC_GETFLAGS, b"\x00" * 4))[0]
        if flags & FS_IMMUTABLE_FL:
            fcntl.ioctl(f.fileno(), FS_IOC_SETFLAGS, struct.pack("<I", flags & ~FS_IMMUTABLE_FL))
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass

def cleanup():
    for n in ("fwupd-test", "fwupd-skip"):
        remove_var(n)
    subprocess.run(["rm", "-rf", DIR], check=True)
    os.unlink("/root/fwupd-skip.orig")

if __name__ == "__main__":
    {"setup": setup, "assert-attempted": assert_attempted,
     "assert-untouched": assert_untouched, "cleanup": cleanup}[sys.argv[1]]()
PYEOF
}

# The boot manager, the stub and the kernel extend PCR 12 (kernel-config) and log every extension
# into the TPM event log the kernel exposes. Replaying the PCR 12 events of the log must give the
# live PCR value, the measured data must correspond to what the kernel actually received, and a
# non-default profile must have been measured (the default profile is not).
pcr12_check() {
    cat >/root/pcr12-check.py <<'PYEOF'
#!/usr/bin/env python3
"""Verify the PCR 12 (kernel-config) TPM measurements recorded during this boot."""
import hashlib
import json
import os
import struct
import sys

PCR = 12
SHA256 = 0x000b
EV_EVENT_TAG = 0x00000006
EV_IPL = 0x0000000d
UKI_PROFILE_TAG = 0x13aed6db
SPEC_ID = b"Spec ID Event03\x00"

def die(msg):
    raise SystemExit(f"PCR 12 check failed: {msg}")

def utf16(data):
    # A NUL-terminated UTF-16LE string; the terminator is optional
    if len(data) % 2:
        data += b"\x00"
    return data.decode("utf-16-le").rstrip("\x00")

def main():
    profile = sys.argv[1]

    log = None
    for path in ("/sys/kernel/security/tpm0/binary_bios_measurements",
                 "/sys/kernel/security/tpm0/binary_tpm_eventlog"):
        if os.path.exists(path):
            log = open(path, "rb").read()
            break
    if log is None:
        print("the kernel does not expose the TPM event log, skipping the PCR 12 check")
        return

    # The log starts with the Spec ID event in the legacy format (cf.
    # validate_firmware_header() in src/pcrlock/pcrlock-firmware.c): pcrIndex,
    # eventType, zeroed sha1 digest, eventDataSize, then the TCG_EfiSpecIDEvent
    # with the table of hash algorithms as (algorithm ID, digest size) pairs.
    pcr, etype, digest, size = struct.unpack_from("<II20sI", log, 0)
    if pcr != 0 or etype != 0x3 or digest != b"\x00" * 20:
        die(f"unexpected event log header: pcr={pcr} type={etype:#x}")
    off = 32
    if log[off:off + 16] != SPEC_ID:
        die("missing Spec ID event signature")
    (n_algs,) = struct.unpack_from("<I", log, off + 24)
    if not 1 <= n_algs <= 16:
        die(f"implausible number of hash algorithms in the event log: {n_algs}")
    algs = struct.unpack_from(f"<{2 * n_algs}H", log, off + 28)
    alg_sz_pairs = {algs[i]: algs[i + 1] for i in range(0, len(algs), 2)}
    if SHA256 not in alg_sz_pairs:
        print("the TPM event log has no sha256 bank, skipping the PCR 12 check")
        return
    off += size

    # Replay the PCR 12 events. Each record is TCG_PCR_EVENT2: pcrIndex, eventType,
    # the digests (count, then one hash algorithm entry per algorithm of the Spec
    # ID table), eventSize, and the event data.
    state = b"\x00" * 32
    ipl = []
    tags = []
    while off < len(log):
        p, etype, count = struct.unpack_from("<III", log, off)
        if count > 16:
            die(f"implausible number of digests in an event log record: {count}")
        doff = off + 12
        digests = {}
        for _ in range(count):
            (h,) = struct.unpack_from("<H", log, doff)
            d = alg_sz_pairs.get(h, 0)
            if h not in digests:
                digests[h] = log[doff + 2:doff + 2 + d]
            doff += 2 + d
        (esize,) = struct.unpack_from("<I", log, doff)
        data = log[doff + 4:doff + 4 + esize]
        off = doff + 4 + esize
        if p != PCR:
            continue
        if etype == EV_IPL:
            try:
                ipl.append(utf16(data))
            except UnicodeDecodeError:
                pass
        elif etype == EV_EVENT_TAG and len(data) >= 8:
            tag, tsize = struct.unpack_from("<II", data, 0)
            if tag == UKI_PROFILE_TAG and tsize + 8 <= len(data):
                try:
                    tags.append(utf16(data[8:8 + tsize]))
                except UnicodeDecodeError:
                    die("malformed UTF-16 data in the UKI profile tag event")
        if SHA256 not in digests:
            die("PCR 12 event without a sha256 digest")
        state = hashlib.sha256(state + digests[SHA256]).digest()

    if not ipl and not tags:
        die("no PCR 12 measurements in the event log")

    # The firmware event log stops where the kernel takes over. Extensions made by userspace
    # (like the os-separator) are in the TPM measurement log instead, so the replay covers both
    # sources, firmware events first (cf. event_log_load() in src/pcrlock/pcrlock.c).
    userspace = os.environ.get("SYSTEMD_MEASURE_LOG_USERSPACE", "/run/log/systemd/tpm2-measure.log")
    if os.path.exists(userspace):
        with open(userspace) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    die(f"malformed TPM measurement log entry: {line!r}")
                if entry.get("pcr") != PCR:
                    continue
                digest = None
                for d in entry.get("digests", []):
                    if d.get("hashAlg") == "sha256":
                        digest = d
                        break
                if digest is None:
                    die(f"PCR 12 entry without a sha256 digest in the TPM measurement log: {line!r}")
                try:
                    state = hashlib.sha256(state + bytes.fromhex(digest["digest"])).digest()
                except (KeyError, ValueError, TypeError):
                    die(f"malformed sha256 digest in the TPM measurement log: {line!r}")

    live = None
    for path in (f"/sys/class/tpm/tpm0/pcr-sha256/{PCR}", f"/sys/class/tpm0/tpm0/pcr-{PCR}"):
        if os.path.exists(path):
            live = open(path).read().strip()
            break
    if live is None:
        print("no sha256 PCR bank exposed via sysfs, skipping the PCR 12 check")
        return
    # The kernel may format the sysfs PCR value with any hex case, so compare case-insensitively.
    if state.hex() != live.lower():
        die(f"live PCR 12 is {live}, replaying the event log gives {state.hex()}")

    # At least one of the measured strings must have made it into the kernel command line of the
    # measured boot, i.e. the measured kernel configuration is what the kernel received.
    with open("/proc/cmdline") as f:
        cmdline = f.read().strip()
    if not any(s and s in cmdline for s in ipl):
        die(f"none of the measured strings {ipl!r} is part of the kernel command line {cmdline!r}")

    if profile == "main":
        # The default profile is not measured into the TPM.
        if tags:
            die(f"the default profile must not be measured, found profile tag events {tags!r}")
    else:
        if not tags:
            die(f"profile {profile} was not measured into PCR 12")
        for t in tags:
            # The boot manager measures the profile marker, the stub the profile itself; both
            # must agree.
            if not any(s == f"@{t}" or s.startswith(f"@{t} ") for s in ipl):
                die(f"no boot manager profile marker matching tag {t!r} among {ipl!r}")

    print(f"PCR 12 check passed (profile {profile}): {len(ipl)} IPL string(s), {len(tags)} profile tag(s)")

if __name__ == "__main__":
    main()
PYEOF
    python3 /root/pcr12-check.py "$ID"
}

# Queue the capsule fixtures and enter the firmware update stages.
fwupdate_start() {
    fwupdate_helper
    python3 /root/fwupdate-helper.py setup
    echo fwupdate >"$TOFU_STAGE"
    bootctl set-default "multi-profile.efi@tofu"
    reboot
    exit 0
}

# This function checks which addons the stub trusted on first use on a boot where the modified addon is
# not on the ESP yet.
tofu_addons_check() {
    if [[ -e "$TOFU_CRT" ]]; then
        [[ "$(stub_variable StubTofuAddons)" == "$(printf '%s\n' \
            '\loader\addons\tofu-keys.addon.efi' '\loader\addons\tofu-unsigned.addon.efi')" ]]
        tofu_keys_check
    else
        [[ "$(stub_variable StubTofuAddons)" == '\loader\addons\tofu-unsigned.addon.efi' ]]
    fi
}

tofu_cleanup() {
    rm -f "$(bootctl --print-esp-path)"/loader/addons/tofu-*.addon.efi "$TOFU_STAGE" \
        "$TOFU_CRT" "$TOFU_PLANTED_CRT"
}

echo "CURRENT UKI ($CURRENT_UKI):"
ukify inspect "$CURRENT_UKI"
if test -f /run/systemd/stub/profile; then
    echo "CURRENT PROFILE:"
    cat /run/systemd/stub/profile
fi

# systemd-measure is optional
if [ -x "$MEASURE" ]; then
    echo "CURRENT MEASUREMENT:"
    "$MEASURE" --current
fi
if test -f /run/systemd/tpm2-pcr-signature.json; then
    echo "CURRENT SIGNATURE:"
    jq </run/systemd/tpm2-pcr-signature.json
fi

echo "CURRENT EVENT LOG + PCRS:"
/usr/lib/systemd/systemd-pcrlock

test -f /run/systemd/stub/profile

# shellcheck source=/dev/null
. /run/systemd/stub/profile

# Check the kernel-config (PCR 12) measurements of this boot, whatever the profile.
pcr12_check

if [[ "$ID" == "tofu" ]]; then
    grep testprofiletofu=1 /proc/cmdline
    # The state variable is absent when the firmware update stages boot this entry without the TOFU
    # chain having run (i.e. when the TOFU scenarios were not supported on this system).
    stub_variable StubTofuState || :
    stub_variable StubTofuAddons || :

    case "$(cat "$TOFU_STAGE")" in
        enroll)
            # The unsigned addon is trusted on first use and used, the one signed with an untrusted key
            # isn't, even though it was there on the first boot too.
            [[ "$(stub_variable StubTofuState)" == enrolled ]]
            tofu_addons_check
            grep tofuunsigned=1 /proc/cmdline
            (! grep tofuwrongkey=1 /proc/cmdline)
            echo verify >"$TOFU_STAGE"
            reboot
            exit 0
            ;;
        verify)
            # The same addon is trusted again via the record
            [[ "$(stub_variable StubTofuState)" == verified ]]
            tofu_addons_check
            grep tofuunsigned=1 /proc/cmdline
            (! grep tofuwrongkey=1 /proc/cmdline)

            # Replace it with a modified one, which must not be trusted
            tofu_addon tofu-unsigned tofuunsigned=2
            echo modified >"$TOFU_STAGE"
            reboot
            exit 0
            ;;
        modified)
            [[ "$(stub_variable StubTofuState)" == verified ]]
            (! grep tofuunsigned= /proc/cmdline)
            (! grep tofuwrongkey=1 /proc/cmdline)

            if [[ -e "$TOFU_CRT" ]]; then
                # The untouched key addon is unaffected by the rejection of its modified neighbour
                [[ "$(stub_variable StubTofuAddons)" == '\loader\addons\tofu-keys.addon.efi' ]]
                tofu_keys_check

                # Replace the key addon with one carrying a different certificate, as an attacker with
                # access to the ESP would. Nothing of it may reach the OS on the next boot.
                openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
                    -subj /CN=tofu-planted-key -days 2 -keyout /dev/null -out "$TOFU_PLANTED_CRT"
                rm -f "$(bootctl --print-esp-path)/loader/addons/tofu-keys.addon.efi"
                tofu_key_addon "$TOFU_PLANTED_CRT"
                echo planted >"$TOFU_STAGE"
                reboot
                exit 0
            fi

            (! stub_variable StubTofuAddons)
            tofu_cleanup
            touch "$TOFU_TESTED"
            fwupdate_start
            ;;
        planted)
            [[ "$(stub_variable StubTofuState)" == verified ]]
            (! stub_variable StubTofuAddons)
            (! grep tofuunsigned= /proc/cmdline)
            (! grep tofuwrongkey=1 /proc/cmdline)

            # The planted certificate and the certificate enrolled on the earlier boots are neither a
            # credential nor in the keyring. keyctl writes into a file, so that a failure to list the
            # keyring fails the test.
            (! systemd-creds --system cat keyring-setup.dm-verity.tofu-key)
            keyctl list %:.dm-verity >/tmp/tofu-keyring.list
            (! grep tofu- /tmp/tofu-keyring.list)
            rm -f /tmp/tofu-keyring.list

            tofu_cleanup
            touch "$TOFU_TESTED"
            fwupdate_start
            ;;
        fwupdate)
            # The capsule was processed on this boot, before the OS started: the variable must be
            # marked as attempted and carry the attempt time, whether the firmware accepted or
            # rejected the capsule.
            python3 /root/fwupdate-helper.py assert-attempted
            # The boot manager must have found the boot disk, i.e. the capsule services are available.
            [[ -f /sys/firmware/efi/efivars/BootloaderSupportsFwupd-0abba7dc-e516-4167-bbf5-4d9d1c739416 ]]
            echo fwupdate-neg >"$TOFU_STAGE"
            bootctl set-default "multi-profile.efi@tofu"
            reboot
            exit 0
            ;;
        fwupdate-neg)
            # The variable without the ATTEMPT_UPDATE flag must be left completely untouched.
            python3 /root/fwupdate-helper.py assert-untouched
            python3 /root/fwupdate-helper.py cleanup
            bootctl set-default ""
            touch /testok
            exit 0
            ;;
        *)
            exit 1
            ;;
    esac
fi

if [[ "$ID" == "main" ]]; then
    if [[ -f /root/encrypted.raw ]]; then
        exit 1
    fi

    # Prepare a disk image, locked to the PCR measurements of the current UKI
    truncate -s 32M /root/encrypted.raw
    echo -n "geheim" >/root/encrypted.secret
    cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom /root/encrypted.raw --key-file=/root/encrypted.secret
    systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs= --unlock-key-file=/root/encrypted.secret /root/encrypted.raw
    rm -f /root/encrypted.secret
fi

# Validate that with the current profile we can fulfill the PCR 11 policy
systemd-cryptsetup attach multiprof /root/encrypted.raw - tpm2-device=auto,headless=1
systemd-cryptsetup detach multiprof

if [[ "$ID" == "main" ]]; then
    if "$SD_PCRLOCK" is-supported; then
        # lock-uki generates a .pcrlock file for each profile that enables PCRLOCK=. Profile @0 enables it
        # by default, and Profile2 (@2) sets PCRLOCK=yes.
        "$SD_PCRLOCK" lock-uki --pcrlock="$PCRLOCK_UKI" "$CURRENT_UKI"
        test -f "$PCRLOCK_UKI"
        test ! -e "${PCRLOCK_UKI%.pcrlock}@1.pcrlock"
        test -f "${PCRLOCK_UKI%.pcrlock}@2.pcrlock"
        test ! -e "${PCRLOCK_UKI%.pcrlock}@3.pcrlock"

        # make-policy picks a random NV index out of 24 if none is specified. Each policy that is created
        # here gets an NV index of its own, so that the NV index of one policy is never picked for another.
        "$SD_PCRLOCK" make-policy --pcr=11 --nv-index=0x1d1020d
        jq -e '.pcrValues | any(.pcr == 11)' "$PCRLOCK_POLICY" >/dev/null

        # Prepare a second disk image, bound to the systemd-pcrlock policy only
        truncate -s 32M "$PCRLOCK_IMAGE"
        echo -n "geheim" >/root/pcrlocked.secret
        cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$PCRLOCK_IMAGE" --key-file=/root/pcrlocked.secret
        systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs= --tpm2-public-key= --tpm2-pcrlock="$PCRLOCK_POLICY" --unlock-key-file=/root/pcrlocked.secret "$PCRLOCK_IMAGE"
        rm -f /root/pcrlocked.secret

        systemd-cryptsetup attach pcrlocked "$PCRLOCK_IMAGE" - tpm2-device=auto,tpm2-pcrlock="$PCRLOCK_POLICY",headless=1
        systemd-cryptsetup detach pcrlocked

        # The firmware measures the boot loader, the UKI and the global addon into PCR 4, and the result is
        # the same for every profile of the UKI.
        esp=$(bootctl --print-esp-path)
        loader=$(bootctl --print-loader-path)
        # With shim, mkosi installs systemd-boot as grub*.efi and the firmware measures shim first.
        if [[ "${loader,,}" == */efi/boot/grub*.efi ]]; then
            arch=$(bootctl --print-efi-architecture)
            "$SD_PCRLOCK" lock-pe --pcrlock="$PCRLOCK_SHIM" "$esp/EFI/BOOT/BOOT${arch^^}.EFI"
        fi
        "$SD_PCRLOCK" lock-pe --pcrlock="$PCRLOCK_LOADER" "$loader"
        "$SD_PCRLOCK" lock-pe --pcrlock="$PCRLOCK_ADDON" "$esp/loader/addons/test.addon.efi"
        "$SD_PCRLOCK" lock-secureboot-policy
        "$SD_PCRLOCK" lock-secureboot-authority
        "$SD_PCRLOCK" log --pcr=4+7
        "$SD_PCRLOCK" make-policy --policy="$PCRLOCK_POLICY_PCR4" --pcr=4+7 --nv-index=0x1d1020e
        jq -e '.pcrValues | any(.pcr == 4)' "$PCRLOCK_POLICY_PCR4" >/dev/null
        jq -e '.pcrValues | any(.pcr == 7)' "$PCRLOCK_POLICY_PCR4" >/dev/null
    fi

    # Give the UKI a mixed case name with a boot counter. Entry IDs are matched case insensitively
    # and without the counter, so the lower case ID without counter has to keep working.
    mv "$CURRENT_UKI" "$(dirname "$CURRENT_UKI")/Multi-Profile+3.efi"
    bootctl set-default "multi-profile.efi@profile1"
    reboot
    exit 0
elif [[ "$ID" == "profile1" ]]; then
    grep testprofile1=1 /proc/cmdline

    if [[ -f "$PCRLOCK_IMAGE" ]]; then
        # profile1 does not enable PCRLOCK=, hence it has no .pcrlock file and does not satisfy the policy.
        (! systemd-cryptsetup attach pcrlocked "$PCRLOCK_IMAGE" - tpm2-device=auto,tpm2-pcrlock="$PCRLOCK_POLICY",headless=1)

        # make-policy must not replace the policy with one that does not cover PCR 11.
        cp "$PCRLOCK_POLICY" /tmp/pcrlock.json
        "$SD_PCRLOCK" make-policy --pcr=11 2>&1 | tee /tmp/make-policy.log
        grep "excluded from PCR locking" /tmp/make-policy.log >/dev/null
        cmp "$PCRLOCK_POLICY" /tmp/pcrlock.json

        # --force skips the check in make-policy. The TPM refuses the update then, because the recovery PIN
        # is sealed against the policy that this boot does not satisfy.
        (! "$SD_PCRLOCK" make-policy --pcr=11 --force)
        cmp "$PCRLOCK_POLICY" /tmp/pcrlock.json
        rm -f /tmp/pcrlock.json /tmp/make-policy.log

        # profile1 satisfies the policy for PCR 4 and PCR 7. make-policy must not replace it with a policy
        # that does not cover PCR 4, although PCR 11 is not among the selected PCRs.
        cp "$PCRLOCK_POLICY_PCR4" /tmp/pcrlock-pcr4.json
        "$SD_PCRLOCK" make-policy --policy="$PCRLOCK_POLICY_PCR4" --pcr=4+7 2>&1 | tee /tmp/make-policy.log
        grep "excluded from PCR locking" /tmp/make-policy.log >/dev/null
        cmp "$PCRLOCK_POLICY_PCR4" /tmp/pcrlock-pcr4.json
        rm -f /tmp/pcrlock-pcr4.json /tmp/make-policy.log

        # If no policy exists yet, make-policy creates one from the PCRs that the event log of profile1 allows.
        "$SD_PCRLOCK" make-policy --policy=/tmp/pcrlock-new.json --pcr=4+7+11 --nv-index=0x1d1020f
        jq -e '.pcrValues | any(.pcr == 7)' /tmp/pcrlock-new.json >/dev/null
        jq -e '.pcrValues | any(.pcr == 4 or .pcr == 11) | not' /tmp/pcrlock-new.json >/dev/null
        "$SD_PCRLOCK" remove-policy --policy=/tmp/pcrlock-new.json
    fi

    # The renamed UKI with the boot counter has to be what systemd-boot booted.
    [[ "$(basename "$STUB_PATH")" == Multi-Profile+* ]]
    # The profile ID is "Profile2", the lower case entry ID has to match it anyway.
    bootctl set-default "multi-profile.efi@profile2"
    reboot
    exit 0
elif [[ "$ID" == "Profile2" ]]; then
    grep testprofile2=1 /proc/cmdline
    rm /root/encrypted.raw

    if [[ -f "$PCRLOCK_IMAGE" ]]; then
        # Profile2 sets PCRLOCK=yes, hence it satisfies the policy and make-policy works.
        systemd-cryptsetup attach pcrlocked "$PCRLOCK_IMAGE" - tpm2-device=auto,tpm2-pcrlock="$PCRLOCK_POLICY",headless=1
        systemd-cryptsetup detach pcrlocked
        "$SD_PCRLOCK" make-policy --pcr=11
        jq -e '.pcrValues | any(.pcr == 11)' "$PCRLOCK_POLICY" >/dev/null

        "$SD_PCRLOCK" make-policy --policy="$PCRLOCK_POLICY_PCR4" --pcr=4+7
        jq -e '.pcrValues | any(.pcr == 4)' "$PCRLOCK_POLICY_PCR4" >/dev/null

        rm "$PCRLOCK_IMAGE"
        "$SD_PCRLOCK" remove-policy --policy="$PCRLOCK_POLICY_PCR4"
        "$SD_PCRLOCK" unlock-pe --pcrlock="$PCRLOCK_SHIM"
        "$SD_PCRLOCK" unlock-pe --pcrlock="$PCRLOCK_LOADER"
        "$SD_PCRLOCK" unlock-pe --pcrlock="$PCRLOCK_ADDON"
        "$SD_PCRLOCK" unlock-secureboot-policy
        "$SD_PCRLOCK" unlock-secureboot-authority
        "$SD_PCRLOCK" remove-policy
        "$SD_PCRLOCK" unlock-uki --pcrlock="$PCRLOCK_UKI"
        test ! -e "$PCRLOCK_UKI"
        test ! -e "${PCRLOCK_UKI%.pcrlock}@2.pcrlock"
    fi

    # The test image is built with secure boot auto-enrollment, hence when this test runs under UEFI
    # firmware, the boot manager already enrolled the keys on a previous boot. If the firmware exposes
    # the SecureBoot variable but secure boot is not active, the enrollment did not work and the TOFU
    # scenarios below would silently skip - fail loudly instead.
    if [[ -f /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c ]]; then
        [[ "$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d ' ')" == 1 ]]
    fi

    if [[ -e "$TOFU_TESTED" ]]; then
        echo "Trusting addons on first use was tested on a previous run already, its record persists, skipping it"
    elif tofu_supported; then
        # An unsigned addon to trust on first use, and one signed with a key the firmware doesn't trust,
        # which must never be trusted on first use.
        tofu_cleanup
        tofu_addon tofu-unsigned tofuunsigned=1
        openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=tofu -days 1 \
            -keyout /tmp/tofu.key -out /tmp/tofu.crt
        tofu_addon tofu-wrongkey tofuwrongkey=1 \
            --signtool=systemd-sbsign --secureboot-private-key=/tmp/tofu.key --secureboot-certificate=/tmp/tofu.crt
        if tofu_keys_supported; then
            # A certificate provisioned for the kernel keyring, in an addon built by systemd-firstboot
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
                -subj /CN=tofu-enrolled-key -days 2 -keyout /dev/null -out "$TOFU_CRT"
            tofu_key_addon "$TOFU_CRT"
        fi
        echo enroll >"$TOFU_STAGE"
        bootctl set-default "multi-profile.efi@tofu"
        reboot
        exit 0
    else
        echo "Trusting addons on first use cannot be tested here, skipping it"
    fi

    # Firmware update scenario: queue a capsule for the next boot and let the boot manager process it.
    # (Runs also when the TOFU scenarios were skipped, so that it is not gated on Secure Boot.)
    fwupdate_start
else
    exit 1
fi
