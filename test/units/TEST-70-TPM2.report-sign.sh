#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test report signing through the TPM2 backend (systemd-report-sign-tpm2), driven
# via the io.systemd.Report Varlink interface (the GenerateSigned method). This is
# the TPM2 counterpart to the plain software backend test in
# TEST-74-AUX-UTILS.report.sh; it lives here because it needs a real TPM, which
# only the TPM2 integration test provides.
#
# The TPM2 backend returns a set of signed TPM attestations (a PCR quote, one
# NV certification per NvPCR, and a session audit digest), together with the
# signing key's public area and the pcrlock event log. For each attestation we
# reconstruct the TPMT_SIGNATURE and verify it against the supplied public key
# with tpm2_verifysignature. We also confirm the report digest is carried in the
# extraData field of the session audit attestation.
#
# We currently don't confirm that the session audit digest is consistent with the
# rest of the report components.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

# The TPM2 backend is only built/installed with OpenSSL and TPM2 support, so
# skip if the socket isn't present.
if ! systemctl cat systemd-report-sign-tpm2.socket &>/dev/null; then
    echo "systemd-report-sign-tpm2.socket is not installed, skipping TPM2 report signing test."
    exit 0
fi

# We create the EK and verify the attestation signatures with the tpm2-tools.
if ! command -v tpm2_createek >/dev/null || \
   ! command -v tpm2_loadexternal >/dev/null || \
   ! command -v tpm2_verifysignature >/dev/null; then
    echo "tpm2-tools not installed, skipping TPM2 report signing test."
    exit 0
fi

WORK="$(mktemp -d)"

at_exit() {
    set +e
    systemctl stop systemd-report.socket systemd-report-sign-tpm2.socket
    rm -rf "$WORK"
}
trap at_exit EXIT

# The TPM2 backend creates its signing key as a child of the TPM's endorsement
# key. In a QEMU/swtpm guest there is no EK certificate, and the backend only
# provisions an EK when a matching certificate is present. Create and persist
# an EK directly. This fails if one already is already present, so ignore that.
if ! tpm2_createek -c 0x81010001 -G ecc; then
    echo "tpm2_createek failed, assuming an EK is already present."
fi

# The TPM2 backend reads the event log from pcrlock's Varlink interface, so make
# sure its socket is up.
systemctl start systemd-pcrlock.socket

systemctl start systemd-report.socket
systemctl start systemd-report-sign-tpm2.socket

# Ask systemd-report to generate a *signed* report over Varlink. The reply
# carries the signed report as base64-encoded JSON-SEQ data.
varlinkctl call /run/systemd/io.systemd.Report io.systemd.Report.GenerateSigned \
    '{"matches":["io.systemd.Manager.UnitsTotal"]}' | jq -r .reportData | base64 -d >"$WORK/report.seq"

# The first JSON-SEQ record is the report itself. This is exactly the byte
# sequence that got signed, including the leading record separator (0x1e) and
# the trailing newline, so 'head -n1' reproduces it verbatim.
head -n1 "$WORK/report.seq" >"$WORK/message.bin"
tr -d '\036' <"$WORK/message.bin" | jq -e '.mediaType == "application/vnd.io.systemd.report"' >/dev/null

# The remaining record(s) are signature objects, one per enabled backend. Pick
# out the one produced by the TPM2 backend (the plain backend may be enabled too).
sig_json=""
while IFS= read -r line; do
    rec="$(echo "$line" | tr -d '\036')"
    [[ -n "$rec" ]] || continue
    if [[ "$(echo "$rec" | jq -r '.mechanism // empty')" == "tpm2" ]]; then
        sig_json="$rec"
    fi
done < <(tail -n +2 "$WORK/report.seq")
test -n "$sig_json"

[ "$(echo "$sig_json" | jq -r .mediaType)" = "application/vnd.io.systemd.report.signature" ]

# The sha256 recorded in the signature must match the digest of the report bytes.
report_digest="$(sha256sum "$WORK/message.bin" | cut -d' ' -f1)"
[ "$(echo "$sig_json" | jq -r .sha256)" = "$report_digest" ]

# Decode a lowercase hex string (read from stdin) into raw bytes.
unhex() { tr '[:lower:]' '[:upper:]' | basenc --base16 -d; }

# 16-bit big-endian byte count of a hex string, as 4 hex digits.
be16_len() { printf '%04x' $(( ${#1} / 2 )); }

# TPM_ALG_ID values.
declare -A SIG_ALG_ID=( [RSASSA]=0014 [RSAPSS]=0016 [ECDSA]=0018 [ECSCHNORR]=001a )
declare -A HASH_ALG_ID=( [SHA1]=0004 [SHA256]=000b [SHA384]=000c [SHA512]=000d )

# Reconstruct the marshaled TPMT_SIGNATURE from a signature JSON object, so we
# can hand it to tpm2_verifysignature. The layout is:
#   sigAlg (UINT16) | hashAlg (UINT16) | <scheme specific>
# with the scheme-specific part being a size-prefixed signature buffer for RSA,
# or size-prefixed R and S buffers for ECC.
signature_to_tpm_hex() {
    local sig="${1:?}"
    local alg hash

    alg="$(echo "$sig" | jq -r .sigAlg)"
    hash="$(echo "$sig" | jq -r .signature.hash)"

    local out="${SIG_ALG_ID[$alg]:?unknown sigAlg $alg}${HASH_ALG_ID[$hash]:?unknown hash $hash}"

    case "$alg" in
        RSASSA|RSAPSS)
            local s
            s="$(echo "$sig" | jq -r .signature.sig)"
            out+="$(be16_len "$s")$s"
            ;;
        ECDSA|ECSCHNORR)
            local r s
            r="$(echo "$sig" | jq -r .signature.signatureR)"
            s="$(echo "$sig" | jq -r .signature.signatureS)"
            out+="$(be16_len "$r")$r$(be16_len "$s")$s"
            ;;
        *)
            echo "Unsupported signature algorithm $alg" >&2
            return 1
            ;;
    esac

    echo "$out"
}

# Load the attestation public key, which is already just the TPM2B_PUBLIC structure.
echo "$sig_json" | jq -r '.data["publicKey"]' | unhex >"$WORK/ak.pub"
tpm2_loadexternal -Q -C n -u "$WORK/ak.pub" -c "$WORK/ak.ctx"

# Verify every report component signature against the attestation blob, using
# the attestation public key.
n_components="$(echo "$sig_json" | jq '.data.components | length')"
[ "$n_components" -gt 0 ]

# The backend attests every defined NvPCR. Count them via systemd-analyze so
# we know how many components to expect.
expected_nvpcrs="$(systemd-analyze nvpcrs --json=short | jq 'length')"
[ "$expected_nvpcrs" -gt 0 ]

saw_pcr=0
saw_audit=0
n_nvpcr=0

for i in $(seq 0 $((n_components - 1))); do
    comp="$(echo "$sig_json" | jq -c ".data.components[$i]")"
    type="$(echo "$comp" | jq -r .type)"

    # The signed message is the serialized TPM2B_ATTEST attestation data.
    echo "$comp" | jq -r '.["attestInfo"]' | unhex >"$WORK/attest-$i.bin"

    # The hash algorithm used by the signing scheme, needed to digest the message.
    halg="$(echo "$comp" | jq -r .signature.signature.hash | tr '[:upper:]' '[:lower:]')"

    signature_to_tpm_hex "$(echo "$comp" | jq -c .signature)" | unhex >"$WORK/sig-$i.bin"

    tpm2_verifysignature -c "$WORK/ak.ctx" -g "$halg" \
        -m "$WORK/attest-$i.bin" -s "$WORK/sig-$i.bin"

    case "$type" in
        pcr)
            saw_pcr=1
            ;;
        nvcpr)
            n_nvpcr=$((n_nvpcr + 1))
            # NvPCR components additionally carry the readable name, the
            # serialized NV public area, and the authenticated data that was
            # digested into the attestation's qualifying data. Ensure they're
            # populated.
            [ -n "$(echo "$comp" | jq -r '.["nvpcrName"] // empty')" ]
            [ -n "$(echo "$comp" | jq -r '.["nvPublic"] // empty')" ]
            [ -n "$(echo "$comp" | jq -r '.["authenticatedData"] // empty')" ]
            ;;
        session-audit)
            saw_audit=1
            audit_comp="$comp"
            ;;
    esac
done

# Make sure we saw the expected components.
[ "$saw_pcr" -eq 1 ]
[ "$saw_audit" -eq 1 ]
[ "$n_nvpcr" -eq "$expected_nvpcrs" ]

# The report digest supplied over Varlink is passed as the qualifying data of
# the session audit attestation, so it must appear in the extraData field of
# that attestation's TPM2B_ATTEST blob. The relevant part of the serialized
# TPMS_ATTEST structure is:
#   magic          UINT32                 (4 bytes)
#   type           UINT16                 (2 bytes)
#   qualifiedSigner TPM2B_NAME            (UINT16 size + <size> bytes)
#   extraData      TPM2B_DATA             (UINT16 size + <size> bytes)
#   ...
# qualifiedSigner is variable length (it depends on the signing key's name
# algorithm), so parse its length to locate extraData rather than assuming a
# fixed offset.
attest_hex="$(echo "$audit_comp" | jq -r '.["attestInfo"]')"

# magic must be TPM_GENERATED_VALUE and type TPM_ST_ATTEST_SESSION_AUDIT (0x8016).
[ "${attest_hex:0:8}" = "ff544347" ]
[ "${attest_hex:8:4}" = "8016" ]

qs_size=$(( 16#${attest_hex:12:4} ))
ed_off=$(( 16 + qs_size * 2 ))
ed_size=$(( 16#${attest_hex:$ed_off:4} ))
ed_hex="${attest_hex:$((ed_off + 4)):$((ed_size * 2))}"

# The report is digested with SHA256 and the qualifying data is the serialized
# TPMT_HA of this.
[ "$ed_hex" = "000b${report_digest}" ]
