#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -ex

export LC_CTYPE=C.UTF-8

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
clang_version="$($CC --version | sed -nr 's/.*version ([^ ]+?) .*/\1/p' | sed -r 's/-$//')"

SANITIZER=${SANITIZER:-address -fsanitize-address-use-after-scope}
flags="-O1 -fno-omit-frame-pointer -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER"

clang_lib="/usr/lib64/clang/${clang_version}/lib/linux"
[ -d "$clang_lib" ] || clang_lib="/usr/lib/clang/${clang_version}/lib/linux"

export CFLAGS=${CFLAGS:-$flags}
export CXXFLAGS=${CXXFLAGS:-$flags}
export LDFLAGS=${LDFLAGS:--L${clang_lib}}

export WORK=${WORK:-$(pwd)}
export OUT=${OUT:-$(pwd)/out}
mkdir -p "$OUT"

build="$WORK/build"
rm -rf "$build"
mkdir -p "$build"

if [ -z "$FUZZING_ENGINE" ]; then
    fuzzflag="llvm-fuzz=true"
else
    fuzzflag="oss-fuzz=true"

    apt-get update
    apt-get install -y gperf m4 gettext python3-pip \
        libcap-dev libmount-dev \
        pkg-config wget python3-jinja2 zipmerge

    if [[ "$ARCHITECTURE" == i386 ]]; then
        apt-get install -y pkg-config:i386 libcap-dev:i386 libmount-dev:i386
    fi

    # gnu-efi is installed here to enable -Dgnu-efi behind which fuzz-bcd
    # is hidden. It isn't linked against efi. It doesn't
    # even include "efi.h" because "bcd.c" can work in "unit test" mode
    # where it isn't necessary.
    apt-get install -y gnu-efi zstd

    pip3 install -r .github/workflows/requirements.txt --require-hashes

    # https://github.com/google/oss-fuzz/issues/6868
    ORIG_PYTHONPATH=$(python3 -c 'import sys;print(":".join(sys.path[1:]))')
    export PYTHONPATH="$ORIG_PYTHONPATH:/usr/lib/python3/dist-packages/"

    if [[ "$SANITIZER" == undefined ]]; then
        additional_ubsan_checks=pointer-overflow,alignment
        UBSAN_FLAGS="-fsanitize=$additional_ubsan_checks -fno-sanitize-recover=$additional_ubsan_checks"
        CFLAGS="$CFLAGS $UBSAN_FLAGS"
        CXXFLAGS="$CXXFLAGS $UBSAN_FLAGS"
    fi

    if [[ "$SANITIZER" == introspector ]]; then
        # fuzz-introspector passes -fuse-ld=gold and -flto using CFLAGS/LDFLAGS and due to
        # https://github.com/mesonbuild/meson/issues/6377#issuecomment-575977919 and
        # https://github.com/mesonbuild/meson/issues/6377 it doesn't mix well with meson.
        # It's possible to build systemd with duct tape there using something like
        # https://github.com/google/oss-fuzz/pull/7583#issuecomment-1104011067 but
        # apparently even with gold and lto some parts of systemd are missing from
        # reports (presumably due to https://github.com/google/oss-fuzz/issues/7598).
        # Let's just fail here for now to make it clear that fuzz-introspector isn't supported.
        exit 1
    fi
fi

if ! meson "$build" "-D$fuzzflag" -Db_lundef=false; then
    cat "$build/meson-logs/meson-log.txt"
    exit 1
fi

ninja -v -C "$build" fuzzers

# Compressed BCD files are kept in test/test-bcd so let's unpack them
# and put them all in the seed corpus.
bcd=$(mktemp -d)
for i in test/test-bcd/*.zst; do
     unzstd "$i" -o "$bcd/$(basename "${i%.zst}")";
done
zip -jqr "$OUT/fuzz-bcd_seed_corpus.zip" "$bcd"
rm -rf "$bcd"

hosts=$(mktemp)
wget -O "$hosts" https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
zip -jq "$OUT/fuzz-etc-hosts_seed_corpus.zip" "$hosts"
rm -rf "$hosts"

# The seed corpus is a separate flat archive for each fuzzer,
# with a fixed name ${fuzzer}_seed_corpus.zip.
for d in test/fuzz/fuzz-*; do
    zip -jqr "$OUT/$(basename "$d")_seed_corpus.zip" "$d"
done

# get fuzz-dns-packet corpus
df="$build/dns-fuzzing"
git clone --depth 1 https://github.com/CZ-NIC/dns-fuzzing "$df"
zip -jqr "$OUT/fuzz-dns-packet_seed_corpus.zip" "$df/packet"

install -Dt "$OUT/src/shared/" \
        "$build"/src/shared/libsystemd-shared-*.so \
        "$build"/src/core/libsystemd-core-*.so

# Most i386 libraries have to be brought to the runtime environment somehow. Ideally they
# should be linked statically but since it isn't possible another way to keep them close
# to the fuzz targets is used here. The dependencies are copied to "$OUT/src/shared" and
# then `rpath` is tweaked to make it possible for the linker to find them there. "$OUT/src/shared"
# is chosen because the runtime search path of all the fuzz targets already points to it
# to load "libsystemd-shared" and "libsystemd-core". Stuff like that should be avoided on
# x86_64 because it tends to break coverage reports, fuzz-introspector, CIFuzz and so on.
if [[ "$ARCHITECTURE" == i386 ]]; then
    for lib_path in $(ldd "$OUT"/src/shared/libsystemd-shared-*.so | perl -lne 'print $1 if m{=>\s+(/lib\S+)}'); do
        lib_name=$(basename "$lib_path")
        cp "$lib_path" "$OUT/src/shared"
        patchelf --set-rpath \$ORIGIN "$OUT/src/shared/$lib_name"
    done
    patchelf --set-rpath \$ORIGIN "$OUT"/src/shared/libsystemd-shared-*.so
fi

wget -O "$OUT/fuzz-json.dict" https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/json.dict

find "$build" -maxdepth 1 -type f -executable -name "fuzz-*" -exec mv {} "$OUT" \;
find src -type f -name "fuzz-*.dict" -exec cp {} "$OUT" \;
cp src/fuzz/*.options "$OUT"

if [[ "$MERGE_WITH_OSS_FUZZ_CORPORA" == "yes" ]]; then
    for f in "$OUT/"fuzz-*; do
        [[ -x "$f" ]] || continue
        fuzzer=$(basename "$f")
        t=$(mktemp)
        if wget -O "$t" "https://storage.googleapis.com/systemd-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/systemd_${fuzzer}/public.zip"; then
            zipmerge "$OUT/${fuzzer}_seed_corpus.zip" "$t"
        fi
        rm -rf "$t"
    done
fi
