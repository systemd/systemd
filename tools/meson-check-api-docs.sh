#!/bin/sh
set -eu

sd_good=0
sd_total=0
udev_good=0
udev_total=0

for symbol in `nm -g --defined-only "$@" | grep " T " | cut -d" " -f3 | sort -u` ; do
    if test -f ${MESON_BUILD_ROOT}/man/$symbol.3 ; then
        echo "✓ Symbol $symbol() is documented."
        good=1
    else
        printf "  \x1b[1;31mSymbol $symbol() lacks documentation.\x1b[0m\n"
        good=0
    fi

    case $symbol in
        sd_*)
            ((sd_good+=good))
            ((sd_total+=1))
            ;;
        udev_*)
            ((udev_good+=good))
            ((udev_total+=1))
            ;;
        *)
            echo 'unknown symbol prefix'
            exit 1
    esac
done

echo "libsystemd: $sd_good/$sd_total libudev: $udev_good/$udev_total"
