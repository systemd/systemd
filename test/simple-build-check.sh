#/bin/sh

EXTRAS="extras/chassis_id extras/scsi_id extras/volume_id"

[ -z "$KERNEL_DIR" ] && KERNEL_DIR=/lib/modules/`uname -r`/build
echo KERNEL_DIR: "$KERNEL_DIR"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all EXTRAS="$EXTRAS" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all DEBUG=true EXTRAS="$EXTRAS"  || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all USE_LOG=false EXTRAS="$EXTRAS"  || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all USE_KLIBC=true DEBUG=true EXTRAS="$EXTRAS" KERNEL_DIR="$KERNEL_DIR" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all USE_KLIBC=true USE_LOG=false EXTRAS="$EXTRAS" KERNEL_DIR="$KERNEL_DIR" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null

