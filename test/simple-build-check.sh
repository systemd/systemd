#/bin/sh

EXTRA="extras/chassis_id extras/scsi_id extras/volume_id"

make spotless EXTRAS="$EXTRA" >/dev/null
make all EXTRAS="$EXTRA" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRA" >/dev/null
make all DEBUG=true EXTRAS="$EXTRA"  || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRA" >/dev/null
make all USE_LOG=false EXTRAS="$EXTRA"  || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRA" >/dev/null
make all USE_KLIBC=true DEBUG=true EXTRAS="$EXTRA" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRA" >/dev/null
make all USE_KLIBC=true USE_LOG=false EXTRAS="$EXTRA" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRA" >/dev/null

