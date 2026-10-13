#!/bin/sh
# Install the built libfprint and this sensor's key and calibration.
#
#   sudo ./install.sh --psk goodix.psk --windows /mnt/win
#
#   --psk FILE       the 32-byte TLS key as hex, from the Windows unseal step
#   --windows DIR    a mounted Windows partition (for the OTP calibration in
#                    ProgramData/Goodix/goodix.dat), or
#   --otp FILE       the 64-byte OTP already extracted with tools/extract_otp.py
#
# Run without --psk/--otp/--windows to only reinstall the library.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
DATA=/etc/goodix-521d
PSK= OTP= WIN=

while [ $# -gt 0 ]; do
    case "$1" in
        --psk) PSK=$2; shift 2 ;;
        --otp) OTP=$2; shift 2 ;;
        --windows) WIN=$2; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$HERE/libfprint/build/libfprint/libfprint-2.so" ] || { echo "run ./build.sh first" >&2; exit 1; }

systemctl stop fprintd 2>/dev/null || true

install -d -m 700 -o root -g root "$DATA"
if [ -n "$PSK" ]; then
    hex=$(tr -d ' \r\n' < "$PSK")
    case "$hex" in
        *[!0-9a-fA-F]*) echo "$PSK: not hex" >&2; exit 1 ;;
    esac
    [ ${#hex} -eq 64 ] || { echo "$PSK: expected 64 hex digits" >&2; exit 1; }
    (umask 077; printf '%s\n' "$hex" > "$DATA/psk")
fi
if [ -n "$WIN" ]; then
    python3 "$HERE/tools/extract_otp.py" "$WIN/ProgramData/Goodix/goodix.dat" "$DATA/otp.bin"
elif [ -n "$OTP" ]; then
    install -m 600 -o root -g root "$OTP" "$DATA/otp.bin"
fi
chmod 600 "$DATA"/* 2>/dev/null || true
[ -f "$DATA/psk" ] && [ -f "$DATA/otp.bin" ] || {
    echo "warning: $DATA needs both psk and otp.bin before the sensor will work" >&2; }

meson install -C "$HERE/libfprint/build" --no-rebuild --quiet
ldconfig

echo "Installed. Old prints from other drivers for this sensor won't match:"
echo "  fprintd-delete \$USER && fprintd-enroll"
