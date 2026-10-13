#!/bin/sh
# Build libfprint 1.94.10 with the goodix521d driver into ./libfprint/build.
#
# Debian/Ubuntu build dependencies:
#   sudo apt install git meson ninja-build gcc g++ pkg-config \
#     libglib2.0-dev libgusb-dev libgudev-1.0-dev libpixman-1-dev libssl-dev \
#     libopencv-features2d-dev libopencv-imgproc-dev libopencv-core-dev
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$HERE/libfprint
VERSION=v1.94.10

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$VERSION" \
        https://gitlab.freedesktop.org/libfprint/libfprint.git "$SRC"
    git -C "$SRC" apply "$HERE/libfprint-v1.94.10.patch"
fi

mkdir -p "$SRC/libfprint/drivers/goodix521d"
cp "$HERE"/driver/* "$SRC/libfprint/drivers/goodix521d/"

if [ ! -d "$SRC/build" ]; then
    meson setup "$SRC/build" "$SRC" \
        -Dintrospection=false -Ddoc=false -Dinstalled-tests=false \
        -Dgtk-examples=false -Dudev_hwdb=disabled -Dudev_rules=disabled
fi
ninja -C "$SRC/build"

echo
echo "Built $SRC/build/libfprint/libfprint-2.so. Next: sudo ./install.sh (see README)."
