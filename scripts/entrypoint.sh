#!/bin/bash

set -eux

# A simple entrypoint script which calls Meson inside a container and then
# ensures that all produced files are owned by a regular user.

export CC=${CLANG:-clang-12}
PREFIX=${PREFIX:-/usr/local}
USER_ID=${USER_ID:-1000}
GROUP_ID=${GROUP_ID:-100}

rm -rf build

meson build --prefix ${PREFIX}

pushd build
meson compile
popd

chown -R ${USER_ID}:${GROUP_ID} .
