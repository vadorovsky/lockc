#!/bin/bash

BASE_IMAGE="Arch-Linux.qcow2"
LOCKC_IMAGE="lockc-base.qcow2"

if [ ! -f ${BASE_IMAGE} ]; then
    wget -O ${BASE_IMAGE} \
        https://mirror.pkgbuild.com/images/v20210619.26314/Arch-Linux-x86_64-cloudimg-20210619.26314.qcow2
fi

rm -f ${LOCKC_IMAGE}
cp ${BASE_IMAGE} ${LOCKC_IMAGE}
qemu-img resize ${LOCKC_IMAGE} 40G
virt-resize --expand /dev/sda2 ${BASE_IMAGE} ${LOCKC_IMAGE}

virt-customize -a \
    ${LOCKC_IMAGE} \
    --copy-in ../install-lockc.sh:/usr/sbin/ \
    --run provision.sh
