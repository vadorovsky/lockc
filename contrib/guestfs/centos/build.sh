#!/bin/bash

# This script builds the base qcow2 image for lockc development environment.

BASE_IMAGE="CentOS-8-GenericCloud-8.4.qcow2"
LOCKC_IMAGE="lockc-base.qcow2"

if [ ! -f ${BASE_IMAGE} ]; then
    wget -O ${BASE_IMAGE} \
        https://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2
fi

rm -f ${LOCKC_IMAGE}
cp ${BASE_IMAGE} ${LOCKC_IMAGE}
qemu-img resize ${LOCKC_IMAGE} 40G
virt-resize --expand /dev/sda1 ${BASE_IMAGE} ${LOCKC_IMAGE}

virt-customize -a \
    ${LOCKC_IMAGE} \
    --copy-in ../install-lockc.sh:/usr/sbin/ \
    --run provision.sh
