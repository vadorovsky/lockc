#!/bin/bash

# This script is intended to be running INSIDE guestfs.

set -eux

# TODO(vadorovsky): This is a wacky workaround for even more wackier problem
# with resolv.conf in guestfs. Seems like sysconfig-netconfig is somehow
# messing up with how guestfs is generating resolv.conf. That problem is
# specific for openSUSE.
# 169.254.2.3 is the host's address in qemu user mode networking.
echo "nameserver 169.254.2.3" > /etc/resolv.conf

# Install mainline kernel
rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
dnf -y install https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
dnf --enablerepo=elrepo-kernel -y install kernel-ml
sed -i -e "s|GRUB_DEFAULT.*$|GRUB_DEFAULT=0|" /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
