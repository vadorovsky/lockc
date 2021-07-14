#!/bin/bash

zypper install -y -t pattern \
       devel_basis \
       devel_C_C++
zypper install -y \
       bpftool \
       cargo \
       clang \
       conntrack-tools \
       containerd \
       docker \
       ebtables \
       ethtool \
       libbpf-devel \
       libopenssl-devel \
       llvm \
       podman \
       podman-cni-config \
       rust \
       rustfmt \
       socat \
       tmux \
       wget

sed -i -e "s/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"lsm=bpf,integrity\"/" \
    /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
