#!/bin/bash

# This script is intended to be running INSIDE guestfs.

set -eux

# TODO(vadorovsky): This is a wacky workaround for even more wackier problem
# with resolv.conf in guestfs. Seems like sysconfig-netconfig is somehow
# messing up with how guestfs is generating resolv.conf. That ptoblem is
# specific for openSUSE.
echo "nameserver 169.254.2.3" > /etc/resolv.conf

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
    strace \
    tmux \
    wget


# TODO(vadorovsky): Include BPF as an enabled LSM in openSUSE kernel config.
sed -i -e "s/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"lsm=bpf,integrity\"/" \
    /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

systemctl enable containerd
systemctl enable docker

# TODO(vadorovsky): Try to use CNI from openSUSE packages.
CNI_VERSION="v0.9.1"
mkdir -p /opt/cni/bin
curl -L "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-amd64-${CNI_VERSION}.tgz" | tar -C /opt/cni/bin -xz

DOWNLOAD_DIR=/usr/local/bin
mkdir -p $DOWNLOAD_DIR

# TODO(vadorovsky): Try to use CRI from openSUSE packages.
CRI_TOOLS_VERSION="v1.21.0"
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$CRI_TOOLS_VERSION/crictl-$CRI_TOOLS_VERSION-linux-amd64.tar.gz
tar zxvf crictl-$CRI_TOOLS_VERSION-linux-amd64.tar.gz -C /usr/local/bin
rm -f crictl-$CRI_TOOLS_VERSION-linux-amd64.tar.gz

# Use vanilla kubeadm instead of Kubic kubeadm.
RELEASE="$(curl -sSL https://dl.k8s.io/release/stable.txt)"
cd $DOWNLOAD_DIR
curl -L --remote-name-all https://storage.googleapis.com/kubernetes-release/release/${RELEASE}/bin/linux/amd64/{kubeadm,kubelet,kubectl}
chmod +x {kubeadm,kubelet,kubectl}

RELEASE_VERSION="v0.9.0"
curl -sSL "https://raw.githubusercontent.com/kubernetes/release/${RELEASE_VERSION}/cmd/kubepkg/templates/latest/deb/kubelet/lib/systemd/system/kubelet.service" | sed "s:/usr/bin:${DOWNLOAD_DIR}:g" | tee /etc/systemd/system/kubelet.service
mkdir -p /etc/systemd/system/kubelet.service.d
curl -sSL "https://raw.githubusercontent.com/kubernetes/release/${RELEASE_VERSION}/cmd/kubepkg/templates/latest/deb/kubeadm/10-kubeadm.conf" | sed "s:/usr/bin:${DOWNLOAD_DIR}:g" | tee /etc/systemd/system/kubelet.service.d/10-kubeadm.conf

systemctl enable kubelet
