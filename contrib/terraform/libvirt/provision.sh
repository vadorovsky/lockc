#!/bin/bash

if [ -z "${ENABLE_DOCKER}" ] || [ -z "${ENABLE_K8S_CONTAINERD}" ]; then
    error '$ENABLE_DOCKER $ENABLE_K8S_CONTAINERD must be specified'
    exit 1
fi

# ensure running as root
if [ "$(id -u)" != "0" ]; then
  exec sudo "$0" "$@"
fi

set -eux

# TODO(vadorovsky): Include BPF as an enabled LSM in openSUSE kernel config.
sed -i -e "s/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"lsm=bpf,integrity\"/" \
    /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

# Load br_netfilter
cat >> /etc/modules-load.d/99-k8s.conf << EOF
br_netfilter
EOF

# Network-related sysctls
cat >> /etc/sysctl.d/99-k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
EOF

# Add 9p drivers to dracut
cat >> /etc/dracut.conf.d/90-9p.conf << EOF
# Add 9p 9pnet and 9pnet_virtio modules
add_drivers+=" 9p 9pnet 9pnet_virtio "
EOF

# Rebuild initrd with dracut
mkinitrd

if [[ ${ENABLE_DOCKER} == "true" ]]; then
    DOCKER_VERSION=$(curl -s https://api.github.com/repos/moby/moby/releases/latest | jq -r '.tag_name' | sed -e 's/^v//')
    curl -L "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" | sudo tar -C /usr/local/bin -xz

    systemctl enable docker
fi

if [[ ${ENABLE_K8S_CONTAINERD} == "true" ]]; then
    CONTAINERD_URL=$(curl -s https://api.github.com/repos/containerd/containerd/releases/latest | jq -r '.assets[] | select(.browser_download_url | contains("cri-containerd-cni") and endswith("linux-amd64.tar.gz")) | .browser_download_url')
    curl -L "${CONTAINERD_URL}" | sudo tar --no-overwrite-dir -C / -xz

    systemctl enable containerd

    CNI_VERSION=$(curl -s https://api.github.com/repos/containernetworking/plugins/releases/latest | jq -r '.tag_name')
    ARCH="amd64"
    mkdir -p /opt/cni/bin
    curl -L "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz" | sudo tar -C /opt/cni/bin -xz

    DOWNLOAD_DIR=/usr/local/bin
    mkdir -p $DOWNLOAD_DIR

    RELEASE="$(curl -sSL https://dl.k8s.io/release/stable.txt)"
    cd $DOWNLOAD_DIR
    curl -L --remote-name-all https://storage.googleapis.com/kubernetes-release/release/${RELEASE}/bin/linux/amd64/{kubeadm,kubelet,kubectl}
    chmod +x {kubeadm,kubelet,kubectl}

    RELEASE_VERSION=$(curl -s https://api.github.com/repos/kubernetes/release/releases/latest | jq -r '.name')
    curl -sSL "https://raw.githubusercontent.com/kubernetes/release/${RELEASE_VERSION}/cmd/kubepkg/templates/latest/deb/kubelet/lib/systemd/system/kubelet.service" | sed "s:/usr/bin:${DOWNLOAD_DIR}:g" | tee /etc/systemd/system/kubelet.service
    mkdir -p /etc/systemd/system/kubelet.service.d
    curl -sSL "https://raw.githubusercontent.com/kubernetes/release/${RELEASE_VERSION}/cmd/kubepkg/templates/latest/deb/kubeadm/10-kubeadm.conf" | sed "s:/usr/bin:${DOWNLOAD_DIR}:g" | tee /etc/systemd/system/kubelet.service.d/10-kubeadm.conf

    systemctl enable kubelet
fi

exit 0
