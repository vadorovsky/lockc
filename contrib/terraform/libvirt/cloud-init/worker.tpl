  - kubeadm join ${control_plane_ip}:6443 --cri-socket /run/containerd/containerd.sock --token ${kubeadm_token} --discovery-token-unsafe-skip-ca-verification
