  - kubeadm init --cri-socket /run/containerd/containerd.sock
  - mkdir -p /home/${username}/.kube
  - sudo cp -i /etc/kubernetes/admin.conf /home/${username}/.kube/config
  - sudo chown ${username} /home/${username}/.kube/config
