#cloud-config

hostname: ${hostname}
locale: ${locale}
timezone: ${timezone}

mounts:
  - [ lockc, /home/${username}/lockc, 9p, "trans=virtio,version=9p2000.L,rw", "0", "0" ]
  - [ kernel, /home/${username}/kernel, 9p, "trans=virtio,version=9p2000.L,rw", "0", "0" ]

users:
  - name: ${username}
    groups: users, docker
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
${authorized_keys}

runcmd:
  - install-lockc.sh
  - systemctl restart containerd.service docker.service
  - systemctl enable --now lockcd.service
${commands}
